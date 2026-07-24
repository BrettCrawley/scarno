# Copyright 2026 Brett Crawley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Go module manifest parser — REQ-13.

Parses ``go.mod``, ``go.sum``, and ``vendor/modules.txt`` into a unified
list of :class:`Dependency` objects with ``ecosystem="go"``.

Safety:
  * Line-length cap (SEC-NEW-24) — lines > 10 KB are skipped.
  * File-size cap (``MAX_FILE_BYTES``) on every input.
  * No shell invocations — strictly static file inspection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from scarno.findings.rules import RULES
from scarno.models import Dependency, DependencyStatus, Finding
from scarno.security import MAX_FILE_BYTES, sanitise

_STUB_REASON = "declared — source analysis pending"
_MAX_LINE_LEN = 10_240  # SEC-NEW-24: skip lines > 10 KB
_MAX_SNIPPET = 200


@dataclass
class _RawDep:
    name: str
    version: str | None
    source: str
    indirect: bool = False


@dataclass
class _GoParseResult:
    deps: list[_RawDep] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


# ── Public coordinator ─────────────────────────────────────────────────────


def parse_all_go_dependency_files(
    project_path: str,
) -> tuple[list[Dependency], list[str], list[Finding]]:
    """Return ``(dependencies, errors, findings)``. Never raises."""
    errors: list[str] = []
    findings: list[Finding] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"go: could not resolve project path — {exc}")
        return [], errors, findings
    if not root.is_dir():
        return [], errors, findings

    result = _GoParseResult()

    _parse_go_mod(root, result)
    _parse_go_sum(root, result)
    _check_vendor(root, result)

    errors.extend(result.errors)
    findings.extend(result.findings)

    deps = _deduplicate(result.deps)
    return deps, errors, findings


# ── Helpers ────────────────────────────────────────────────────────────────


def _read_lines(path: Path, result: _GoParseResult) -> list[str] | None:
    """Size-capped line reader; returns None if unreadable."""
    if not path.exists():
        return None
    try:
        size = path.stat().st_size
    except OSError as exc:
        result.errors.append(f"{path.name}: stat failed — {exc}")
        return None
    if size > MAX_FILE_BYTES:
        result.errors.append(f"{path.name}: exceeds size limit; skipped")
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path.name}: read failed — {exc}")
        return None
    return text.splitlines()


# ── go.mod ─────────────────────────────────────────────────────────────────

# Directives we handle
_REQUIRE_RE = re.compile(r"^\s*(?P<path>\S+)\s+(?P<version>\S+)")
_REPLACE_RE = re.compile(
    r"^\s*(?P<old>\S+)\s+(?:\S+\s+)?=>\s+(?P<new>\S+)(?:\s+(?P<ver>\S+))?"
)
_EXCLUDE_RE = re.compile(r"^\s*(?P<path>\S+)\s+(?P<version>\S+)")


def _parse_go_mod(root: Path, result: _GoParseResult) -> None:
    lines = _read_lines(root / "go.mod", result)
    if lines is None:
        return

    # State machine: outside / inside require()/replace()/exclude()/retract()
    block: str | None = None
    excludes: set[tuple[str, str]] = set()
    replaces: dict[str, tuple[str, str | None]] = {}  # old → (new, ver)

    for raw_line in lines:
        if len(raw_line) > _MAX_LINE_LEN:
            result.errors.append(
                f"go.mod: line exceeds {_MAX_LINE_LEN} chars; skipped"
            )
            continue

        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        # Block open
        if line.startswith("require") and "(" in line:
            block = "require"
            continue
        if line.startswith("replace") and "(" in line:
            block = "replace"
            continue
        if line.startswith("exclude") and "(" in line:
            block = "exclude"
            continue
        if line.startswith("retract"):
            if "(" in line:
                block = "retract"
            # Single-line retract — skip (applies to THIS module's own versions)
            continue
        if line == ")":
            block = None
            continue

        # Single-line directives
        if block is None:
            if line.startswith("require "):
                _handle_require_line(line[len("require "):], result)
            elif line.startswith("replace "):
                _handle_replace_line(line[len("replace "):], replaces, result)
            elif line.startswith("exclude "):
                _handle_exclude_line(line[len("exclude "):], excludes)
            continue

        # Inside a block
        if block == "require":
            _handle_require_line(line, result)
        elif block == "replace":
            _handle_replace_line(line, replaces, result)
        elif block == "exclude":
            _handle_exclude_line(line, excludes)
        # retract block lines: silently consumed

    # Apply replaces
    for dep in result.deps:
        if dep.name in replaces:
            new_path, new_ver = replaces[dep.name]
            if new_path.startswith("./") or new_path.startswith("../"):
                dep.version = "local"
            else:
                dep.name = dep.name  # keep original name for matching
                if new_ver:
                    dep.version = new_ver

    # Apply excludes
    result.deps = [
        d
        for d in result.deps
        if (d.name, d.version or "") not in excludes
    ]


def _handle_require_line(line: str, result: _GoParseResult) -> None:
    m = _REQUIRE_RE.match(line)
    if not m:
        return
    indirect = "// indirect" in line
    result.deps.append(
        _RawDep(
            name=m.group("path"),
            version=m.group("version"),
            source="go.mod:require" + (" (indirect)" if indirect else ""),
            indirect=indirect,
        )
    )


def _handle_replace_line(
    line: str,
    replaces: dict[str, tuple[str, str | None]],
    result: _GoParseResult,
) -> None:
    m = _REPLACE_RE.match(line)
    if not m:
        return
    old = m.group("old")
    new = m.group("new")
    ver = m.group("ver")
    replaces[old] = (new, ver)

    # TS-DS-002: remote URL replace
    if new.startswith("https://") or new.startswith("http://"):
        rule = RULES["TS-DS-002"]
        result.findings.append(
            Finding(
                rule_id="TS-DS-002",
                kind=rule.kind,
                severity=rule.severity,
                file_path="go.mod",
                line=1,
                snippet=sanitise(f"replace {old} => {new}")[:_MAX_SNIPPET],
                message=rule.message,
                remediation=rule.remediation,
            )
        )


def _handle_exclude_line(
    line: str, excludes: set[tuple[str, str]]
) -> None:
    m = _EXCLUDE_RE.match(line)
    if m:
        excludes.add((m.group("path"), m.group("version")))


# ── go.sum ─────────────────────────────────────────────────────────────────


def _parse_go_sum(root: Path, result: _GoParseResult) -> None:
    """Override dep versions with what go.sum actually resolved."""
    lines = _read_lines(root / "go.sum", result)
    if lines is None:
        return

    # go.sum format: `module version hash`
    # Each module typically has two entries (archive + go.mod hash).
    resolved: dict[str, str] = {}
    for raw_line in lines:
        if len(raw_line) > _MAX_LINE_LEN:
            continue
        parts = raw_line.strip().split()
        if len(parts) < 3:
            continue
        name = parts[0]
        version = parts[1]
        # Strip `/go.mod` suffix from version
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        resolved[name] = version

    # Merge: if go.sum has a resolved version, override go.mod's
    for dep in result.deps:
        if dep.name in resolved:
            dep.version = resolved[dep.name]


# ── vendor/modules.txt ─────────────────────────────────────────────────────


def _check_vendor(root: Path, result: _GoParseResult) -> None:
    """Cross-check vendor/modules.txt against go.mod declarations."""
    vendor_path = root / "vendor" / "modules.txt"
    lines = _read_lines(vendor_path, result)
    if lines is None:
        return

    # Parse module names from `# module version` lines
    vendored_modules: set[str] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("# ") and not line.startswith("## "):
            parts = line[2:].split()
            if parts:
                vendored_modules.add(parts[0])

    declared_names = {d.name for d in result.deps}

    # Mark vendored deps
    for dep in result.deps:
        if dep.name in vendored_modules:
            dep.source = dep.source + " (vendored)"

    # Flag stowaways: in vendor but not in go.mod
    for mod in vendored_modules:
        if mod not in declared_names:
            result.errors.append(
                f"vendor/modules.txt lists {mod} but it is not in go.mod — "
                f"vendor directory may be stale"
            )

    # Flag missing: in go.mod but not vendored
    for name in declared_names:
        if name not in vendored_modules:
            result.errors.append(
                f"go.mod requires {name} but vendor/modules.txt does not "
                f"list it — run `go mod vendor` to sync"
            )


# ── Deduplication ──────────────────────────────────────────────────────────


def _deduplicate(raw: list[_RawDep]) -> list[Dependency]:
    """Produce final Dependency list, deduped by module path."""
    by_name: dict[str, _RawDep] = {}
    for dep in raw:
        if not dep.name:
            continue
        existing = by_name.get(dep.name)
        if existing is None:
            by_name[dep.name] = dep
        else:
            # Prefer the version from go.sum (which replaces in-place)
            if dep.version and not existing.version:
                by_name[dep.name] = dep

    return [
        Dependency(
            name=d.name,
            version=d.version,
            status=DependencyStatus.UNCERTAIN,
            reason=_STUB_REASON + (" (indirect)" if d.indirect else ""),
            entry_points=[],
            entry_points_used=0,
            entry_points_total=0,
            source=d.source,
            ecosystem="go",
        )
        for d in by_name.values()
    ]
