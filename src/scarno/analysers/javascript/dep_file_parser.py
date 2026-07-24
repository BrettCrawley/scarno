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

"""JavaScript / TypeScript / Node.js dependency file parser — REQ-10.

Parses the full npm-ecosystem manifest + lock surface (plus Deno) into a
unified list of :class:`Dependency` objects with ``ecosystem="npm"``.
Every dep carries ``status=UNCERTAIN`` until the REQ-11 source analyser
refines it.

Safety:
  * JSON parse errors are caught; depth-cap enforced on nested objects
    to prevent JSON bombs (SEC-NEW-20).
  * YAML parsed via ``yaml.safe_load`` only (SEC-NEW-21).
  * ``bun.lockb`` (binary) is refused with a warning — no attempt to
    decode a native-format file (FR-106).
  * File-size cap (``MAX_FILE_BYTES``) on every input.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from scarno.models import (
    Dependency,
    DependencyStatus,
    DepEdge,
    Finding,
    FindingSeverity,
)
from scarno.findings.rules import RULES
from scarno.models import FindingKind
from scarno.security import (
    LOCKFILE_MAX_BYTES,
    LOCKFILE_MAX_EDGES,
    MAX_FILE_BYTES,
    sanitise,
    sanitise_declared_version,
)


def _emit_npm_edge(
    result: "_NpmParseResult",
    parent: str,
    child: str,
    declared_version: str | None,
) -> None:
    """REQ-19 — append one DepEdge to ``result.edges`` with sanitised version.

    Stops appending silently once ``LOCKFILE_MAX_EDGES`` is reached so a
    crafted lockfile cannot exhaust memory via the edge list itself
    (SEC-NEW-37). Caller should additionally check ``len(result.edges)
    >= LOCKFILE_MAX_EDGES`` and emit a truncation note when the cap is
    first crossed.
    """
    if len(result.edges) >= LOCKFILE_MAX_EDGES:
        return
    result.edges.append(
        DepEdge(
            parent=parent,
            child=child,
            declared_version=sanitise_declared_version(declared_version),
        )
    )

_STUB_REASON = "declared — source analysis pending"
_MAX_JSON_DEPTH = 1000
_MAX_SNIPPET = 200

# REQ-18 / FR-180 — DefinitelyTyped @types/* runtime-pair recognition.
# ``@types/lodash`` → runtime ``lodash``.
# ``@types/node-fetch`` → runtime ``node-fetch`` (hyphenated).
# ``@types/scope__pkg`` → runtime ``@scope/pkg`` (double-underscore is the
# DefinitelyTyped convention for the scope separator).
_TYPES_PACKAGE_RE = re.compile(r"^@types/(?P<runtime>.+)$")


def _runtime_target_for_types_stub(name: str) -> str | None:
    """Return the runtime npm package name a ``@types/X`` stub describes,
    or ``None`` when ``name`` isn't a ``@types/*`` package.

    Per the DefinitelyTyped convention, scoped runtime packages are
    encoded with ``__`` as the scope separator: ``@types/foo__bar``
    pairs with ``@foo/bar``. The result is re-validated by the caller
    against ``_is_valid_npm_name`` (SEC-NEW-36) before being used as
    a key.
    """
    m = _TYPES_PACKAGE_RE.match(name)
    if m is None:
        return None
    inner = m.group("runtime")
    if "__" in inner:
        scope, _, rest = inner.partition("__")
        return f"@{scope}/{rest}"
    return inner

# npm package-name spec: optional `@scope/` prefix + name. Allows
# lowercase letters, digits, `-`, `.`, `_`, `~`. Explicitly excludes `..`
# segments, `/` other than the scope separator, backslashes, and any
# absolute-path-shaped construct so attacker-controlled names cannot be
# interpolated into filesystem paths under ``node_modules`` (SEC-002).
_NPM_NAME_RE = re.compile(
    r"^(?:@[a-z0-9_~][a-z0-9._~-]*\/)?[a-z0-9_~][a-z0-9._~-]*$",
    re.IGNORECASE,
)


def _is_valid_npm_name(name: str) -> bool:
    """Return True if ``name`` is a syntactically valid npm package name.

    Used to gate every parsed dep before it reaches downstream code that
    interpolates the name into a filesystem path
    (``node_modules/<name>/package.json``). A failing name would let an
    attacker traverse outside the project root via ``..`` segments
    (SEC-002).
    """
    if not name or len(name) > 214:  # npm spec hard limit
        return False
    if name.startswith(".") or name.startswith("_"):
        return False
    if ".." in name or "\\" in name:
        return False
    return bool(_NPM_NAME_RE.match(name))

# Precedence of dep files (higher wins on version conflict). Mirrors
# the Python-side precedence semantics from REQ-2.
_PRECEDENCE: dict[str, int] = {
    "bun.lock": 80,
    "pnpm-lock.yaml": 75,
    "yarn.lock": 70,
    "package-lock.json": 65,
    "npm-shrinkwrap.json": 65,
    "deno.lock": 60,
    "package.json": 40,
    "deno.json": 35,
    "deno.jsonc": 35,
}

# Lifecycle hooks that execute code at install time (TS-SI-007).
_INSTALL_HOOKS: tuple[str, ...] = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
)


@dataclass
class _RawDep:
    name: str
    version: str | None
    source: str


@dataclass
class _NpmParseResult:
    deps: list[_RawDep] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # REQ-19 — per-edge declared versions emitted by lockfile parsers.
    # Empty for parsers that don't yet emit edges (e.g. package.json
    # alone — no parent→child relationships visible without a lockfile).
    edges: list["DepEdge"] = field(default_factory=list)  # noqa: F821 — forward ref


class _NpmReturnValue(tuple[list[Dependency], list[str], list["Finding"]]):
    """3-tuple return preserving back-compat unpacking with an attached
    ``.edges`` attribute carrying REQ-19 ``DepEdge`` records.

    Existing callers do ``deps, errors, findings = parse_all_npm_dependency_files(...)``
    — they continue to work, since iteration yields exactly 3 elements.
    REQ-19-aware callers read ``result.edges`` via attribute access.
    """

    edges: list["DepEdge"]  # noqa: F821 — type annotation only; populated in __new__

    def __new__(
        cls,
        deps: list[Dependency],
        errors: list[str],
        findings: list[Finding],
        edges: list["DepEdge"],  # noqa: F821
    ) -> "_NpmReturnValue":
        instance = super().__new__(cls, (deps, errors, findings))
        instance.edges = edges
        return instance


# ── Public coordinator ─────────────────────────────────────────────────────


def parse_all_npm_dependency_files(
    project_path: str,
    *,
    exclude_dev: bool = False,
) -> "_NpmReturnValue":
    """Return ``(dependencies, errors, findings)``. Never raises.

    REQ-17: ``exclude_dev`` drops every dep whose ``source`` label denotes
    npm ``devDependencies`` (e.g. ``package.json:devDependencies``).
    """
    errors: list[str] = []
    findings: list[Finding] = []
    edges: list["DepEdge"] = []  # noqa: F821 — REQ-19, forward ref
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"javascript: could not resolve project path — {exc}")
        return _NpmReturnValue([], errors, findings, edges)
    if not root.is_dir():
        return _NpmReturnValue([], errors, findings, edges)

    raw_deps: list[_RawDep] = []

    # Order matters for precedence; we collect everything then dedup.
    for handler in (
        _parse_package_json,
        _parse_package_lock_json,
        _parse_npm_shrinkwrap_json,
        _parse_yarn_lock,
        _parse_pnpm_lock_yaml,
        _parse_bun_lock,
        _parse_bun_lockb,
        _parse_deno_json,
        _parse_deno_lock,
    ):
        result = handler(root)
        raw_deps.extend(result.deps)
        errors.extend(result.errors)
        findings.extend(result.findings)
        edges.extend(result.edges)

    # npmrc scan (security finding — not a dep)
    findings.extend(_scan_npmrc(root, errors))

    # REQ-17 — drop devDependencies when --exclude-dev is on.
    if exclude_dev:
        raw_deps = [
            r for r in raw_deps
            if "devDependencies" not in r.source
        ]

    deps = _deduplicate(raw_deps, errors)
    # REQ-18 / FR-180 — pair @types/X stubs with runtime X. ``is_type_stub``
    # is set on the stub; the source-analyser later resolves the runtime
    # state to refine the stub's ``status`` and ``reason``.
    declared_names = {d.name for d in deps}
    paired_deps: list[Dependency] = []
    for dep in deps:
        runtime_target = _runtime_target_for_types_stub(dep.name)
        if runtime_target is None:
            paired_deps.append(dep)
            continue
        # SEC-NEW-36 — re-validate the derived runtime name against the
        # npm validator. A malicious ``@types/<traversal>`` would have
        # been rejected upstream by ``_is_valid_npm_name`` already, but
        # this is defence-in-depth in case any future code path bypasses
        # ``_deduplicate``.
        if not _is_valid_npm_name(runtime_target):
            paired_deps.append(dep)
            continue
        runtime_present = runtime_target in declared_names
        reason = (
            f"type stubs for {runtime_target!r} which is declared as a "
            f"dependency"
            if runtime_present
            else (
                f"type stub for {runtime_target!r} but runtime package "
                f"not found in declared dependencies — manual review "
                f"required"
            )
        )
        paired_deps.append(
            Dependency(
                name=dep.name,
                version=dep.version,
                status=dep.status,
                reason=reason,
                entry_points=list(dep.entry_points),
                entry_points_used=dep.entry_points_used,
                entry_points_total=dep.entry_points_total,
                source=dep.source,
                vendored_path=dep.vendored_path,
                resolved=dep.resolved,
                is_type_stub=True,
                ecosystem=dep.ecosystem,
                is_transitive=dep.is_transitive,
            )
        )
    # REQ-19 (SEC-NEW-37) — enforce the global edge cap across all
    # parsers' contributions; we may have collected up to N edges per
    # parser, but the final return is bounded to LOCKFILE_MAX_EDGES.
    if len(edges) > LOCKFILE_MAX_EDGES:
        truncated = len(edges) - LOCKFILE_MAX_EDGES
        edges = edges[:LOCKFILE_MAX_EDGES]
        errors.append(
            f"npm dep_edges: edge cap reached "
            f"({LOCKFILE_MAX_EDGES} edges); {truncated} further edges "
            f"truncated."
        )
    # REQ-23 — extract overrides + flag matching direct deps as pin_override.
    overrides = _extract_overrides(root, errors=errors)
    _detect_npm_pin_overrides(paired_deps, overrides)
    return _NpmReturnValue(paired_deps, errors, findings, edges)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _read_json_bounded(
    path: Path, result: _NpmParseResult
) -> dict[str, Any] | None:
    """Size-capped, depth-capped JSON load."""
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
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.errors.append(f"{path.name}: JSON parse error — {exc}")
        return None
    except RecursionError:
        result.errors.append(
            f"{path.name}: JSON nesting exceeds safe depth; skipped"
        )
        return None
    if not _check_depth(data, _MAX_JSON_DEPTH):
        result.errors.append(
            f"{path.name}: JSON nesting exceeds {_MAX_JSON_DEPTH}; skipped"
        )
        return None
    if not isinstance(data, dict):
        result.errors.append(f"{path.name}: root must be a JSON object")
        return None
    return data


def _check_depth(value: Any, limit: int) -> bool:
    """Iterative depth check — returns False if nesting exceeds ``limit``.

    Iterative (explicit stack) so very deep payloads don't overflow
    Python's own recursion limit before the cap is reached — the guard
    needs to win the race against the interpreter (SEC-NEW-20).
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return False
        if isinstance(node, dict):
            for v in node.values():
                stack.append((v, depth + 1))
        elif isinstance(node, list):
            for v in node:
                stack.append((v, depth + 1))
    return True


def _strip_json_comments(text: str) -> str:
    """Strip // and /* */ comments — used for JSONC (bun.lock, deno.jsonc).

    Conservative: doesn't strip inside string literals. Good enough for
    JSONC which doesn't use nested tricks.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    string_char = ""
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                # line comment
                end = text.find("\n", i)
                if end < 0:
                    return "".join(out)
                i = end
                continue
            if nxt == "*":
                # block comment
                end = text.find("*/", i + 2)
                if end < 0:
                    return "".join(out)
                i = end + 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


# ── package.json ────────────────────────────────────────────────────────────


def _parse_package_json(root: Path) -> _NpmParseResult:
    result = _NpmParseResult()
    for name in ("package.json",):
        path = root / name
        if not path.exists():
            continue
        data = _read_json_bounded(path, result)
        if data is None:
            continue
        for section, label in (
            ("dependencies", "package.json:dependencies"),
            ("devDependencies", "package.json:devDependencies"),
            ("peerDependencies", "package.json:peerDependencies"),
            ("optionalDependencies", "package.json:optionalDependencies"),
        ):
            entries = data.get(section)
            if not isinstance(entries, dict):
                continue
            for pkg, ver in entries.items():
                if not isinstance(pkg, str):
                    continue
                version = ver if isinstance(ver, str) else None
                result.deps.append(
                    _RawDep(name=pkg, version=version, source=label)
                )
        # Install-hook lifecycle scripts → TS-SI-007 finding
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for hook in _INSTALL_HOOKS:
                cmd = scripts.get(hook)
                if isinstance(cmd, str) and cmd.strip():
                    rule = RULES["TS-SI-007"]
                    result.findings.append(
                        Finding(
                            rule_id="TS-SI-007",
                            kind=rule.kind,
                            severity=rule.severity,
                            file_path="package.json",
                            line=1,
                            snippet=sanitise(
                                f'"{hook}": "{cmd}"'
                            )[:_MAX_SNIPPET],
                            message=rule.message,
                            remediation=rule.remediation,
                        )
                    )
    return result


# ── package-lock.json / npm-shrinkwrap.json ────────────────────────────────


def _parse_package_lock_json(root: Path) -> _NpmParseResult:
    return _parse_npm_lockfile(root / "package-lock.json", "package-lock.json")


def _parse_npm_shrinkwrap_json(root: Path) -> _NpmParseResult:
    return _parse_npm_lockfile(root / "npm-shrinkwrap.json", "npm-shrinkwrap.json")


def _parse_npm_lockfile(path: Path, label: str) -> _NpmParseResult:
    result = _NpmParseResult()
    if not path.exists():
        return result
    # REQ-19 / SEC-NEW-37 — tighter lockfile-specific cap (8 MiB) is checked
    # before the generic 10 MiB MAX_FILE_BYTES inside _read_json_bounded.
    # Adversarial 9 MiB lockfiles get a clear "too large" error rather than
    # silently scraping into the JSON parser.
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size > LOCKFILE_MAX_BYTES:
        result.errors.append(
            f"{path.name}: lockfile size {size} bytes exceeds the "
            f"{LOCKFILE_MAX_BYTES}-byte cap; skipped (too large)."
        )
        return result
    data = _read_json_bounded(path, result)
    if data is None:
        return result
    packages = data.get("packages")
    if isinstance(packages, dict):
        # npm lockfileVersion 2/3 format
        root_entry = packages.get("")
        if isinstance(root_entry, dict):
            for section in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                entries = root_entry.get(section)
                if isinstance(entries, dict):
                    for pkg, ver in entries.items():
                        if isinstance(pkg, str):
                            v = ver if isinstance(ver, str) else None
                            result.deps.append(
                                _RawDep(name=pkg, version=v, source=label)
                            )
                            # REQ-19 — root-edge for each direct dep.
                            _emit_npm_edge(result, "", pkg, v)
        # Resolve `node_modules/<name>` entries at depth 1 (top-level deps)
        for key, entry in packages.items():
            if not key.startswith("node_modules/"):
                continue
            rest = key[len("node_modules/") :]
            # Skip nested paths (node_modules/foo/node_modules/bar)
            if "/node_modules/" in rest:
                continue
            name = rest
            if isinstance(entry, dict):
                version = entry.get("version")
                if isinstance(version, str):
                    result.deps.append(
                        _RawDep(name=name, version=version, source=label)
                    )
                # REQ-19 — emit transitive edges from this package's
                # ``dependencies`` block. This is what produces distinct
                # diamond edges for `<parent>:<child>:<declared-range>`
                # (TA-207). The edges record the DECLARED specifier
                # value, not the resolved version recorded under
                # `node_modules/<child>` (resolved is REQ-20 territory).
                child_deps = entry.get("dependencies")
                if isinstance(child_deps, dict):
                    for child, child_ver in child_deps.items():
                        if isinstance(child, str):
                            cv = (
                                child_ver
                                if isinstance(child_ver, str)
                                else None
                            )
                            _emit_npm_edge(result, name, child, cv)
                            if (
                                len(result.edges) >= LOCKFILE_MAX_EDGES
                            ):
                                result.errors.append(
                                    f"{path.name}: lockfile edge cap "
                                    f"reached ({LOCKFILE_MAX_EDGES}); "
                                    f"further edges truncated."
                                )
                                return result
    else:
        # npm lockfileVersion 1 format — `dependencies` at top level
        top = data.get("dependencies")
        if isinstance(top, dict):
            for pkg, info in top.items():
                if isinstance(pkg, str) and isinstance(info, dict):
                    v = info.get("version")
                    result.deps.append(
                        _RawDep(
                            name=pkg,
                            version=v if isinstance(v, str) else None,
                            source=label,
                        )
                    )
    return result


# ── yarn.lock ──────────────────────────────────────────────────────────────


_YARN_DEP_HEADER_RE = re.compile(
    r'^"?(?P<name>@?[A-Za-z0-9_./\-]+?)(?:@[^"]+)"?'
)
_YARN_VERSION_RE = re.compile(r'^\s{2,}version\s+"(?P<version>[^"]+)"')


def _parse_yarn_lock(root: Path) -> _NpmParseResult:
    result = _NpmParseResult()
    path = root / "yarn.lock"
    if not path.exists():
        return result
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            result.errors.append("yarn.lock: exceeds size limit; skipped")
            return result
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"yarn.lock: read failed — {exc}")
        return result

    # Yarn v1 format: each package block starts at column 0 with one or
    # more quoted specifiers. v2+ Berry is YAML. Try v2 first, then fall
    # back to v1.
    if _is_yarn_berry(text):
        _parse_yarn_berry(text, result)
    else:
        _parse_yarn_v1(text, result)
    return result


def _is_yarn_berry(text: str) -> bool:
    return "__metadata:" in text[:2000]


def _parse_yarn_berry(text: str, result: _NpmParseResult) -> None:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        result.errors.append(f"yarn.lock (berry): YAML parse error — {exc}")
        return
    if not isinstance(data, dict):
        return
    for key, info in data.items():
        if key == "__metadata" or not isinstance(info, dict):
            continue
        name = _yarn_berry_name(key)
        if not name:
            continue
        version = info.get("version")
        result.deps.append(
            _RawDep(
                name=name,
                version=version if isinstance(version, str) else None,
                source="yarn.lock",
            )
        )


def _yarn_berry_name(key: Any) -> str | None:
    """Extract package name from a yarn Berry lock key like
    ``"lodash@npm:^4.17.21"`` or ``"@scope/name@npm:…"``."""
    if not isinstance(key, str):
        return None
    # Strip surrounding quotes if YAML preserved them
    stripped = key.strip().strip('"')
    # First comma-separated entry if multi
    first = stripped.split(",", 1)[0].strip().strip('"')
    # Scoped: @scope/name@... → name ends before the second @
    if first.startswith("@"):
        second_at = first.find("@", 1)
        if second_at < 0:
            return first
        return first[:second_at]
    at = first.find("@")
    return first if at < 0 else first[:at]


def _parse_yarn_v1(text: str, result: _NpmParseResult) -> None:
    """State-machine parser for yarn v1 — no regex backtracking."""
    current_name: str | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            current_name = None
            continue
        if not raw_line[0].isspace():
            # Package header line
            current_name = _yarn_v1_header_name(raw_line)
            continue
        if current_name is None:
            continue
        match = _YARN_VERSION_RE.match(raw_line)
        if match is not None:
            version = match.group("version")
            result.deps.append(
                _RawDep(
                    name=current_name,
                    version=version,
                    source="yarn.lock",
                )
            )
            # REQ-19 — root-edge for the dep. yarn.lock v1 is flat
            # (no nested transitive declarations exposed by the parser
            # at this iteration), so all edges hang off the project root.
            _emit_npm_edge(result, "", current_name, version)
            current_name = None


def _yarn_v1_header_name(line: str) -> str | None:
    """Extract the package name from a yarn-v1 block header.

    Example header lines:
      ``"@scope/pkg@^1.0.0":``
      ``lodash@^4.17.21, lodash@~4.17.0:``
    """
    header = line.rstrip(":").strip()
    # Take first comma-separated spec
    first = header.split(",", 1)[0].strip().strip('"')
    if first.startswith("@"):
        second_at = first.find("@", 1)
        if second_at < 0:
            return first
        return first[:second_at]
    at = first.find("@")
    return first if at < 0 else first[:at]


# ── pnpm-lock.yaml ─────────────────────────────────────────────────────────


def _parse_pnpm_lock_yaml(root: Path) -> _NpmParseResult:
    result = _NpmParseResult()
    path = root / "pnpm-lock.yaml"
    if not path.exists():
        return result
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    # SEC-NEW-37 — tighter lockfile cap before the generic MAX_FILE_BYTES.
    if size > LOCKFILE_MAX_BYTES:
        result.errors.append(
            f"pnpm-lock.yaml: lockfile size {size} bytes exceeds the "
            f"{LOCKFILE_MAX_BYTES}-byte cap; skipped (too large)."
        )
        return result
    try:
        if size > MAX_FILE_BYTES:
            result.errors.append("pnpm-lock.yaml: exceeds size limit; skipped")
            return result
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"pnpm-lock.yaml: read failed — {exc}")
        return result
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        result.errors.append(f"pnpm-lock.yaml: YAML parse error — {exc}")
        return result
    if not isinstance(data, dict):
        return result

    importers = data.get("importers")
    if isinstance(importers, dict):
        # pnpm v6+ format — each importer is a workspace; root is "."
        root_importer = importers.get(".")
        if isinstance(root_importer, dict):
            _extract_pnpm_importer(root_importer, result)
    else:
        # Older pnpm — dependencies at top level
        for section in ("dependencies", "devDependencies"):
            entries = data.get(section)
            if isinstance(entries, dict):
                for pkg, ver in entries.items():
                    if isinstance(pkg, str):
                        v = ver if isinstance(ver, str) else None
                        result.deps.append(
                            _RawDep(name=pkg, version=v, source="pnpm-lock.yaml")
                        )
                        # REQ-19 — root-edge.
                        _emit_npm_edge(result, "", pkg, v)

    # REQ-19 — emit transitive edges from each `packages.<key>` entry's
    # ``dependencies`` block. pnpm v6+ keys look like ``/react@18.2.0``;
    # we strip the leading slash and version suffix to derive the parent
    # name.
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_key, pkg_entry in packages.items():
            if not isinstance(pkg_key, str) or not isinstance(pkg_entry, dict):
                continue
            parent_name = _pnpm_parent_name(pkg_key)
            if parent_name is None:
                continue
            child_deps = pkg_entry.get("dependencies")
            if not isinstance(child_deps, dict):
                continue
            for child, child_ver in child_deps.items():
                if not isinstance(child, str):
                    continue
                cv = child_ver if isinstance(child_ver, str) else None
                _emit_npm_edge(result, parent_name, child, cv)
                if len(result.edges) >= LOCKFILE_MAX_EDGES:
                    result.errors.append(
                        f"pnpm-lock.yaml: lockfile edge cap reached "
                        f"({LOCKFILE_MAX_EDGES}); further edges truncated."
                    )
                    return result
    return result


def _pnpm_parent_name(packages_key: str) -> str | None:
    """Derive the package name from a pnpm `packages.<key>` key.

    pnpm v6+ uses ``/react@18.2.0`` (or ``/@scope/pkg@1.0.0`` for
    scoped packages). Returns the bare package name without the
    leading slash or the ``@<version>`` suffix.
    """
    s = packages_key.lstrip("/")
    if not s:
        return None
    if s.startswith("@"):
        # Scoped: keep first ``@<scope>`` then split at the next ``@``.
        second_at = s.find("@", 1)
        return s if second_at < 0 else s[:second_at]
    at = s.find("@")
    return s if at < 0 else s[:at]


def _extract_pnpm_importer(
    importer: dict[str, Any], result: _NpmParseResult
) -> None:
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        entries = importer.get(section)
        if not isinstance(entries, dict):
            continue
        for pkg, info in entries.items():
            if not isinstance(pkg, str):
                continue
            version: str | None = None
            if isinstance(info, dict):
                v = info.get("version")
                if isinstance(v, str):
                    version = v
            elif isinstance(info, str):
                version = info
            result.deps.append(
                _RawDep(name=pkg, version=version, source="pnpm-lock.yaml")
            )


# ── bun.lock (JSONC) and bun.lockb (binary — refused) ──────────────────────


def _parse_bun_lock(root: Path) -> _NpmParseResult:
    result = _NpmParseResult()
    path = root / "bun.lock"
    if not path.exists():
        return result
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            result.errors.append("bun.lock: exceeds size limit; skipped")
            return result
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"bun.lock: read failed — {exc}")
        return result
    cleaned = _strip_json_comments(text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        result.errors.append(f"bun.lock: JSONC parse error — {exc}")
        return result
    if not isinstance(data, dict):
        return result
    # bun.lock format (v0+): packages map keyed by dep name
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg, info in packages.items():
            if not isinstance(pkg, str):
                continue
            version: str | None = None
            if isinstance(info, list) and info:
                # bun format: [specifier, resolved, …]
                spec = info[0]
                if isinstance(spec, str):
                    # Extract version after last @
                    at = spec.rfind("@")
                    if at > 0:
                        version = spec[at + 1 :]
            elif isinstance(info, dict):
                v = info.get("version")
                if isinstance(v, str):
                    version = v
            result.deps.append(
                _RawDep(name=pkg, version=version, source="bun.lock")
            )
    return result


def _parse_bun_lockb(root: Path) -> _NpmParseResult:
    """Refuse to parse the binary bun.lockb format (FR-106)."""
    result = _NpmParseResult()
    path = root / "bun.lockb"
    if not path.exists():
        return result
    if not (root / "bun.lock").exists():
        result.errors.append(
            "bun.lockb: binary lockfile detected but no companion bun.lock. "
            "Commit bun.lock (text JSONC) so Scarno can parse it."
        )
    return result


# ── Deno ───────────────────────────────────────────────────────────────────


def _parse_deno_json(root: Path) -> _NpmParseResult:
    result = _NpmParseResult()
    for name in ("deno.json", "deno.jsonc"):
        path = root / name
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            result.errors.append(f"{name}: read failed — {exc}")
            continue
        cleaned = _strip_json_comments(text) if name.endswith("jsonc") else text
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            result.errors.append(f"{name}: parse error — {exc}")
            continue
        if not isinstance(data, dict):
            continue
        imports = data.get("imports")
        if isinstance(imports, dict):
            for _, target in imports.items():
                if not isinstance(target, str):
                    continue
                parsed = _parse_deno_specifier(target, name)
                if parsed is not None:
                    result.deps.append(parsed)
    return result


def _parse_deno_specifier(spec: str, source: str) -> _RawDep | None:
    """Parse a Deno import specifier like ``npm:lodash@^4`` or ``jsr:@std/fs``."""
    if spec.startswith("npm:"):
        body = spec[len("npm:") :]
    elif spec.startswith("jsr:"):
        body = spec[len("jsr:") :]
    else:
        return None
    # Scoped vs unscoped
    if body.startswith("@"):
        second_at = body.find("@", 1)
        if second_at < 0:
            return _RawDep(name=body, version=None, source=source)
        return _RawDep(
            name=body[:second_at],
            version=body[second_at + 1 :] or None,
            source=source,
        )
    at = body.find("@")
    if at < 0:
        return _RawDep(name=body, version=None, source=source)
    return _RawDep(name=body[:at], version=body[at + 1 :] or None, source=source)


def _parse_deno_lock(root: Path) -> _NpmParseResult:
    result = _NpmParseResult()
    path = root / "deno.lock"
    if not path.exists():
        return result
    data = _read_json_bounded(path, result)
    if data is None:
        return result
    # deno.lock v3+ structure: packages.specifiers map
    packages = data.get("packages")
    if isinstance(packages, dict):
        specifiers = packages.get("specifiers")
        if isinstance(specifiers, dict):
            for spec, _resolved in specifiers.items():
                if not isinstance(spec, str):
                    continue
                parsed = _parse_deno_specifier(spec, "deno.lock")
                if parsed is not None:
                    result.deps.append(parsed)
    return result


# ── .npmrc — security scan (TS-SI-008) ─────────────────────────────────────


_DEFAULT_NPM_REGISTRIES: frozenset[str] = frozenset(
    {
        "https://registry.npmjs.org/",
        "https://registry.npmjs.org",
        "https://registry.yarnpkg.com/",
        "https://registry.yarnpkg.com",
    }
)


def _scan_npmrc(root: Path, errors: list[str]) -> list[Finding]:
    out: list[Finding] = []
    path = root / ".npmrc"
    if not path.exists():
        return out
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f".npmrc: read failed — {exc}")
        return out
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Look for `registry=` or `@scope:registry=` assignments
        match = re.match(r"^(?:@[^:]+:)?registry\s*=\s*(?P<url>\S+)", stripped)
        if match is None:
            continue
        url = match.group("url").rstrip("/") + "/"
        if url in _DEFAULT_NPM_REGISTRIES or url.rstrip("/") in _DEFAULT_NPM_REGISTRIES:
            continue
        rule = RULES["TS-SI-008"]
        out.append(
            Finding(
                rule_id="TS-SI-008",
                kind=rule.kind,
                severity=rule.severity,
                file_path=".npmrc",
                line=lineno,
                snippet=sanitise(stripped)[:_MAX_SNIPPET],
                message=rule.message,
                remediation=rule.remediation,
            )
        )
    return out


# ── Deduplication ──────────────────────────────────────────────────────────


def _deduplicate(raw: list[_RawDep], errors: list[str]) -> list[Dependency]:
    by_name: dict[str, _RawDep] = {}
    rejected_names: set[str] = set()
    for dep in raw:
        if not dep.name:
            continue
        # SEC-002 — drop names that would escape ``node_modules/<name>/``
        # when interpolated into a filesystem path downstream. Sanitise
        # the rejected name before logging so adversarial values cannot
        # poison terminal/CI output.
        if not _is_valid_npm_name(dep.name):
            if dep.name not in rejected_names:
                rejected_names.add(dep.name)
                errors.append(
                    f"npm: dependency name {sanitise(dep.name)!r} is not a "
                    f"valid package identifier; rejected"
                )
            continue
        existing = by_name.get(dep.name)
        if existing is None:
            by_name[dep.name] = dep
            continue
        existing_pri = _source_priority(existing.source)
        new_pri = _source_priority(dep.source)
        if new_pri > existing_pri:
            if (
                existing.version
                and dep.version
                and existing.version != dep.version
            ):
                errors.append(
                    f"Package '{dep.name}' declared with conflicting versions: "
                    f"'{existing.version}' ({existing.source}) vs '{dep.version}' "
                    f"({dep.source}) — using {dep.source} version"
                )
            by_name[dep.name] = dep
        elif new_pri < existing_pri:
            if (
                existing.version
                and dep.version
                and existing.version != dep.version
            ):
                errors.append(
                    f"Package '{dep.name}' declared with conflicting versions: "
                    f"'{existing.version}' ({existing.source}) vs '{dep.version}' "
                    f"({dep.source}) — using {existing.source} version"
                )
            if existing.version is None and dep.version is not None:
                by_name[dep.name] = _RawDep(
                    name=existing.name,
                    version=dep.version,
                    source=existing.source,
                )
        # equal priority → keep first-seen

    return [
        Dependency(
            name=rd.name,
            version=rd.version,
            status=DependencyStatus.UNCERTAIN,
            reason=_STUB_REASON,
            entry_points=[],
            entry_points_used=0,
            entry_points_total=0,
            source=rd.source,
            ecosystem="npm",
        )
        for rd in by_name.values()
    ]


def _source_priority(source: str) -> int:
    if source in _PRECEDENCE:
        return _PRECEDENCE[source]
    base = source.split(":", 1)[0]
    return _PRECEDENCE.get(base, 0)


# ── REQ-20 / FR-205 — resolved-version detection (npm) ──────────────────────


def resolve_versions_from_lockfile(project_path: str) -> dict[str, str]:
    """Return ``{package_name: resolved_version}`` from the project's
    npm lockfile (``package-lock.json`` v2/v3). The "resolved" version
    is whatever the lockfile records as the installed version of each
    top-level ``node_modules/<name>`` entry — for npm + ``overrides``
    this reflects the override target.
    """
    root = Path(project_path)
    lock_path = root / "package-lock.json"
    if not lock_path.exists():
        return {}
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return {}
    out: dict[str, str] = {}
    for key, entry in packages.items():
        if not key.startswith("node_modules/") or not isinstance(entry, dict):
            continue
        rest = key[len("node_modules/"):]
        if "/node_modules/" in rest:
            continue
        version = entry.get("version")
        if isinstance(version, str):
            out[rest] = version
    return out


# ── REQ-23 — npm / yarn / pnpm pin-override detection (PR-5) ────────────────
#
# Three mechanisms force a package to a specific version:
#   * ``overrides`` in package.json (npm 8+)
#   * ``resolutions`` in package.json (yarn classic + Berry; pnpm also reads)
#   * ``pnpm.overrides`` under package.json#pnpm
#
# A direct dep whose source-level usage looks zero MUST NOT be flagged
# for removal when it is itself the target of one of these mechanisms.
# SEC-NEW-45 caps prevent pathological overrides trees from blowing up
# the extractor or matcher.

_NPM_OVERRIDES_MAX_ENTRIES: int = 2048
_NPM_OVERRIDES_MAX_NESTING: int = 8


@dataclass(frozen=True)
class NpmOverride:
    """REQ-23 — a single override directive from package.json.

    ``mechanism`` identifies which packaging-system field this came
    from. ``nested_under`` is non-empty for npm-8+ targeted overrides
    (``overrides.parent.child``) and pnpm's ``parent>child`` syntax.
    """

    target_name: str
    target_constraint: str | None
    forced_version: str
    mechanism: str
    nested_under: str | None
    raw_key: str


def _extract_overrides(
    pkg_root: "Path", *, errors: list[str]
) -> list[NpmOverride]:
    """Parse ``overrides`` / ``resolutions`` / ``pnpm.overrides`` from
    ``pkg_root/package.json``. Returns an empty list when the file is
    missing or has no override directives.

    SEC-NEW-45 caps: ``_NPM_OVERRIDES_MAX_ENTRIES=2048`` flat entries
    and ``_NPM_OVERRIDES_MAX_NESTING=8`` levels of targeted nesting.
    Invalid npm names are silently dropped (SEC-NEW-34 reuse).
    """
    pkg_path = pkg_root / "package.json"
    if not pkg_path.exists():
        return []
    try:
        size = pkg_path.stat().st_size
    except OSError:
        return []
    if size > MAX_FILE_BYTES:
        return []
    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[NpmOverride] = []
    truncated = False
    nesting_capped = False

    def _emit(record: NpmOverride) -> bool:
        nonlocal truncated
        if len(out) >= _NPM_OVERRIDES_MAX_ENTRIES:
            truncated = True
            return False
        out.append(record)
        return True

    def _walk_overrides(
        node: object, *, mechanism: str, parent_chain: tuple[str, ...]
    ) -> None:
        """Recursive walk into targeted-overrides nesting (npm-8+ syntax).

        ``node`` may be a string (final version pin) or a dict (further
        targeted nesting). ``parent_chain`` records the nested-under
        path; depth = len(parent_chain).
        """
        nonlocal nesting_capped
        if len(parent_chain) > _NPM_OVERRIDES_MAX_NESTING:
            nesting_capped = True
            return
        if isinstance(node, str):
            # ``parent_chain[-1]`` is the target name; the version is
            # ``node``; everything above is the nested_under path.
            if not parent_chain:
                return
            target = parent_chain[-1]
            nested = (
                "/".join(parent_chain[:-1]) if len(parent_chain) > 1 else None
            )
            if not _is_valid_npm_name(target):
                return
            _emit(
                NpmOverride(
                    target_name=target,
                    target_constraint=None,
                    forced_version=node,
                    mechanism=mechanism,
                    nested_under=nested,
                    raw_key=".".join(parent_chain),
                )
            )
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if not isinstance(key, str):
                    continue
                _walk_overrides(
                    value,
                    mechanism=mechanism,
                    parent_chain=parent_chain + (key,),
                )

    # (1) npm `overrides` field — can be flat or targeted-nested.
    overrides = data.get("overrides")
    if isinstance(overrides, dict):
        for key, value in overrides.items():
            if not isinstance(key, str):
                continue
            if isinstance(value, str):
                if not _is_valid_npm_name(key):
                    continue
                _emit(
                    NpmOverride(
                        target_name=key,
                        target_constraint=None,
                        forced_version=value,
                        mechanism="npm-overrides",
                        nested_under=None,
                        raw_key=key,
                    )
                )
            elif isinstance(value, dict):
                # Targeted: overrides.<parent>.<child>: <ver>
                _walk_overrides(
                    value,
                    mechanism="npm-overrides",
                    parent_chain=(key,),
                )

    # (2) yarn `resolutions` — flat. Keys may have glob prefixes
    # (e.g. ``**/lodash``) or version constraints (e.g. ``lodash@<5``).
    resolutions = data.get("resolutions")
    if isinstance(resolutions, dict):
        for raw_key, value in resolutions.items():
            if not isinstance(raw_key, str) or not isinstance(value, str):
                continue
            target_name, target_constraint = _split_yarn_resolution_key(
                raw_key
            )
            if target_name is None or not _is_valid_npm_name(target_name):
                continue
            _emit(
                NpmOverride(
                    target_name=target_name,
                    target_constraint=target_constraint,
                    forced_version=value,
                    mechanism="yarn-resolutions",
                    nested_under=None,
                    raw_key=raw_key,
                )
            )

    # (3) pnpm.overrides — flat. Keys may use the ``parent>child``
    # nested syntax.
    pnpm_block = data.get("pnpm")
    pnpm_overrides = (
        pnpm_block.get("overrides")
        if isinstance(pnpm_block, dict)
        else None
    )
    if isinstance(pnpm_overrides, dict):
        for raw_key, value in pnpm_overrides.items():
            if not isinstance(raw_key, str) or not isinstance(value, str):
                continue
            target_name, nested_under = _split_pnpm_overrides_key(raw_key)
            if target_name is None or not _is_valid_npm_name(target_name):
                continue
            _emit(
                NpmOverride(
                    target_name=target_name,
                    target_constraint=None,
                    forced_version=value,
                    mechanism="pnpm-overrides",
                    nested_under=nested_under,
                    raw_key=raw_key,
                )
            )

    if truncated:
        errors.append(
            f"npm overrides: entry cap ({_NPM_OVERRIDES_MAX_ENTRIES}) "
            f"reached; remaining entries truncated."
        )
    if nesting_capped:
        errors.append(
            f"npm overrides: nesting cap ({_NPM_OVERRIDES_MAX_NESTING}) "
            f"reached; deeper targeted entries skipped."
        )
    return out


def _split_yarn_resolution_key(
    raw_key: str,
) -> tuple[str | None, str | None]:
    """Yarn ``resolutions`` key parsing.

    Accepts: ``"lodash"`` / ``"**/lodash"`` / ``"lodash@<5"`` /
    ``"parent/lodash"`` / ``"**/parent/lodash@<5"``.

    Returns ``(target_name, target_constraint)`` — constraint is the
    glob / version suffix (preserved for diagnostics) or ``None`` when
    the key is a plain target name.
    """
    constraint: str | None = None
    name = raw_key
    if "@" in name and not name.startswith("@"):
        name, _, version_suffix = name.partition("@")
        constraint = version_suffix or None
    # Strip globbed path prefixes — the last path segment is the
    # actual target.
    if "/" in name:
        parts = name.split("/")
        # Handle scoped packages: the LAST segment before any further
        # ``/`` could be an ``@scope/pkg``. Walk from the end and
        # rejoin scoped trailing segment.
        last = parts[-1]
        if last.startswith("@") and len(parts) >= 2:
            name = f"{parts[-2]}/{last}" if parts[-2].startswith("@") else last
        else:
            name = last
        # If the resolution key was a pure glob like ``**``, name will
        # contain '*' — that's not a valid npm name and the caller's
        # validator rejects it.
        constraint = constraint or "/".join(parts[:-1]) or None
    if "*" in name:
        return None, None
    return name, constraint


def _split_pnpm_overrides_key(raw_key: str) -> tuple[str | None, str | None]:
    """pnpm.overrides key parsing for the ``parent>child`` nested syntax.

    Returns ``(target_name, nested_under)``. A plain key returns
    ``(name, None)``; ``"parent>child"`` returns ``("child", "parent")``.
    """
    if ">" in raw_key:
        parent, _, child = raw_key.rpartition(">")
        parent = parent.strip()
        child = child.strip()
        if not child:
            return None, None
        return child, parent or None
    return raw_key, None


def _detect_npm_pin_overrides(
    deps: list[Dependency], overrides: list[NpmOverride]
) -> None:
    """Mutate ``deps`` in place: flag each direct dep whose name
    matches an override target with ``pin_override=True``,
    ``pin_override_kind`` per the mechanism, and a narrative target.

    Exact-string match only (SUC-54) — no fuzzy / case-insensitive
    matching, defending against homoglyph attacks.

    NEW-ARCH-007 mutex: a dep already flagged ``manifest_redundant``
    is left alone (manifest-redundant wins).
    """
    if not overrides:
        return
    by_target: dict[str, NpmOverride] = {}
    for o in overrides:
        # First-write-wins; if multiple mechanisms target the same
        # name, the first one (parse order: npm → yarn → pnpm) is
        # recorded as the canonical pin. Other mechanisms still
        # apply via separate detector passes if added later.
        by_target.setdefault(o.target_name, o)

    kind_map = {
        "npm-overrides": "NPM_OVERRIDES",
        "yarn-resolutions": "YARN_RESOLUTIONS",
        "pnpm-overrides": "PNPM_OVERRIDES",
    }

    for dep in deps:
        if dep.manifest_redundant:
            continue
        if dep.pin_override:
            continue
        match = by_target.get(dep.name)
        if match is None:
            continue
        kind = kind_map.get(match.mechanism)
        if kind is None:
            continue
        target_text = (
            f"pinned via {match.mechanism} to {match.forced_version}"
            + (
                f" (nested under {match.nested_under})"
                if match.nested_under
                else ""
            )
        )
        object.__setattr__(dep, "pin_override", True)
        object.__setattr__(dep, "pin_override_kind", kind)
        object.__setattr__(dep, "pin_override_target", target_text)
