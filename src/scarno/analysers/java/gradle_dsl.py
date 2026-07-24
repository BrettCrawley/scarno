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

"""REQ-21b — Gradle DSL pin-directive walker (PR-6).

Pure static analysis of ``build.gradle`` (Groovy) and ``build.gradle.kts``
(Kotlin) files. Five DSL constructs flagged as pin overrides:

* ``force("g:a:v")`` inside ``resolutionStrategy`` blocks.
* ``strictly("v")`` inside a dep's ``version { ... }`` block.
* ``constraints { implementation("g:a:v") { ... } }`` declarations.
* ``resolutionStrategy.eachDependency { useVersion("v") }`` closures —
  detected with both literal and *dynamic* (non-literal) arguments.
* ``exclude(group = "...", module = "...")`` directives on a dep.

Dynamic ``useVersion()`` calls (where the argument is a function call
or variable reference, not a string literal) are recorded with
``dynamic=True``. The classifier downgrades the matched dep to
``UNCERTAIN`` rather than forcing ``IN_USE``, and the reporter renders
it in a dedicated "DO NOT REMOVE — dynamic Gradle pin" section
(R-Phase9-02 closure).

Safety:

* All extraction is bounded regex with anchored patterns (mirrors
  ``gradle.py``'s SEC-NEW-16 stance — no catastrophic backtracking).
* ``_GRADLE_MAX_FORCE_DIRECTIVES = 256`` / ``_GRADLE_MAX_EXCLUSIONS
  = 256`` caps prevent pathological build scripts from blowing up
  the directive lists (SEC-NEW-41).
* ``_GRADLE_PARSE_TIMEOUT_S = 8`` wall-clock guard across all
  files in one ``parse_*`` call — if the walker exceeds this, it
  records a sanitised note and skips the remaining files rather
  than hanging.
* Never executes any DSL content (mirrors ADR-002 / SEC-011).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from scarno.security import MAX_FILE_BYTES, sanitise

_GRADLE_MAX_FORCE_DIRECTIVES: int = 256
_GRADLE_MAX_EXCLUSIONS: int = 256
_GRADLE_PARSE_TIMEOUT_S: int = 8

# Per-line byte cap — mirrors the existing gradle.py policy. Keeps the
# regex linear in file size regardless of pathological input shapes.
_MAX_LINE_BYTES: int = 64 * 1024


# ── Directive records ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class GradleForceDirective:
    """REQ-21b record: one Gradle pin directive (force / strictly /
    constraints / eachDependency).

    ``version`` is ``None`` when ``dynamic`` is True (the literal value
    isn't known statically). ``source`` names the DSL construct that
    produced this record so the reporter can attribute pins clearly
    (e.g. ``"resolutionStrategy.force"``).
    """

    group: str
    artifact: str
    version: str | None
    source: str
    dynamic: bool = False


@dataclass(frozen=True)
class GradleExclusion:
    """REQ-21b record: one Gradle ``exclude(group = ..., module = ...)``
    directive. ``parent_dep_coord`` records which dep declared it
    (may be None when the exclusion appears at configuration level)."""

    excluded_group: str
    excluded_artifact: str
    parent_dep_coord: str | None = None


# ── Regex patterns (bounded; ReDoS-safe) ───────────────────────────────────


_FORCE_GAV_RE = re.compile(
    r'''
    \bforce\s*\(?
    \s*["']
    (?P<group>[\w.\-]+)
    :
    (?P<artifact>[\w.\-]+)
    :
    (?P<version>[\w.\-+]+)
    ["']
    ''',
    re.VERBOSE,
)


_STRICTLY_RE = re.compile(
    r'''
    (?:implementation|api|runtimeOnly|compileOnly|testImplementation)
    \s*\(?\s*["']
    (?P<group>[\w.\-]+)
    :
    (?P<artifact>[\w.\-]+)
    ["']\s*\)?
    \s*\{
    [^{}]{0,500}
    version\s*\{
    [^{}]{0,500}
    strictly\s*\(?\s*["']
    (?P<version>[\w.\-+]+)
    ["']
    ''',
    re.VERBOSE | re.DOTALL,
)


_CONSTRAINT_DEP_RE = re.compile(
    r'''
    (?:implementation|api|runtimeOnly|compileOnly|testImplementation)
    \s*\(?\s*["']
    (?P<group>[\w.\-]+)
    :
    (?P<artifact>[\w.\-]+)
    :
    (?P<version>[\w.\-+]+)
    ["']
    ''',
    re.VERBOSE,
)


_EACH_DEP_LITERAL_RE = re.compile(
    r'''
    requested\.group\s*==\s*["'](?P<group>[\w.\-]+)["']
    \s*(?:&&|and)\s*
    requested\.name\s*==\s*["'](?P<artifact>[\w.\-]+)["']
    [\s\S]{0,500}?
    useVersion\s*\(?\s*["'](?P<version>[\w.\-+]+)["']
    ''',
    re.VERBOSE,
)


# Dynamic useVersion: argument starts with an identifier followed by `(`
# (function call) OR is a bare identifier reference. Rejects string
# literals so the literal path above wins first.
_USEVERSION_DYNAMIC_RE = re.compile(
    r'''
    useVersion\s*\(
    \s*
    (?![\s"'])      # argument doesn't start with whitespace/quote
    [A-Za-z_]\w*    # identifier
    ''',
    re.VERBOSE,
)


_EXCLUDE_RE = re.compile(
    r'''
    \bexclude\s*\(?
    \s*group\s*[:=]\s*["'](?P<group>[\w.\-]+)["']
    \s*,?\s*
    module\s*[:=]\s*["'](?P<module>[\w.\-]+)["']
    \s*\)?
    ''',
    re.VERBOSE,
)


# ── File reading + caps ────────────────────────────────────────────────────


def _read_bounded(path: Path, errors: list[str]) -> str:
    """Read ``path`` with file-size + line-length caps. Returns empty
    string on any failure (caller continues without raising)."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            errors.append(
                f"{path.name}: exceeds size limit; skipped"
            )
            return ""
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{path.name}: read failed — {sanitise(str(exc))}")
        return ""
    for ln in text.splitlines():
        if len(ln) > _MAX_LINE_BYTES:
            errors.append(
                f"{path.name}: line exceeds {_MAX_LINE_BYTES}-byte cap; "
                f"skipped."
            )
            return ""
    return text


# ── Public API ─────────────────────────────────────────────────────────────


def parse_pin_directives(
    build_files: list[Path], *, errors: list[str] | None = None
) -> list[GradleForceDirective]:
    """Walk every build-file and return the union of pin directives found.

    Records exceeding ``_GRADLE_MAX_FORCE_DIRECTIVES`` are truncated
    with a sanitised note in ``errors``. The overall wall-clock budget
    is ``_GRADLE_PARSE_TIMEOUT_S`` seconds — exceeding it stops the
    walk and records a parse-timeout error.
    """
    if errors is None:
        errors = []
    out: list[GradleForceDirective] = []
    start = time.monotonic()
    truncated = False

    def _emit(record: GradleForceDirective) -> bool:
        nonlocal truncated
        if len(out) >= _GRADLE_MAX_FORCE_DIRECTIVES:
            truncated = True
            return False
        out.append(record)
        return True

    for path in build_files:
        if time.monotonic() - start > _GRADLE_PARSE_TIMEOUT_S:
            errors.append(
                f"Gradle DSL parse exceeded {_GRADLE_PARSE_TIMEOUT_S}s "
                f"timeout; remaining files skipped."
            )
            break
        text = _read_bounded(path, errors)
        if not text:
            continue

        for m in _FORCE_GAV_RE.finditer(text):
            if not _emit(
                GradleForceDirective(
                    group=m.group("group"),
                    artifact=m.group("artifact"),
                    version=m.group("version"),
                    source="resolutionStrategy.force",
                )
            ):
                break
        if truncated:
            break

        for m in _STRICTLY_RE.finditer(text):
            if not _emit(
                GradleForceDirective(
                    group=m.group("group"),
                    artifact=m.group("artifact"),
                    version=m.group("version"),
                    source="strictly",
                )
            ):
                break
        if truncated:
            break

        for block_text in _extract_constraints_blocks(text):
            for m in _CONSTRAINT_DEP_RE.finditer(block_text):
                if not _emit(
                    GradleForceDirective(
                        group=m.group("group"),
                        artifact=m.group("artifact"),
                        version=m.group("version"),
                        source="constraints",
                    )
                ):
                    break
            if truncated:
                break
        if truncated:
            break

        for m in _EACH_DEP_LITERAL_RE.finditer(text):
            if not _emit(
                GradleForceDirective(
                    group=m.group("group"),
                    artifact=m.group("artifact"),
                    version=m.group("version"),
                    source="eachDependency.useVersion",
                )
            ):
                break
        if truncated:
            break

        if _USEVERSION_DYNAMIC_RE.search(text):
            _emit(
                GradleForceDirective(
                    group="*",
                    artifact="*",
                    version=None,
                    source="eachDependency.useVersion(dynamic)",
                    dynamic=True,
                )
            )
        if truncated:
            break

    if truncated:
        errors.append(
            f"Gradle DSL: force-directive cap "
            f"({_GRADLE_MAX_FORCE_DIRECTIVES}) reached; remaining "
            f"directives truncated."
        )
    return out


def parse_exclusions(
    build_files: list[Path], *, errors: list[str] | None = None
) -> list[GradleExclusion]:
    """Walk every build-file and return ``exclude(group, module)``
    records. Capped at ``_GRADLE_MAX_EXCLUSIONS``."""
    if errors is None:
        errors = []
    out: list[GradleExclusion] = []
    start = time.monotonic()
    truncated = False
    for path in build_files:
        if time.monotonic() - start > _GRADLE_PARSE_TIMEOUT_S:
            errors.append(
                f"Gradle DSL exclusions parse exceeded "
                f"{_GRADLE_PARSE_TIMEOUT_S}s timeout; remaining files skipped."
            )
            break
        text = _read_bounded(path, errors)
        if not text:
            continue
        for m in _EXCLUDE_RE.finditer(text):
            if len(out) >= _GRADLE_MAX_EXCLUSIONS:
                truncated = True
                break
            out.append(
                GradleExclusion(
                    excluded_group=m.group("group"),
                    excluded_artifact=m.group("module"),
                    parent_dep_coord=None,
                )
            )
        if truncated:
            break
    if truncated:
        errors.append(
            f"Gradle DSL: exclusion cap ({_GRADLE_MAX_EXCLUSIONS}) "
            f"reached; remaining entries truncated."
        )
    return out


# ── Helpers ────────────────────────────────────────────────────────────────


def _extract_constraints_blocks(text: str) -> list[str]:
    """Return the body of each ``constraints { ... }`` block.

    Uses a balanced-brace state machine on lines so nested braces
    (e.g. ``because { ... }`` inside a constraint) don't terminate
    the block early.
    """
    blocks: list[str] = []
    inside = False
    depth = 0
    current: list[str] = []
    for line in text.splitlines():
        if not inside:
            idx = line.find("constraints")
            if idx >= 0:
                brace_idx = line.find("{", idx)
                if brace_idx >= 0:
                    inside = True
                    rest = line[brace_idx + 1:]
                    depth = 1 + rest.count("{") - rest.count("}")
                    if depth <= 0:
                        inside = False
                        depth = 0
                        continue
                    current = [rest]
                    continue
        else:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                current.append(line)
                blocks.append("\n".join(current))
                inside = False
                depth = 0
                current = []
            else:
                current.append(line)
    if inside and current:
        blocks.append("\n".join(current))
    return blocks
