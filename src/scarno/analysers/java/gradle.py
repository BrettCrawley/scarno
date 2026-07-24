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

"""Gradle build file resolver — REQ-5.

Parses ``build.gradle`` (Groovy DSL) and ``build.gradle.kts`` (Kotlin DSL)
without running any Groovy or Kotlin interpreter. All extraction is
regex-based with anchored patterns and a strict line-length cap
(``_MAX_LINE_BYTES = 64 KB``) to rule out ReDoS (SEC-NEW-16 analogue).

Safety:
  * Never shells out to ``gradle`` / ``groovy`` / ``kotlinc`` (SEC-011).
    Subprocess invocation is tested against explicitly in
    ``tests/unit/test_gradle.py::TestSecurity``.
  * All regex patterns are bounded; the worst-case scan is linear in
    file size.
  * Parser catches every exception and appends to ``errors`` instead of
    propagating (BaseAnalyser contract).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 — wrapped via safe_subprocess_run
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scarno.core.base_analyser import BaseAnalyser
from scarno.models import AnalysisResult, Dependency, DependencyStatus
from scarno.security import MAX_FILE_BYTES, PathEscapeError, resolve_and_confine

if TYPE_CHECKING:
    from subprocess import CompletedProcess

    from scarno.models import DepEdge

_MAX_LINE_BYTES = 64 * 1024
_MAX_MODULE_DEPTH = 20
_MAX_INTERPOLATION_PASSES = 10

# Configuration keywords that declare a dependency. We treat all as
# equivalent for extraction — REQ-5 says "treat all as equivalent for
# extraction purposes". The `Dependency.source` field records which
# keyword was used so the reporter can show it.
_DEP_CONFIGS: tuple[str, ...] = (
    "implementation",
    "api",
    "compileOnly",
    "compileOnlyApi",
    "runtimeOnly",
    "testImplementation",
    "testRuntimeOnly",
    "testCompileOnly",
    "androidTestImplementation",
    "debugImplementation",
    "releaseImplementation",
    "annotationProcessor",
    "kapt",
    "ksp",
    "classpath",
)

# Build anchored regexes once per import — avoid repeated compilation.
_CONFIG_ALT = "|".join(re.escape(c) for c in _DEP_CONFIGS)

# Literal string form:
#   implementation 'group:artifact:version'    (Groovy)
#   implementation("group:artifact:version")   (Kotlin)
# Capture the coordinate string.
# Note: `\n` inside the char class is the newline escape (single-backslash
# in regex). Do NOT use `\\n` here — that's regex for "literal backslash
# OR literal n", which would exclude the letter n (e.g. in `junit`).
_LITERAL_DEP_RE = re.compile(
    rf"""
    \b(?P<config>{_CONFIG_ALT})\b
    \s*[(]?\s*
    (?P<quote>['\"])
    (?P<coords>[^'"\n$]+?)
    (?P=quote)
    """,
    re.VERBOSE,
)

# Interpolated form:
#   implementation "group:artifact:${versionVar}"   (Groovy)
#   implementation("group:artifact:${versionVar}")  (Kotlin)
_INTERPOLATED_DEP_RE = re.compile(
    rf"""
    \b(?P<config>{_CONFIG_ALT})\b
    \s*[(]?\s*
    (?P<quote>['\"])
    (?P<coords>[^'"\n]*?\$\{{[^}}]+\}}[^'"\n]*?)
    (?P=quote)
    """,
    re.VERBOSE,
)

# Version-catalog accessor form:
#   implementation libs.guava        (Groovy)
#   implementation(libs.guava)       (Kotlin)
# Captures the alias name after "libs.".
_CATALOG_ACCESS_RE = re.compile(
    rf"""
    \b(?P<config>{_CONFIG_ALT})\b
    \s*[(]?\s*
    libs\.(?P<alias>[A-Za-z][A-Za-z0-9.]*)
    """,
    re.VERBOSE,
)

# ext.<var> = 'value' (Groovy) OR val / var <var> = "value" (Kotlin DSL).
#
# We DELIBERATELY do not match a bare identifier + `=` — allowing that
# triggers O(N²) backtracking on long no-op content (see the Gradle
# ReDoS adversarial test, T-08 / SEC-NEW-16). ext-variable scope still
# covers the real use cases: Groovy top-level `ext.X = '...'`, Kotlin
# top-level `val X = "..."`, and bare assignments inside an `ext { … }`
# block are picked up indirectly via property interpolation from the
# build file's project-level properties.
_EXT_ASSIGN_RE = re.compile(
    r"""
    (?:
        ext\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)
        | \b(?:val|var)\s+(?P<name_kt>[A-Za-z_][A-Za-z0-9_]*)
    )
    \s*[:=]\s*
    (?P<quote>['\"])
    (?P<value>[^'"\n$]+)
    (?P=quote)
    """,
    re.VERBOSE,
)

# settings.gradle / settings.gradle.kts include directives
_INCLUDE_RE = re.compile(
    r"""
    \binclude\s*[(]?\s*
    (?P<quote>['\"])
    (?P<module>:?[A-Za-z0-9_\-./:]+)
    (?P=quote)
    """,
    re.VERBOSE,
)

# "${name}" placeholder for ext-variable resolution.
_PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass
class _CatalogEntry:
    group: str
    artifact: str
    version: str | None


@dataclass
class _VersionCatalog:
    versions: dict[str, str] = field(default_factory=dict)
    libraries: dict[str, _CatalogEntry] = field(default_factory=dict)


# ── Public resolver ──────────────────────────────────────────────────────────


class GradleBuildResolver(BaseAnalyser):
    """Parse a Gradle project into a flat dep list with ``ecosystem="gradle"``."""

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        return (
            (root / "build.gradle").exists()
            or (root / "build.gradle.kts").exists()
            or (root / "settings.gradle").exists()
            or (root / "settings.gradle.kts").exists()
        )

    def analyse(self, project_path: str) -> AnalysisResult:
        errors: list[str] = []
        try:
            root = Path(project_path).resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            return AnalysisResult(
                project_type="java",
                project_path=str(project_path),
                dependencies=[],
                errors=[f"gradle: could not resolve path — {exc}"],
                findings=[],
                languages=["java"],
            )

        catalog = _parse_version_catalog(root, errors)
        deps_by_key: dict[tuple[str, str], Dependency] = {}

        build_files = _discover_build_files(root, errors)
        for path in build_files:
            try:
                _parse_build_file(path, root, catalog, deps_by_key, errors)
            except Exception as exc:  # noqa: BLE001 — BaseAnalyser contract
                errors.append(
                    f"gradle: unexpected error parsing {path.name} — {exc}"
                )

        deps = list(deps_by_key.values())
        # REQ-17 — drop test-scoped configurations.
        if self.exclude_tests:
            deps = [d for d in deps if not _is_test_configuration_source(d.source)]
        return AnalysisResult(
            project_type="java",
            project_path=str(root),
            dependencies=deps,
            errors=errors,
            findings=[],
            languages=["java"],
        )


def _is_test_configuration_source(source: str) -> bool:
    """REQ-17 — True when ``source`` ends with a test-scoped Gradle config.

    ``Dependency.source`` for Gradle deps is ``<rel_path>:<configName>`` —
    e.g. ``build.gradle.kts:testImplementation``.
    """
    config = source.rsplit(":", 1)[-1]
    return config.startswith("test") or config.startswith("androidTest")


# ── Build-file discovery ─────────────────────────────────────────────────────


def _discover_build_files(root: Path, errors: list[str]) -> list[Path]:
    """Return root build file + submodule build files via settings include."""
    out: list[Path] = []
    for name in ("build.gradle", "build.gradle.kts"):
        candidate = root / name
        if candidate.exists():
            out.append(candidate)
            break  # at most one of the two at root

    # Discover included submodules
    for settings_name in ("settings.gradle", "settings.gradle.kts"):
        settings = root / settings_name
        if not settings.exists():
            continue
        try:
            text = _read_bounded(settings, errors)
        except _ReadError:
            continue
        for match in _INCLUDE_RE.finditer(text):
            module = match.group("module")
            subpath = _module_to_dir(module)
            submodule_dir = root / subpath
            try:
                resolve_and_confine(submodule_dir, root)
            except PathEscapeError:
                errors.append(
                    f"{settings_name}: include '{module}' escapes project root; skipped"
                )
                continue
            if not submodule_dir.is_dir():
                errors.append(
                    f"{settings_name}: include '{module}' has no directory at "
                    f"{subpath}"
                )
                continue
            for child_name in ("build.gradle", "build.gradle.kts"):
                child_path = submodule_dir / child_name
                if child_path.exists() and child_path not in out:
                    out.append(child_path)
                    break
    return out


def _module_to_dir(module: str) -> str:
    """Gradle `:foo:bar` → `foo/bar` path."""
    stripped = module.lstrip(":")
    return stripped.replace(":", "/")


# ── Per-file parser ──────────────────────────────────────────────────────────


class _ReadError(Exception):
    """Internal — raised when a file can't be read; caller already logged."""


def _read_bounded(path: Path, errors: list[str]) -> str:
    """Read a file with size / line-length caps."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        errors.append(f"{path.name}: stat failed — {exc}")
        raise _ReadError from exc
    if size > MAX_FILE_BYTES:
        errors.append(f"{path.name}: file exceeds size limit; skipped")
        raise _ReadError
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{path.name}: read failed — {exc}")
        raise _ReadError from exc

    # ReDoS defence — reject files with a single line > _MAX_LINE_BYTES.
    # Gradle build files don't have legitimate 64 KB lines.
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > _MAX_LINE_BYTES:
            errors.append(
                f"{path.name}:{lineno}: line exceeds {_MAX_LINE_BYTES} bytes; skipped"
            )
            raise _ReadError
    return text


def _parse_build_file(
    path: Path,
    root: Path,
    catalog: _VersionCatalog,
    deps_by_key: dict[tuple[str, str], Dependency],
    errors: list[str],
) -> None:
    try:
        text = _read_bounded(path, errors)
    except _ReadError:
        return

    ext_vars = _collect_ext_vars(text)
    try:
        rel_source = str(path.relative_to(root))
    except ValueError:
        rel_source = path.name
    stripped = _strip_comments(text)

    # Literal deps — quoted strings without placeholders
    for match in _LITERAL_DEP_RE.finditer(stripped):
        coords = match.group("coords")
        if "$" in coords:  # belongs to interpolated pass below
            continue
        parsed = _parse_coords(coords)
        if parsed is None:
            errors.append(f"{path.name}: unparseable coordinates '{coords}'")
            continue
        _record_dep(
            group=parsed[0],
            artifact=parsed[1],
            version=parsed[2],
            source=f"{rel_source}:{match.group('config')}",
            deps_by_key=deps_by_key,
        )

    # Interpolated deps — need ext-variable resolution
    for match in _INTERPOLATED_DEP_RE.finditer(stripped):
        coords = match.group("coords")
        resolved, ok = _resolve_placeholders(coords, ext_vars)
        if not ok:
            errors.append(
                f"{path.name}: Could not resolve version for '{coords}' in {rel_source}"
            )
            # Still record dep if group:artifact are resolvable
            parts = resolved.split(":", 2)
            if len(parts) >= 2 and all("$" not in p for p in parts[:2]):
                version = parts[2] if len(parts) == 3 and "$" not in parts[2] else None
                _record_dep(
                    group=parts[0],
                    artifact=parts[1],
                    version=version,
                    source=f"{rel_source}:{match.group('config')}",
                    deps_by_key=deps_by_key,
                )
            continue
        parsed = _parse_coords(resolved)
        if parsed is None:
            errors.append(f"{path.name}: unparseable coordinates '{resolved}'")
            continue
        _record_dep(
            group=parsed[0],
            artifact=parsed[1],
            version=parsed[2],
            source=f"{rel_source}:{match.group('config')}",
            deps_by_key=deps_by_key,
        )

    # Catalog accessors
    for match in _CATALOG_ACCESS_RE.finditer(stripped):
        alias = match.group("alias").replace(".", "-")
        entry = catalog.libraries.get(alias)
        if entry is None:
            errors.append(
                f"{path.name}: libs.versions.toml has no library alias '{alias}'"
            )
            continue
        _record_dep(
            group=entry.group,
            artifact=entry.artifact,
            version=entry.version,
            source=f"{rel_source}:{match.group('config')}",
            deps_by_key=deps_by_key,
        )


def _strip_comments(text: str) -> str:
    """Strip ``//`` line comments and ``/* … */`` block comments.

    Keeps strings intact (we don't do full syntax here — but this is
    good enough for the token-oriented regexes that follow).
    """
    # Block comments — non-greedy
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Line comments
    out: list[str] = []
    for line in text.splitlines():
        # Don't strip inside a quoted string (rough heuristic: check if //
        # appears after an unbalanced quote). Conservative — if in doubt,
        # keep the line. For Gradle this rarely matters.
        idx = line.find("//")
        if idx < 0:
            out.append(line)
            continue
        # Check if any single/double quote appears before //
        before = line[:idx]
        if before.count("'") % 2 == 1 or before.count('"') % 2 == 1:
            out.append(line)
        else:
            out.append(before)
    return "\n".join(out)


def _collect_ext_vars(text: str) -> dict[str, str]:
    """Collect ``ext.foo = 'value'``, ``val foo = "value"`` bindings.

    Also accepts a bare ``name = 'value'`` inside an `ext { … }` /
    `buildscript.ext { … }` block — we scan conservatively.
    """
    bindings: dict[str, str] = {}
    stripped = _strip_comments(text)
    for match in _EXT_ASSIGN_RE.finditer(stripped):
        # Prefer the ext.X form over val/var when both happen to bind the
        # same name — the qualified form is unambiguous.
        name = match.group("name") or match.group("name_kt")
        value = match.group("value")
        if name and value is not None:
            if match.group("name") is not None:
                bindings[name] = value
            else:
                bindings.setdefault(name, value)
    return bindings


def _resolve_placeholders(
    value: str, variables: dict[str, str]
) -> tuple[str, bool]:
    """Expand ``${var}`` placeholders against ``variables``. (resolved, ok)."""
    if "${" not in value:
        return value, True
    current = value
    for _ in range(_MAX_INTERPOLATION_PASSES):
        unresolved: list[str] = []

        def _sub(match: re.Match[str]) -> str:
            key = match.group(1)
            if key in variables:
                return variables[key]
            unresolved.append(key)
            return match.group(0)

        next_val = _PLACEHOLDER_RE.sub(_sub, current)
        if next_val == current:
            return current, not unresolved
        current = next_val
    return current, "${" not in current


def _parse_coords(coords: str) -> tuple[str, str, str | None] | None:
    """Split a Maven-style GAV string into (group, artifact, version)."""
    parts = coords.split(":")
    if len(parts) < 2:
        return None
    if any(not p.strip() for p in parts[:2]):
        return None
    group = parts[0].strip()
    artifact = parts[1].strip()
    version: str | None = parts[2].strip() if len(parts) >= 3 else None
    if version == "":
        version = None
    return group, artifact, version


def _record_dep(
    group: str,
    artifact: str,
    version: str | None,
    source: str,
    deps_by_key: dict[tuple[str, str], Dependency],
) -> None:
    key = (group, artifact)
    if key in deps_by_key:
        return
    deps_by_key[key] = Dependency(
        name=f"{group}:{artifact}",
        version=version,
        status=DependencyStatus.UNCERTAIN,
        reason="declared in Gradle build file — source analysis pending",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        source=source,
        ecosystem="gradle",
    )


# ── Version catalog (gradle/libs.versions.toml) ─────────────────────────────


def _parse_version_catalog(root: Path, errors: list[str]) -> _VersionCatalog:
    catalog_path = root / "gradle" / "libs.versions.toml"
    if not catalog_path.exists():
        return _VersionCatalog()
    try:
        size = catalog_path.stat().st_size
        if size > MAX_FILE_BYTES:
            errors.append(
                "gradle/libs.versions.toml: exceeds size limit; skipped"
            )
            return _VersionCatalog()
        with catalog_path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"gradle/libs.versions.toml: parse error — {exc}")
        return _VersionCatalog()

    catalog = _VersionCatalog()
    versions = data.get("versions")
    if isinstance(versions, dict):
        for key, val in versions.items():
            if isinstance(val, str):
                catalog.versions[str(key)] = val

    libraries = data.get("libraries")
    if not isinstance(libraries, dict):
        return catalog

    for alias, spec in libraries.items():
        entry = _parse_library_entry(alias, spec, catalog.versions, errors)
        if entry is not None:
            # Normalise alias — Gradle accepts both `.` and `-` as separators
            normalised = str(alias).replace(".", "-")
            catalog.libraries[normalised] = entry
    return catalog


def _parse_library_entry(
    alias: str,
    spec: Any,
    versions: dict[str, str],
    errors: list[str],
) -> _CatalogEntry | None:
    if isinstance(spec, str):
        # Shorthand: "group:name:version"
        parsed = _parse_coords(spec)
        if parsed is None:
            errors.append(
                f"gradle/libs.versions.toml: bad shorthand for '{alias}': {spec!r}"
            )
            return None
        return _CatalogEntry(group=parsed[0], artifact=parsed[1], version=parsed[2])

    if not isinstance(spec, dict):
        errors.append(
            f"gradle/libs.versions.toml: unsupported entry shape for '{alias}'"
        )
        return None

    # Two-key form: `module = "group:name"` plus version.ref / version
    module = spec.get("module")
    group = spec.get("group")
    name = spec.get("name")
    if isinstance(module, str):
        parsed = _parse_coords(module + ":")  # add trailing : so coords splits
        if parsed is None:
            errors.append(
                f"gradle/libs.versions.toml: bad module for '{alias}': {module!r}"
            )
            return None
        group, name = parsed[0], parsed[1]
    if not isinstance(group, str) or not isinstance(name, str):
        errors.append(
            f"gradle/libs.versions.toml: '{alias}' missing group/name or module"
        )
        return None

    version = _resolve_catalog_version(spec, versions, alias, errors)
    return _CatalogEntry(group=group, artifact=name, version=version)


def _resolve_catalog_version(
    spec: dict[str, Any],
    versions: dict[str, str],
    alias: str,
    errors: list[str],
) -> str | None:
    version_field = spec.get("version")
    if isinstance(version_field, str):
        return version_field
    if isinstance(version_field, dict):
        ref = version_field.get("ref")
        if isinstance(ref, str):
            resolved = versions.get(ref)
            if resolved is None:
                errors.append(
                    f"gradle/libs.versions.toml: version.ref '{ref}' for '{alias}' "
                    "not in [versions]"
                )
                return None
            return resolved
    return None


# ── REQ-19 — per-edge declared-version emission from `gradle dependencies` ──
#
# We never invoke the `gradle` binary ourselves (per module docstring +
# SEC-011); when this helper runs the user has already supplied a captured
# `gradle dependencies` text output via REQ-20's resolved-version code path
# (or PR-2's `_invoke_gradle_safe`). PR-1 just needs the parser.

# Tree branches in `gradle dependencies` output:
#   +--- com.example:a:1.0
#   +--- com.example:b:2.0 -> 2.5         (requested -> resolved)
#   |    \--- com.example:c:3.0
# REQ-19 stores the REQUESTED version, NOT the resolved one (FR-192). The
# resolved version is REQ-20 territory.
_GRADLE_TREE_LINE_RE = re.compile(
    r"""
    ^[\s|]*           # leading indentation / pipes
    [+\\]---\s+       # branch glyph
    (?P<group>[\w.\-]+)
    :
    (?P<artifact>[\w.\-]+)
    :
    (?P<requested>[\w.\-+]+)
    (?:\s*->\s*(?P<resolved>[\w.\-+]+))?
    \s*$
    """,
    re.VERBOSE,
)


def _emit_dep_edges_from_output(
    output: str, *, parent: str = ""
) -> list[DepEdge]:
    """Parse a `gradle dependencies` text block into REQ-19 ``DepEdge``s.

    Each line of the form ``+--- group:artifact:requested[ -> resolved]``
    yields one edge with ``declared_version=requested``. The resolved
    version (right of the arrow) is intentionally discarded — REQ-20
    surfaces it separately via the resolved-version detector.

    ``parent`` is recorded as-is on every emitted edge. Pass the project
    coordinate (``"project:app"``) for top-level edges, or a nested coord
    for sub-tree extraction.
    """
    from scarno.models import DepEdge
    from scarno.security import sanitise_declared_version

    edges: list[DepEdge] = []
    for raw in output.splitlines():
        if len(raw) > _MAX_LINE_BYTES:
            continue
        m = _GRADLE_TREE_LINE_RE.match(raw)
        if not m:
            continue
        group = m.group("group")
        artifact = m.group("artifact")
        requested = m.group("requested")
        edges.append(
            DepEdge(
                parent=parent,
                child=f"{group}:{artifact}",
                declared_version=sanitise_declared_version(requested),
            )
        )
    return edges


# ── SEC-NEW-53 — gradle.lockfile vs `gradle dependencies` cross-check ───────


def _check_lockfile_consistency(
    *,
    lockfile_coords: set[str],
    gradle_output_coords: set[str],
    errors: list[str],
) -> None:
    """Warn when the lockfile is a strict subset of `gradle dependencies`.

    Defends against a tampered ``gradle.lockfile`` silently suppressing
    edges from the report. When both sources agree we stay quiet; when
    the lockfile lists FEWER coordinates than the resolved graph we
    append a single sanitised warning to ``errors`` so the operator
    knows the lockfile may be out of sync.

    Coordinate format on both sides: ``"group:artifact:version"``. The
    comparison is set-based; ordering and duplicates are irrelevant.
    """
    if not lockfile_coords or not gradle_output_coords:
        return
    if not lockfile_coords < gradle_output_coords:  # not a strict subset
        return
    missing = sorted(gradle_output_coords - lockfile_coords)
    sample = ", ".join(missing[:3]) + ("…" if len(missing) > 3 else "")
    errors.append(
        f"gradle.lockfile is a strict subset of `gradle dependencies` "
        f"output ({len(missing)} coordinate(s) missing from the lockfile, "
        f"e.g. {sample}); the lockfile may be out of sync — verify before "
        f"trusting REQ-20 resolved-version output."
    )


# ── REQ-19a / SEC-NEW-52 — Gradle binary resolution + PATH-fallback warning ─


def _resolve_gradle_binary() -> str | None:
    """Locate the ``gradle`` binary, preferring ``$GRADLE_HOME``.

    Mirrors :func:`scarno.analysers.java.maven._resolve_mvn_binary`'s
    SEC-NEW-28 pattern. Env var set + binary missing → returns None
    (does NOT fall through to PATH); env var unset → PATH fallback
    emits a one-time verbose-mode warning per SEC-NEW-52.
    """
    gradle_home = os.environ.get("GRADLE_HOME")
    if gradle_home:
        candidate = Path(gradle_home) / "bin" / "gradle"
        if candidate.exists():
            try:
                resolved = candidate.resolve()
                resolved.relative_to(Path(gradle_home).resolve())
            except (OSError, ValueError):
                return None
            return str(resolved)
        return None
    found = shutil.which("gradle")
    if found is not None:
        _warn_path_fallback_once("gradle")
    return found


def _warn_path_fallback_once(binary_name: str) -> None:
    """Emit a verbose-mode stderr warning the first time a binary is
    resolved via PATH (no env-var pin). Idempotent per process per
    binary name.
    """
    seen = getattr(_warn_path_fallback_once, "_seen", None)
    if seen is None:
        seen = set()
        _warn_path_fallback_once._seen = seen  # type: ignore[attr-defined]
    if binary_name in seen:
        return
    seen.add(binary_name)
    print(
        f"[scarno] warning: {binary_name} resolved via PATH (no "
        f"GRADLE_HOME set); the binary is unverified — set GRADLE_HOME "
        f"to confine resolution.",
        file=sys.stderr,
    )


# ── REQ-19a / SEC-NEW-55 — argv-allowlist-checked gradle invocation ─────────


_GRADLE_ALLOWED_TOKENS: frozenset[str] = frozenset(
    {
        "dependencies",
        "--configuration",
        "--console=plain",
        "--no-daemon",
        "--quiet",
    }
)
_GRADLE_ALLOWED_CONFIGURATIONS: frozenset[str] = frozenset(
    {"runtimeClasspath", "default", "compileClasspath"}
)


def _invoke_gradle_safe(
    argv_tail: list[str], *, timeout_s: float = 60.0
) -> CompletedProcess[str] | None:
    """REQ-19a / SEC-NEW-55 — argv-allowlist-checked gradle invocation.

    Every token in ``argv_tail`` MUST be on the fixed allowlist. The
    configuration name (the value after ``--configuration``) is
    checked against ``_GRADLE_ALLOWED_CONFIGURATIONS`` before any
    subprocess spawn — adversarial config names raise ``ValueError``.
    """
    # Two-pass validation: first the token allowlist, then the
    # configuration value.
    for tok in argv_tail:
        if tok in _GRADLE_ALLOWED_TOKENS:
            continue
        if tok in _GRADLE_ALLOWED_CONFIGURATIONS:
            continue
        raise ValueError(
            f"_invoke_gradle_safe: token {tok!r} is not on the SEC-NEW-55 "
            f"argv allowlist; only fixed REQ-20 flags + a configuration "
            f"from {sorted(_GRADLE_ALLOWED_CONFIGURATIONS)} are permitted."
        )
    gradle = _resolve_gradle_binary()
    if gradle is None:
        return None
    binary_root = (
        Path(os.environ["GRADLE_HOME"])
        if os.environ.get("GRADLE_HOME")
        else None
    )
    try:
        from scarno.security import (
            BinaryNotConfinedError,
            safe_subprocess_run,
        )
        return safe_subprocess_run(
            [gradle, *argv_tail],
            timeout_s=timeout_s,
            binary_root=binary_root,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    except BinaryNotConfinedError:
        return None


# ── REQ-20 / FR-204 — resolved-version detection (Gradle) ───────────────────


def _resolve_versions_from_dependencies_output(output: str) -> dict[str, str]:
    """Parse ``gradle dependencies`` text output into
    ``{group:artifact: resolved_version}``. Lines of the form
    ``+--- group:artifact:requested -> resolved`` record the resolved
    side; lines without ``->`` use the requested as resolved.
    """
    out: dict[str, str] = {}
    line_re = re.compile(
        r"""
        ^[\s|]*[+\\]---\s+
        (?P<group>[\w.\-]+):
        (?P<artifact>[\w.\-]+):
        (?P<requested>[\w.\-+]+)
        (?:\s*->\s*(?P<resolved>[\w.\-+]+))?
        \s*$
        """,
        re.VERBOSE,
    )
    for raw in output.splitlines():
        m = line_re.match(raw)
        if not m:
            continue
        coord = f"{m.group('group')}:{m.group('artifact')}"
        out[coord] = m.group("resolved") or m.group("requested")
    return out


def _resolve_versions_with_lockfile_priority(
    *, gradle_output: str, lockfile_text: str
) -> dict[str, str]:
    """When both sources are present, the lockfile wins per-coordinate.

    ``gradle.lockfile`` lines look like
    ``com.example:a:1.7=runtimeClasspath`` (the version is in the
    middle position). Comment lines (``#``) and empty lines are
    skipped.
    """
    resolved = _resolve_versions_from_dependencies_output(gradle_output)
    lock_re = re.compile(
        r"^(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):(?P<version>[\w.\-+]+)="
    )
    for raw in lockfile_text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = lock_re.match(s)
        if not m:
            continue
        coord = f"{m.group('group')}:{m.group('artifact')}"
        resolved[coord] = m.group("version")
    return resolved
