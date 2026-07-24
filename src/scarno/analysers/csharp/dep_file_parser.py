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

"""C# / .NET manifest + lock parser — REQ-15.

Parses the NuGet / MSBuild dependency surface:
  * ``*.csproj`` / ``*.fsproj`` / ``*.vbproj`` — ``<PackageReference>``
  * ``Directory.Packages.props`` — Central Package Management (CPM)
  * ``packages.config`` — legacy NuGet v2 format
  * ``*.sln`` — multi-project discovery
  * ``packages.lock.json`` — NuGet lock-file version resolution
  * ``nuget.config`` — custom registry detection (TS-SI-015)
  * MSBuild ``<Exec>`` → TS-SI-016, ``<UsingTask>`` → TS-SI-017

Safety:
  * DOCTYPE rejection pre-parse (SEC-NEW-25) — same defence as Maven.
  * File-size cap (``MAX_FILE_BYTES``) on every input.
  * Circular ``.sln`` / project-reference cycle detection.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from scarno.findings.rules import RULES
from scarno.models import Dependency, DependencyStatus, Finding
from scarno.security import (
    MAX_FILE_BYTES,
    PathEscapeError,
    resolve_and_confine,
    sanitise,
)

_STUB_REASON = "declared — source analysis pending"
_MAX_SNIPPET = 200

# MSBuild XML namespace (optional in SDK-style projects)
_MSBUILD_NS = "{http://schemas.microsoft.com/developer/msbuild/2003}"

# Default NuGet registries (TS-SI-015 fires for anything else)
_DEFAULT_NUGET_SOURCES: frozenset[str] = frozenset(
    {
        "https://api.nuget.org/v3/index.json",
        "https://api.nuget.org/v3/index.json/",
    }
)

# Project file extensions
_PROJECT_EXTS: tuple[str, ...] = ("*.csproj", "*.fsproj", "*.vbproj")

# DOCTYPE detection regex
_DOCTYPE_RE = re.compile(rb"<!DOCTYPE\b", re.IGNORECASE)

# .sln project line regex
_SLN_PROJECT_RE = re.compile(
    r'Project\("[^"]*"\)\s*=\s*"[^"]*"\s*,\s*"(?P<path>[^"]+)"'
)


@dataclass
class _CsharpParseResult:
    deps: dict[str, _RawDep] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Central Package Management version map
    cpm_versions: dict[str, str] = field(default_factory=dict)
    # Track visited project paths to detect cycles
    visited_projects: set[str] = field(default_factory=set)


@dataclass
class _RawDep:
    name: str
    version: str | None
    source: str


# ── Public coordinator ─────────────────────────────────────────────────────


def parse_all_csharp_dependency_files(
    project_path: str,
) -> tuple[list[Dependency], list[str], list[Finding]]:
    """Return ``(dependencies, errors, findings)``. Never raises."""
    errors: list[str] = []
    findings: list[Finding] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"csharp: could not resolve project path — {exc}")
        return [], errors, findings
    if not root.is_dir():
        return [], errors, findings

    result = _CsharpParseResult()

    # Load CPM before project files so versions can be resolved
    _parse_directory_packages_props(root, result)

    # Discover projects: prefer .sln, fall back to globbing
    project_files = _discover_projects(root, result)

    for proj_path in project_files:
        _parse_project_file(proj_path, root, result)

    # Legacy packages.config
    _parse_packages_config(root, result)

    # packages.lock.json version resolution
    _parse_packages_lock_json(root, result)

    # nuget.config security scan
    _scan_nuget_config(root, result)

    errors.extend(result.errors)
    findings.extend(result.findings)

    deps = [
        Dependency(
            name=d.name,
            version=d.version,
            status=DependencyStatus.UNCERTAIN,
            reason=_STUB_REASON,
            entry_points=[],
            entry_points_used=0,
            entry_points_total=0,
            source=d.source,
            ecosystem="nuget",
        )
        for d in result.deps.values()
    ]
    return deps, errors, findings


# ── Helpers ────────────────────────────────────────────────────────────────


def _read_xml(path: Path, result: _CsharpParseResult) -> ET.Element | None:
    """Size-capped, DOCTYPE-rejecting XML load."""
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
        raw = path.read_bytes()
    except OSError as exc:
        result.errors.append(f"{path.name}: read failed — {exc}")
        return None

    # SEC-NEW-25: reject DOCTYPE before parsing
    if _DOCTYPE_RE.search(raw[:4096]):
        result.errors.append(
            f"{path.name}: contains DOCTYPE declaration — refused "
            f"(entity-expansion defence)"
        )
        return None

    try:
        # B314 — DOCTYPE already rejected above (SEC-NEW-25); with no DTD
        # present the residual xml.etree attack surface (external entities,
        # billion-laughs) is unreachable. defusedxml would add a transitive
        # dependency without strengthening the guarantee.
        return ET.fromstring(raw)  # nosec B314
    except ET.ParseError as exc:
        result.errors.append(f"{path.name}: XML parse error — {exc}")
        return None


def _read_text(path: Path, result: _CsharpParseResult) -> str | None:
    if not path.exists():
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        result.errors.append(f"{path.name}: exceeds size limit; skipped")
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path.name}: read failed — {exc}")
        return None


# ── Project discovery ──────────────────────────────────────────────────────


def _discover_projects(
    root: Path, result: _CsharpParseResult
) -> list[Path]:
    """Find project files: prefer .sln, fall back to globbing."""
    sln_files = list(root.glob("*.sln"))
    if sln_files:
        return _projects_from_sln(sln_files[0], root, result)

    # No .sln — glob for project files directly
    projects: list[Path] = []
    for ext in _PROJECT_EXTS:
        for p in root.rglob(ext):
            rel_parts = p.relative_to(root).parts
            if any(part in {"bin", "obj", ".git"} for part in rel_parts):
                continue
            projects.append(p)
    return projects


def _projects_from_sln(
    sln_path: Path, root: Path, result: _CsharpParseResult
) -> list[Path]:
    """Extract project paths from a .sln file.

    Project references are confined to the project root (SEC-002): any
    ``..`` traversal, absolute path, or symlink chain that escapes
    ``root`` is rejected with a sanitised error and the entry skipped.
    The .sln content is operator-untrusted and an unconstrained path
    join would otherwise let a crafted reference read arbitrary
    ``.csproj``-shaped files outside the analysed directory.
    """
    text = _read_text(sln_path, result)
    if text is None:
        return []

    projects: list[Path] = []
    for m in _SLN_PROJECT_RE.finditer(text):
        rel = m.group("path").replace("\\", "/")
        try:
            proj_path = resolve_and_confine(sln_path.parent / rel, root)
        except PathEscapeError:
            result.errors.append(
                f"{sln_path.name}: project reference "
                f"{sanitise(rel)!r} escapes project root; skipped"
            )
            continue
        if proj_path.is_file() and proj_path.suffix in (
            ".csproj", ".fsproj", ".vbproj"
        ):
            projects.append(proj_path)
    return projects


# ── Directory.Packages.props (CPM) ────────────────────────────────────────


def _parse_directory_packages_props(
    root: Path, result: _CsharpParseResult
) -> None:
    path = root / "Directory.Packages.props"
    tree = _read_xml(path, result)
    if tree is None:
        return

    for elem in _iter_elements(tree, "PackageVersion"):
        name = elem.get("Include")
        version = elem.get("Version")
        if name:
            result.cpm_versions[name] = version or ""


# ── Project file parsing ──────────────────────────────────────────────────


def _parse_project_file(
    path: Path, root: Path, result: _CsharpParseResult
) -> None:
    resolved = str(path.resolve())
    if resolved in result.visited_projects:
        return  # cycle detection
    result.visited_projects.add(resolved)

    tree = _read_xml(path, result)
    if tree is None:
        return

    proj_name = path.name

    # Extract PackageReference elements
    for elem in _iter_elements(tree, "PackageReference"):
        name = elem.get("Include")
        if not name:
            continue
        # Version: attribute > child element > CPM > VersionOverride
        version = elem.get("VersionOverride") or elem.get("Version")
        if version is None:
            # Try child element — use explicit `is not None` because
            # ET.Element.__bool__ is falsy when the element has no children.
            ver_elem = elem.find("Version")
            if ver_elem is None:
                ver_elem = elem.find(f"{_MSBUILD_NS}Version")
            if ver_elem is not None and ver_elem.text:
                version = ver_elem.text.strip()
        if version is None:
            # Fall back to CPM
            version = result.cpm_versions.get(name)

        if name not in result.deps:
            result.deps[name] = _RawDep(
                name=name, version=version, source=f"{proj_name}:PackageReference"
            )

    # MSBuild security checks
    _check_msbuild_security(tree, proj_name, result)


def _check_msbuild_security(
    tree: ET.Element, proj_name: str, result: _CsharpParseResult
) -> None:
    """Detect <Exec> and <UsingTask> in project files."""
    # <Exec Command="..."/>
    for elem in _iter_elements(tree, "Exec"):
        cmd = elem.get("Command")
        if cmd and cmd.strip():
            rule = RULES["TS-SI-016"]
            result.findings.append(
                Finding(
                    rule_id="TS-SI-016",
                    kind=rule.kind,
                    severity=rule.severity,
                    file_path=proj_name,
                    line=1,
                    snippet=sanitise(f'<Exec Command="{cmd}">')[:_MAX_SNIPPET],
                    message=rule.message,
                    remediation=rule.remediation,
                )
            )

    # <UsingTask TaskName="..." AssemblyFile="..."/>
    for elem in _iter_elements(tree, "UsingTask"):
        asm = elem.get("AssemblyFile")
        if asm and asm.strip():
            rule = RULES["TS-SI-017"]
            result.findings.append(
                Finding(
                    rule_id="TS-SI-017",
                    kind=rule.kind,
                    severity=rule.severity,
                    file_path=proj_name,
                    line=1,
                    snippet=sanitise(
                        f'<UsingTask AssemblyFile="{asm}">'
                    )[:_MAX_SNIPPET],
                    message=rule.message,
                    remediation=rule.remediation,
                )
            )


def _iter_elements(tree: ET.Element, tag: str) -> Iterator[ET.Element]:
    """Yield elements matching ``tag`` with or without MSBuild namespace."""
    yield from tree.iter(tag)
    yield from tree.iter(f"{_MSBUILD_NS}{tag}")


# ── packages.config (legacy) ──────────────────────────────────────────────


def _parse_packages_config(root: Path, result: _CsharpParseResult) -> None:
    path = root / "packages.config"
    tree = _read_xml(path, result)
    if tree is None:
        return

    for elem in tree.iter("package"):
        name = elem.get("id")
        version = elem.get("version")
        if name and name not in result.deps:
            result.deps[name] = _RawDep(
                name=name,
                version=version,
                source="packages.config",
            )


# ── packages.lock.json ────────────────────────────────────────────────────


def _parse_packages_lock_json(
    root: Path, result: _CsharpParseResult
) -> None:
    path = root / "packages.lock.json"
    text = _read_text(path, result)
    if text is None:
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.errors.append(f"packages.lock.json: JSON parse error — {exc}")
        return
    if not isinstance(data, dict):
        return

    deps_section = data.get("dependencies")
    if not isinstance(deps_section, dict):
        return

    # Structure: { "net8.0": { "PackageName": { "resolved": "1.2.3", ... } } }
    for _tfm, packages in deps_section.items():
        if not isinstance(packages, dict):
            continue
        for name, info in packages.items():
            if not isinstance(info, dict):
                continue
            resolved = info.get("resolved")
            if not isinstance(resolved, str):
                continue
            # Override existing dep version with resolved version
            if name in result.deps:
                result.deps[name].version = resolved
            else:
                result.deps[name] = _RawDep(
                    name=name,
                    version=resolved,
                    source="packages.lock.json",
                )


# ── nuget.config (TS-SI-015) ──────────────────────────────────────────────


def _scan_nuget_config(root: Path, result: _CsharpParseResult) -> None:
    path = root / "nuget.config"
    # Also try NuGet.Config (case-sensitive filesystems)
    if not path.exists():
        path = root / "NuGet.Config"
    tree = _read_xml(path, result)
    if tree is None:
        return

    for elem in _iter_elements(tree, "add"):
        # Look for <add key="..." value="https://..." /> inside <packageSources>
        value = elem.get("value")
        if not value or not value.startswith("http"):
            continue
        normalised = value.rstrip("/") + "/"
        if normalised in _DEFAULT_NUGET_SOURCES or value in _DEFAULT_NUGET_SOURCES:
            continue
        rule = RULES["TS-SI-015"]
        result.findings.append(
            Finding(
                rule_id="TS-SI-015",
                kind=rule.kind,
                severity=rule.severity,
                file_path=path.name,
                line=1,
                snippet=sanitise(f'<add value="{value}"/>')[:_MAX_SNIPPET],
                message=rule.message,
                remediation=rule.remediation,
            )
        )
