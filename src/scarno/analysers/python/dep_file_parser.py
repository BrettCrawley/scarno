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

"""Python dependency file parser — REQ-2.

Parses declared dependencies from all eight supported Python dependency
formats into a unified, deduplicated list of :class:`Dependency`. Every
returned dep carries ``status=UNCERTAIN`` and
``reason="declared — source analysis pending"`` as a placeholder for
the REQ-3 source analyser to refine.

Safety guarantees:
  * ``setup.py`` and any other Python source are parsed via ``ast.parse``
    — never ``exec`` / ``eval`` / ``importlib`` / ``subprocess`` (SEC-001).
  * All filesystem reads are confined to the project root via
    :func:`scarno.security.resolve_and_confine` (SEC-002).
  * Parser is pure-Python, no network (SEC-010 analogue).
  * Coordinator never raises; errors append to the returned list.
"""
from __future__ import annotations

import ast
import configparser
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from packaging.requirements import InvalidRequirement, Requirement

from scarno.models import Dependency, DependencyStatus
from scarno.security import (
    MAX_DEP_NAME_LEN,
    MAX_FILE_BYTES,
    PathEscapeError,
    resolve_and_confine,
)

_STUB_REASON = "declared — source analysis pending"
_MAX_R_DEPTH = 10
_MAX_INCLUDE_GROUP_DEPTH = 10

# Precedence — higher wins. Value is an int; larger = higher priority.
# REQ-2b extends this with environment.yml + PEP 518 / PEP 735 source labels.
_PRECEDENCE: dict[str, int] = {
    "Pipfile.lock": 80,
    "poetry.lock": 70,
    "uv.lock": 60,
    "environment.yml": 55,
    "environment.yml:pip": 55,
    "requirements.txt": 50,
    "pyproject.toml": 40,
    "pyproject.toml:project": 40,
    "pyproject.toml:poetry": 40,
    "pyproject.toml:dependency-groups": 35,
    "pyproject.toml:build-system": 33,
    "setup.py": 30,
    "tox.ini": 25,
    "setup.cfg": 20,
    ".gitlab-ci.yml": 15,
    "Dockerfile": 15,
    "Containerfile": 15,
    "noxfile.py": 15,
    "Pipfile": 10,
}

# A conservative stdlib guard. Python 3.10+ provides `sys.stdlib_module_names`.
_STDLIB_NAMES: frozenset[str] = frozenset(sys.stdlib_module_names)


@dataclass
class _RawDep:
    name: str
    version: str | None
    source: str
    is_transitive: bool = False


def _normalise(name: str) -> str:
    """Apply PEP 503 canonical-name normalisation."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _name_too_long(name: str) -> bool:
    return len(name) > MAX_DEP_NAME_LEN


def _is_type_stub(name: str) -> tuple[bool, str | None]:
    """Return (is_stub, runtime_name_if_resolvable)."""
    canonical = _normalise(name)
    if canonical.startswith("types-"):
        return True, canonical[len("types-") :] or None
    if canonical.endswith("-stubs"):
        return True, canonical[: -len("-stubs")] or None
    if canonical in {"mypy-extensions", "typing-extensions", "typing-inspect"}:
        return True, None
    return False, None


def _file_too_large(path: Path) -> bool:
    try:
        return path.stat().st_size > MAX_FILE_BYTES
    except OSError:
        return False


# ── requirements.txt ─────────────────────────────────────────────────────────


def _parse_requirement_line(
    raw: str, file_path: str, errors: list[str]
) -> _RawDep | None:
    """Parse a single requirement line; append to errors on failure."""
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    # Strip inline comments while preserving semantic ';' markers.
    comment_pos = line.find(" #")
    if comment_pos >= 0:
        line = line[:comment_pos].rstrip()
    if not line:
        return None
    if line.startswith("-e ") or line.startswith("--editable"):
        return None
    if line.startswith("-") or line.startswith("--"):
        # pip option other than -r/-e (e.g. --index-url). Ignore silently.
        return None
    if "://" in line or line.startswith(("http://", "https://", "git+", "file:")):
        return None
    try:
        req = Requirement(line)
    except InvalidRequirement as exc:
        errors.append(f"{file_path}: could not parse line '{raw.strip()}' — {exc}")
        return None
    name = req.name
    if _name_too_long(name):
        errors.append(
            f"{file_path}: dependency name exceeds {MAX_DEP_NAME_LEN} chars; truncated"
        )
        name = name[:MAX_DEP_NAME_LEN]
    spec = str(req.specifier) if req.specifier else None
    version: str | None = None
    if spec:
        exact = re.match(r"^==([^,]+)$", spec)
        if exact:
            version = exact.group(1).strip()
        else:
            version = spec  # store raw specifier; REQ-3 onwards may refine
    return _RawDep(name=name, version=version, source="requirements.txt")


def _parse_requirements_txt(
    path: Path,
    project_root: Path,
    errors: list[str],
    visited: set[Path] | None = None,
    depth: int = 0,
) -> list[_RawDep]:
    """Parse a requirements file, following ``-r`` / ``-c`` includes."""
    if visited is None:
        visited = set()
    resolved_self: Path
    try:
        resolved_self = resolve_and_confine(path, project_root)
    except PathEscapeError as exc:
        errors.append(f"requirements include escape blocked: {exc}")
        return []
    if resolved_self in visited:
        errors.append(
            f"{resolved_self.name}: circular include detected (cycle at {resolved_self})"
        )
        return []
    if depth > _MAX_R_DEPTH:
        errors.append(
            f"{resolved_self.name}: include chain exceeds max depth {_MAX_R_DEPTH}"
        )
        return []
    if _file_too_large(resolved_self):
        errors.append(f"{resolved_self.name}: file exceeds size limit; skipped")
        return []
    try:
        text = resolved_self.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{resolved_self.name}: could not read file — {exc}")
        return []
    visited = visited | {resolved_self}
    out: list[_RawDep] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            parts = stripped.split(maxsplit=1)
            if len(parts) < 2:
                continue
            include_target = parts[1].strip()
            include_path = (resolved_self.parent / include_target).resolve()
            try:
                resolve_and_confine(include_path, project_root)
            except PathEscapeError as exc:
                errors.append(
                    f"requirements.txt: include '{include_target}' escapes project root — {exc}"
                )
                continue
            if not include_path.exists():
                errors.append(
                    f"requirements.txt: included file not found: {include_target}"
                )
                continue
            out.extend(
                _parse_requirements_txt(
                    include_path, project_root, errors, visited, depth + 1
                )
            )
            continue
        dep = _parse_requirement_line(raw_line, resolved_self.name, errors)
        if dep is not None:
            out.append(dep)
    return out


# ── pyproject.toml ───────────────────────────────────────────────────────────


def _parse_pyproject_toml(path: Path, errors: list[str]) -> list[_RawDep]:
    if _file_too_large(path):
        errors.append("pyproject.toml: file exceeds size limit; skipped")
        return []
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"pyproject.toml: TOML parse error — {exc}")
        return []

    out: list[_RawDep] = []
    project = data.get("project") or {}

    # PEP 621 main deps
    for entry in project.get("dependencies", []) or []:
        if not isinstance(entry, str):
            continue
        dep = _parse_pep508_entry(entry, "pyproject.toml:project", errors)
        if dep is not None:
            out.append(dep)

    # PEP 621 extras
    extras = project.get("optional-dependencies") or {}
    if isinstance(extras, dict):
        for group_name, group_deps in extras.items():
            if not isinstance(group_deps, list):
                continue
            src = f"pyproject.toml:project.optional-dependencies.{group_name}"
            for entry in group_deps:
                if isinstance(entry, str):
                    dep = _parse_pep508_entry(entry, src, errors)
                    if dep is not None:
                        out.append(dep)

    # Poetry deps
    poetry = (data.get("tool") or {}).get("poetry") or {}
    out.extend(_parse_poetry_section(poetry, errors))

    # PEP 518 — [build-system].requires (REQ-2b)
    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        requires = build_system.get("requires")
        if requires is None:
            pass
        elif isinstance(requires, list):
            for entry in requires:
                if not isinstance(entry, str):
                    continue
                dep = _parse_pep508_entry(
                    entry, "pyproject.toml:build-system", errors
                )
                if dep is not None:
                    out.append(dep)
        else:
            errors.append(
                "pyproject.toml: [build-system].requires must be a list"
            )

    # PEP 735 — [dependency-groups] (REQ-2b)
    dep_groups = data.get("dependency-groups")
    if isinstance(dep_groups, dict):
        out.extend(_parse_dependency_groups(dep_groups, errors))

    return out


def _parse_dependency_groups(
    groups: dict[str, Any], errors: list[str]
) -> list[_RawDep]:
    """Resolve ``[dependency-groups]`` including ``include-group`` chains."""
    out: list[_RawDep] = []
    for name in groups:
        _resolve_group(name, groups, out, errors, visited=[])
    return out


def _resolve_group(
    name: str,
    groups: dict[str, Any],
    out: list[_RawDep],
    errors: list[str],
    visited: list[str],
) -> None:
    if name in visited:
        errors.append(
            "pyproject.toml: [dependency-groups] cycle detected: "
            + " → ".join(visited + [name])
        )
        return
    if len(visited) > _MAX_INCLUDE_GROUP_DEPTH:
        errors.append(
            "pyproject.toml: [dependency-groups] include depth exceeded "
            f"{_MAX_INCLUDE_GROUP_DEPTH}"
        )
        return
    entries = groups.get(name)
    if entries is None:
        errors.append(
            f"pyproject.toml: [dependency-groups] references unknown group '{name}'"
        )
        return
    if not isinstance(entries, list):
        errors.append(
            f"pyproject.toml: [dependency-groups].{name} must be a list"
        )
        return
    source = f"pyproject.toml:dependency-groups.{name}"
    for entry in entries:
        if isinstance(entry, str):
            dep = _parse_pep508_entry(entry, source, errors)
            if dep is not None:
                out.append(dep)
        elif isinstance(entry, dict):
            target = entry.get("include-group")
            if isinstance(target, str):
                _resolve_group(
                    target, groups, out, errors, visited + [name]
                )
            else:
                errors.append(
                    f"pyproject.toml: [dependency-groups].{name} contains "
                    "invalid item"
                )
        else:
            errors.append(
                f"pyproject.toml: [dependency-groups].{name} contains invalid item"
            )


def _parse_poetry_section(poetry: dict[str, Any], errors: list[str]) -> list[_RawDep]:
    out: list[_RawDep] = []

    def _extract(group: dict[str, Any], source: str) -> None:
        for name, spec in group.items():
            if name == "python":
                continue
            version: str | None = None
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                v = spec.get("version")
                if isinstance(v, str):
                    version = v
            out.append(_RawDep(name=name, version=version, source=source))

    deps = poetry.get("dependencies")
    if isinstance(deps, dict):
        _extract(deps, "pyproject.toml:poetry")
    dev_deps = poetry.get("dev-dependencies")
    if isinstance(dev_deps, dict):
        _extract(dev_deps, "pyproject.toml:poetry.dev-dependencies")
    groups = poetry.get("group")
    if isinstance(groups, dict):
        for gname, gval in groups.items():
            if isinstance(gval, dict):
                gdeps = gval.get("dependencies")
                if isinstance(gdeps, dict):
                    _extract(gdeps, f"pyproject.toml:poetry.group.{gname}")
    return out


def _parse_pep508_entry(
    entry: str, source: str, errors: list[str]
) -> _RawDep | None:
    try:
        req = Requirement(entry)
    except InvalidRequirement as exc:
        errors.append(f"{source}: could not parse '{entry}' — {exc}")
        return None
    name = req.name
    if _name_too_long(name):
        errors.append(
            f"{source}: dependency name exceeds {MAX_DEP_NAME_LEN} chars; truncated"
        )
        name = name[:MAX_DEP_NAME_LEN]
    version: str | None = None
    if req.specifier:
        spec = str(req.specifier)
        exact = re.match(r"^==([^,]+)$", spec)
        version = exact.group(1).strip() if exact else spec
    return _RawDep(name=name, version=version, source=source)


# ── setup.py ─────────────────────────────────────────────────────────────────


def _parse_setup_py(path: Path, errors: list[str]) -> list[_RawDep]:
    if _file_too_large(path):
        errors.append("setup.py: file exceeds size limit; skipped")
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"setup.py: could not read file — {exc}")
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        errors.append(f"setup.py: syntax error — {exc}")
        return []

    # Resolve simple module-level variable assignments so we can dereference
    # ``install_requires=VAR`` when VAR is a list literal earlier in the file.
    simple_bindings: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if isinstance(tgt, ast.Name):
                simple_bindings[tgt.id] = node.value

    out: list[_RawDep] = []
    found_setup_call = False
    for walked in ast.walk(tree):
        if not isinstance(walked, ast.Call):
            continue
        if not _is_setup_call(walked):
            continue
        found_setup_call = True
        for kw in walked.keywords:
            if kw.arg == "install_requires":
                out.extend(
                    _extract_requirement_list(
                        kw.value,
                        simple_bindings,
                        "setup.py:install_requires",
                        errors,
                    )
                )
            elif kw.arg == "extras_require":
                out.extend(_extract_extras_dict(kw.value, simple_bindings, errors))

    if not found_setup_call:
        errors.append("setup.py: no setup() call found")

    return out


def _is_setup_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id == "setup":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "setup":
        return True
    return False


def _extract_requirement_list(
    value: ast.AST,
    bindings: dict[str, ast.AST],
    source: str,
    errors: list[str],
) -> list[_RawDep]:
    # Dereference a single-level variable reference.
    if isinstance(value, ast.Name) and value.id in bindings:
        value = bindings[value.id]
    if not isinstance(value, (ast.List, ast.Tuple)):
        errors.append(
            f"setup.py: dynamic install_requires detected — dependencies may be incomplete"
        )
        return []
    out: list[_RawDep] = []
    for item in value.elts:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            dep = _parse_pep508_entry(item.value, source, errors)
            if dep is not None:
                out.append(dep)
    return out


def _extract_extras_dict(
    value: ast.AST,
    bindings: dict[str, ast.AST],
    errors: list[str],
) -> list[_RawDep]:
    if isinstance(value, ast.Name) and value.id in bindings:
        value = bindings[value.id]
    if not isinstance(value, ast.Dict):
        return []
    out: list[_RawDep] = []
    for k, v in zip(value.keys, value.values, strict=False):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
            continue
        group = k.value
        source = f"setup.py:extras_require.{group}"
        out.extend(_extract_requirement_list(v, bindings, source, errors))
    return out


# ── setup.cfg ────────────────────────────────────────────────────────────────


def _parse_setup_cfg(path: Path, errors: list[str]) -> list[_RawDep]:
    if _file_too_large(path):
        errors.append("setup.cfg: file exceeds size limit; skipped")
        return []
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as exc:
        errors.append(f"setup.cfg: parse error — {exc}")
        return []
    out: list[_RawDep] = []
    if parser.has_option("options", "install_requires"):
        raw = parser.get("options", "install_requires")
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            dep = _parse_pep508_entry(stripped, "setup.cfg:install_requires", errors)
            if dep is not None:
                out.append(dep)
    if parser.has_section("options.extras_require"):
        for key, raw in parser.items("options.extras_require"):
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                dep = _parse_pep508_entry(
                    stripped, f"setup.cfg:extras_require.{key}", errors
                )
                if dep is not None:
                    out.append(dep)
    return out


# ── Pipfile / Pipfile.lock ───────────────────────────────────────────────────


def _parse_pipfile(path: Path, errors: list[str]) -> list[_RawDep]:
    if _file_too_large(path):
        errors.append("Pipfile: file exceeds size limit; skipped")
        return []
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"Pipfile: TOML parse error — {exc}")
        return []

    out: list[_RawDep] = []
    for section, label in (("packages", "Pipfile"), ("dev-packages", "Pipfile:dev")):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            version: str | None = None
            if isinstance(spec, str):
                if spec != "*":
                    version = spec
            elif isinstance(spec, dict):
                v = spec.get("version")
                if isinstance(v, str) and v != "*":
                    version = v
            out.append(_RawDep(name=name, version=version, source=label))
    return out


def _parse_pipfile_lock(path: Path, errors: list[str]) -> list[_RawDep]:
    if _file_too_large(path):
        errors.append("Pipfile.lock: file exceeds size limit; skipped")
        return []
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"Pipfile.lock: JSON parse error — {exc}")
        return []
    if not isinstance(data, dict):
        errors.append("Pipfile.lock: top-level JSON must be an object")
        return []
    out: list[_RawDep] = []
    for section in ("default", "develop"):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name, info in entries.items():
            version: str | None = None
            if isinstance(info, dict):
                v = info.get("version")
                if isinstance(v, str):
                    version = v.lstrip("=").strip() or None
            out.append(_RawDep(name=name, version=version, source="Pipfile.lock"))
    return out


# ── poetry.lock / uv.lock — both are TOML with [[package]] lists ─────────────

# Dependency graph: package name → set of its direct dependency names.
DepGraph = dict[str, set[str]]


def _parse_lock_toml(path: Path, label: str, errors: list[str]) -> list[_RawDep]:
    if _file_too_large(path):
        errors.append(f"{label}: file exceeds size limit; skipped")
        return []
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{label}: TOML parse error — {exc}")
        return []
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    out: list[_RawDep] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if isinstance(name, str):
            out.append(
                _RawDep(
                    name=name,
                    version=version if isinstance(version, str) else None,
                    source=label,
                )
            )
    return out


def _parse_poetry_lock(
    path: Path, direct_names: set[str], errors: list[str]
) -> tuple[list[_RawDep], DepGraph]:
    """Parse ``poetry.lock`` with full dependency graph extraction.

    *direct_names* is the set of canonical package names declared in
    ``pyproject.toml [tool.poetry.dependencies]`` (already parsed before
    this function is called). Everything else in the lock is transitive.
    """
    label = "poetry.lock"
    empty: tuple[list[_RawDep], DepGraph] = ([], {})
    if _file_too_large(path):
        errors.append(f"{label}: file exceeds size limit; skipped")
        return empty
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{label}: TOML parse error — {exc}")
        return empty
    packages = data.get("package")
    if not isinstance(packages, list):
        return empty

    graph: DepGraph = {}
    out: list[_RawDep] = []

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        if not isinstance(name, str):
            continue
        canonical = _normalise(name)
        version = pkg.get("version")

        # Build graph edges from [package.dependencies].
        pkg_deps = pkg.get("dependencies")
        if isinstance(pkg_deps, dict):
            dep_names: set[str] = set()
            for dep_name in pkg_deps:
                if isinstance(dep_name, str):
                    dep_names.add(_normalise(dep_name))
            graph[canonical] = dep_names

        is_transitive = canonical not in direct_names
        out.append(
            _RawDep(
                name=name,
                version=version if isinstance(version, str) else None,
                source=label,
                is_transitive=is_transitive,
            )
        )

    return out, graph


def _parse_uv_lock(
    path: Path, errors: list[str]
) -> tuple[list[_RawDep], DepGraph]:
    """Parse ``uv.lock`` with full dependency graph extraction.

    Returns ``(deps, graph)`` where *graph* maps each normalised package
    name to the set of normalised names it directly depends on. Deps
    from the root project's ``dependencies`` list are marked as direct
    (``is_transitive=False``); all others are transitive.
    """
    label = "uv.lock"
    empty: tuple[list[_RawDep], DepGraph] = ([], {})
    if _file_too_large(path):
        errors.append(f"{label}: file exceeds size limit; skipped")
        return empty
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{label}: TOML parse error — {exc}")
        return empty
    packages = data.get("package")
    if not isinstance(packages, list):
        return empty

    # First pass: find the root project and build the graph.
    graph: DepGraph = {}
    root_direct_names: set[str] = set()
    all_packages: list[dict[str, Any]] = []

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        if not isinstance(name, str):
            continue
        canonical = _normalise(name)
        all_packages.append(pkg)

        # Extract this package's dependency edges.
        pkg_deps = pkg.get("dependencies")
        if isinstance(pkg_deps, list):
            dep_names: set[str] = set()
            for dep_entry in pkg_deps:
                if isinstance(dep_entry, dict):
                    dep_name = dep_entry.get("name")
                    if isinstance(dep_name, str):
                        dep_names.add(_normalise(dep_name))
            graph[canonical] = dep_names

        # Detect root project: editable source or virtual workspace.
        source = pkg.get("source")
        if isinstance(source, dict) and (
            "editable" in source or "virtual" in source
        ):
            root_direct_names = graph.get(canonical, set())
            # Also include dev-dependencies as direct.
            dev_deps = pkg.get("dev-dependencies")
            if isinstance(dev_deps, dict):
                for _group, dep_list in dev_deps.items():
                    if isinstance(dep_list, list):
                        for dep_entry in dep_list:
                            if isinstance(dep_entry, dict):
                                dep_name = dep_entry.get("name")
                                if isinstance(dep_name, str):
                                    root_direct_names.add(_normalise(dep_name))

    # Second pass: emit _RawDep entries tagged direct vs transitive.
    out: list[_RawDep] = []
    for pkg in all_packages:
        name = pkg.get("name")
        if not isinstance(name, str):
            continue
        canonical = _normalise(name)
        version = pkg.get("version")
        # Skip the root project itself.
        source = pkg.get("source")
        if isinstance(source, dict) and (
            "editable" in source or "virtual" in source
        ):
            continue
        is_transitive = canonical not in root_direct_names
        out.append(
            _RawDep(
                name=name,
                version=version if isinstance(version, str) else None,
                source=label,
                is_transitive=is_transitive,
            )
        )

    return out, graph


# ── Conda environment.yml (REQ-2b) ───────────────────────────────────────────


def _parse_environment_yml(path: Path, errors: list[str]) -> list[_RawDep]:
    """Parse a Conda environment file.

    Uses ``yaml.safe_load`` exclusively (SEC-NEW-13). Returns
    dependencies from both the top-level ``dependencies:`` list and
    the nested ``pip:`` sub-list. Excludes the ``python`` pseudo-dep
    and ignores top-level ``name:`` / ``channels:`` / ``prefix:``.
    """
    if _file_too_large(path):
        errors.append("environment.yml: file exceeds size limit; skipped")
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"environment.yml: could not read file — {exc}")
        return []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        errors.append(f"environment.yml: YAML parse error — {exc}")
        return []
    if not isinstance(data, dict):
        return []
    raw_deps = data.get("dependencies")
    if not isinstance(raw_deps, list):
        return []

    out: list[_RawDep] = []
    for item in raw_deps:
        if isinstance(item, str):
            dep = _parse_conda_scalar(item, "environment.yml", errors)
            if dep is not None:
                out.append(dep)
        elif isinstance(item, dict):
            pip_list = item.get("pip")
            if isinstance(pip_list, list):
                for pip_entry in pip_list:
                    if isinstance(pip_entry, str):
                        dep = _parse_pep508_entry(
                            pip_entry, "environment.yml:pip", errors
                        )
                        if dep is not None:
                            out.append(dep)
    return out


def _parse_conda_scalar(
    raw: str, source: str, errors: list[str]
) -> _RawDep | None:
    """Parse a Conda dependency scalar like ``numpy=1.26`` or ``numpy``."""
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return None
    # Conda-forge URL-style deps are rare but legal; skip them.
    if "::" in stripped and "/" in stripped:
        return None
    # Split on the first '=' (version separator). Conda uses '=' for pin,
    # '==' for strict. Either way, take the LHS as the name.
    name_part = stripped
    version: str | None = None
    for sep in ("==", ">=", "<=", "!=", "~=", "=", ">", "<"):
        if sep in stripped:
            idx = stripped.find(sep)
            name_part = stripped[:idx].strip()
            version = stripped[idx + len(sep) :].strip() or None
            break
    name = name_part
    # Exclude the python pseudo-dep.
    if _normalise(name) == "python":
        return None
    if _name_too_long(name):
        errors.append(
            f"{source}: dependency name exceeds {MAX_DEP_NAME_LEN} chars; truncated"
        )
        name = name[:MAX_DEP_NAME_LEN]
    return _RawDep(name=name, version=version, source=source)


# ── Coordinator ──────────────────────────────────────────────────────────────


def _deduplicate(raw_deps: list[_RawDep], errors: list[str]) -> list[_RawDep]:
    """Apply PEP 503 normalisation + precedence-based dedup."""
    by_canonical: dict[str, _RawDep] = {}
    # Track whether any source marks the dep as direct (False wins).
    transitive_flags: dict[str, bool] = {}
    for dep in raw_deps:
        canonical = _normalise(dep.name)
        if canonical in _STDLIB_NAMES:
            errors.append(
                f"{dep.source}: '{dep.name}' is a Python stdlib module; excluded"
            )
            continue
        # If ANY source says "direct", the dep is direct.
        if canonical in transitive_flags:
            transitive_flags[canonical] = (
                transitive_flags[canonical] and dep.is_transitive
            )
        else:
            transitive_flags[canonical] = dep.is_transitive
        current = by_canonical.get(canonical)
        if current is None:
            by_canonical[canonical] = _RawDep(
                name=canonical,
                version=dep.version,
                source=dep.source,
            )
            continue
        current_pri = _source_priority(current.source)
        new_pri = _source_priority(dep.source)
        if new_pri > current_pri:
            # new wins. Warn about any version mismatch.
            if (
                current.version
                and dep.version
                and current.version != dep.version
                and current.version != dep.version  # explicit — placeholder for normalisation
            ):
                errors.append(
                    f"Package '{canonical}' declared with conflicting versions: "
                    f"'{current.version}' ({current.source}) vs '{dep.version}' "
                    f"({dep.source}) — using {dep.source} version"
                )
            by_canonical[canonical] = _RawDep(
                name=canonical,
                version=dep.version or current.version,
                source=dep.source,
            )
        elif new_pri < current_pri:
            if (
                current.version
                and dep.version
                and current.version != dep.version
            ):
                errors.append(
                    f"Package '{canonical}' declared with conflicting versions: "
                    f"'{current.version}' ({current.source}) vs '{dep.version}' "
                    f"({dep.source}) — using {current.source} version"
                )
            # keep current; maybe fill missing version
            if current.version is None and dep.version is not None:
                by_canonical[canonical] = _RawDep(
                    name=canonical,
                    version=dep.version,
                    source=current.source,
                )
        # equal priority: keep first-seen; silently ignore duplicate

    # Apply the resolved transitive flags.
    result: list[_RawDep] = []
    for dep in by_canonical.values():
        canonical = _normalise(dep.name)
        result.append(
            _RawDep(
                name=dep.name,
                version=dep.version,
                source=dep.source,
                is_transitive=transitive_flags.get(canonical, False),
            )
        )
    return result


def _source_priority(source: str) -> int:
    """Return the precedence priority for a ``_RawDep.source`` label."""
    # Exact match first, then strip any ``:suffix`` and retry.
    if source in _PRECEDENCE:
        return _PRECEDENCE[source]
    base = source.split(":", 1)[0]
    if base in _PRECEDENCE:
        return _PRECEDENCE[base]
    # GitHub workflow / Gitea / other path-based labels
    if base.startswith(".github/workflows/") or base.startswith(".gitea/workflows/"):
        return 15
    # Dockerfile variants (e.g., Dockerfile.prod)
    if base.startswith("Dockerfile") or base.endswith(".Dockerfile"):
        return 15
    return 0


def _apply_type_stub_detection(
    raw_deps: list[_RawDep],
) -> list[tuple[_RawDep, bool, str | None]]:
    """Return ``(dep, is_stub, runtime_ref)`` triples."""
    names = {_normalise(d.name) for d in raw_deps}
    out: list[tuple[_RawDep, bool, str | None]] = []
    for dep in raw_deps:
        is_stub, runtime = _is_type_stub(dep.name)
        if is_stub and runtime is not None and runtime not in names:
            # Runtime not declared — leave runtime_ref so the coordinator
            # can mark status UNCERTAIN with a descriptive reason.
            out.append((dep, True, runtime))
        else:
            out.append((dep, is_stub, runtime))
    return out


_TEST_GROUP_NAMES: frozenset[str] = frozenset({"test", "tests", "dev"})
_TEST_REQUIREMENTS_FILES: tuple[str, ...] = (
    "requirements-test.txt",
    "requirements-tests.txt",
    "requirements-dev.txt",
    "test-requirements.txt",
    "dev-requirements.txt",
)


def _is_test_scope_source(source: str) -> bool:
    """REQ-17 — return True when the dep source label denotes a test group.

    Examples:
      pyproject.toml:project.optional-dependencies.test  -> True
      pyproject.toml:project.optional-dependencies.dev   -> True
      pyproject.toml:dependency-groups:test              -> True
      pyproject.toml:poetry.group.test                   -> True
      requirements-test.txt                              -> True
      pyproject.toml:project                             -> False
    """
    s = source.lower()
    if s in {f.lower() for f in _TEST_REQUIREMENTS_FILES}:
        return True
    if "optional-dependencies" in s:
        # Trailing component is the group name.
        tail = s.rsplit(".", 1)[-1]
        if tail in _TEST_GROUP_NAMES:
            return True
    if "dependency-groups" in s:
        tail = s.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
        if tail in _TEST_GROUP_NAMES:
            return True
    if "poetry.group" in s:
        for name in _TEST_GROUP_NAMES:
            if f"poetry.group.{name}" in s:
                return True
    return False


def parse_all_dependency_files(
    project_path: str,
    *,
    exclude_tests: bool = False,
) -> tuple[list[Dependency], list[str], DepGraph]:
    """Parse every supported Python dependency file under ``project_path``.

    Never raises — parse failures append to the ``errors`` list and the
    coordinator continues with remaining files. Returns a deduplicated
    list of :class:`Dependency` objects (all with ``status=UNCERTAIN``
    and ``reason="declared — source analysis pending"``), the error list,
    and a dependency graph extracted from ``uv.lock`` (empty dict when no
    lock file is present).
    """
    errors: list[str] = []
    dep_graph: DepGraph = {}
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"could not resolve project path: {exc}")
        return [], errors, dep_graph
    if not root.is_dir():
        return [], errors, dep_graph

    raw: list[_RawDep] = []

    # Parse each format if present.
    req_file = root / "requirements.txt"
    if req_file.exists():
        raw.extend(_parse_requirements_txt(req_file, root, errors))

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        raw.extend(_parse_pyproject_toml(pyproject, errors))

    setup_py = root / "setup.py"
    if setup_py.exists():
        raw.extend(_parse_setup_py(setup_py, errors))

    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        raw.extend(_parse_setup_cfg(setup_cfg, errors))

    pipfile = root / "Pipfile"
    if pipfile.exists():
        raw.extend(_parse_pipfile(pipfile, errors))

    pipfile_lock = root / "Pipfile.lock"
    if pipfile_lock.exists():
        raw.extend(_parse_pipfile_lock(pipfile_lock, errors))

    poetry_lock = root / "poetry.lock"
    if poetry_lock.exists():
        # Identify direct poetry deps from already-parsed pyproject.toml entries.
        poetry_direct = {
            _normalise(d.name) for d in raw
            if d.source.startswith("pyproject.toml:poetry")
        }
        poetry_deps, poetry_graph = _parse_poetry_lock(
            poetry_lock, poetry_direct, errors
        )
        raw.extend(poetry_deps)
        if poetry_graph:
            dep_graph.update(poetry_graph)

    uv_lock = root / "uv.lock"
    if uv_lock.exists():
        uv_deps, dep_graph = _parse_uv_lock(uv_lock, errors)
        raw.extend(uv_deps)

    # REQ-17 — auxiliary test/dev requirements files. We always parse them
    # so the dep set reflects the project; the ``exclude_tests`` filter is
    # applied at the bottom of this function.
    for req_name in _TEST_REQUIREMENTS_FILES:
        aux_req = root / req_name
        if aux_req.exists():
            for raw_dep in _parse_requirements_txt(aux_req, root, errors):
                # Tag the source so the test-scope filter recognises it.
                raw.append(
                    _RawDep(
                        name=raw_dep.name,
                        version=raw_dep.version,
                        source=req_name,
                        is_transitive=raw_dep.is_transitive,
                    )
                )

    # REQ-2b — Conda environment.yml / environment.yaml
    for env_name in ("environment.yml", "environment.yaml"):
        env_file = root / env_name
        if env_file.exists():
            raw.extend(_parse_environment_yml(env_file, errors))
            break

    # REQ-2c — container / CI files (Dockerfile, workflows, tox.ini, noxfile.py)
    from scarno.analysers.python.container_ci_parser import (
        parse_container_and_ci_deps,
    )

    ci_deps, ci_errors = parse_container_and_ci_deps(str(root))
    errors.extend(ci_errors)
    for dep in ci_deps:
        raw.append(_RawDep(name=dep.name, version=dep.version, source=dep.source))

    # REQ-17 — drop test-scoped declared deps before downstream processing.
    if exclude_tests:
        raw = [r for r in raw if not _is_test_scope_source(r.source)]

    deduped = _deduplicate(raw, errors)
    annotated = _apply_type_stub_detection(deduped)

    deps: list[Dependency] = []
    for raw_dep, is_stub, runtime_ref in annotated:
        canonical = _normalise(raw_dep.name)
        reason = _STUB_REASON
        status = DependencyStatus.UNCERTAIN
        if is_stub:
            if runtime_ref and runtime_ref in {_normalise(d.name) for d in deduped}:
                status = DependencyStatus.IN_USE
                reason = f"type stub for '{runtime_ref}' which is declared as a dependency"
            elif runtime_ref:
                reason = (
                    f"type stub for '{runtime_ref}' but runtime package not found in "
                    f"declared dependencies — manual review required"
                )
        deps.append(
            Dependency(
                name=canonical,
                version=raw_dep.version,
                status=status,
                reason=reason,
                entry_points=[],
                entry_points_used=0,
                entry_points_total=0,
                source=raw_dep.source,
                is_type_stub=is_stub,
                ecosystem="pypi",
                is_transitive=raw_dep.is_transitive,
            )
        )
    return deps, errors, dep_graph
