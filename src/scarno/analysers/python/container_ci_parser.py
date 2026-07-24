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

"""Container & CI dependency extractor — REQ-2c.

Parses `Dockerfile`, `Containerfile`, GitHub Actions workflow YAML,
`.gitlab-ci.yml`, `tox.ini`, and `noxfile.py` for Python dependencies
that are installed at build or test time and therefore don't show up in
any declarative dep file.

Safety:
  * YAML: ``yaml.safe_load`` only (SEC-NEW-15).
  * Regex-based parsers use anchored patterns with a per-line length cap
    (``_MAX_LINE_BYTES = 64 KB``) to rule out ReDoS (SEC-NEW-16).
  * ``noxfile.py`` is parsed via ``ast.parse`` — never executed
    (SEC-NEW-18, SEC-001).
  * ``tox.ini`` interpolation depth is capped at
    ``_MAX_INTERPOLATION_DEPTH = 10`` with cycle detection (SEC-NEW-17).
"""
from __future__ import annotations

import ast
import configparser
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from packaging.requirements import InvalidRequirement, Requirement

from scarno.models import Dependency, DependencyStatus
from scarno.security import MAX_FILE_BYTES

_STUB_REASON = "declared — source analysis pending"
_MAX_LINE_BYTES = 64 * 1024
_MAX_INTERPOLATION_DEPTH = 10
# Dockerfiles should be small; reject anything over 1 MB.
_MAX_DOCKERFILE_BYTES = 1 * 1024 * 1024

# Recognised pip/conda install verbs; anchored start-of-token.
_PIP_INSTALL_TOKENS: tuple[tuple[str, ...], ...] = (
    ("pip", "install"),
    ("pip3", "install"),
    ("uv", "pip", "install"),
    ("conda", "install"),
)
# Match "python -m pip install ..." in shell scripts.
_PYTHON_M_PIP_RE = re.compile(
    r"\bpython[0-9]*\s+-m\s+pip\s+install\b", re.IGNORECASE
)

_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


@dataclass
class _ExtractedDep:
    name: str
    version: str | None
    source: str


def parse_container_and_ci_deps(
    project_path: str,
) -> tuple[list[Dependency], list[str]]:
    """Extract Python deps from container/CI files.

    Never raises. Returns the full per-source list (deduplication
    happens in :func:`dep_file_parser.parse_all_dependency_files`).
    """
    errors: list[str] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"container_ci_parser: could not resolve path — {exc}")
        return [], errors
    if not root.is_dir():
        return [], errors

    extracted: list[_ExtractedDep] = []
    extracted.extend(_scan_dockerfiles(root, errors))
    extracted.extend(_scan_github_workflows(root, errors))
    extracted.extend(_scan_gitlab_ci(root, errors))
    extracted.extend(_scan_tox_ini(root, errors))
    extracted.extend(_scan_noxfile(root, errors))

    deps: list[Dependency] = []
    for ex in extracted:
        canonical = _normalise(ex.name)
        deps.append(
            Dependency(
                name=canonical,
                version=ex.version,
                status=DependencyStatus.UNCERTAIN,
                reason=f"declared via {ex.source} — source analysis pending",
                entry_points=[],
                entry_points_used=0,
                entry_points_total=0,
                source=ex.source,
                ecosystem="pypi",
            )
        )
    return deps, errors


# ── Dockerfile ──────────────────────────────────────────────────────────────


def _scan_dockerfiles(root: Path, errors: list[str]) -> list[_ExtractedDep]:
    candidates: list[Path] = []
    for pattern in ("Dockerfile", "Dockerfile.*", "Containerfile", "*.Dockerfile"):
        candidates.extend(root.rglob(pattern))
    out: list[_ExtractedDep] = []
    for path in candidates:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _MAX_DOCKERFILE_BYTES:
            errors.append(
                f"{path.name}: exceeds size limit ({_MAX_DOCKERFILE_BYTES} bytes); skipped"
            )
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{path.name}: read failed — {exc}")
            continue
        label = _dockerfile_label(root, path)
        out.extend(_extract_from_shell_block(text, label, errors))
    return out


def _dockerfile_label(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return path.name
    parts = rel.parts
    if len(parts) == 1:
        return parts[0]
    return parts[0]


def _extract_from_shell_block(
    text: str, source_label: str, errors: list[str]
) -> list[_ExtractedDep]:
    """Extract pip-install package names from a shell script fragment.

    Handles both Dockerfile ``RUN`` blocks and YAML workflow ``run:``
    strings. Line-continuation (``\\`` at end of line) is joined before
    parsing. Long lines are rejected to guarantee bounded runtime.
    """
    out: list[_ExtractedDep] = []
    joined_lines = _join_continuations(text, source_label, errors)
    for line in joined_lines:
        if len(line) > _MAX_LINE_BYTES:
            errors.append(
                f"{source_label}: line exceeds {_MAX_LINE_BYTES} bytes; skipped"
            )
            continue
        content = _strip_dockerfile_prefix(line)
        if content is None:
            continue
        out.extend(_extract_install_from_shell_line(content, source_label, errors))
    return out


def _join_continuations(
    text: str, source_label: str, errors: list[str]
) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    total_joined = 0
    for raw_line in text.splitlines():
        stripped = raw_line.rstrip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1].rstrip())
            total_joined += 1
            if total_joined > 200:
                errors.append(
                    f"{source_label}: line-continuation chain exceeded 200 lines; truncated"
                )
                out.append(" ".join(buf))
                buf = []
                total_joined = 0
            continue
        if buf:
            buf.append(stripped)
            out.append(" ".join(buf))
            buf = []
            total_joined = 0
        else:
            out.append(stripped)
    if buf:
        out.append(" ".join(buf))
    return out


def _strip_dockerfile_prefix(line: str) -> str | None:
    """Return the shell content of a Dockerfile line, or None for non-run."""
    stripped = line.lstrip()
    if not stripped:
        return None
    # Dockerfile instruction prefix
    for prefix in ("RUN ", "CMD ", "ENTRYPOINT "):
        if stripped.upper().startswith(prefix):
            return stripped[len(prefix):]
    # Already plain shell content (YAML run step)
    return stripped


def _extract_install_from_shell_line(
    content: str, source: str, errors: list[str]
) -> list[_ExtractedDep]:
    """Scan a shell line for a pip/conda install and harvest package args."""
    out: list[_ExtractedDep] = []
    # Split on shell operators; each chunk is evaluated independently.
    for chunk in re.split(r"\s*(?:&&|\|\||;|\|)\s*", content):
        tokens = chunk.strip().split()
        if not tokens:
            continue
        install_idx = _find_install_start(tokens)
        if install_idx is None:
            continue
        pkg_tokens = tokens[install_idx:]
        out.extend(_extract_pkgs_from_tokens(pkg_tokens, source, errors))
    return out


def _find_install_start(tokens: list[str]) -> int | None:
    """Return the index of the first positional arg after pip/conda install."""
    if _PYTHON_M_PIP_RE.search(" ".join(tokens)):
        # Find the 'install' token
        for idx in range(len(tokens) - 1):
            if tokens[idx] == "pip" and tokens[idx + 1] == "install":
                return idx + 2
    for prefix in _PIP_INSTALL_TOKENS:
        if len(tokens) < len(prefix):
            continue
        if tuple(tokens[: len(prefix)]) == prefix:
            return len(prefix)
    return None


def _extract_pkgs_from_tokens(
    tokens: list[str], source: str, errors: list[str]
) -> list[_ExtractedDep]:
    out: list[_ExtractedDep] = []
    skip_next = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if skip_next:
            skip_next = False
            i += 1
            continue
        # -r / --requirement redirect — record as reference only
        if tok in ("-r", "--requirement"):
            if i + 1 < len(tokens):
                target = tokens[i + 1]
                out.append(
                    _ExtractedDep(
                        name=f"__ref__:{target}",
                        version=None,
                        source=f"{source}:-r {target}",
                    )
                )
                skip_next = True
            i += 1
            continue
        # Skip pip options and their args
        if tok.startswith("-"):
            if tok in (
                "--index-url",
                "-i",
                "--extra-index-url",
                "--find-links",
                "-f",
                "--constraint",
                "-c",
                "--target",
                "--prefix",
            ):
                skip_next = True
            i += 1
            continue
        if "$" in tok:
            errors.append(
                f"{source}: unresolved variable in 'pip install {tok}' — package ignored"
            )
            i += 1
            continue
        parsed = _parse_pip_pkg_token(tok)
        if parsed is not None:
            name, version = parsed
            out.append(
                _ExtractedDep(name=name, version=version, source=source)
            )
        i += 1
    # Filter out ref markers — they're placeholders only
    return [d for d in out if not d.name.startswith("__ref__:")]


def _parse_pip_pkg_token(tok: str) -> tuple[str, str | None] | None:
    """Parse a single positional arg to ``pip install``."""
    # URLs / VCS refs / local paths — skip.
    if "://" in tok or tok.startswith(("./", "/", "file:")):
        return None
    # Try packaging's Requirement for PEP 508.
    try:
        req = Requirement(tok)
    except InvalidRequirement:
        # Fall back to simple `name==version` split (for conda-style).
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:==(.+))?$", tok)
        if m is None:
            return None
        return m.group(1), m.group(2)
    name = req.name
    if not _IDENT_RE.match(name):
        return None
    version: str | None = None
    if req.specifier:
        spec = str(req.specifier)
        exact = re.match(r"^==([^,]+)$", spec)
        version = exact.group(1).strip() if exact else spec
    return name, version


# ── GitHub Actions / GitLab CI ───────────────────────────────────────────────


def _scan_github_workflows(root: Path, errors: list[str]) -> list[_ExtractedDep]:
    out: list[_ExtractedDep] = []
    for workflow_root in (root / ".github" / "workflows", root / ".gitea" / "workflows"):
        if not workflow_root.is_dir():
            continue
        for pattern in ("*.yml", "*.yaml"):
            for path in workflow_root.glob(pattern):
                out.extend(_scan_workflow_file(path, root, errors))
    return out


def _scan_workflow_file(
    path: Path, root: Path, errors: list[str]
) -> list[_ExtractedDep]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > MAX_FILE_BYTES:
        errors.append(f"{path.name}: exceeds size limit; skipped")
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"{path.name}: read failed — {exc}")
        return []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        errors.append(f"{path.name}: YAML parse error — {exc}")
        return []
    if not isinstance(data, dict):
        return []
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    source_base = str(rel).replace("\\", "/")
    return _extract_from_workflow_jobs(data.get("jobs"), source_base, errors)


def _extract_from_workflow_jobs(
    jobs: Any, source_base: str, errors: list[str]
) -> list[_ExtractedDep]:
    out: list[_ExtractedDep] = []
    if not isinstance(jobs, dict):
        return out
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if isinstance(run, str):
                label = f"{source_base}:{job_name}.steps[{idx}]"
                out.extend(_extract_from_shell_block(run, label, errors))
    return out


def _scan_gitlab_ci(root: Path, errors: list[str]) -> list[_ExtractedDep]:
    path = root / ".gitlab-ci.yml"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f".gitlab-ci.yml: read failed — {exc}")
        return []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        errors.append(f".gitlab-ci.yml: YAML parse error — {exc}")
        return []
    if not isinstance(data, dict):
        return []
    out: list[_ExtractedDep] = []
    for job_name, job in data.items():
        if not isinstance(job, dict):
            continue
        for key in ("before_script", "script", "after_script"):
            script = job.get(key)
            if isinstance(script, list):
                for line in script:
                    if isinstance(line, str):
                        out.extend(
                            _extract_from_shell_block(
                                line, f".gitlab-ci.yml:{job_name}.{key}", errors
                            )
                        )
    return out


# ── tox.ini ─────────────────────────────────────────────────────────────────


_TOX_REF_RE = re.compile(r"\{\[(?P<section>[^\]]+)\](?P<key>[^}]+)\}")


def _scan_tox_ini(root: Path, errors: list[str]) -> list[_ExtractedDep]:
    path = root / "tox.ini"
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > MAX_FILE_BYTES:
        errors.append("tox.ini: exceeds size limit; skipped")
        return []
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as exc:
        errors.append(f"tox.ini: parse error — {exc}")
        return []
    out: list[_ExtractedDep] = []
    for section in parser.sections():
        if not (section == "testenv" or section.startswith("testenv:") or section == "tox"):
            continue
        for key in ("deps", "requires"):
            if parser.has_option(section, key):
                raw = parser.get(section, key)
                resolved = _resolve_tox_value(
                    raw, parser, visited=[(section, key)], errors=errors
                )
                label = f"tox.ini:{section}"
                for line in resolved.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    dep = _parse_tox_dep_line(stripped, label, errors)
                    if dep is not None:
                        out.append(dep)
    return out


def _resolve_tox_value(
    raw: str,
    parser: configparser.ConfigParser,
    visited: list[tuple[str, str]],
    errors: list[str],
) -> str:
    if len(visited) > _MAX_INTERPOLATION_DEPTH:
        errors.append(
            f"tox.ini: interpolation depth exceeded {_MAX_INTERPOLATION_DEPTH}"
        )
        return raw

    def _sub(match: re.Match[str]) -> str:
        section = match.group("section")
        key = match.group("key")
        pair = (section, key)
        if pair in visited:
            errors.append(
                f"tox.ini: interpolation cycle detected: "
                + " → ".join(f"[{s}].{k}" for s, k in visited + [pair])
            )
            return ""
        if not parser.has_option(section, key):
            return ""
        inner = parser.get(section, key)
        return _resolve_tox_value(inner, parser, visited + [pair], errors)

    return _TOX_REF_RE.sub(_sub, raw)


def _parse_tox_dep_line(
    raw: str, source: str, errors: list[str]
) -> _ExtractedDep | None:
    try:
        req = Requirement(raw)
    except InvalidRequirement:
        return None
    name = req.name
    if not _IDENT_RE.match(name):
        return None
    version: str | None = None
    if req.specifier:
        spec = str(req.specifier)
        exact = re.match(r"^==([^,]+)$", spec)
        version = exact.group(1).strip() if exact else spec
    return _ExtractedDep(name=name, version=version, source=source)


# ── noxfile.py ──────────────────────────────────────────────────────────────


def _scan_noxfile(root: Path, errors: list[str]) -> list[_ExtractedDep]:
    for candidate in ("noxfile.py", "nox.py"):
        path = root / candidate
        if path.exists():
            return _parse_noxfile(path, errors)
    return []


def _parse_noxfile(path: Path, errors: list[str]) -> list[_ExtractedDep]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > MAX_FILE_BYTES:
        errors.append(f"{path.name}: exceeds size limit; skipped")
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{path.name}: could not read — {exc}")
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        errors.append(f"{path.name}: syntax error — {exc}")
        return []

    out: list[_ExtractedDep] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "install"):
            continue
        # Accept session.install(...) — func.value is a Name like "session".
        if not isinstance(func.value, ast.Name):
            continue
        name = _noxfile_install_name(node.args)
        if name is None and node.args:
            errors.append(
                f"{path.name}: dynamic session.install — deps may be incomplete"
            )
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                token = arg.value.strip()
                if not token:
                    continue
                parsed = _parse_pip_pkg_token(token)
                if parsed is not None:
                    pkg_name, version = parsed
                    out.append(
                        _ExtractedDep(
                            name=pkg_name, version=version, source=path.name
                        )
                    )
    return out


def _noxfile_install_name(args: list[ast.expr]) -> str | None:
    if not args:
        return None
    first = args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None
