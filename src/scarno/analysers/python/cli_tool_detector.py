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

"""CLI tool usage detector.

Detects packages that are invoked as command-line tools rather than
imported in Python source code. Without this, tools like gunicorn,
celery, uvicorn, etc. would be falsely classified as SAFE.

Detection sources:
  * Dockerfile CMD / ENTRYPOINT instructions
  * Procfile process declarations
  * Shell scripts (``*.sh``) in project root and ``docker/`` directory
  * pyproject.toml ``[project.scripts]`` console entry points
  * Presence of tool-specific config files (e.g. ``gunicorn.conf.py``)

Safety:
  * All reads are confined via the caller's root resolution.
  * No execution of analysed files — text scanning only.
  * File size limits respected (MAX_FILE_BYTES).
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from scarno.security import MAX_FILE_BYTES

# Maps CLI command names to their PyPI distribution names.
CLI_TOOL_TO_PACKAGE: dict[str, str] = {
    "gunicorn": "gunicorn",
    "uvicorn": "uvicorn",
    "celery": "celery",
    "alembic": "alembic",
    "flask": "flask",
    "django-admin": "django",
    "pytest": "pytest",
    "py.test": "pytest",
    "mypy": "mypy",
    "black": "black",
    "ruff": "ruff",
    "isort": "isort",
    "pre-commit": "pre-commit",
    "uwsgi": "uwsgi",
    "daphne": "daphne",
    "hypercorn": "hypercorn",
    "fastapi": "fastapi",
    "streamlit": "streamlit",
    "jupyter": "jupyter",
    "ipython": "ipython",
    "sphinx-build": "sphinx",
    "mkdocs": "mkdocs",
    "pip-compile": "pip-tools",
    "pip-sync": "pip-tools",
    "tox": "tox",
    "nox": "nox",
    "coverage": "coverage",
    "flake8": "flake8",
    "pylint": "pylint",
    "bandit": "bandit",
    "httpie": "httpie",
    "http": "httpie",
}

# Maps config file names/patterns to the package they imply usage of.
CONFIG_FILE_TO_PACKAGE: dict[str, str] = {
    "gunicorn.conf.py": "gunicorn",
    "gunicorn_config.py": "gunicorn",
    "alembic.ini": "alembic",
    "celeryconfig.py": "celery",
    "uwsgi.ini": "uwsgi",
    ".flake8": "flake8",
    "mypy.ini": "mypy",
    ".mypy.ini": "mypy",
    "pytest.ini": "pytest",
    "conftest.py": "pytest",
    ".pre-commit-config.yaml": "pre-commit",
    "mkdocs.yml": "mkdocs",
    "mkdocs.yaml": "mkdocs",
    ".streamlit": "streamlit",
    "noxfile.py": "nox",
    "tox.ini": "tox",
    ".pylintrc": "pylint",
    "pylintrc": "pylint",
}


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _read_text_safe(path: Path) -> str | None:
    """Read a file as text, respecting size limits."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _extract_command_word(line: str) -> str | None:
    """Extract the first command word from a shell-style line."""
    # Strip JSON array syntax: ["gunicorn", "app:app"] → gunicorn
    stripped = line.strip()
    if stripped.startswith("["):
        try:
            parts = json.loads(stripped)
            if isinstance(parts, list) and parts:
                return str(parts[0]).strip()
        except (json.JSONDecodeError, ValueError):
            pass
    # Shell form: strip common prefixes (exec, python -m, etc.)
    words = stripped.split()
    if not words:
        return None
    # Skip common shell wrappers
    idx = 0
    while idx < len(words) and words[idx] in ("exec", "sudo", "env", "nohup"):
        idx += 1
    if idx < len(words):
        cmd = words[idx]
        # Strip path prefix: /usr/local/bin/gunicorn → gunicorn
        return cmd.rsplit("/", 1)[-1]
    return None


def _detect_from_dockerfiles(root: Path) -> set[str]:
    """Extract CLI tools from Dockerfile CMD/ENTRYPOINT instructions."""
    tools: set[str] = set()
    patterns = ["Dockerfile", "Dockerfile.*", "Containerfile", "*.Dockerfile"]
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(root.glob(pattern))
    docker_dir = root / "docker"
    if docker_dir.is_dir():
        for pattern in patterns:
            candidates.extend(docker_dir.glob(pattern))

    for path in candidates:
        text = _read_text_safe(path)
        if text is None:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            upper = stripped.upper()
            if upper.startswith("CMD ") or upper.startswith("ENTRYPOINT "):
                prefix_len = 4 if upper.startswith("CMD ") else 11
                remainder = stripped[prefix_len:].strip()
                cmd = _extract_command_word(remainder)
                if cmd and cmd in CLI_TOOL_TO_PACKAGE:
                    tools.add(CLI_TOOL_TO_PACKAGE[cmd])
    return tools


def _detect_from_procfile(root: Path) -> set[str]:
    """Extract CLI tools from Procfile."""
    tools: set[str] = set()
    procfile = root / "Procfile"
    if not procfile.exists():
        return tools
    text = _read_text_safe(procfile)
    if text is None:
        return tools
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: <process_type>: <command>
        if ":" not in line:
            continue
        _, command = line.split(":", 1)
        cmd = _extract_command_word(command.strip())
        if cmd and cmd in CLI_TOOL_TO_PACKAGE:
            tools.add(CLI_TOOL_TO_PACKAGE[cmd])
    return tools


def _detect_from_shell_scripts(root: Path) -> set[str]:
    """Scan shell scripts for known CLI tool invocations."""
    tools: set[str] = set()
    candidates: list[Path] = list(root.glob("*.sh"))
    docker_dir = root / "docker"
    if docker_dir.is_dir():
        candidates.extend(docker_dir.glob("*.sh"))
    scripts_dir = root / "scripts"
    if scripts_dir.is_dir():
        candidates.extend(scripts_dir.glob("*.sh"))
    # Common named scripts
    for name in ("entrypoint.sh", "start.sh", "run.sh", "docker-entrypoint.sh"):
        candidate = root / name
        if candidate.exists() and candidate not in candidates:
            candidates.append(candidate)

    tool_names = set(CLI_TOOL_TO_PACKAGE.keys())
    for path in candidates:
        text = _read_text_safe(path)
        if text is None:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Check if any known tool name appears as a command word.
            cmd = _extract_command_word(stripped)
            if cmd and cmd in tool_names:
                tools.add(CLI_TOOL_TO_PACKAGE[cmd])
    return tools


def _detect_from_pyproject_scripts(root: Path) -> set[str]:
    """Extract packages referenced by pyproject.toml [project.scripts]."""
    tools: set[str] = set()
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return tools
    try:
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return tools
    scripts = (data.get("project") or {}).get("scripts")
    if not isinstance(scripts, dict):
        return tools
    # Each value is like "myapp.cli:main" — the top-level module is the package.
    for _name, entry_point in scripts.items():
        if isinstance(entry_point, str) and ":" in entry_point:
            module_path = entry_point.split(":")[0]
            top_module = module_path.split(".")[0]
            tools.add(_normalise(top_module))
    return tools


def _detect_from_config_files(root: Path) -> set[str]:
    """Detect packages whose config files are present."""
    tools: set[str] = set()
    for filename, package in CONFIG_FILE_TO_PACKAGE.items():
        candidate = root / filename
        if candidate.exists():
            tools.add(package)
    # Also check for alembic/ directory
    if (root / "alembic").is_dir():
        tools.add("alembic")
    # Check for migrations/ with alembic env.py
    migrations = root / "migrations"
    if migrations.is_dir() and (migrations / "env.py").exists():
        tools.add("alembic")
    return tools


def detect_cli_tool_usage(
    project_path: str,
) -> tuple[set[str], list[str]]:
    """Detect packages used as CLI tools (not imported in source).

    Returns ``(set of canonical package names, errors)``.
    """
    errors: list[str] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError):
        return set(), errors

    tools: set[str] = set()
    tools |= _detect_from_dockerfiles(root)
    tools |= _detect_from_procfile(root)
    tools |= _detect_from_shell_scripts(root)
    tools |= _detect_from_pyproject_scripts(root)
    tools |= _detect_from_config_files(root)

    # Normalise all package names.
    return {_normalise(t) for t in tools}, errors
