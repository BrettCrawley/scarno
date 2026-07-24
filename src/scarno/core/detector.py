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

"""Project-type auto-detection.

REQ-9 introduced :func:`detect_project_types` which returns **every**
applicable language as a list. :func:`detect_project_type` is kept as a
legacy wrapper returning the primary (first-detected) language plus the
historical "both Java and Python present — using Java" stderr warning
so existing REQ-1 smoke tests remain green.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Indicator-file tables. The detector only checks for *presence*;
# analyser modules decide how to parse when their language is active.
#
# Phase 5 (JS/TS), Phase 6 (Go), Phase 7 (C#) extend these; the
# registry returns ``None`` for their languages until analyser modules
# register themselves.

_JAVA_INDICATORS: tuple[str, ...] = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)

_PYTHON_INDICATORS: tuple[str, ...] = (
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "environment.yml",
    "environment.yaml",
)

_JAVASCRIPT_INDICATORS: tuple[str, ...] = (
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "deno.json",
    "deno.jsonc",
    "deno.lock",
    "tsconfig.json",
    "jsconfig.json",
)

_GO_INDICATORS: tuple[str, ...] = (
    "go.mod",
    "go.sum",
)

_CSHARP_INDICATORS: tuple[str, ...] = (
    "global.json",
    "Directory.Packages.props",
    "packages.config",
    "packages.lock.json",
    "nuget.config",
)

_CSHARP_GLOB_INDICATORS: tuple[str, ...] = (
    "*.csproj",
    "*.fsproj",
    "*.vbproj",
    "*.sln",
)

# CSS-family indicators — only detect as "css" when no JS indicator is
# present (otherwise CSS analysis is subsumed by the JS analyser).
_CSS_GLOB_INDICATORS: tuple[str, ...] = (
    "*.css",
    "*.scss",
    "*.sass",
    "*.less",
)


def _has_any(root: Path, names: tuple[str, ...]) -> bool:
    return any((root / name).exists() for name in names)


_EXCLUDED_DETECT_DIRS: frozenset[str] = frozenset(
    {"node_modules", ".git", "vendor", "bin", "obj", "dist", "build"}
)


def _has_any_glob(root: Path, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        for match in root.rglob(pattern):
            # Skip matches inside excluded directories
            rel_parts = match.relative_to(root).parts
            if any(p in _EXCLUDED_DETECT_DIRS for p in rel_parts[:-1]):
                continue
            return True
    return False


def detect_project_types(project_path: str | Path) -> list[str]:
    """Return every applicable language key for ``project_path``.

    Order is stable: ``java``, ``python``, ``javascript``, ``css``,
    ``go``, ``csharp`` — matching the phase order so the legacy
    :func:`detect_project_type` reliably returns ``java`` when both
    Java and Python indicators are present (REQ-1 contract).
    """
    path = Path(project_path)
    if not path.is_dir():
        return []

    detected: list[str] = []

    if _has_any(path, _JAVA_INDICATORS):
        detected.append("java")

    if _has_any(path, _PYTHON_INDICATORS):
        detected.append("python")

    if _has_any(path, _JAVASCRIPT_INDICATORS):
        detected.append("javascript")

    # CSS always detected alongside JS when stylesheets are present —
    # JS projects routinely import CSS (@import "~normalize.css") and
    # CSS-side Findings (remote @import, file:// url) must surface even
    # when JS is the primary language.
    if _has_any_glob(path, _CSS_GLOB_INDICATORS):
        detected.append("css")

    if _has_any(path, _GO_INDICATORS):
        detected.append("go")

    if _has_any(path, _CSHARP_INDICATORS) or _has_any_glob(
        path, _CSHARP_GLOB_INDICATORS
    ):
        detected.append("csharp")

    return detected


def detect_project_type(project_path: str | Path) -> str | None:
    """Return the primary / first-detected language (legacy API).

    Preserves the historical REQ-1 behaviour: when both ``java`` and
    ``python`` indicators are present, ``java`` wins and a stderr
    warning is emitted. For other multi-language combinations we emit
    a gentler warning pointing the user at ``--language`` / the
    polyglot orchestrator.
    """
    all_types = detect_project_types(project_path)
    if not all_types:
        return None

    if "java" in all_types and "python" in all_types:
        print(
            "Warning: both Java and Python indicator files present; "
            "using Java. Pass an explicit path to the intended "
            "subproject, or rely on --language, if that is wrong.",
            file=sys.stderr,
        )
    elif len(all_types) > 1:
        print(
            "Warning: multiple project types detected "
            f"({', '.join(all_types)}); returning the first for legacy "
            "callers. Use the polyglot orchestrator to analyse all.",
            file=sys.stderr,
        )

    return all_types[0]
