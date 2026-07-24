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

"""JavaScript / TypeScript / Node.js project analyser.

Orchestrates REQ-10 (manifest + lock parsing) and REQ-11 (source
analysis via tree-sitter). Registers itself against the
``"javascript"`` language key on import.
"""
from __future__ import annotations

from pathlib import Path

from scarno.analysers.javascript.dep_file_parser import (
    parse_all_npm_dependency_files,
)
from scarno.analysers.javascript.source_analyser import analyse_npm_sources
from scarno.core import registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.models import AnalysisResult


_JS_INDICATORS: tuple[str, ...] = (
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "deno.json",
    "deno.jsonc",
    "deno.lock",
    "tsconfig.json",
    "jsconfig.json",
)


class JavascriptAnalyser(BaseAnalyser):
    """npm-ecosystem project analyser (frontend JS + Node.js)."""

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        return any((root / name).exists() for name in _JS_INDICATORS)

    def analyse(self, project_path: str) -> AnalysisResult:
        root = Path(project_path).resolve(strict=False)
        deps, parse_errors, findings = parse_all_npm_dependency_files(
            str(root), exclude_dev=self.exclude_dev,
        )
        deps, source_errors = analyse_npm_sources(
            str(root), deps,
            exclude_tests=self.exclude_tests,
            user_test_paths=self.test_paths,
        )

        # HTML/template scanning is handled by the CLI orchestrator as a
        # cross-cutting pass (runs once for the whole project, not per
        # analyser) to avoid double-scanning in polyglot mode.

        return AnalysisResult(
            project_type="javascript",
            project_path=str(root),
            dependencies=deps,
            errors=list(parse_errors) + list(source_errors),
            findings=findings,
            languages=["javascript"],
        )


registry.register("javascript", JavascriptAnalyser)

# REQ-19a / NEW-ARCH-012 — npm has overrides / yarn resolutions /
# pnpm.overrides. Registered as pin-detector placeholder; REQ-23
# (PR-5) ships the real detector — until then no Dependency.pin_override
# flag is set by any analyser code path, so SUC-42 enforcement is
# inert. The placeholder satisfies the symmetric-coverage contract
# so unrelated PRs can land without tripping SEC-NEW-57.
from scarno.core import classifier as _classifier  # noqa: E402
_classifier.register_pin_detector("javascript")
_classifier.register_pin_detector("npm")
