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

"""Python project analyser — orchestrates REQ-2 + REQ-3.

Calls :func:`parse_all_dependency_files` (REQ-2) for declared deps,
then :func:`analyse_source_files` (REQ-3) to refine each one's status.
The orchestrator never raises — every parse / analysis failure is
accumulated into the returned ``AnalysisResult.errors`` list.
"""
from __future__ import annotations

from pathlib import Path

from scarno.analysers.python.dep_file_parser import parse_all_dependency_files
from scarno.analysers.python.source_analyser import (
    analyse_source_files_with_findings,
)
from scarno.core import registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.models import AnalysisResult

_SUPPORTED_INDICATORS: tuple[str, ...] = (
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
)


class PythonAnalyser(BaseAnalyser):
    """Python-project analyser for REQ-1 / REQ-2 / REQ-3 pipeline."""

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        return any((root / name).exists() for name in _SUPPORTED_INDICATORS)

    def analyse(self, project_path: str) -> AnalysisResult:
        root = Path(project_path).resolve(strict=False)
        deps, parse_errors, dep_graph = parse_all_dependency_files(
            str(root),
            exclude_tests=self.exclude_tests,
        )
        deps, source_errors, findings = analyse_source_files_with_findings(
            str(root), deps, use_gitignore=self.use_gitignore,
            dep_graph=dep_graph,
            exclude_tests=self.exclude_tests,
            user_test_paths=self.test_paths,
        )
        return AnalysisResult(
            project_type="python",
            project_path=str(root),
            dependencies=deps,
            errors=list(parse_errors) + list(source_errors),
            findings=findings,
            languages=["python"],
            dep_graph=dep_graph or {},
        )


# REQ-9 — self-register with the core registry on import.
registry.register("python", PythonAnalyser)

# REQ-19a / NEW-ARCH-012 — Python wheels have no transitive-version
# pin mechanism analogous to Maven <exclusions> or npm overrides.
# Register against the language AND its emitted ecosystem so the
# classifier's symmetric-coverage test (SEC-NEW-57) passes.
from scarno.core import classifier as _classifier  # noqa: E402
_classifier.register_no_pin_mechanism("python")
_classifier.register_no_pin_mechanism("pypi")
