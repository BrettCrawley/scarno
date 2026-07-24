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

"""Go analyser — REQ-13 (manifest) + REQ-14 (source).

Registered under the ``"go"`` language key. The orchestrator routes
here when ``go.mod`` or ``go.sum`` is detected in the project root.
"""
from __future__ import annotations

from pathlib import Path

from scarno.analysers.go.dep_file_parser import parse_all_go_dependency_files
from scarno.analysers.go.source_analyser import analyse_go_sources
from scarno.core import registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.models import AnalysisResult


class GoAnalyser(BaseAnalyser):
    """Go-ecosystem analyser: go.mod + go.sum + source imports."""

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        return root.is_dir() and (
            (root / "go.mod").exists() or (root / "go.sum").exists()
        )

    def analyse(self, project_path: str) -> AnalysisResult:
        root = Path(project_path).resolve(strict=False)
        deps, parse_errors, findings = parse_all_go_dependency_files(str(root))
        deps, source_errors = analyse_go_sources(str(root), deps)
        return AnalysisResult(
            project_type="go",
            project_path=str(root),
            dependencies=deps,
            errors=list(parse_errors) + list(source_errors),
            findings=findings,
            languages=["go"],
        )


registry.register("go", GoAnalyser)

# REQ-19a / NEW-ARCH-012 — Go modules use `replace` directives but
# have no transitive-version pin mechanism analogous to <exclusions>
# / overrides. Registered as no-pin-mechanism.
from scarno.core import classifier as _classifier  # noqa: E402
_classifier.register_no_pin_mechanism("go")
