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

"""C# / .NET analyser — REQ-15 (manifest) + REQ-16 (source).

Registered under the ``"csharp"`` language key. The orchestrator routes
here when ``.csproj``, ``.fsproj``, ``.vbproj``, ``global.json``,
``nuget.config``, or other NuGet indicators are detected.
"""
from __future__ import annotations

from pathlib import Path

from scarno.analysers.csharp.dep_file_parser import (
    parse_all_csharp_dependency_files,
)
from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
from scarno.core import registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.models import AnalysisResult

_PROJECT_EXTS = (".csproj", ".fsproj", ".vbproj", ".sln")


class CsharpAnalyser(BaseAnalyser):
    """C# / .NET ecosystem analyser: NuGet manifests + source ``using`` directives."""

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        for ext in _PROJECT_EXTS:
            for _ in root.rglob(f"*{ext}"):
                return True
        return (root / "global.json").exists() or (root / "nuget.config").exists()

    def analyse(self, project_path: str) -> AnalysisResult:
        root = Path(project_path).resolve(strict=False)
        deps, parse_errors, findings = parse_all_csharp_dependency_files(str(root))
        deps, source_errors = analyse_csharp_sources(str(root), deps)
        return AnalysisResult(
            project_type="csharp",
            project_path=str(root),
            dependencies=deps,
            errors=list(parse_errors) + list(source_errors),
            findings=findings,
            languages=["csharp"],
        )


registry.register("csharp", CsharpAnalyser)

# REQ-19a / NEW-ARCH-012 — NuGet PackageReference / lock files don't
# carry exclusion / override constructs analogous to Maven / npm.
from scarno.core import classifier as _classifier  # noqa: E402
_classifier.register_no_pin_mechanism("csharp")
_classifier.register_no_pin_mechanism("nuget")
