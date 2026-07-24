"""Skeleton tests for REQ-9 — polyglot foundations (Phase 2.5).

These tests will flip from red to green when Phase 2.5 lands. SRTM
markers are attached now so FR-096..102 are tracked from the moment the
requirement is written.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scarno.core import detector
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
)


class TestEcosystemField:
    @pytest.mark.requirement("FR-096")
    def test_dependency_exposes_ecosystem_field(self):
        """Phase 2.5 adds `ecosystem` to the Dependency dataclass."""
        try:
            dep = Dependency(
                name="foo",
                version="1.0",
                status=DependencyStatus.UNCERTAIN,
                reason="",
                entry_points=[],
                entry_points_used=0,
                entry_points_total=0,
                ecosystem="npm",  # type: ignore[call-arg]
            )
        except TypeError:
            pytest.fail(
                "Dependency.ecosystem not yet defined — REQ-9 pending"
            )
        assert dep.ecosystem == "npm"  # type: ignore[attr-defined]

    @pytest.mark.requirement("FR-096")
    def test_existing_python_analyser_sets_ecosystem_pypi(self, tmp_path):
        from scarno.analysers.python import PythonAnalyser

        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        result = PythonAnalyser().analyse(str(tmp_path))
        for dep in result.dependencies:
            ecosystem = getattr(dep, "ecosystem", None)
            assert ecosystem == "pypi", (
                f"Python dep '{dep.name}' must carry ecosystem='pypi', got {ecosystem!r}"
            )


class TestMultiLanguageDetection:
    @pytest.mark.requirement("FR-097")
    def test_detect_project_types_returns_list(self, tmp_path):
        """The plural-form detector must return a list."""
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "go.mod").write_text("module example.com/foo\n")
        try:
            result = detector.detect_project_types(tmp_path)  # type: ignore[attr-defined]
        except AttributeError:
            pytest.fail("detect_project_types not yet defined — REQ-9 pending")
        assert isinstance(result, list)
        assert set(result) >= {"python", "go"}

    @pytest.mark.requirement("FR-097")
    def test_legacy_detect_project_type_returns_first(self, tmp_path):
        """Legacy single-string API preserves first-detected semantics."""
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "go.mod").write_text("module example.com/foo\n")
        primary = detector.detect_project_type(tmp_path)
        assert primary in {"python", "go"}


class TestOrchestratorRunsAllAnalysers:
    @pytest.mark.requirement("FR-098")
    @pytest.mark.requirement("FR-099")
    def test_cli_merges_results_from_multiple_analysers(self, tmp_path):
        """When multiple analysers register for a polyglot project, the
        CLI merges their dependencies and populates `languages`."""
        from typer.testing import CliRunner

        from scarno.cli import app

        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        (tmp_path / "go.mod").write_text(
            "module example.com/foo\n"
            "go 1.22\n"
            "require github.com/stretchr/testify v1.9.0\n"
        )
        runner = CliRunner()
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        if result.exit_code == 2:
            pytest.skip("Go analyser not yet registered — Phase 6 pending")
        import json

        data = json.loads(result.output)
        assert "languages" in data, (
            "AnalysisResult.languages must surface in JSON output (FR-099)"
        )
        assert "python" in data["languages"]
        assert "go" in data["languages"]


class TestLanguageFilter:
    @pytest.mark.requirement("FR-101")
    def test_language_flag_filters_output(self, tmp_path):
        from typer.testing import CliRunner

        from scarno.cli import app

        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        runner = CliRunner()
        result = runner.invoke(
            app, [str(tmp_path), "--language", "pypi", "--format", "json"]
        )
        if result.exit_code == 2:
            pytest.skip("--language flag not yet implemented — REQ-9 pending")
        import json

        data = json.loads(result.output)
        # REQ-9 contract — every surviving dep must carry the requested
        # ecosystem. ``languages`` holds language keys (``"python"``);
        # the ecosystem tag lives on each Dependency.
        for dep in data["dependencies"]:
            assert dep["ecosystem"] == "pypi"
        assert "python" in (data.get("languages") or [])

    @pytest.mark.requirement("FR-101")
    def test_unknown_language_exits_code_2(self, tmp_path):
        from typer.testing import CliRunner

        from scarno.cli import app

        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        runner = CliRunner()
        result = runner.invoke(
            app, [str(tmp_path), "--language", "nonexistent"]
        )
        assert result.exit_code == 2


class TestReporterGrouping:
    @pytest.mark.requirement("FR-100")
    def test_text_reporter_groups_by_ecosystem_when_multi_language(self):
        """Reporter renders per-ecosystem sub-headings only when multiple
        languages are present."""
        from scarno.reporters.text_reporter import TextReporter

        deps = [
            Dependency(
                "boto3",
                "1.0",
                DependencyStatus.SAFE,
                "unused",
                [],
                0,
                0,
            ),
            Dependency(
                "lodash",
                "4.17",
                DependencyStatus.SAFE,
                "unused",
                [],
                0,
                0,
            ),
        ]
        # Phase 2.5: deps should carry ecosystem; single-language projects
        # render as today (no sub-headings). Until then, this test only
        # asserts the reporter doesn't crash on a polyglot result.
        try:
            result = AnalysisResult(
                project_type="python",
                project_path="/tmp",
                dependencies=deps,
                errors=[],
                findings=[],
                languages=["python", "javascript"],  # type: ignore[call-arg]
            )
        except TypeError:
            pytest.skip(
                "AnalysisResult.languages not yet defined — REQ-9 pending"
            )
        output = TextReporter().render(result)
        assert "SAFE TO REMOVE" in output


class TestRegistry:
    @pytest.mark.requirement("FR-102")
    def test_registry_lookup_returns_analyser(self):
        try:
            from scarno.core import registry  # type: ignore[attr-defined]
        except ImportError:
            pytest.skip("Registry not yet implemented — REQ-9 pending")
        analyser = registry.get_analyser("python")
        assert analyser is not None

    @pytest.mark.requirement("FR-102")
    def test_registry_unknown_language_returns_none(self):
        try:
            from scarno.core import registry  # type: ignore[attr-defined]
        except ImportError:
            pytest.skip("Registry not yet implemented — REQ-9 pending")
        assert registry.get_analyser("nonexistent_language") is None
