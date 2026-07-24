"""End-to-end smoke tests using the simple_python fixture."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def simple_python(fixtures_dir: Path) -> Path:
    return fixtures_dir / "simple_python"


class TestSmokeTests:
    @pytest.mark.requirement("FR-001")
    def test_help_prints_usage(self, runner):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output or "scarno" in result.output.lower()

    @pytest.mark.requirement("FR-001")
    def test_simple_python_exits_not_2(self, runner, simple_python):
        result = runner.invoke(app, [str(simple_python)])
        assert result.exit_code != 2

    @pytest.mark.requirement("FR-001")
    def test_simple_python_json_format_valid(self, runner, simple_python):
        result = runner.invoke(app, [str(simple_python), "--format", "json"])
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "project_type" in data
        assert data["project_type"] == "python"

    @pytest.mark.requirement("FR-001")
    def test_simple_python_requests_in_output(self, runner, simple_python):
        result = runner.invoke(app, [str(simple_python), "--format", "json"])
        data = json.loads(result.output)
        names = [d["name"] for d in data["dependencies"]]
        assert "requests" in names

    @pytest.mark.requirement("FR-001")
    def test_simple_python_boto3_in_output(self, runner, simple_python):
        result = runner.invoke(app, [str(simple_python), "--format", "json"])
        data = json.loads(result.output)
        names = [d["name"] for d in data["dependencies"]]
        assert "boto3" in names

    @pytest.mark.requirement("FR-002")
    def test_exit_code_1_when_safe_deps_found(self, runner, simple_python):
        result = runner.invoke(app, [str(simple_python), "--format", "json"])
        data = json.loads(result.output)
        has_safe = any(d["status"] == "SAFE" for d in data["dependencies"])
        if has_safe:
            assert result.exit_code == 1

    @pytest.mark.requirement("FR-001")
    def test_text_format_contains_at_least_one_section(self, runner, simple_python):
        result = runner.invoke(app, [str(simple_python), "--format", "text"])
        sections = {"SAFE TO REMOVE", "UNCERTAIN", "IN USE"}
        assert any(s in result.output for s in sections)

    @pytest.mark.requirement("FR-033")
    def test_output_flag_creates_file(self, runner, simple_python, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app,
            [str(simple_python), "--format", "json", "--output", str(out)],
        )
        assert result.exit_code in (0, 1)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "project_type" in data

    @pytest.mark.requirement("FR-001")
    def test_verbose_flag_does_not_corrupt_json_stdout(self, runner, simple_python):
        result = runner.invoke(
            app,
            [str(simple_python), "--format", "json", "--verbose"],
        )
        assert result.exit_code in (0, 1)
        json.loads(result.output)

    @pytest.mark.requirement("FR-003")
    def test_analysis_result_has_required_schema_fields(self, runner, simple_python):
        result = runner.invoke(app, [str(simple_python), "--format", "json"])
        data = json.loads(result.output)
        assert "project_type" in data
        assert "project_path" in data
        assert "dependencies" in data
        assert "errors" in data
        for dep in data["dependencies"]:
            assert "name" in dep
            assert "status" in dep
            assert "reason" in dep
            assert "entry_points" in dep
            assert "entry_points_used" in dep
            assert "entry_points_total" in dep
