"""Integration tests validating security controls at trust boundary crossings.

B1: CLI args → Zone 1
B2: Zone 2 → Zone 3 (filesystem reads)
B5: Zone 1 → Zone 5 (output)
"""
from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from scarno.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestB1CLIBoundary:
    @pytest.mark.requirement("SEC-002")
    @pytest.mark.integration
    def test_resolved_path_used_not_raw_string(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        project_path = data.get("project_path", "")
        assert os.path.isabs(project_path)
        assert ".." not in project_path


class TestB2FilesystemBoundary:
    @pytest.mark.requirement("T-07")
    @pytest.mark.integration
    def test_full_analysis_skips_symlinked_files_outside_root(self, runner, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        (project / "main.py").write_text("import requests\n")
        if os.path.exists("/etc/passwd"):
            (project / "sneaky.py").symlink_to("/etc/passwd")
        result = runner.invoke(app, [str(project), "--format", "json"])
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        output_text = json.dumps(data)
        assert "root:" not in output_text
        assert "/bin/" not in output_text


class TestB5OutputBoundary:
    @pytest.mark.requirement("SEC-003")
    @pytest.mark.requirement("SEC-004")
    @pytest.mark.integration
    def test_json_output_parseable_with_adversarial_project(self, runner, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\ndependencies = [\'requests==2.31.0\']\n'
        )
        result = runner.invoke(app, [str(project), "--format", "json"])
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "dependencies" in data

    @pytest.mark.requirement("R-01")
    @pytest.mark.requirement("ARCH-SEC-004")
    @pytest.mark.integration
    def test_json_output_includes_version_and_timestamp(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        assert "scarno_version" in data
        assert "analysis_timestamp" in data

    @pytest.mark.requirement("I-03")
    @pytest.mark.requirement("PRV-002")
    @pytest.mark.integration
    def test_error_messages_in_json_do_not_contain_source_content(
        self, runner, tmp_path
    ):
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        (project / "main.py").write_text(
            'API_KEY = "super_secret_key_12345"\nimport requests\n'
        )
        result = runner.invoke(app, [str(project), "--format", "json"])
        data = json.loads(result.output)
        output_text = json.dumps(data)
        assert "super_secret_key_12345" not in output_text
