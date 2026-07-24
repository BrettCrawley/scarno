"""Tests for the CLI entry point: argument validation, path resolution,
privilege check, verbose flag, exception sanitisation."""
from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from scarno.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestCLIPathResolution:
    @pytest.mark.requirement("FR-001")
    def test_no_args_defaults_to_current_directory(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 1)

    @pytest.mark.requirement("FR-001")
    def test_explicit_path_arg_used(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code in (0, 1)

    @pytest.mark.requirement("FR-002")
    def test_unsupported_project_type_exits_code_2(self, runner, tmp_path):
        result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 2

    @pytest.mark.requirement("FR-002")
    def test_unsupported_message_in_stderr(self, runner, tmp_path):
        result = runner.invoke(app, [str(tmp_path)])
        assert "No supported project type detected" in result.output or result.exit_code == 2

    @pytest.mark.requirement("SEC-002")
    @pytest.mark.security
    def test_nonexistent_path_exits_code_2(self, runner):
        result = runner.invoke(app, ["/nonexistent/path/that/does/not/exist"])
        assert result.exit_code == 2


class TestOutputFlag:
    @pytest.mark.requirement("FR-033")
    def test_output_flag_writes_file(self, runner, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        out_file = tmp_path / "report.json"
        result = runner.invoke(
            app, [str(project), "--format", "json", "--output", str(out_file)]
        )
        assert result.exit_code in (0, 1)
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "project_type" in data

    @pytest.mark.requirement("SEC-NEW-11")
    @pytest.mark.security
    def test_output_outside_cwd_errors_by_default(self, runner, tmp_path, monkeypatch):
        """--output resolving outside CWD must error, not proceed silently."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        outside_file = tmp_path / "outside.json"
        monkeypatch.chdir(project)
        result = runner.invoke(
            app, [str(project), "--output", str(outside_file)]
        )
        assert result.exit_code == 2
        assert "external" in result.output.lower() or "outside" in result.output.lower()

    @pytest.mark.requirement("SEC-NEW-11")
    @pytest.mark.security
    def test_output_path_traversal_blocked(self, runner, tmp_path, monkeypatch):
        """--output ../../.ssh/authorized_keys must be blocked."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        monkeypatch.chdir(project)
        evil_output = str(tmp_path / ".." / ".." / ".ssh" / "authorized_keys")
        result = runner.invoke(app, [str(project), "--output", evil_output])
        assert result.exit_code == 2


class TestPrivilegeCheck:
    @pytest.mark.requirement("SEC-005")
    @pytest.mark.requirement("GAP-06")
    def test_root_warning_emitted_when_root(self, runner, tmp_path, monkeypatch):
        if hasattr(os, "getuid"):
            monkeypatch.setattr(os, "getuid", lambda: 0)
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(app, [str(tmp_path)], catch_exceptions=False)
        assert "root" in result.output.lower() or "administrator" in result.output.lower()


class TestFormatFlag:
    @pytest.mark.requirement("FR-082")
    def test_markdown_format_produces_checklist(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["boto3"]\n'
        )
        # Markdown is now the default format AND default omits-output
        # auto-writes to a file. Pass an explicit --output so this test
        # gets a deterministic, tmp-confined target it can read back.
        out_file = tmp_path / "report.md"
        result = runner.invoke(
            app,
            [str(tmp_path), "--format", "markdown", "--output", str(out_file)],
        )
        assert result.exit_code in (0, 1)
        rendered = out_file.read_text(encoding="utf-8")
        assert "# Scarno analysis" in rendered
        assert "- [ ]" in rendered  # actionable checkbox

    @pytest.mark.requirement("FR-082")
    def test_md_alias_accepted(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["boto3"]\n'
        )
        out_file = tmp_path / "report.md"
        result = runner.invoke(
            app,
            [str(tmp_path), "--format", "md", "--output", str(out_file)],
        )
        assert result.exit_code in (0, 1)
        assert "# Scarno analysis" in out_file.read_text(encoding="utf-8")

    @pytest.mark.requirement("FR-082")
    def test_sarif_format_produces_valid_sarif(self, runner, tmp_path):
        import json as _json

        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["boto3"]\n'
        )
        result = runner.invoke(app, [str(tmp_path), "--format", "sarif"])
        assert result.exit_code in (0, 1)
        data = _json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "scarno"

    @pytest.mark.requirement("FR-082")
    def test_unknown_format_exits_code_2(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        result = runner.invoke(app, [str(tmp_path), "--format", "xml"])
        assert result.exit_code == 2


class TestLanguageFilter:
    @pytest.mark.requirement("FR-101")
    def test_language_pypi_accepted(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        result = runner.invoke(
            app,
            [str(tmp_path), "--language", "pypi", "--format", "json"],
        )
        assert result.exit_code in (0, 1)

    @pytest.mark.requirement("FR-101")
    def test_language_unknown_ecosystem_exits_2(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        result = runner.invoke(
            app, [str(tmp_path), "--language", "npm"]
        )
        assert result.exit_code == 2

    @pytest.mark.requirement("FR-101")
    def test_language_invalid_value_exits_2(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        result = runner.invoke(
            app, [str(tmp_path), "--language", "not-a-real-ecosystem"]
        )
        assert result.exit_code == 2


class TestVerboseFlag:
    @pytest.mark.requirement("FR-001")
    def test_verbose_output_goes_to_stderr_not_stdout(self, runner, tmp_path):
        """--verbose debug lines must not corrupt stdout (which carries the report)."""
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(
            app, [str(tmp_path), "--verbose", "--format", "json"]
        )
        try:
            json.loads(result.output)
        except json.JSONDecodeError:
            pytest.fail("--verbose corrupted JSON stdout output")


class TestExceptionSanitisation:
    @pytest.mark.requirement("I-01")
    @pytest.mark.security
    def test_exception_does_not_expose_traceback_in_non_verbose(
        self, runner, tmp_path, monkeypatch
    ):
        """Unhandled exceptions must produce one-line message without traceback."""
        def _boom(_):
            raise RuntimeError("internal boom")

        # REQ-9 — CLI now calls the plural detector; patch both the new
        # and legacy names so this test survives either dispatch path.
        monkeypatch.setattr(
            "scarno.core.detector.detect_project_types",
            _boom,
        )
        monkeypatch.setattr(
            "scarno.core.detector.detect_project_type",
            _boom,
        )
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 2
        assert "Traceback" not in result.output
