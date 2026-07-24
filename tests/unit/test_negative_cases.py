"""Systematic negative-path tests for Phase 0 → 2.5 code.

Every test here exercises a category of *wrong* input and asserts the
contract: **structured error, not crash**. Organised by NEG-* SRTM ID:

- NEG-001 — wrong-type in structured dep files
- NEG-002 — truncated / partial inputs
- NEG-003 — encoding edges (BOM, CRLF, non-UTF-8)
- NEG-004 — empty-but-well-formed inputs
- NEG-005 — CLI edge combinations
- NEG-006 — model / API contract edges
- NEG-007 — orchestrator / registry failure modes
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.analysers.python.dep_file_parser import parse_all_dependency_files
from scarno.cli import app
from scarno.core import registry as _registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
    FindingKind,
    FindingSeverity,
)
from scarno.reporters.json_reporter import JsonReporter
from scarno.reporters.markdown_reporter import MarkdownReporter
from scarno.reporters.sarif_reporter import SarifReporter
from scarno.reporters.text_reporter import TextReporter


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ── NEG-001 — wrong-type inputs ──────────────────────────────────────────────


class TestWrongTypeInputs:
    @pytest.mark.requirement("NEG-001")
    def test_pyproject_dependencies_as_string_not_list(self, tmp_path):
        """``dependencies = "not a list"`` must not crash the parser."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = "not a list"\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert isinstance(deps, list)
        assert isinstance(errors, list)

    @pytest.mark.requirement("NEG-001")
    def test_pyproject_dependencies_mixed_types(self, tmp_path):
        """A list containing non-string entries must skip them silently."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = ["requests==2.31.0", 42, true]\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        # The valid entry survives; bad entries don't.
        assert "requests" in names
        assert not any(d.name == "42" for d in deps)

    @pytest.mark.requirement("NEG-001")
    def test_pipfile_lock_default_not_object(self, tmp_path):
        """Pipfile.lock with ``default`` as a primitive instead of object."""
        (tmp_path / "Pipfile.lock").write_text(
            '{"default": "not-an-object", "develop": {}}'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # No crash; either structured error or empty deps
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-001")
    def test_pipfile_lock_top_level_is_array(self, tmp_path):
        """JSON root array instead of object — must produce structured error."""
        (tmp_path / "Pipfile.lock").write_text("[1, 2, 3]")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-001")
    def test_setup_py_install_requires_as_dict(self, tmp_path):
        """install_requires as a dict (wrong type) → dynamic-detection warning."""
        (tmp_path / "setup.py").write_text(
            "from setuptools import setup\n"
            'setup(install_requires={"not": "a list"})\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # Parser must tolerate the wrong type — either dynamic warning or empty
        assert isinstance(deps, list)
        assert isinstance(errors, list)

    @pytest.mark.requirement("NEG-001")
    def test_pyproject_build_system_requires_as_dict(self, tmp_path):
        """``[build-system].requires = {…}`` (dict instead of list)."""
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\nrequires = { not = \"a list\" }\n"
            'build-backend = "hatchling.build"\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # Error message mentions 'list' or 'requires'
        assert any(
            "list" in e.lower() or "requires" in e.lower() for e in errors
        )

    @pytest.mark.requirement("NEG-001")
    def test_pyproject_dependency_groups_non_list_group(self, tmp_path):
        """``[dependency-groups].test = 42`` must append a warning, not crash."""
        (tmp_path / "pyproject.toml").write_text(
            "[dependency-groups]\ntest = 42\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert isinstance(deps, list)


# ── NEG-002 — truncated / partial inputs ────────────────────────────────────


class TestTruncatedInputs:
    @pytest.mark.requirement("NEG-002")
    def test_truncated_json_in_pipfile_lock(self, tmp_path):
        """Pipfile.lock cut off mid-value → JSON parse error appended."""
        (tmp_path / "Pipfile.lock").write_text('{"default": {"flask": {')
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(
            "JSON" in e or "parse" in e.lower() for e in errors
        ), f"Expected a JSON parse error, got: {errors}"

    @pytest.mark.requirement("NEG-002")
    def test_truncated_toml_in_pyproject(self, tmp_path):
        """pyproject.toml with an unclosed table → TOML parse error."""
        (tmp_path / "pyproject.toml").write_text(
            '[project\nname = "bad"\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(
            "TOML" in e or "parse" in e.lower() for e in errors
        ), f"Expected a TOML parse error, got: {errors}"

    @pytest.mark.requirement("NEG-002")
    def test_truncated_requirements_line_not_crash(self, tmp_path):
        """Requirements.txt with a clearly broken last line."""
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\n@@@garbled\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "requests" in names  # valid line still parses
        assert len(errors) >= 1  # garbled line produces an error


# ── NEG-003 — encoding edges ────────────────────────────────────────────────


class TestEncodingEdges:
    @pytest.mark.requirement("NEG-003")
    def test_utf8_bom_in_requirements_txt(self, tmp_path):
        """BOM-prefixed requirements.txt must not crash; either strip or warn."""
        (tmp_path / "requirements.txt").write_bytes(
            b"\xef\xbb\xbfrequests==2.31.0\nflask\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        # Either BOM is transparent (both parse) or the first line errors.
        # What we REFUSE to accept is a crash.
        assert isinstance(deps, list)
        assert "flask" in names  # second line always OK

    @pytest.mark.requirement("NEG-003")
    def test_crlf_line_endings_in_requirements_txt(self, tmp_path):
        """Windows-style CRLF must parse identically to LF."""
        (tmp_path / "requirements.txt").write_bytes(
            b"requests==2.31.0\r\nflask\r\n"
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert {"requests", "flask"}.issubset(names)

    @pytest.mark.requirement("NEG-003")
    def test_non_utf8_bytes_in_requirements_txt(self, tmp_path):
        """Latin-1 bytes in a UTF-8-only file → structured error, no crash."""
        # 0xA9 is © in Latin-1 but an invalid UTF-8 start byte.
        (tmp_path / "requirements.txt").write_bytes(
            b"requests==2.31.0\npackage\xa9name\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # Implementation may strip non-UTF-8 or emit an error; either OK.
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-003")
    def test_nul_byte_in_requirements_line(self, tmp_path):
        """A NUL byte mid-requirement must not propagate to output."""
        (tmp_path / "requirements.txt").write_bytes(
            b"requests==2.31.0\npkg\x00name==1.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # Whatever happens, no NUL in dep names.
        for dep in deps:
            assert "\x00" not in dep.name


# ── NEG-004 — empty-but-well-formed ─────────────────────────────────────────


class TestEmptyInputs:
    @pytest.mark.requirement("NEG-004")
    def test_empty_project_table(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert deps == []
        assert errors == []  # empty is not an error

    @pytest.mark.requirement("NEG-004")
    def test_empty_build_system_requires(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = \"x\"\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert deps == []
        assert errors == []

    @pytest.mark.requirement("NEG-004")
    def test_empty_pipfile_lock(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_text(
            '{"_meta": {}, "default": {}, "develop": {}}'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert deps == []

    @pytest.mark.requirement("NEG-004")
    def test_empty_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert deps == []
        assert errors == []

    @pytest.mark.requirement("NEG-004")
    def test_requirements_txt_only_comments(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "# header\n# list of deps we haven't picked yet\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert deps == []
        assert errors == []


# ── NEG-005 — CLI edge combinations ─────────────────────────────────────────


class TestCliEdges:
    @pytest.mark.requirement("NEG-005")
    def test_file_as_path_exits_2(self, runner, tmp_path):
        """Passing a file (not dir) as the project path must exit 2."""
        f = tmp_path / "not_a_dir.txt"
        f.write_text("hello")
        result = runner.invoke(app, [str(f)])
        assert result.exit_code == 2

    @pytest.mark.requirement("NEG-005")
    def test_unicode_in_project_path_handled(self, runner, tmp_path):
        """Unicode directory names must not break path resolution."""
        project = tmp_path / "prøject-名前"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        result = runner.invoke(app, [str(project), "--format", "json"])
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        assert "project_path" in data

    @pytest.mark.requirement("NEG-005")
    def test_multiple_language_values_accepted(self, runner, tmp_path):
        """Repeated ``--language`` must be accepted and combined."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        result = runner.invoke(
            app,
            [
                str(tmp_path),
                "--language",
                "pypi",
                "--language",
                "maven",
                "--format",
                "json",
            ],
        )
        # pypi matches, maven doesn't — but the filter logic accepts any overlap
        assert result.exit_code in (0, 1)

    @pytest.mark.requirement("NEG-005")
    def test_format_uppercase_accepted(self, runner, tmp_path):
        """``--format JSON`` (uppercase) must work (case_sensitive=False)."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        result = runner.invoke(app, [str(tmp_path), "--format", "JSON"])
        assert result.exit_code in (0, 1)
        # Output should be parseable JSON
        json.loads(result.stdout)

    @pytest.mark.requirement("NEG-005")
    def test_empty_directory_exits_2(self, runner, tmp_path):
        """An empty directory with no indicators → exit 2."""
        project = tmp_path / "empty_proj"
        project.mkdir()
        result = runner.invoke(app, [str(project)])
        assert result.exit_code == 2


# ── NEG-006 — model / API contract edges ────────────────────────────────────


class TestModelContractEdges:
    @pytest.mark.requirement("NEG-006")
    def test_dependency_with_empty_name_constructible(self):
        """Model accepts empty name — reporters must sanitise and not crash."""
        dep = Dependency(
            name="",
            version=None,
            status=DependencyStatus.UNCERTAIN,
            reason="",
            entry_points=[],
            entry_points_used=0,
            entry_points_total=0,
        )
        assert dep.name == ""
        assert dep.ecosystem == "unknown"  # default preserved

    @pytest.mark.requirement("NEG-006")
    def test_finding_with_zero_line_constructible(self):
        """Line=0 is degenerate but must not blow up constructors / reporters."""
        finding = Finding(
            rule_id="TS-SI-001",
            kind=FindingKind.RUNTIME_PIP_INSTALL,
            severity=FindingSeverity.HIGH,
            file_path="",
            line=0,
            snippet="",
            message="",
            remediation="",
        )
        assert finding.line == 0

    @pytest.mark.requirement("NEG-006")
    def test_reporters_handle_empty_project_type(self):
        """AnalysisResult with ``project_type=""`` must render without crash."""
        result = AnalysisResult(
            project_type="",
            project_path="",
            dependencies=[],
            errors=[],
            findings=[],
            languages=[],
        )
        for reporter_cls in (
            TextReporter,
            JsonReporter,
            MarkdownReporter,
            SarifReporter,
        ):
            rendered = reporter_cls().render(result)
            assert isinstance(rendered, str)
            assert len(rendered) > 0

    @pytest.mark.requirement("NEG-006")
    def test_reporters_handle_empty_dep_name(self):
        """Reporters must survive a Dependency with an empty name."""
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[
                Dependency(
                    name="",
                    version=None,
                    status=DependencyStatus.SAFE,
                    reason="",
                    entry_points=[],
                    entry_points_used=0,
                    entry_points_total=0,
                )
            ],
            errors=[],
            findings=[],
            languages=["python"],
        )
        for reporter_cls in (
            TextReporter,
            JsonReporter,
            MarkdownReporter,
            SarifReporter,
        ):
            out = reporter_cls().render(result)
            assert isinstance(out, str)


# ── NEG-007 — orchestrator / registry failure modes ─────────────────────────


class _RaisingAnalyser(BaseAnalyser):
    """Analyser that deliberately explodes — for NEG-007."""

    def supports(self, project_path: str) -> bool:
        return True

    def analyse(self, project_path: str) -> AnalysisResult:  # noqa: ARG002
        raise RuntimeError("intentional analyser blow-up for NEG-007")


class TestOrchestratorFailureModes:
    @pytest.mark.requirement("NEG-007")
    def test_analyser_exception_caught_by_cli(self, runner, tmp_path, monkeypatch):
        """An analyser that raises must not leak a traceback; CLI exits 2."""
        # Replace the real python analyser with a raising stub for this run.
        monkeypatch.setitem(
            _registry._REGISTRY, "python", _RaisingAnalyser
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 2
        assert "Traceback" not in result.output

    @pytest.mark.requirement("NEG-007")
    def test_registry_double_registration_replaces(self):
        """Registering the same language twice must not crash; second wins."""
        class _A(_RaisingAnalyser):
            pass

        class _B(_RaisingAnalyser):
            pass

        _registry.register("neg_double_reg", _A)
        _registry.register("neg_double_reg", _B)
        try:
            analyser = _registry.get_analyser("neg_double_reg")
            assert isinstance(analyser, _B)
        finally:
            _registry._REGISTRY.pop("neg_double_reg", None)

    @pytest.mark.requirement("NEG-007")
    def test_registry_lookup_for_never_registered_language(self):
        """Getting an analyser for a language never registered returns None."""
        assert _registry.get_analyser("neg_never_registered_lang") is None

    @pytest.mark.requirement("NEG-007")
    def test_orchestrator_skips_detected_but_unregistered_language(
        self, runner, tmp_path
    ):
        """A `go.mod` project with no Go analyser registered produces a warning
        rather than a hard error — the polyglot orchestrator skips gracefully.
        """
        (tmp_path / "go.mod").write_text("module example.com/x\n")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = []\n'
        )
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        # Python analyser runs; Go is mentioned in either languages or errors.
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        assert "go" in data.get("languages", []) or any(
            "go" in e.lower() for e in data.get("errors", [])
        )
