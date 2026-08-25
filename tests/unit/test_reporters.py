"""Tests for TextReporter and JsonReporter — pure functions, no I/O."""
from __future__ import annotations

import json
import re

import pytest

from scarno.models import AnalysisResult, Dependency, DependencyStatus, EntryPoint
from scarno.reporters.json_reporter import JsonReporter
from scarno.reporters.text_reporter import TextReporter


@pytest.fixture
def text_reporter() -> TextReporter:
    return TextReporter()


@pytest.fixture
def json_reporter() -> JsonReporter:
    return JsonReporter()


@pytest.fixture
def mixed_result() -> AnalysisResult:
    return AnalysisResult(
        project_type="python",
        project_path="/tmp/test",
        dependencies=[
            Dependency(
                "requests",
                "2.31.0",
                DependencyStatus.SAFE,
                "No usage found",
                [],
                0,
                0,
            ),
            Dependency(
                "flask",
                "3.0.0",
                DependencyStatus.IN_USE,
                "Imported in app.py",
                [
                    EntryPoint("flask.Flask", "class", True),
                    EntryPoint("flask.request", "constant", False),
                ],
                1,
                2,
            ),
            Dependency(
                "boto3",
                "1.26.0",
                DependencyStatus.UNCERTAIN,
                "Dynamic import detected",
                [],
                0,
                0,
            ),
        ],
        errors=["A non-fatal warning"],
    )


class TestTextReporter:
    @pytest.mark.requirement("FR-030")
    def test_safe_section_present_when_safe_deps_exist(self, text_reporter, mixed_result):
        output = text_reporter.render(mixed_result)
        assert "SAFE TO REMOVE" in output

    @pytest.mark.requirement("FR-030")
    def test_uncertain_section_present(self, text_reporter, mixed_result):
        output = text_reporter.render(mixed_result)
        assert "UNCERTAIN" in output

    @pytest.mark.requirement("FR-030")
    def test_in_use_section_present(self, text_reporter, mixed_result):
        output = text_reporter.render(mixed_result)
        assert "IN USE" in output

    @pytest.mark.requirement("FR-030")
    def test_section_order_safe_uncertain_inuse(self, text_reporter, mixed_result):
        output = text_reporter.render(mixed_result)
        safe_pos = output.index("SAFE TO REMOVE")
        uncertain_pos = output.index("UNCERTAIN")
        inuse_pos = output.index("IN USE")
        assert safe_pos < uncertain_pos < inuse_pos

    @pytest.mark.requirement("FR-030")
    def test_entry_points_summary_shown_when_present(self, text_reporter, mixed_result):
        output = text_reporter.render(mixed_result)
        assert "1 / 2" in output or "1/2" in output

    @pytest.mark.requirement("FR-030")
    def test_used_entry_points_prefixed_with_checkmark(self, text_reporter, mixed_result):
        output = text_reporter.render(mixed_result)
        assert "flask.Flask" in output
        assert "✓" in output

    @pytest.mark.requirement("FR-030")
    def test_unused_entry_points_omitted_from_text(self, text_reporter, mixed_result):
        """flask.request is unused — must NOT appear in text output."""
        output = text_reporter.render(mixed_result)
        assert "flask.request" not in output

    @pytest.mark.requirement("SEC-003")
    @pytest.mark.requirement("SEC-013")
    @pytest.mark.security
    def test_ansi_escape_in_dep_name_stripped_from_text(self, text_reporter):
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "\x1b[2Jmalicious\x1b[0m",
                    "1.0",
                    DependencyStatus.SAFE,
                    "No usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
        )
        output = text_reporter.render(result)
        assert "\x1b" not in output
        assert "malicious" in output

    @pytest.mark.requirement("SEC-003")
    @pytest.mark.requirement("SEC-NEW-03")
    @pytest.mark.security
    def test_c1_escape_in_dep_name_stripped_from_text(self, text_reporter):
        """8-bit CSI/OSC (U+009B / U+009D) must not reach the terminal.

        ``_ANSI_RE`` only removes the ESC-prefixed 7-bit forms, so the
        single-byte C1 equivalents have to be caught by the control-char
        strip — otherwise a dependency name can clear the screen or forge
        report text on a terminal that decodes C1 from UTF-8.
        """
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "\u009b2Jmalicious\u009d0;title",
                    "1.0",
                    DependencyStatus.SAFE,
                    "No usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
        )
        output = text_reporter.render(result)
        for c1 in range(0x80, 0xA0):
            assert chr(c1) not in output
        assert "malicious" in output

    @pytest.mark.requirement("SEC-NEW-10")
    @pytest.mark.security
    def test_rich_markup_in_dep_name_escaped(self, text_reporter):
        """Rich markup like [bold]evil[/bold] must not trigger formatting."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "[bold red]evil[/bold red]",
                    "1.0",
                    DependencyStatus.SAFE,
                    "No usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
        )
        output = text_reporter.render(result)
        assert "[bold red]" not in output or "evil" in output

    @pytest.mark.requirement("FR-030")
    def test_empty_result_produces_valid_output(self, text_reporter):
        result = AnalysisResult("python", "/tmp", [], [])
        output = text_reporter.render(result)
        assert isinstance(output, str)

    @pytest.mark.requirement("FR-030")
    def test_warnings_section_shown_when_errors_present(self, text_reporter, mixed_result):
        output = text_reporter.render(mixed_result)
        assert "WARNINGS" in output or "A non-fatal warning" in output


class TestJsonReporter:
    @pytest.mark.requirement("FR-032")
    def test_output_is_valid_json(self, json_reporter, mixed_result):
        output = json_reporter.render(mixed_result)
        data = json.loads(output)
        assert isinstance(data, dict)

    @pytest.mark.requirement("FR-032")
    def test_required_fields_present(self, json_reporter, mixed_result):
        data = json.loads(json_reporter.render(mixed_result))
        assert "project_type" in data
        assert "project_path" in data
        assert "dependencies" in data

    @pytest.mark.requirement("ARCH-SEC-004")
    @pytest.mark.requirement("R-01")
    def test_version_and_timestamp_present(self, json_reporter, mixed_result):
        data = json.loads(json_reporter.render(mixed_result))
        assert "scarno_version" in data
        assert "analysis_timestamp" in data
        assert re.match(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", data["analysis_timestamp"]
        )

    @pytest.mark.requirement("FR-032")
    def test_entry_points_array_in_dep(self, json_reporter, mixed_result):
        data = json.loads(json_reporter.render(mixed_result))
        flask_dep = next(d for d in data["dependencies"] if d["name"] == "flask")
        assert "entry_points" in flask_dep
        assert isinstance(flask_dep["entry_points"], list)
        assert len(flask_dep["entry_points"]) == 2

    @pytest.mark.requirement("SEC-004")
    @pytest.mark.security
    def test_json_uses_json_dumps_not_fstrings(self, json_reporter):
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    'evil"name":{"injected":true}',
                    "1.0",
                    DependencyStatus.SAFE,
                    "No usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
        )
        output = json_reporter.render(result)
        data = json.loads(output)
        dep = data["dependencies"][0]
        assert isinstance(dep["name"], str)
        assert "injected" not in data

    @pytest.mark.requirement("SEC-NEW-03")
    @pytest.mark.security
    def test_control_chars_stripped_from_json_fields(self, json_reporter):
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "pkg\x00\x01\r",
                    "1.0",
                    DependencyStatus.SAFE,
                    "reason\x00",
                    [],
                    0,
                    0,
                )
            ],
            [],
        )
        output = json_reporter.render(result)
        assert "\x00" not in output
        assert "\x01" not in output

    @pytest.mark.requirement("PRV-003")
    @pytest.mark.requirement("ARCH-SEC-002")
    @pytest.mark.security
    def test_json_output_contains_no_source_code_content(self, json_reporter):
        """AnalysisResult must not carry source code content fields."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "requests",
                    "2.31.0",
                    DependencyStatus.IN_USE,
                    "Imported in main.py",
                    [],
                    0,
                    0,
                )
            ],
            [],
        )
        data = json.loads(json_reporter.render(result))
        dep = data["dependencies"][0]
        forbidden_fields = {
            "source_text",
            "matched_line",
            "file_excerpt",
            "source_content",
        }
        assert not forbidden_fields.intersection(dep.keys())
