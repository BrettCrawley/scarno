"""REQ-17 — EntryPoint.usage_count tally tests.

Verifies that every used entry point carries an integer ``usage_count``
that matches the number of source-level reference sites, and that the
text / JSON / SARIF / Markdown reporters surface it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


class TestUsageCountField:
    @pytest.mark.requirement("FR-150")
    def test_entry_point_dataclass_has_usage_count_field(self):
        from scarno.models import EntryPoint
        ep = EntryPoint(name="x.y", kind="function", used=True)
        assert hasattr(ep, "usage_count")
        assert ep.usage_count == 0

    @pytest.mark.requirement("FR-150")
    def test_entry_point_usage_count_can_be_set(self):
        from scarno.models import EntryPoint
        ep = EntryPoint(name="x.y", kind="function", used=True, usage_count=12)
        assert ep.usage_count == 12


class TestPythonUsageCount:
    @pytest.mark.requirement("FR-150")
    def test_python_usage_count_matches_call_sites(self, tmp_path):
        # 3 call sites of os.path.join (which is stdlib so won't be counted),
        # but for our purpose we use a non-stdlib import that is installed:
        # 'json' is stdlib too.  Use 'pytest' (definitely installed in the
        # test environment).
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )
        from scarno.models import Dependency, DependencyStatus

        _write(tmp_path / "main.py", (
            "import pytest\n"
            "pytest.fail('a')\n"
            "pytest.fail('b')\n"
            "pytest.fail('c')\n"
            "pytest.skip('s')\n"
        ))
        deps = [Dependency(
            name="pytest", version="0", status=DependencyStatus.UNCERTAIN,
            reason="", source="x", ecosystem="pypi",
        )]
        updated, _errors = analyse_source_files(str(tmp_path), deps)
        pytest_dep = next(d for d in updated if d.name == "pytest")
        # IN_USE classification populated; entry points enumerated.
        assert pytest_dep.status == DependencyStatus.IN_USE
        ep_by_name = {ep.name: ep for ep in pytest_dep.entry_points}
        assert "pytest.fail" in ep_by_name
        assert ep_by_name["pytest.fail"].used is True
        assert ep_by_name["pytest.fail"].usage_count == 3
        assert ep_by_name["pytest.skip"].used is True
        assert ep_by_name["pytest.skip"].usage_count == 1

    @pytest.mark.requirement("FR-150")
    def test_python_unused_entry_point_has_zero_count(self, tmp_path):
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )
        from scarno.models import Dependency, DependencyStatus

        _write(tmp_path / "main.py", "import pytest\n")  # imported, never called
        deps = [Dependency(
            name="pytest", version="0", status=DependencyStatus.UNCERTAIN,
            reason="", source="x", ecosystem="pypi",
        )]
        updated, _ = analyse_source_files(str(tmp_path), deps)
        pytest_dep = next(d for d in updated if d.name == "pytest")
        for ep in pytest_dep.entry_points:
            if not ep.used:
                assert ep.usage_count == 0


class TestReporterRendering:
    @pytest.mark.requirement("FR-150")
    def test_text_reporter_renders_usage_count_suffix(self):
        from scarno.models import (
            AnalysisResult, Dependency, DependencyStatus, EntryPoint,
        )
        from scarno.reporters.text_reporter import TextReporter

        dep = Dependency(
            name="flask", version="3.0.0",
            status=DependencyStatus.IN_USE, reason="imported",
            entry_points=[
                EntryPoint(name="flask.Flask", kind="class",
                           used=True, usage_count=23),
                EntryPoint(name="flask.Blueprint", kind="class",
                           used=True, usage_count=4),
                EntryPoint(name="flask.unused", kind="function",
                           used=False, usage_count=0),
            ],
            entry_points_used=2, entry_points_total=3,
            ecosystem="pypi",
        )
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[dep], languages=["python"],
        )
        out = TextReporter().render(result)
        # Usage count suffix appears for used entry points only
        assert "23" in out and "flask.Flask" in out
        assert "4" in out and "flask.Blueprint" in out

    @pytest.mark.requirement("FR-150")
    def test_json_reporter_carries_usage_count_field(self):
        from scarno.models import (
            AnalysisResult, Dependency, DependencyStatus, EntryPoint,
        )
        from scarno.reporters.json_reporter import JsonReporter

        dep = Dependency(
            name="flask", version="3.0.0",
            status=DependencyStatus.IN_USE, reason="imported",
            entry_points=[
                EntryPoint(name="flask.Flask", kind="class",
                           used=True, usage_count=11),
            ],
            entry_points_used=1, entry_points_total=1,
            ecosystem="pypi",
        )
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[dep], languages=["python"],
        )
        rendered = JsonReporter().render(result)
        data = json.loads(rendered)
        flask_dep = data["dependencies"][0]
        ep = flask_dep["entry_points"][0]
        assert ep["usage_count"] == 11

    @pytest.mark.requirement("FR-150")
    def test_markdown_reporter_renders_usage_count_suffix(self):
        from scarno.models import (
            AnalysisResult, Dependency, DependencyStatus, EntryPoint,
        )
        from scarno.reporters.markdown_reporter import MarkdownReporter

        dep = Dependency(
            name="flask", version="3.0.0",
            status=DependencyStatus.IN_USE, reason="imported",
            entry_points=[
                EntryPoint(name="flask.Flask", kind="class",
                           used=True, usage_count=7),
            ],
            entry_points_used=1, entry_points_total=1,
            ecosystem="pypi",
        )
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[dep], languages=["python"],
        )
        out = MarkdownReporter().render(result)
        # Markdown shows the count alongside the entry point line.
        assert "flask.Flask" in out
        assert "7" in out

    @pytest.mark.requirement("FR-150")
    def test_sarif_reporter_includes_usage_count_in_properties(self):
        from scarno.models import (
            AnalysisResult, Dependency, DependencyStatus, EntryPoint,
        )
        from scarno.reporters.sarif_reporter import SarifReporter

        dep = Dependency(
            name="flask", version="3.0.0",
            status=DependencyStatus.IN_USE, reason="imported",
            entry_points=[
                EntryPoint(name="flask.Flask", kind="class",
                           used=True, usage_count=9),
            ],
            entry_points_used=1, entry_points_total=1,
            ecosystem="pypi",
        )
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[dep], languages=["python"],
        )
        rendered = SarifReporter().render(result)
        # Loose assertion: 9 must appear somewhere associated with the entry
        # point name. Strict schema assertion lives in the SARIF reporter
        # tests; here we just verify the integer is carried through.
        assert '"usage_count"' in rendered
        assert "9" in rendered
