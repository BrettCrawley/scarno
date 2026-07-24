"""Tests for per-ecosystem grouping in reporters (REQ-9 / FR-100)."""
from __future__ import annotations

import json

import pytest

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
)
from scarno.reporters.json_reporter import JsonReporter
from scarno.reporters.markdown_reporter import MarkdownReporter
from scarno.reporters.text_reporter import TextReporter


def _dep(name: str, status: DependencyStatus, ecosystem: str) -> Dependency:
    return Dependency(
        name=name,
        version="1.0",
        status=status,
        reason=f"unused in {ecosystem}",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        ecosystem=ecosystem,
    )


@pytest.fixture
def polyglot_result() -> AnalysisResult:
    return AnalysisResult(
        project_type="python",
        project_path="/tmp/demo",
        dependencies=[
            _dep("boto3", DependencyStatus.SAFE, "pypi"),
            _dep("lodash", DependencyStatus.SAFE, "npm"),
            _dep("stretchr-testify", DependencyStatus.SAFE, "go"),
        ],
        errors=[],
        findings=[],
        languages=["python", "javascript", "go"],
    )


@pytest.fixture
def single_language_result() -> AnalysisResult:
    return AnalysisResult(
        project_type="python",
        project_path="/tmp/demo",
        dependencies=[
            _dep("boto3", DependencyStatus.SAFE, "pypi"),
            _dep("requests", DependencyStatus.IN_USE, "pypi"),
        ],
        errors=[],
        findings=[],
        languages=["python"],
    )


class TestTextReporter:
    @pytest.mark.requirement("FR-100")
    def test_polyglot_groups_by_ecosystem(self, polyglot_result):
        output = TextReporter().render(polyglot_result)
        # Each ecosystem renders as a sub-heading within the section
        assert "[go]" in output
        assert "[npm]" in output
        assert "[pypi]" in output

    @pytest.mark.requirement("FR-100")
    def test_single_language_has_no_ecosystem_subheadings(
        self, single_language_result
    ):
        """Single-language projects keep today's flat rendering."""
        output = TextReporter().render(single_language_result)
        assert "[pypi]" not in output


class TestMarkdownReporter:
    @pytest.mark.requirement("FR-100")
    def test_polyglot_uses_h3_ecosystem_subheadings(self, polyglot_result):
        output = MarkdownReporter().render(polyglot_result)
        assert "### [pypi]" in output
        assert "### [npm]" in output
        assert "### [go]" in output

    @pytest.mark.requirement("FR-100")
    def test_single_language_has_no_subheadings(self, single_language_result):
        output = MarkdownReporter().render(single_language_result)
        assert "### [pypi]" not in output


class TestJsonReporter:
    @pytest.mark.requirement("FR-099")
    def test_json_exposes_languages_field(self, polyglot_result):
        data = json.loads(JsonReporter().render(polyglot_result))
        assert data["languages"] == ["python", "javascript", "go"]

    @pytest.mark.requirement("FR-099")
    def test_every_dep_carries_ecosystem(self, polyglot_result):
        data = json.loads(JsonReporter().render(polyglot_result))
        for dep in data["dependencies"]:
            assert dep.get("ecosystem") in {"pypi", "npm", "go"}
