"""PR-3 red tests — REQ-21 / FR-215: Maven pin-override reporter sections
(TA-256 + TA-257).
"""
from __future__ import annotations

import json

import pytest


def _result_with_maven_pin():
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
    )
    return AnalysisResult(
        project_type="java",
        project_path="/tmp/x",
        dependencies=[
            Dependency(
                name="com.example:patched-x",
                version="1.5",
                status=DependencyStatus.IN_USE,
                reason="exclusion-override pin",
                pin_override=True,
                pin_override_kind="EXCLUSION",
                pin_override_target=(
                    "substitutes for excluded transitive of com.example:lib-y"
                ),
                ecosystem="maven",
            ),
        ],
        dep_edges=[
            DepEdge(
                parent="",
                child="com.example:patched-x",
                declared_version="1.5",
            ),
        ],
    )


@pytest.mark.requirement("FR-215")
def test_pinning_overrides_section_rendered():
    """TA-256 — Markdown reporter emits a 'Pinning overrides (Maven)'
    section listing each pin_override dep with the substitution
    narrative."""
    from scarno.reporters.markdown_reporter import MarkdownReporter

    rendered = MarkdownReporter().render(_result_with_maven_pin())
    assert "Pinning overrides" in rendered
    assert "patched-x" in rendered
    assert "exclu" in rendered.lower(), (
        "Maven exclusion-override narrative missing from rendered output"
    )


@pytest.mark.requirement("FR-215")
def test_sarif_TS_DEP_PIN_OVERRIDE_MAVEN():
    """TA-257 — SARIF reporter emits TS-DEP-PIN-OVERRIDE-MAVEN at
    severity 'note' for each Maven pin_override dep."""
    from scarno.reporters.sarif_reporter import SarifReporter

    sarif_str = SarifReporter().render(_result_with_maven_pin())
    sarif = json.loads(sarif_str)
    rule_ids = {
        r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]
    }
    assert "TS-DEP-PIN-OVERRIDE-MAVEN" in rule_ids
    pin_results = [
        r for r in sarif["runs"][0].get("results", [])
        if r.get("ruleId") == "TS-DEP-PIN-OVERRIDE-MAVEN"
    ]
    assert len(pin_results) == 1
    assert pin_results[0].get("level") == "note"
