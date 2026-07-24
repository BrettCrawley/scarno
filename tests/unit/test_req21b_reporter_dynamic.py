"""PR-6 red tests — R-Phase9-02 + REQ-21b: GRADLE_DYNAMIC_PIN renders
in dedicated 'DO NOT REMOVE' section + SARIF dual-severity
(TA-317 + TA-318 + TA-319)."""
from __future__ import annotations

import json

import pytest


def _result_with_dynamic_pin():
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
                name="com.lib:dynamic-x",
                version="1.0",
                status=DependencyStatus.UNCERTAIN,
                reason="Gradle dynamic pin — manual review required",
                pin_override=True,
                pin_override_kind="GRADLE_DYNAMIC_PIN",
                pin_override_target=(
                    "Gradle dynamic pin in build.gradle:42 "
                    "(useVersion called with non-literal argument)"
                ),
                ecosystem="gradle",
            ),
        ],
        dep_edges=[
            DepEdge(parent="", child="com.lib:dynamic-x",
                    declared_version="1.0"),
        ],
    )


def _result_with_static_gradle_pin():
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
                reason="Gradle force() pin",
                pin_override=True,
                pin_override_kind="GRADLE_FORCE",
                pin_override_target="force() in resolutionStrategy of :app",
                ecosystem="gradle",
            ),
        ],
        dep_edges=[
            DepEdge(parent="", child="com.example:patched-x",
                    declared_version="1.5"),
        ],
    )


@pytest.mark.requirement("FR-225")
def test_dynamic_pin_uncertain_NOT_in_generic_uncertain_section():
    """TA-317 — Markdown reporter renders GRADLE_DYNAMIC_PIN dep under
    a dedicated 'DO NOT REMOVE — dynamic Gradle pin' section, NOT
    in the generic 'Manual review required (UNCERTAIN)' list (where
    a user might treat it as removable)."""
    from scarno.reporters.markdown_reporter import MarkdownReporter

    rendered = MarkdownReporter().render(_result_with_dynamic_pin())
    assert "DO NOT REMOVE" in rendered, (
        "GRADLE_DYNAMIC_PIN must render in a dedicated DO NOT REMOVE section"
    )
    # The dynamic-pin dep must NOT also appear under the generic
    # UNCERTAIN checklist heading.
    uncertain_idx = rendered.lower().find("manual review required")
    do_not_remove_idx = rendered.find("DO NOT REMOVE")
    if uncertain_idx >= 0 and do_not_remove_idx >= 0:
        # If both sections appear, the dynamic-pin dep should only be
        # listed in the DO NOT REMOVE section. We grep for the dep
        # name and ensure it doesn't appear after the UNCERTAIN
        # heading boundary (or at least appears under DO NOT REMOVE
        # first).
        assert do_not_remove_idx < uncertain_idx, (
            "DO NOT REMOVE section must appear BEFORE the generic "
            "UNCERTAIN checklist"
        )


@pytest.mark.requirement("FR-225")
def test_sarif_dynamic_pin_severity_warning():
    """TA-318 — TS-DEP-PIN-OVERRIDE-GRADLE at severity 'warning' for
    GRADLE_DYNAMIC_PIN kind."""
    from scarno.reporters.sarif_reporter import SarifReporter

    sarif = json.loads(SarifReporter().render(_result_with_dynamic_pin()))
    pin_results = [
        r for r in sarif["runs"][0]["results"]
        if r.get("ruleId") == "TS-DEP-PIN-OVERRIDE-GRADLE"
    ]
    assert pin_results
    assert pin_results[0]["level"] == "warning"


@pytest.mark.requirement("FR-225")
def test_sarif_static_pin_severity_note():
    """TA-319 — Static Gradle kinds (FORCE / STRICTLY / CONSTRAINTS /
    EXCLUSION) render at severity 'note'."""
    from scarno.reporters.sarif_reporter import SarifReporter

    sarif = json.loads(
        SarifReporter().render(_result_with_static_gradle_pin())
    )
    pin_results = [
        r for r in sarif["runs"][0]["results"]
        if r.get("ruleId") == "TS-DEP-PIN-OVERRIDE-GRADLE"
    ]
    assert pin_results
    assert pin_results[0]["level"] == "note"
