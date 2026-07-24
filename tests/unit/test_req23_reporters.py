"""PR-5 red tests — REQ-23 / FR-246: npm pin-override reporter sections
(TA-304 + TA-305)."""
from __future__ import annotations

import json

import pytest


def _result_with_npm_pin():
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
    )
    return AnalysisResult(
        project_type="javascript",
        project_path="/tmp/x",
        dependencies=[
            Dependency(
                name="lodash",
                version="4.17.21",
                status=DependencyStatus.IN_USE,
                reason="npm overrides pin",
                pin_override=True,
                pin_override_kind="NPM_OVERRIDES",
                pin_override_target="pinned via overrides to 4.17.21",
                ecosystem="npm",
            ),
        ],
        dep_edges=[
            DepEdge(parent="", child="lodash", declared_version="4.17.21"),
        ],
    )


@pytest.mark.requirement("FR-246")
def test_pinning_overrides_npm_section():
    """TA-304 — Markdown reporter includes the npm sub-table inside
    the existing 'Pinning overrides' section (REQ-21 / 21b / 23 share
    the section; PR-5 adds the npm rows)."""
    from scarno.reporters.markdown_reporter import MarkdownReporter

    rendered = MarkdownReporter().render(_result_with_npm_pin())
    assert "Pinning overrides" in rendered
    assert "lodash" in rendered
    assert "NPM_OVERRIDES" in rendered or "overrides" in rendered.lower()


@pytest.mark.requirement("FR-246")
def test_sarif_TS_DEP_PIN_OVERRIDE_NPM():
    """TA-305 — SARIF reporter emits TS-DEP-PIN-OVERRIDE-NPM at level
    'note' for each npm pin_override dep."""
    from scarno.reporters.sarif_reporter import SarifReporter

    sarif = json.loads(SarifReporter().render(_result_with_npm_pin()))
    rule_ids = {
        r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]
    }
    assert "TS-DEP-PIN-OVERRIDE-NPM" in rule_ids
    results = [
        r for r in sarif["runs"][0].get("results", [])
        if r.get("ruleId") == "TS-DEP-PIN-OVERRIDE-NPM"
    ]
    assert len(results) == 1
    assert results[0].get("level") == "note"
