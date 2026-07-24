"""PR-4 red tests — REQ-22 / FR-235: ABI-diff reporter sections
(TA-288 + TA-289)."""
from __future__ import annotations

import json

import pytest


def _result_with_abi_findings():
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        Finding,
        FindingKind,
        FindingSeverity,
    )
    return AnalysisResult(
        project_type="java",
        project_path="/tmp",
        dependencies=[
            Dependency(name="com.thirdparty:helper", version="1.5.0",
                       status=DependencyStatus.IN_USE, reason="",
                       ecosystem="maven"),
        ],
        findings=[
            Finding(
                rule_id="TS-ABI-RUNTIME-RISK",
                kind=FindingKind.ABI_RUNTIME_RISK,
                severity=FindingSeverity.HIGH,
                file_path="src/main/java/UsesHelper.java",
                line=42,
                snippet="Helper.utilityMethod()",
                message=(
                    "Helper.utilityMethod called by your source, exists in "
                    "declared 1.2.0 but REMOVED in resolved 1.5.0"
                ),
                remediation="Pin helper to 1.2.0 or update call sites",
                package_hint="com.thirdparty:helper",
            ),
        ],
    )


@pytest.mark.requirement("FR-235")
def test_cross_version_abi_section_rendered():
    """TA-288 — Markdown reporter emits the 'Cross-version ABI risks'
    section when ABI_RUNTIME_RISK / ABI_DRIFT findings are present."""
    from scarno.reporters.markdown_reporter import MarkdownReporter

    rendered = MarkdownReporter().render(_result_with_abi_findings())
    assert "ABI" in rendered or "Cross-version" in rendered
    assert "utilityMethod" in rendered


@pytest.mark.requirement("FR-235")
def test_sarif_TS_ABI_RUNTIME_RISK_severity_error():
    """TA-289 — SARIF reporter emits TS-ABI-RUNTIME-RISK at level error
    (HIGH severity maps to SARIF 'error' per the existing severity
    table)."""
    from scarno.reporters.sarif_reporter import SarifReporter

    sarif = json.loads(SarifReporter().render(_result_with_abi_findings()))
    rule_ids = {
        r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]
    }
    assert "TS-ABI-RUNTIME-RISK" in rule_ids
    risk_results = [
        r for r in sarif["runs"][0]["results"]
        if r.get("ruleId") == "TS-ABI-RUNTIME-RISK"
    ]
    assert risk_results
    assert risk_results[0]["level"] == "error"
