"""PR-2 red test — FR-207 SARIF rule TS-DEP-MULTI-VERSION emission. TA-234."""
from __future__ import annotations

import json

import pytest


@pytest.mark.requirement("FR-207")
def test_sarif_TS_DEP_MULTI_VERSION_emitted():
    """TA-234 — Each entry in multi_version_coords produces exactly one
    SARIF result with rule id TS-DEP-MULTI-VERSION at severity 'note'."""
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        VersionedNode,
    )
    from scarno.reporters.sarif_reporter import SarifReporter

    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/x",
        dependencies=[
            Dependency(name="x", version=None, status=DependencyStatus.IN_USE, reason=""),
        ],
        dep_edges=[
            DepEdge(parent="", child="x", declared_version="1.1"),
            DepEdge(parent="", child="x", declared_version="1.2"),
        ],
        versioned_nodes=[
            VersionedNode(canonical="x", declared_version="1.1",
                          status=DependencyStatus.IN_USE, is_resolved=True),
            VersionedNode(canonical="x", declared_version="1.2",
                          status=DependencyStatus.SAFE, removable=True),
        ],
        multi_version_coords=["x"],
    )
    sarif_str = SarifReporter().render(result)
    sarif = json.loads(sarif_str)
    rule_ids = {
        r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]
    }
    assert "TS-DEP-MULTI-VERSION" in rule_ids
    multi_results = [
        r for r in sarif["runs"][0].get("results", [])
        if r.get("ruleId") == "TS-DEP-MULTI-VERSION"
    ]
    assert len(multi_results) == 1
    assert multi_results[0].get("level") == "note"
