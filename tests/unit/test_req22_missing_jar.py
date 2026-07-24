"""PR-4 red test — REQ-22 / FR-236: graceful skip when JAR not cached.
TA-275."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.requirement("FR-236")
def test_jar_not_cached_graceful_skip(tmp_path):
    """TA-275 — Resolved JAR not in m2: a sanitised note appears in the
    AnalysisResult.errors list; analysis completes without raising;
    no Finding emitted for the skipped coord.
    """
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        VersionedNode,
    )

    # Empty m2 — no JARs at all.
    m2 = tmp_path / "m2"
    m2.mkdir()
    differ = CrossVersionAbiDiffer(
        m2_root=m2,
        invoke_javap=lambda *_a: None,
    )
    result = AnalysisResult(
        project_type="java",
        project_path="/tmp",
        dependencies=[
            Dependency(name="com.example:lib", version="1.5",
                       status=DependencyStatus.IN_USE, reason="",
                       ecosystem="maven", imported_directly=True),
        ],
        dep_edges=[
            DepEdge(parent="", child="com.example:lib",
                    declared_version="1.2"),
            DepEdge(parent="", child="com.example:lib",
                    declared_version="1.5"),
        ],
        versioned_nodes=[
            VersionedNode(canonical="com.example:lib",
                          declared_version="1.2",
                          status=DependencyStatus.IN_USE),
            VersionedNode(canonical="com.example:lib",
                          declared_version="1.5",
                          status=DependencyStatus.IN_USE,
                          is_resolved=True),
        ],
        multi_version_coords=["com.example:lib"],
    )
    findings = differ.diff_all(result, source_symbols={})
    # No ABI Findings (jars unavailable to diff).
    assert findings == []
    # A note must appear in result.errors mentioning the skip.
    msg = " ".join(result.errors).lower()
    assert "not cached" in msg or "skip" in msg, (
        f"expected 'not cached' / 'skip' note; got {result.errors!r}"
    )
