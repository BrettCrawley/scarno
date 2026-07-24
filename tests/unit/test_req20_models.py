"""PR-2 red tests — REQ-20 data model: VersionedNode +
AnalysisResult.versioned_nodes / multi_version_coords (TA-220, FR-200).
"""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-200")
def test_versioned_node_dataclass_fields():
    """TA-220 — VersionedNode carries canonical / declared_version /
    status / is_resolved / removable / reason."""
    from scarno.models import (
        DependencyStatus,
        VersionedNode,
    )

    node = VersionedNode(
        canonical="com.example:x",
        declared_version="1.1",
        status=DependencyStatus.IN_USE,
    )
    assert node.canonical == "com.example:x"
    assert node.declared_version == "1.1"
    assert node.status is DependencyStatus.IN_USE
    assert node.is_resolved is False
    assert node.removable is False
    assert node.reason == ""


@pytest.mark.requirement("FR-200")
def test_analysis_result_versioned_nodes_default_empty():
    """TA-220 — AnalysisResult.versioned_nodes / multi_version_coords
    default to empty containers. Phase-9 fields are additive."""
    from scarno.models import AnalysisResult

    result = AnalysisResult(project_type="java", project_path="/tmp/x")
    assert result.versioned_nodes == []
    assert result.multi_version_coords == []
