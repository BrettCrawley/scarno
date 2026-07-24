"""PR-2 red test — FR-206 markdown 'Multiple versions detected' section.
TA-233."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-206")
def test_multi_version_section_rendered():
    """TA-233 — When multi_version_coords is non-empty, the markdown
    reporter emits a 'Multiple versions detected' table listing each
    coordinate, its declared versions, the resolved version, and the
    per-version removable status."""
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        VersionedNode,
    )
    from scarno.reporters.markdown_reporter import MarkdownReporter

    deps = [
        Dependency(name="x", version=None, status=DependencyStatus.IN_USE, reason=""),
    ]
    edges = [
        DepEdge(parent="", child="x", declared_version="1.1"),
        DepEdge(parent="", child="x", declared_version="1.2"),
    ]
    versioned_nodes = [
        VersionedNode(
            canonical="x", declared_version="1.1",
            status=DependencyStatus.IN_USE,
            is_resolved=True,
        ),
        VersionedNode(
            canonical="x", declared_version="1.2",
            status=DependencyStatus.SAFE,
            removable=True,
            reason="only reachable through unused parent(s)",
        ),
    ]
    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/x",
        dependencies=deps,
        dep_edges=edges,
        versioned_nodes=versioned_nodes,
        multi_version_coords=["x"],
    )
    rendered = MarkdownReporter().render(result)
    assert "Multiple versions detected" in rendered
    # Both versions named in the table.
    assert "1.1" in rendered and "1.2" in rendered
