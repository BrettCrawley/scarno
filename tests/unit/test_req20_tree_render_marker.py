"""PR-2 red test — FR-194 (extended) resolved-version marker in tree.
TA-235."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-206")
def test_resolved_version_marker_in_tree():
    """TA-235 — When a versioned_node is marked is_resolved=True, the
    rendered tree row for that (canonical, version) carries a visible
    marker (e.g. ``← resolved`` or ``+`` diff prefix)."""
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        VersionedNode,
    )
    from scarno.reporters.markdown_reporter import MarkdownReporter

    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/x",
        dependencies=[
            Dependency(name="alpha", version="2.0",
                       status=DependencyStatus.IN_USE, reason=""),
            Dependency(name="beta", version="3.0",
                       status=DependencyStatus.IN_USE, reason=""),
            Dependency(name="x", version=None,
                       status=DependencyStatus.IN_USE, reason="",
                       is_transitive=True),
        ],
        dep_edges=[
            DepEdge(parent="", child="alpha", declared_version="2.0"),
            DepEdge(parent="", child="beta", declared_version="3.0"),
            DepEdge(parent="alpha", child="x", declared_version="1.1"),
            DepEdge(parent="beta", child="x", declared_version="1.2"),
        ],
        versioned_nodes=[
            VersionedNode(canonical="x", declared_version="1.1",
                          status=DependencyStatus.IN_USE, is_resolved=True),
            VersionedNode(canonical="x", declared_version="1.2",
                          status=DependencyStatus.IN_USE),
        ],
        multi_version_coords=["x"],
    )
    rendered = MarkdownReporter().render(result)
    # The resolved row should carry SOME visible marker — the spec
    # leaves the exact glyph to the implementer; we accept either of
    # the two suggested forms in the architecture doc.
    found_marker = False
    for line in rendered.splitlines():
        if "x@1.1" in line and (
            "resolved" in line.lower() or line.startswith("+")
        ):
            found_marker = True
            break
    assert found_marker, (
        "resolved-version marker missing from x@1.1 row in rendered tree"
    )
