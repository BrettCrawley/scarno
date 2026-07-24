"""PR-2 red test — FR-203 resolved-version detection (Maven). TA-224a..b."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-203")
def test_maven_resolved_version_via_dependency_tree(monkeypatch):
    """TA-224a — When `mvn dependency:tree` reports a resolved version,
    the corresponding versioned_node is marked is_resolved=True."""
    from scarno.analysers.java import maven as _maven

    # Implementation MUST expose a helper that turns mvn output into a
    # resolved-version map. Test the helper directly so we don't need
    # to spawn mvn.
    output = "+- com.example:x:jar:1.2:compile\n"
    resolved = _maven._resolve_versions_from_dependency_tree(output)
    assert resolved.get("com.example:x") == "1.2"


@pytest.mark.requirement("FR-203")
def test_maven_resolved_version_fallback_nearest_wins():
    """TA-224b — When mvn output is unavailable, REQ-20's fallback
    walks dep_edges and picks the shortest path to the coordinate.
    """
    from scarno.analysers.java import maven as _maven
    from scarno.models import DepEdge

    edges = [
        DepEdge(parent="", child="alpha", declared_version="2.0"),
        DepEdge(parent="alpha", child="x", declared_version="1.1"),
        DepEdge(parent="", child="beta", declared_version="3.0"),
        DepEdge(parent="beta", child="mid", declared_version="4.0"),
        DepEdge(parent="mid", child="x", declared_version="1.2"),
    ]
    resolved = _maven._nearest_wins_from_edges(edges)
    # alpha → x is length 2 (root → alpha → x); beta → mid → x is length 3.
    # Nearest wins: alpha's 1.1.
    assert resolved.get("x") == "1.1"
