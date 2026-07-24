"""PR-2 red tests — SEC-NEW-39 per-coordinate version cap (TA-232a..b).

A coordinate with > 64 declared versions is treated as adversarial
input. The classifier truncates versioned_nodes for that coordinate
to 64 entries with the resolved version retained.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-39")
def test_per_coord_version_cap_truncates_at_64():
    """TA-232a — 100 declared versions of one coord truncated to 64;
    errors[] contains a truncation note."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        DepEdge,
    )

    deps = [
        Dependency(name="alpha", version=None, status=DependencyStatus.IN_USE, reason=""),
        Dependency(name="x", version=None, status=DependencyStatus.IN_USE, reason=""),
    ]
    edges = [DepEdge(parent="", child="alpha", declared_version="1.0")]
    edges += [
        DepEdge(parent="alpha", child="x", declared_version=f"1.{i}")
        for i in range(100)
    ]
    out_deps, vnodes, multi = _cls.classify_versioned(deps, edges)
    x_versions = [n for n in vnodes if n.canonical == "x"]
    assert len(x_versions) == 64, (
        f"version cap not enforced; got {len(x_versions)} entries for x"
    )


@pytest.mark.requirement("SEC-NEW-39")
def test_per_coord_version_cap_resolved_never_dropped():
    """TA-232b — Resolved version is retained even when ranked outside
    the first 64."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        DepEdge,
    )

    deps = [
        Dependency(name="alpha", version=None, status=DependencyStatus.IN_USE, reason=""),
        Dependency(name="x", version=None, status=DependencyStatus.IN_USE, reason=""),
    ]
    edges = [DepEdge(parent="", child="alpha", declared_version="1.0")]
    edges += [
        DepEdge(parent="alpha", child="x", declared_version=f"1.{i}")
        for i in range(100)
    ]
    # Resolved version is the 80th — sits outside the first 64 if sorted
    # ascending. Must be retained regardless.
    resolved_versions = {"x": "1.80"}
    out_deps, vnodes, multi = _cls.classify_versioned(
        deps, edges, resolved_versions=resolved_versions
    )
    x_versions = {
        n.declared_version for n in vnodes if n.canonical == "x"
    }
    assert "1.80" in x_versions, (
        "resolved version dropped by the per-coord cap"
    )
