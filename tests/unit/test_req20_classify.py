"""PR-2 red tests — REQ-20 classifier (TA-220a..d).

The classifier lives at src/scarno/core/classifier.py (NEW module).
Every ecosystem analyser routes through it.
"""
from __future__ import annotations

import pytest


def _make_dep(name, status):
    from scarno.models import Dependency
    return Dependency(name=name, version=None, status=status, reason="")


# ── TA-220a ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-201")
def test_diamond_partial_safe():
    """TA-220a — Diamond where x@1.2 is only reachable via SAFE parent
    classifies x@1.2 SAFE-removable; x@1.1 (via IN_USE parent) IN_USE.
    """
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus, DepEdge

    deps = [
        _make_dep("alpha", DependencyStatus.IN_USE),
        _make_dep("beta", DependencyStatus.SAFE),
        _make_dep("x", DependencyStatus.IN_USE),
    ]
    edges = [
        DepEdge(parent="", child="alpha", declared_version="2.0"),
        DepEdge(parent="", child="beta", declared_version="3.0"),
        DepEdge(parent="alpha", child="x", declared_version="1.1"),
        DepEdge(parent="beta", child="x", declared_version="1.2"),
    ]
    _, vnodes, _ = _cls.classify_versioned(deps, edges)

    by_version = {n.declared_version: n for n in vnodes if n.canonical == "x"}
    assert by_version["1.1"].status is DependencyStatus.IN_USE
    assert by_version["1.2"].status is DependencyStatus.SAFE
    assert by_version["1.2"].removable is True
    assert by_version["1.1"].removable is False


# ── TA-220b ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-202")
def test_diamond_partial_in_use_promotes():
    """TA-220b — Both alpha (IN_USE) → x@1.1 and beta (IN_USE) → x@1.2.
    Both x versions IN_USE; multi_version_coords lists x; no version
    flagged removable."""
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus, DepEdge

    deps = [
        _make_dep("alpha", DependencyStatus.IN_USE),
        _make_dep("beta", DependencyStatus.IN_USE),
        _make_dep("x", DependencyStatus.IN_USE),
    ]
    edges = [
        DepEdge(parent="", child="alpha", declared_version="2.0"),
        DepEdge(parent="", child="beta", declared_version="3.0"),
        DepEdge(parent="alpha", child="x", declared_version="1.1"),
        DepEdge(parent="beta", child="x", declared_version="1.2"),
    ]
    _, vnodes, multi = _cls.classify_versioned(deps, edges)

    x_versions = [n for n in vnodes if n.canonical == "x"]
    assert len(x_versions) == 2
    assert all(n.status is DependencyStatus.IN_USE for n in x_versions)
    assert all(n.removable is False for n in x_versions)
    assert "x" in multi


# ── TA-220c ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-200")
def test_classify_canonical_legacy_path_unchanged():
    """TA-220c — When dep_edges is empty, classify_canonical (the
    legacy Python-analyser-extracted helper) is invoked and its output
    matches pre-Phase-9 behaviour byte-for-byte for canonical-only
    inputs."""
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus

    deps = [
        _make_dep("alpha", DependencyStatus.IN_USE),
        _make_dep("orphan", DependencyStatus.SAFE),
    ]
    graph = {"alpha": set(), "orphan": set()}
    out = _cls.classify_canonical(deps, graph)
    statuses = {d.name: d.status for d in out}
    assert statuses["alpha"] is DependencyStatus.IN_USE
    assert statuses["orphan"] is DependencyStatus.SAFE


# ── TA-220d ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-200")
def test_dependency_status_rollup_any_version_in_use():
    """TA-220d — After classify_versioned, Dependency.status is the
    any-version-IN_USE rollup of versioned_nodes for that coordinate.
    """
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus, DepEdge

    deps = [
        _make_dep("alpha", DependencyStatus.IN_USE),
        _make_dep("beta", DependencyStatus.SAFE),
        _make_dep("x", DependencyStatus.SAFE),  # initial — should be lifted
    ]
    edges = [
        DepEdge(parent="", child="alpha", declared_version="2.0"),
        DepEdge(parent="", child="beta", declared_version="3.0"),
        DepEdge(parent="alpha", child="x", declared_version="1.1"),
        DepEdge(parent="beta", child="x", declared_version="1.2"),
    ]
    out_deps, _, _ = _cls.classify_versioned(deps, edges)

    x = next(d for d in out_deps if d.name == "x")
    # x@1.1 is IN_USE (via alpha) → rollup must be IN_USE.
    assert x.status is DependencyStatus.IN_USE
