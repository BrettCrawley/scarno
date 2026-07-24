"""PR-1 red tests — REQ-19 data model.

These tests assert against the future DepEdge / AnalysisResult API. They
MUST fail red against the pre-Phase-9 codebase. Each TA-XXX matches an
entry in ``docs/scarno-test-plan-phase9.md``.
"""
from __future__ import annotations

import dataclasses

import pytest


# ── TA-200 ──────────────────────────────────────────────────────────────────


class TestDepEdgeDataclass:
    @pytest.mark.requirement("FR-190")
    def test_depedge_dataclass_is_frozen(self):
        """TA-200 — DepEdge is a frozen dataclass.

        Mutating any field after construction raises FrozenInstanceError.
        The frozen contract is what lets the classifier (REQ-20) hash edges
        in the diamond-graph traversal without defensive copies.
        """
        from scarno.models import DepEdge

        edge = DepEdge(
            parent="com.example:alpha",
            child="com.example:x",
            declared_version="1.1",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            edge.declared_version = "1.2"  # type: ignore[misc]

    # ── TA-201 ──────────────────────────────────────────────────────────────

    @pytest.mark.requirement("FR-190")
    def test_depedge_default_scope_runtime(self):
        """TA-201 — DepEdge.scope defaults to 'runtime'.

        Non-runtime scopes (test, provided, compile, dev) must be supplied
        explicitly so they can never be inferred silently from a
        partially-parsed manifest.
        """
        from scarno.models import DepEdge

        edge = DepEdge(parent="", child="root:lib", declared_version="1.0")
        assert edge.scope == "runtime"


# ── TA-202 ──────────────────────────────────────────────────────────────────


class TestDepGraphDerivation:
    @pytest.mark.requirement("FR-195")
    def test_dep_graph_derived_from_dep_edges(self):
        """TA-202 — AnalysisResult derives dep_graph from dep_edges in __post_init__.

        Consumers reading the legacy ``dep_graph`` field (canonical→canonical
        map) must keep working when only the new ``dep_edges`` is supplied.
        """
        from scarno.models import AnalysisResult, DepEdge

        edges = [
            DepEdge(parent="root", child="alpha", declared_version="2.0"),
            DepEdge(parent="root", child="beta", declared_version="3.0"),
            DepEdge(parent="alpha", child="x", declared_version="1.1"),
            DepEdge(parent="beta", child="x", declared_version="1.2"),
        ]
        result = AnalysisResult(
            project_type="java",
            project_path="/tmp/test",
            dep_edges=edges,
        )
        # Legacy dep_graph must reflect the canonical-only projection.
        assert result.dep_graph == {
            "root": {"alpha", "beta"},
            "alpha": {"x"},
            "beta": {"x"},
        }

    @pytest.mark.requirement("FR-195")
    def test_dep_graph_kept_when_supplied_explicitly(self):
        """TA-202b — When both dep_graph and dep_edges are supplied, the
        explicit dep_graph wins (no overwrite by derivation).

        Caller-supplied dep_graph is the legacy path; we never silently
        overwrite it.
        """
        from scarno.models import AnalysisResult, DepEdge

        legacy_graph = {"alpha": {"beta"}}
        result = AnalysisResult(
            project_type="java",
            project_path="/tmp/test",
            dep_graph=legacy_graph,
            dep_edges=[DepEdge(parent="X", child="Y", declared_version="1")],
        )
        assert result.dep_graph == legacy_graph
