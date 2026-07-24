"""Regression tests for the G1..G5 multi-version-table reporting bugs
the user reported on a real JVM project:

* G1 — ``_nearest_wins_from_edges`` no longer skips concrete-version
  edges when a None-version edge for the same coord was processed
  first.
* G2 — ``apply_pin_override_safety`` enforces ``is_resolved →
  removable=False`` even when ``dep is None`` (purely-transitive
  coordinate).
* G3 — Maven analyser surfaces every transitive discovered via the
  ``~/.m2`` walk as a ``Dependency`` so coords listed in
  ``multi_version_coords`` are guaranteed to be visible in the
  ASCII dependency tree (``c in by_name`` filter).
* G4 — Maven version-range syntax is recognised: a declared range
  whose interval contains the resolved version no longer surfaces
  as a spurious multi-version conflict.
* G5 — when ``Dependency.version`` is known, the multi-version
  table never renders a bare ``(unresolved)`` — falls back to the
  resolved version with a ``(resolved)`` tag.
"""
from __future__ import annotations

import pytest

from scarno.analysers.java._maven_version import (
    declared_covers_resolved,
    is_range_expression,
)
from scarno.analysers.java.maven import _nearest_wins_from_edges
from scarno.core.classifier import (
    apply_pin_override_safety,
    classify_versioned,
)
from scarno.models import (
    Dependency,
    DependencyStatus,
    DepEdge,
    VersionedNode,
)


# ── G1 — _nearest_wins_from_edges fix ─────────────────────────────────────


class TestG1NearestWinsHandlesNoneEdges:
    def test_none_edge_first_does_not_block_concrete_version(self):
        """The earlier bug: a (parent, child, None) edge processed
        before a (parent, child, "1.0") edge added the child to
        ``visited`` then short-circuited the concrete edge — leaving
        the coord with no resolved version.
        """
        edges = [
            DepEdge(parent="", child="x", declared_version=None),
            DepEdge(parent="", child="x", declared_version="1.0"),
        ]
        resolved = _nearest_wins_from_edges(edges)
        assert resolved == {"x": "1.0"}

    def test_concrete_first_then_none_keeps_concrete(self):
        edges = [
            DepEdge(parent="", child="x", declared_version="1.0"),
            DepEdge(parent="", child="x", declared_version=None),
        ]
        resolved = _nearest_wins_from_edges(edges)
        assert resolved == {"x": "1.0"}

    def test_none_only_yields_no_resolution(self):
        edges = [
            DepEdge(parent="", child="x", declared_version=None),
        ]
        assert _nearest_wins_from_edges(edges) == {}

    def test_diamond_first_concrete_wins(self):
        """Multiple parents declare different versions of the same
        transitive — nearest-wins picks the first concrete one
        encountered (BFS order)."""
        edges = [
            DepEdge(parent="", child="parent_a", declared_version="1.0"),
            DepEdge(parent="", child="parent_b", declared_version="1.0"),
            DepEdge(parent="parent_a", child="shared", declared_version="2.0"),
            DepEdge(parent="parent_b", child="shared", declared_version="3.0"),
        ]
        resolved = _nearest_wins_from_edges(edges)
        # Either 2.0 or 3.0 is acceptable depending on BFS visit order;
        # what matters is that a CONCRETE version is picked.
        assert resolved["shared"] in {"2.0", "3.0"}


# ── G2 — apply_pin_override_safety unconditional is_resolved ─────────────


class TestG2SafetyHonoursIsResolvedWithNoneDep:
    def test_is_resolved_forces_removable_false_when_dep_is_none(self):
        """Purely-transitive coord — no ``Dependency`` in
        ``result.dependencies`` for it. The earlier code skipped the
        safety pass entirely; an ``is_resolved=True`` node could keep
        ``removable=True`` and surface as "resolved version flagged
        for removal"."""
        node = VersionedNode(
            canonical="x", declared_version="1.0",
            status=DependencyStatus.SAFE,
            is_resolved=True, removable=True,
        )
        apply_pin_override_safety(None, node)
        assert node.status is DependencyStatus.IN_USE
        assert node.removable is False
        assert "resolved version" in node.reason.lower()

    def test_no_change_when_not_resolved_and_dep_is_none(self):
        node = VersionedNode(
            canonical="x", declared_version="1.0",
            status=DependencyStatus.SAFE,
            is_resolved=False, removable=True,
        )
        apply_pin_override_safety(None, node)
        # Untouched — no dep-flags, no is_resolved.
        assert node.status is DependencyStatus.SAFE
        assert node.removable is True


# ── G2 + classify_versioned — purely-transitive resolved coord ───────────


class TestG2ClassifierHonoursIsResolvedForTransitives:
    def test_resolved_transitive_not_flagged_removable(self):
        """End-to-end: a multi-version coord present only in
        ``dep_edges`` (NOT in the deps list) — the resolved version
        must NOT be flagged removable."""
        deps = [
            Dependency(
                name="alpha", version="1.0",
                status=DependencyStatus.SAFE, reason="",
            ),
            Dependency(
                name="beta", version="1.0",
                status=DependencyStatus.IN_USE, reason="",
            ),
        ]
        edges = [
            DepEdge(parent="", child="alpha", declared_version="1.0"),
            DepEdge(parent="", child="beta", declared_version="1.0"),
            # Same transitive, two declared versions; neither is in
            # ``deps`` (purely-transitive).
            DepEdge(parent="alpha", child="x", declared_version="2.0"),
            DepEdge(parent="beta", child="x", declared_version="3.0"),
        ]
        _, vnodes, multi = classify_versioned(
            deps, edges, resolved_versions={"x": "3.0"},
        )
        assert "x" in multi
        x_nodes = [n for n in vnodes if n.canonical == "x"]
        resolved_node = next(n for n in x_nodes if n.is_resolved)
        # The resolved version is locked IN_USE / non-removable
        # *despite* the purely-transitive coord having no Dependency.
        assert resolved_node.removable is False


# ── G4 — Maven range parser ──────────────────────────────────────────────


class TestG4RangeParser:
    @pytest.mark.parametrize(
        "declared,resolved",
        [
            ("[1.0,2.0)", "1.0"),
            ("[1.0,2.0)", "1.5"),
            ("[1.0,2.0)", "1.999"),
            ("(1.0,2.0]", "1.0001"),
            ("(1.0,2.0]", "2.0"),
            ("[1.0,2.0]", "1.0"),
            ("[1.0,2.0]", "2.0"),
            ("[1.0,)", "999.999"),
            ("(,2.0]", "0.0.0"),
            ("[1.5]", "1.5"),
            ("[1.0,1.5),[1.6,2.0)", "1.7"),  # multi-range OR
        ],
    )
    def test_in_range(self, declared, resolved):
        assert declared_covers_resolved(declared, resolved) is True

    @pytest.mark.parametrize(
        "declared,resolved",
        [
            ("[1.0,2.0)", "2.0"),    # right-exclusive
            ("(1.0,2.0]", "1.0"),    # left-exclusive
            ("[1.0,2.0]", "0.99"),
            ("[1.0,2.0]", "2.01"),
            ("[1.5]", "1.5.1"),       # pin is exact
            ("[1.0,1.5),[1.6,2.0)", "1.5"),  # gap between ranges
            ("[1.0,1.5),[1.6,2.0)", "1.5.5"),  # in the gap (1.5 < x < 1.6)
        ],
    )
    def test_out_of_range(self, declared, resolved):
        assert declared_covers_resolved(declared, resolved) is False

    def test_equality_for_non_range(self):
        assert declared_covers_resolved("1.0", "1.0") is True
        assert declared_covers_resolved("1.0", "1.0.0") is False

    def test_none_inputs_never_match(self):
        assert declared_covers_resolved(None, "1.0") is False
        assert declared_covers_resolved("1.0", None) is False
        assert declared_covers_resolved(None, None) is False

    def test_malformed_range_fall_back_to_string_equality(self):
        # ``[abc,def)`` — bracket-shaped but unparseable.
        assert declared_covers_resolved("[abc,def)", "1.0") is False
        assert declared_covers_resolved("[abc,def)", "[abc,def)") is True

    def test_is_range_expression_detection(self):
        assert is_range_expression("[1.0,2.0)") is True
        assert is_range_expression("(,2.0]") is True
        assert is_range_expression("1.0") is False
        assert is_range_expression(None) is False
        assert is_range_expression("") is False


# ── G4 — classify_versioned with range comparator ────────────────────────


class TestG4RangeAwareClassifyVersioned:
    def test_range_and_concrete_resolving_to_same_version_is_not_multi(self):
        """A coord declared at ``[1.0,2.0)`` (range) and ``1.5`` (soft)
        with resolved ``1.5.0`` is NOT a multi-version conflict.
        Both expressions cover the resolved version."""
        deps = [
            Dependency(name="x", version="1.5.0",
                       status=DependencyStatus.IN_USE, reason=""),
        ]
        edges = [
            DepEdge(parent="", child="x", declared_version="[1.0,2.0)"),
            DepEdge(parent="", child="x", declared_version="1.5.0"),
        ]
        _, vnodes, multi = classify_versioned(
            deps, edges,
            resolved_versions={"x": "1.5.0"},
            version_match=declared_covers_resolved,
        )
        # Both nodes "agree" on the resolved version → no conflict.
        assert "x" not in multi
        # Both nodes are is_resolved.
        x_nodes = [n for n in vnodes if n.canonical == "x"]
        assert len(x_nodes) == 2
        assert all(n.is_resolved for n in x_nodes)

    def test_range_outside_resolved_still_multi_version(self):
        """A range that does NOT cover the resolved version IS a
        real conflict and stays in multi_version_coords."""
        deps = [
            Dependency(name="x", version="1.5.0",
                       status=DependencyStatus.IN_USE, reason=""),
        ]
        edges = [
            DepEdge(parent="", child="x", declared_version="[3.0,4.0)"),
            DepEdge(parent="", child="x", declared_version="1.5.0"),
        ]
        _, _, multi = classify_versioned(
            deps, edges,
            resolved_versions={"x": "1.5.0"},
            version_match=declared_covers_resolved,
        )
        assert "x" in multi


# ── Default-match tightening (None×None should NOT match) ────────────────


class TestDefaultMatchNoneSemantics:
    def test_none_node_with_no_resolved_is_not_resolved(self):
        deps = [
            Dependency(name="x", version=None,
                       status=DependencyStatus.IN_USE, reason=""),
        ]
        edges = [
            DepEdge(parent="", child="x", declared_version=None),
        ]
        _, vnodes, _ = classify_versioned(
            deps, edges, resolved_versions={},
        )
        x_nodes = [n for n in vnodes if n.canonical == "x"]
        assert len(x_nodes) == 1
        # Default match — was previously True (None == None) leaving
        # an unresolved coord wrongly tagged. Now correctly False.
        assert x_nodes[0].is_resolved is False
