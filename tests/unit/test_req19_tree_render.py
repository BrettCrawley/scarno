"""PR-1 red test — REQ-19 markdown tree renders distinct (canonical, version)
nodes (TA-210).

DepEdge and AnalysisResult.dep_edges are imported lazily inside the test so
that the surrounding test module can still collect on a pre-Phase-9
codebase. The test itself fails red until both the model fields and the
reporter changes land.
"""
from __future__ import annotations

import pytest


# ── TA-210 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-194")
def test_markdown_renders_distinct_versions_as_two_nodes():
    """TA-210 — dep_edges with x@1.1 and x@1.2 (from different parents) render
    as TWO sibling subtrees, not collapsed into one canonical-only node.
    """
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
    )
    from scarno.reporters.markdown_reporter import MarkdownReporter

    edges = [
        DepEdge(parent="", child="alpha", declared_version="2.0"),
        DepEdge(parent="", child="beta", declared_version="3.0"),
        DepEdge(parent="alpha", child="x", declared_version="1.1"),
        DepEdge(parent="beta", child="x", declared_version="1.2"),
    ]
    deps = [
        Dependency(
            name="alpha", version="2.0", status=DependencyStatus.IN_USE, reason=""
        ),
        Dependency(
            name="beta", version="3.0", status=DependencyStatus.IN_USE, reason=""
        ),
        Dependency(
            name="x", version=None, status=DependencyStatus.IN_USE,
            reason="", is_transitive=True,
        ),
    ]
    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/test",
        dependencies=deps,
        dep_edges=edges,
    )
    rendered = MarkdownReporter().render(result)
    # Two distinct version labels must appear in the rendered tree block.
    assert "x@1.1" in rendered, (
        "Expected x@1.1 in the rendered tree; got:\n" + rendered
    )
    assert "x@1.2" in rendered, (
        "Expected x@1.2 in the rendered tree; got:\n" + rendered
    )
    # And the two version labels must each appear at LEAST once
    # underneath their respective parent (alpha → x@1.1; beta → x@1.2).
    # We grep the rendered text for the structural ordering.
    lines = rendered.splitlines()
    alpha_idx = next(
        (i for i, ln in enumerate(lines) if "alpha" in ln and "@2.0" in ln),
        -1,
    )
    beta_idx = next(
        (i for i, ln in enumerate(lines) if "beta" in ln and "@3.0" in ln),
        -1,
    )
    x11_idx = next(
        (i for i, ln in enumerate(lines) if "x@1.1" in ln), -1
    )
    x12_idx = next(
        (i for i, ln in enumerate(lines) if "x@1.2" in ln), -1
    )
    assert alpha_idx >= 0 and beta_idx >= 0
    assert x11_idx > alpha_idx, "x@1.1 must appear after alpha row"
    assert x12_idx > beta_idx, "x@1.2 must appear after beta row"
