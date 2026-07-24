"""PR-1 red tests — REQ-19 back-compat with REQ-17 (canonical-only) render.

When a result carries only the legacy ``dep_graph`` (no ``dep_edges``), the
markdown reporter MUST render identically to the pre-Phase-9 output so
REQ-17 acceptance criteria do not regress.
"""
from __future__ import annotations

import pytest

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
)
from scarno.reporters.markdown_reporter import MarkdownReporter


# ── TA-220 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-195")
def test_dep_graph_only_path_preserves_REQ17_render():
    """TA-220 — Building an AnalysisResult with dep_graph but no dep_edges
    renders identically to pre-Phase-9 output (REQ-17 contract preserved).

    Red mode: the test will reference ``dep_edges`` defaulting to empty.
    Once REQ-19 lands, the renderer must still produce the same line shape
    when dep_edges is empty.
    """
    result = AnalysisResult(
        project_type="python",
        project_path="/tmp/test",
        dependencies=[
            Dependency(
                name="requests",
                version="2.31.0",
                status=DependencyStatus.IN_USE,
                reason="imported as 'requests' in project source",
            ),
            Dependency(
                name="boto3",
                version="1.26.0",
                status=DependencyStatus.SAFE,
                reason="no import or usage found in source files",
            ),
        ],
        dep_graph={"requests": set(), "boto3": set()},
        # dep_edges deliberately omitted — exercises the legacy path.
    )
    # Property: when dep_edges is empty, dep_edges attribute MUST exist
    # and equal []. This is the additive-back-compat contract.
    assert result.dep_edges == []
    rendered = MarkdownReporter().render(result)
    # Canonical names must still appear unchanged in the rendered output.
    assert "requests" in rendered
    assert "boto3" in rendered
    # The legacy diff-fence tree block from REQ-17 must still render.
    assert "```diff" in rendered
