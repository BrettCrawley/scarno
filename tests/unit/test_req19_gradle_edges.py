"""PR-1 red tests — REQ-19 Gradle edge emission (TA-206).

Gradle records ``requested -> resolved`` in its dependency-tree output. The
DepEdge stores the *requested* (declared) version, NOT the resolved one.
REQ-20 will later mark the resolved version separately.
"""
from __future__ import annotations

import pytest

from scarno.analysers.java import gradle as _gradle


# ── TA-206 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-192")
def test_gradle_emits_edge_with_requested_version_not_resolved():
    """TA-206 — ``a:b:1.0 -> 1.5`` in ``gradle dependencies`` output yields
    DepEdge(declared_version='1.0'), not '1.5'.
    """
    output = (
        "+--- com.example:a:1.0 -> 1.5\n"
        "+--- com.example:b:2.0\n"
        "+--- com.example:c:3.0 -> 3.2\n"
    )
    # New REQ-19 helper — does not exist yet pre-Phase-9.
    edges = _gradle._emit_dep_edges_from_output(  # type: ignore[attr-defined]
        output, parent="project:app"
    )

    by_child = {e.child: e.declared_version for e in edges}
    assert by_child.get("com.example:a") == "1.0", (
        "Gradle requested-vs-resolved: declared_version must be 1.0 (requested)"
    )
    assert by_child.get("com.example:b") == "2.0"
    assert by_child.get("com.example:c") == "3.0"
