"""PR-3 red test — REQ-21 / FR-214: classifier defers to pin_override
(TA-255). The classifier was already wired in PR-2; PR-3 verifies the
end-to-end integration with the Maven detector."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-214")
def test_classifier_defers_to_pin_override():
    """TA-255 — Build a Dependency with pin_override=True and run the
    classifier. The corresponding versioned_node ends up IN_USE,
    removable=False, reason naming the pin (SUC-42 enforcement)."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        DepEdge,
    )

    deps = [
        Dependency(
            name="com.example:patched-x",
            version="1.5",
            status=DependencyStatus.SAFE,  # would normally classify SAFE
            reason="",
            pin_override=True,
            pin_override_kind="EXCLUSION",
            pin_override_target=(
                "substitutes for excluded transitive of com.example:lib-y; "
                "manual review recommended — coincidental GA match is possible"
            ),
            ecosystem="maven",
        ),
    ]
    edges = [
        DepEdge(
            parent="",
            child="com.example:patched-x",
            declared_version="1.5",
        ),
    ]
    out_deps, vnodes, _ = _cls.classify_versioned(deps, edges)
    node = next(
        n for n in vnodes
        if n.canonical == "com.example:patched-x"
    )
    assert node.status is DependencyStatus.IN_USE
    assert node.removable is False
    assert (
        "EXCLUSION" in node.reason
        or "pin" in node.reason.lower()
    )
