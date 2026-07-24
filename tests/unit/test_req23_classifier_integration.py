"""PR-5 red test — REQ-23 / FR-245 + SUC-56: classifier defers to npm
pin flags (TA-299)."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-245")
def test_classifier_defers_to_npm_pin_flag():
    """TA-299 — Dependency with pin_override_kind='NPM_OVERRIDES' classifies
    IN_USE via apply_pin_override_safety (SUC-42 enforcement). Same
    mechanism as REQ-21's Maven kinds; PR-5 just verifies the npm kind
    routes through correctly."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        VersionedNode,
    )

    dep = Dependency(
        name="lodash",
        version="4.17.21",
        status=DependencyStatus.SAFE,
        reason="",
        pin_override=True,
        pin_override_kind="NPM_OVERRIDES",
        pin_override_target="pinned via overrides to 4.17.21",
        ecosystem="npm",
    )
    node = VersionedNode(
        canonical="lodash",
        declared_version="4.17.21",
        status=DependencyStatus.SAFE,
        removable=True,
    )
    _cls.apply_pin_override_safety(dep, node)
    assert node.status is DependencyStatus.IN_USE
    assert node.removable is False
