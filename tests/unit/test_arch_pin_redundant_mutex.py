"""PR-2 red tests — REQ-19a NEW-ARCH-007 / FR-251 / SEC-NEW-47:
Dependency __post_init__ + classifier mutex assertion (TA-223a..b).
"""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-251")
def test_post_init_rejects_pin_override_and_manifest_redundant():
    """TA-223a — Constructing Dependency with both flags True raises
    ValueError. Defends against detector-ordering bugs at construction
    time."""
    from scarno.models import Dependency, DependencyStatus

    with pytest.raises(ValueError):
        Dependency(
            name="x",
            version="1.0",
            status=DependencyStatus.IN_USE,
            reason="",
            pin_override=True,
            manifest_redundant=True,
        )


@pytest.mark.requirement("SEC-NEW-47")
def test_classifier_asserts_mutex_on_entry():
    """TA-223b — Even if a future code path mutates both flags AFTER
    construction, the classifier's apply_pin_override_safety asserts
    the invariant on entry. Defence-in-depth."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        VersionedNode,
    )

    dep = Dependency(
        name="x", version="1.0", status=DependencyStatus.IN_USE, reason="",
        pin_override=True,
    )
    # Bypass __post_init__ by mutating the field after construction.
    object.__setattr__(dep, "manifest_redundant", True)
    node = VersionedNode(
        canonical="x", declared_version="1.0",
        status=DependencyStatus.SAFE,
    )
    with pytest.raises(AssertionError):
        _cls.apply_pin_override_safety(dep, node)
