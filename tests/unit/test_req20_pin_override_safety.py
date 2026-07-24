"""PR-2 red tests — SUC-42 pin-override safety (TA-221a..d).

The single highest-impact safety property in Phase 9: the classifier
defers to pin_override + manifest_redundant + is_resolved before
promoting any (canonical, declared_version) node to SAFE.
"""
from __future__ import annotations

import pytest


def _node(*, status, is_resolved=False):
    from scarno.models import VersionedNode
    return VersionedNode(
        canonical="com.example:x",
        declared_version="1.0",
        status=status,
        is_resolved=is_resolved,
        removable=(status.value == "SAFE"),
    )


def _dep(*, pin_override=False, kind=None, manifest_redundant=False):
    from scarno.models import Dependency, DependencyStatus
    return Dependency(
        name="com.example:x",
        version="1.0",
        status=DependencyStatus.SAFE,
        reason="",
        pin_override=pin_override,
        pin_override_kind=kind,
        manifest_redundant=manifest_redundant,
    )


# ── TA-221a ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-46")
def test_apply_pin_override_safety_forces_in_use():
    """TA-221a — pin_override=True, kind=EXCLUSION → status forced
    IN_USE, removable False, reason names the trigger."""
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus

    dep = _dep(pin_override=True, kind="EXCLUSION")
    node = _node(status=DependencyStatus.SAFE)
    _cls.apply_pin_override_safety(dep, node)
    assert node.status is DependencyStatus.IN_USE
    assert node.removable is False
    assert "EXCLUSION" in node.reason or "pin" in node.reason.lower()


# ── TA-221b ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-46")
def test_apply_pin_override_safety_dynamic_downgrades():
    """TA-221b — pin_override_kind=GRADLE_DYNAMIC_PIN → status UNCERTAIN
    (NOT IN_USE), reason mentions manual review (per REQ-21b SUC-48).
    """
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus

    dep = _dep(pin_override=True, kind="GRADLE_DYNAMIC_PIN")
    node = _node(status=DependencyStatus.SAFE)
    _cls.apply_pin_override_safety(dep, node)
    assert node.status is DependencyStatus.UNCERTAIN
    assert "manual" in node.reason.lower() or "review" in node.reason.lower()


# ── TA-221c ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-46")
def test_apply_pin_override_safety_manifest_redundant_forces_in_use():
    """TA-221c — manifest_redundant=True forces IN_USE (FR-150 contract
    extended to the per-version layer)."""
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus

    dep = _dep(manifest_redundant=True)
    node = _node(status=DependencyStatus.SAFE)
    _cls.apply_pin_override_safety(dep, node)
    assert node.status is DependencyStatus.IN_USE
    assert node.removable is False


# ── TA-221d ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-46")
def test_apply_pin_override_safety_resolved_version_forces_in_use():
    """TA-221d — is_resolved=True (the version the package manager
    actually picked) forces IN_USE; you cannot remove the version that
    is on the classpath today."""
    from scarno.core import classifier as _cls
    from scarno.models import DependencyStatus

    dep = _dep()
    node = _node(status=DependencyStatus.SAFE, is_resolved=True)
    _cls.apply_pin_override_safety(dep, node)
    assert node.status is DependencyStatus.IN_USE
    assert node.removable is False
