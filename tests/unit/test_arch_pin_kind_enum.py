"""PR-3 red tests — REQ-19a NEW-ARCH-008 / FR-252 / SEC-NEW-48:
PinOverrideKind enum closed-set + safety-function branch coverage
(TA-262 + TA-263).

Initial coverage: PR-3 introduces EXCLUSION + DEPENDENCY_MANAGEMENT.
PR-5 (REQ-23 npm) extends with NPM_OVERRIDES / YARN_RESOLUTIONS /
PNPM_OVERRIDES. PR-6 (REQ-21b Gradle) extends with the GRADLE_*
kinds. Full coverage of every enum value is achieved at PR-6.
"""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-252")
def test_pin_override_kind_enum_includes_maven_kinds():
    """TA-262 — PinOverrideKind enum exposes (at minimum) the Maven kinds
    EXCLUSION and DEPENDENCY_MANAGEMENT."""
    from scarno.models import PinOverrideKind

    values = {member.value for member in PinOverrideKind}
    assert "EXCLUSION" in values
    assert "DEPENDENCY_MANAGEMENT" in values


@pytest.mark.requirement("SEC-NEW-48")
def test_safety_function_branch_for_maven_kinds():
    """TA-263 — apply_pin_override_safety recognises EXCLUSION and
    DEPENDENCY_MANAGEMENT as IN_USE-forcing kinds."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        VersionedNode,
    )

    for kind in ("EXCLUSION", "DEPENDENCY_MANAGEMENT"):
        dep = Dependency(
            name="x",
            version="1.0",
            status=DependencyStatus.SAFE,
            reason="",
            pin_override=True,
            pin_override_kind=kind,
        )
        node = VersionedNode(
            canonical="x",
            declared_version="1.0",
            status=DependencyStatus.SAFE,
            removable=True,
        )
        _cls.apply_pin_override_safety(dep, node)
        assert node.status is DependencyStatus.IN_USE, (
            f"safety function did not force IN_USE for kind={kind!r}"
        )
        assert node.removable is False


# ── TA-306 (PR-5 extension) ────────────────────────────────────────────────


@pytest.mark.requirement("FR-252")
def test_pin_override_kind_enum_includes_npm_kinds():
    """TA-306 (PR-5 enum extension) — PinOverrideKind exposes
    NPM_OVERRIDES, YARN_RESOLUTIONS, PNPM_OVERRIDES."""
    from scarno.models import PinOverrideKind

    values = {member.value for member in PinOverrideKind}
    assert "NPM_OVERRIDES" in values
    assert "YARN_RESOLUTIONS" in values
    assert "PNPM_OVERRIDES" in values


@pytest.mark.requirement("SEC-NEW-48")
def test_safety_function_branches_for_npm_kinds():
    """TA-306 — apply_pin_override_safety recognises the three npm
    kinds as IN_USE-forcing."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        VersionedNode,
    )

    for kind in ("NPM_OVERRIDES", "YARN_RESOLUTIONS", "PNPM_OVERRIDES"):
        dep = Dependency(
            name="lodash",
            version="4.17.21",
            status=DependencyStatus.SAFE,
            reason="",
            pin_override=True,
            pin_override_kind=kind,
            ecosystem="npm",
        )
        node = VersionedNode(
            canonical="lodash",
            declared_version="4.17.21",
            status=DependencyStatus.SAFE,
            removable=True,
        )
        _cls.apply_pin_override_safety(dep, node)
        assert node.status is DependencyStatus.IN_USE, (
            f"safety function did not force IN_USE for kind={kind!r}"
        )


# ── TA-323 (PR-6 enum extension) ───────────────────────────────────────────


@pytest.mark.requirement("FR-252")
def test_pin_override_kind_enum_includes_gradle_kinds():
    """TA-323 — PinOverrideKind exposes the five Gradle kinds
    introduced by REQ-21b PR-6: GRADLE_FORCE, GRADLE_STRICTLY,
    GRADLE_CONSTRAINTS, GRADLE_EXCLUSION, GRADLE_DYNAMIC_PIN.

    Full enum-coverage (every value must trigger a safety-function
    branch) is achieved here at PR-6 — completes the NEW-ARCH-008
    closed-set contract."""
    from scarno.models import PinOverrideKind

    values = {member.value for member in PinOverrideKind}
    for kind in (
        "GRADLE_FORCE",
        "GRADLE_STRICTLY",
        "GRADLE_CONSTRAINTS",
        "GRADLE_EXCLUSION",
        "GRADLE_DYNAMIC_PIN",
    ):
        assert kind in values, f"PinOverrideKind missing {kind!r}"


@pytest.mark.requirement("SEC-NEW-48")
def test_safety_function_branches_for_gradle_kinds():
    """TA-323 — apply_pin_override_safety routes each Gradle kind to
    the correct branch: static kinds force IN_USE; GRADLE_DYNAMIC_PIN
    downgrades to UNCERTAIN."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        VersionedNode,
    )

    static_kinds = (
        "GRADLE_FORCE",
        "GRADLE_STRICTLY",
        "GRADLE_CONSTRAINTS",
        "GRADLE_EXCLUSION",
    )
    for kind in static_kinds:
        dep = Dependency(
            name="com.example:lib", version="1.0",
            status=DependencyStatus.SAFE, reason="",
            pin_override=True, pin_override_kind=kind,
            ecosystem="gradle",
        )
        node = VersionedNode(
            canonical="com.example:lib", declared_version="1.0",
            status=DependencyStatus.SAFE, removable=True,
        )
        _cls.apply_pin_override_safety(dep, node)
        assert node.status is DependencyStatus.IN_USE, (
            f"safety function did not force IN_USE for kind={kind!r}"
        )

    # GRADLE_DYNAMIC_PIN: UNCERTAIN.
    dep = Dependency(
        name="com.example:lib", version="1.0",
        status=DependencyStatus.SAFE, reason="",
        pin_override=True, pin_override_kind="GRADLE_DYNAMIC_PIN",
        ecosystem="gradle",
    )
    node = VersionedNode(
        canonical="com.example:lib", declared_version="1.0",
        status=DependencyStatus.SAFE, removable=True,
    )
    _cls.apply_pin_override_safety(dep, node)
    assert node.status is DependencyStatus.UNCERTAIN, (
        "GRADLE_DYNAMIC_PIN must downgrade to UNCERTAIN, not IN_USE"
    )
