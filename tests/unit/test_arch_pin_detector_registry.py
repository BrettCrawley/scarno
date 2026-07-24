"""PR-2 red tests — REQ-19a NEW-ARCH-012 / FR-254 / SEC-NEW-57:
pin-detector registry contract (TA-222a..e + SUC-63).
"""
from __future__ import annotations

import importlib
import pkgutil

import pytest


@pytest.mark.requirement("FR-254")
def test_pin_detector_registry_api_register_pin_detector():
    """TA-222a — register_pin_detector adds the ecosystem to the set."""
    from scarno.core import classifier as _cls

    initial = set(_cls._PIN_DETECTOR_REGISTRY)
    _cls.register_pin_detector("test-eco-A")
    try:
        assert "test-eco-A" in _cls._PIN_DETECTOR_REGISTRY
    finally:
        _cls._PIN_DETECTOR_REGISTRY.clear()
        _cls._PIN_DETECTOR_REGISTRY.update(initial)


@pytest.mark.requirement("FR-254")
def test_pin_detector_registry_api_register_no_pin_mechanism():
    """TA-222b — register_no_pin_mechanism adds the ecosystem to the
    no-mechanism set (so the classifier knows there's no detector to
    wait for)."""
    from scarno.core import classifier as _cls

    initial = set(_cls._NO_PIN_MECHANISM_REGISTRY)
    _cls.register_no_pin_mechanism("test-eco-B")
    try:
        assert "test-eco-B" in _cls._NO_PIN_MECHANISM_REGISTRY
    finally:
        _cls._NO_PIN_MECHANISM_REGISTRY.clear()
        _cls._NO_PIN_MECHANISM_REGISTRY.update(initial)


@pytest.mark.requirement("SEC-NEW-57")
def test_symmetric_coverage_after_all_imports():
    """TA-222c — Force-import every analyser module under
    src/scarno/analysers/. The union of pin-detector ∪
    no-pin-mechanism registrations MUST equal the registered-language
    set (no language silently absent from both)."""
    from scarno.core import classifier as _cls
    from scarno.core import registry as _reg
    from scarno import analysers as _ans

    # Force module-import for every analyser sub-package.
    for _modinfo in pkgutil.iter_modules(
        _ans.__path__, prefix=_ans.__name__ + "."
    ):
        importlib.import_module(_modinfo.name)

    languages = set(_reg.registered_languages())
    coverage = (
        _cls._PIN_DETECTOR_REGISTRY | _cls._NO_PIN_MECHANISM_REGISTRY
    )
    missing = languages - coverage
    assert not missing, (
        f"Languages registered with core/registry.py but missing from "
        f"both pin-detector and no-pin-mechanism registries: {sorted(missing)}"
    )


@pytest.mark.requirement("SEC-NEW-57")
def test_pin_detector_and_no_pin_mechanism_disjoint():
    """TA-222d — A language must not appear in BOTH registries. The two
    sets are mutually exclusive choices."""
    from scarno.core import classifier as _cls

    overlap = _cls._PIN_DETECTOR_REGISTRY & _cls._NO_PIN_MECHANISM_REGISTRY
    assert overlap == set(), (
        f"languages registered in BOTH pin-detector and no-pin-mechanism "
        f"sets: {sorted(overlap)}"
    )


@pytest.mark.requirement("SEC-NEW-46")
def test_unregistered_ecosystem_classifier_downgrades_to_uncertain():
    """TA-222e — When the classifier sees a direct dep with no source
    usage in an ecosystem registered in NEITHER set, it downgrades
    SAFE → UNCERTAIN with a reason naming the missing detector. This
    is ADR-012 fail-closed semantics — the structural prevention of
    silent vulnerability reintroduction."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        DepEdge,
    )

    # Use an ecosystem name that is GUARANTEED not to be registered.
    fake_eco = "test-unregistered-ecosystem-xyz"
    initial_pin = set(_cls._PIN_DETECTOR_REGISTRY)
    initial_no_mech = set(_cls._NO_PIN_MECHANISM_REGISTRY)
    _cls._PIN_DETECTOR_REGISTRY.discard(fake_eco)
    _cls._NO_PIN_MECHANISM_REGISTRY.discard(fake_eco)
    try:
        deps = [
            Dependency(
                name="lonely",
                version="1.0",
                status=DependencyStatus.SAFE,
                reason="",
                ecosystem=fake_eco,
            ),
        ]
        edges = [DepEdge(parent="", child="lonely", declared_version="1.0")]
        out_deps, vnodes, _ = _cls.classify_versioned(deps, edges)
        # The (lonely, 1.0) versioned-node must NOT classify SAFE.
        node = next(
            n for n in vnodes
            if n.canonical == "lonely" and n.declared_version == "1.0"
        )
        assert node.status is DependencyStatus.UNCERTAIN, (
            f"unregistered-ecosystem dep must downgrade to UNCERTAIN; "
            f"got {node.status}"
        )
        assert "detector" in node.reason.lower() or fake_eco in node.reason
    finally:
        _cls._PIN_DETECTOR_REGISTRY.clear()
        _cls._PIN_DETECTOR_REGISTRY.update(initial_pin)
        _cls._NO_PIN_MECHANISM_REGISTRY.clear()
        _cls._NO_PIN_MECHANISM_REGISTRY.update(initial_no_mech)
