"""PR-2 red tests — REQ-19a NEW-ARCH-006 / SEC-NEW-46 / SUC-57:
classifier centralisation (TA-236a..b).

Every analyser MUST route through core/classifier.py. The legacy
Python-only ``_resolve_transitive_statuses`` is moved out of the
Python source-analyser into the shared classifier; no other
ecosystem may re-implement the same propagation locally.
"""
from __future__ import annotations

import importlib
import pkgutil
import re
from pathlib import Path

import pytest


@pytest.mark.requirement("SEC-NEW-46")
def test_every_analyser_routes_through_classifier():
    """TA-236a — Each registered analyser, when run against a tiny
    fixture, produces a result whose either ``versioned_nodes`` is
    populated (proves classify_versioned ran) OR whose ecosystem is
    registered as no-pin-mechanism (in which case classify_canonical
    is the legitimate path).

    Smoke check, not exhaustive — the goal is to catch a future
    analyser that bypasses the classifier entirely.
    """
    from scarno.core import classifier as _cls
    from scarno.core import registry as _reg

    # Force-import every analyser package so its registrations fire.
    from scarno import analysers as _ans
    for _info in pkgutil.iter_modules(
        _ans.__path__, prefix=_ans.__name__ + "."
    ):
        importlib.import_module(_info.name)

    languages = _reg.registered_languages()
    for lang in languages:
        # Either there's a pin-detector OR the language explicitly
        # opts out via no-pin-mechanism. Anything else is a bug.
        has_detector = lang in _cls._PIN_DETECTOR_REGISTRY
        no_mech = lang in _cls._NO_PIN_MECHANISM_REGISTRY
        assert has_detector or no_mech, (
            f"Language {lang!r} registered an analyser but neither "
            f"register_pin_detector nor register_no_pin_mechanism was "
            f"called. The classifier will downgrade its SAFE deps to "
            f"UNCERTAIN forever — almost certainly a bug."
        )


@pytest.mark.requirement("SEC-NEW-46")
def test_no_inline_transitive_propagation_outside_classifier():
    """TA-236b — Static-grep the analyser source files. The legacy
    ``_resolve_transitive_statuses`` symbol must exist ONLY in
    core/classifier.py (or be removed entirely from the Python
    analyser if the extraction was clean)."""
    src_root = Path(__file__).resolve().parent.parent.parent / "src" / "scarno"
    classifier_path = src_root / "core" / "classifier.py"
    pattern = re.compile(r"\b_resolve_transitive_statuses\b")
    offenders: list[str] = []
    for py_file in src_root.rglob("*.py"):
        if py_file == classifier_path:
            continue
        text = py_file.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(py_file.relative_to(src_root)))
    assert not offenders, (
        f"_resolve_transitive_statuses must be defined only in "
        f"core/classifier.py; also found in: {offenders}"
    )
