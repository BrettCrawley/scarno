"""PR-1 red tests — SEC-NEW-53 gradle.lockfile vs gradle dependencies cross-check.

When both sources of resolved-version data are present, the parser
compares their coordinate sets. A lockfile that is a strict subset of the
``gradle dependencies`` output emits a sanitised warning so a tampered
lockfile cannot silently suppress edges.
"""
from __future__ import annotations

import pytest

from scarno.analysers.java import gradle as _gradle


# ── TA-224 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-53")
def test_gradle_lockfile_strict_subset_warns():
    """TA-224 — Lockfile lists 1 coord, gradle output lists 3.

    Expect: warning emitted naming the divergence.
    """
    lockfile_coords = {"com.example:a:1.0"}
    gradle_output_coords = {
        "com.example:a:1.0",
        "com.example:b:2.0",
        "com.example:c:3.0",
    }
    errors: list[str] = []
    _gradle._check_lockfile_consistency(  # type: ignore[attr-defined]
        lockfile_coords=lockfile_coords,
        gradle_output_coords=gradle_output_coords,
        errors=errors,
    )
    assert any(
        "lockfile" in msg.lower() and "subset" in msg.lower()
        for msg in errors
    ), f"expected a strict-subset warning; got {errors!r}"


# ── TA-225 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-53")
def test_gradle_lockfile_equal_set_no_warning():
    """TA-225 — Lockfile and gradle output coordinate sets are equal.

    Expect: no warning emitted.
    """
    coords = {"com.example:a:1.0", "com.example:b:2.0"}
    errors: list[str] = []
    _gradle._check_lockfile_consistency(  # type: ignore[attr-defined]
        lockfile_coords=coords,
        gradle_output_coords=coords,
        errors=errors,
    )
    assert errors == [], (
        f"expected no warnings on equal sets; got {errors!r}"
    )
