"""PR-5 red tests — REQ-23 / SUC-55 + SEC-NEW-45: overrides caps
(TA-302 + TA-303)."""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-45")
def test_npm_overrides_max_entries_2048(tmp_path):
    """TA-302 — 5000 overrides entries → 2048 retained with truncation
    note in errors[]."""
    from scarno.analysers.javascript import dep_file_parser as _npm

    overrides = {f"pkg{i}": "1.0.0" for i in range(5000)}
    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app", "version": "1.0.0",
            "overrides": overrides,
        })
    )
    errors: list[str] = []
    out = _npm._extract_overrides(pkg_root, errors=errors)
    assert len(out) <= 2048, (
        f"npm overrides cap not enforced; got {len(out)} entries"
    )
    assert any(
        "cap" in e.lower() or "truncat" in e.lower()
        for e in errors
    ), f"expected truncation note; got {errors!r}"


@pytest.mark.requirement("SEC-NEW-45")
def test_npm_overrides_max_nesting_8(tmp_path):
    """TA-303 — Targeted overrides nested 12 levels deep → 8 levels
    retained; deeper entries are dropped with a cap note."""
    from scarno.analysers.javascript import dep_file_parser as _npm

    # Build a 12-deep nested overrides object.
    leaf_value = "1.0.0"
    nested: dict = {"leaf": leaf_value}
    for i in range(12):
        nested = {f"parent{i}": nested}
    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app", "version": "1.0.0",
            "overrides": nested,
        })
    )
    errors: list[str] = []
    out = _npm._extract_overrides(pkg_root, errors=errors)
    # The deepest legitimate target is `leaf`; if nesting cap is
    # enforced at 8, the leaf is dropped (it sits 12 deep).
    assert not any(o.target_name == "leaf" for o in out), (
        "nesting cap not enforced — leaf at depth 12 was extracted"
    )
    assert any(
        "nest" in e.lower() or "cap" in e.lower()
        for e in errors
    ), f"expected nesting-cap note; got {errors!r}"
