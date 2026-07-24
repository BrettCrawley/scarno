"""PR-5 red tests — REQ-23 / SUC-54 + SEC-NEW-34: override target validation
(TA-300 + TA-301)."""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("FR-244")
def test_invalid_override_target_rejected(tmp_path):
    """TA-300 — overrides target name `lodash..` (traversal-shaped) is
    rejected by _is_valid_npm_name; no NpmOverride record produced."""
    from scarno.analysers.javascript import dep_file_parser as _npm

    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app",
            "version": "1.0.0",
            "overrides": {"lodash..": "4.17.21"},
        })
    )
    overrides = _npm._extract_overrides(pkg_root, errors=[])
    names = {o.target_name for o in overrides}
    assert "lodash.." not in names
    assert all(_npm._is_valid_npm_name(n) for n in names), (
        f"some override targets bypassed the npm-name validator: "
        f"{names}"
    )


@pytest.mark.requirement("FR-244")
def test_homoglyph_override_target_no_match(tmp_path):
    """TA-301 — overrides target `lodаsh` (Cyrillic `а`) MUST NOT
    fuzzy-match real `lodash`. Exact-string match only."""
    from scarno.analysers.javascript import dep_file_parser as _npm

    homoglyph = "lodаsh"  # Cyrillic 'a' (U+0430)
    real = "lodash"
    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app",
            "version": "1.0.0",
            "dependencies": {real: "^4"},
            "overrides": {homoglyph: "4.17.21"},
        })
    )
    # Even if the validator allows the homoglyph (npm spec permits
    # only ASCII so it's probably rejected), the matcher must use
    # exact equality — the homoglyph string MUST NOT match the real
    # string when looking for direct-dep pin targets.
    overrides = _npm._extract_overrides(pkg_root, errors=[])
    matched_lodash = [
        o for o in overrides if o.target_name == real
    ]
    assert not matched_lodash, (
        "homoglyph override target should NOT match the real lodash dep"
    )
