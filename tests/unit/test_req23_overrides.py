"""PR-5 red test — REQ-23 / FR-240: extract npm `overrides`. TA-295."""
from __future__ import annotations

import json

import pytest


@pytest.mark.requirement("FR-240")
def test_extract_overrides_npm(tmp_path):
    """TA-295 — package.json with ``overrides.lodash: "4.17.21"`` produces
    an NpmOverride record with mechanism='npm-overrides'."""
    from scarno.analysers.javascript import dep_file_parser as _npm

    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
            "overrides": {"lodash": "4.17.21"},
        })
    )
    overrides = _npm._extract_overrides(pkg_root, errors=[])
    by_target = {o.target_name: o for o in overrides}
    assert "lodash" in by_target
    assert by_target["lodash"].forced_version == "4.17.21"
    assert by_target["lodash"].mechanism == "npm-overrides"
