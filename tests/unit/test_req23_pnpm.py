"""PR-5 red test — REQ-23 / FR-242: extract pnpm.overrides. TA-297."""
from __future__ import annotations

import json

import pytest


@pytest.mark.requirement("FR-242")
def test_extract_pnpm_overrides(tmp_path):
    """TA-297 — ``pnpm.overrides: {"some-lib>lodash": "4.17.21"}`` →
    NpmOverride with target_name="lodash", nested_under="some-lib"."""
    from scarno.analysers.javascript import dep_file_parser as _npm

    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app",
            "version": "1.0.0",
            "pnpm": {
                "overrides": {"some-lib>lodash": "4.17.21"},
            },
        })
    )
    overrides = _npm._extract_overrides(pkg_root, errors=[])
    matching = [o for o in overrides if o.target_name == "lodash"]
    assert matching, "pnpm.overrides for lodash not extracted"
    assert matching[0].nested_under == "some-lib"
    assert matching[0].mechanism == "pnpm-overrides"
