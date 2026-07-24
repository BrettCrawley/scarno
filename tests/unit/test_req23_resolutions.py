"""PR-5 red test — REQ-23 / FR-241: extract yarn `resolutions`. TA-296."""
from __future__ import annotations

import json

import pytest


@pytest.mark.requirement("FR-241")
def test_extract_resolutions_yarn(tmp_path):
    """TA-296 — yarn-style ``resolutions: {"**/lodash": "4.17.21"}`` →
    NpmOverride with target_name="lodash", mechanism="yarn-resolutions",
    target_constraint preserves the ``**`` glob prefix for diagnostics.
    """
    from scarno.analysers.javascript import dep_file_parser as _npm

    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app",
            "version": "1.0.0",
            "resolutions": {"**/lodash": "4.17.21"},
        })
    )
    overrides = _npm._extract_overrides(pkg_root, errors=[])
    matching = [o for o in overrides if o.target_name == "lodash"]
    assert matching, "yarn resolution for lodash not extracted"
    assert matching[0].mechanism == "yarn-resolutions"
    assert matching[0].forced_version == "4.17.21"
