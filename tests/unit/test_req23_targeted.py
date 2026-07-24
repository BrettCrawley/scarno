"""PR-5 red test — REQ-23 / FR-243: targeted overrides nesting (one level).
TA from architecture §11.3.3."""
from __future__ import annotations

import json

import pytest


@pytest.mark.requirement("FR-243")
def test_npm_targeted_overrides_nested_under(tmp_path):
    """When ``overrides`` is a nested object (npm 8+ targeted syntax)
    ``overrides.some-lib.lodash`` → NpmOverride with
    nested_under="some-lib", target_name="lodash"."""
    from scarno.analysers.javascript import dep_file_parser as _npm

    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app",
            "version": "1.0.0",
            "overrides": {
                "some-lib": {"lodash": "4.17.21"},
            },
        })
    )
    overrides = _npm._extract_overrides(pkg_root, errors=[])
    matching = [
        o for o in overrides
        if o.target_name == "lodash" and o.nested_under == "some-lib"
    ]
    assert matching, (
        "nested overrides.some-lib.lodash entry not extracted"
    )
