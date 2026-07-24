"""PR-5 red tests — REQ-23 / FR-244 + SUC-56: pin-override flagging on
direct dep matches (TA-298)."""
from __future__ import annotations

import json

import pytest


@pytest.mark.requirement("FR-244")
def test_pin_override_flag_set_for_npm_match(tmp_path, monkeypatch):
    """TA-298 — Project has direct `dependencies.lodash` AND
    `overrides.lodash: "4.17.21"`; source code doesn't import lodash.
    Result: lodash dep gets pin_override=True, kind='NPM_OVERRIDES'.
    """
    from scarno.analysers.javascript import (
        JavascriptAnalyser,  # registered in __init__.py
    )

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

    analyser = JavascriptAnalyser()
    result = analyser.analyse(str(pkg_root))

    lodash = next(
        (d for d in result.dependencies if d.name == "lodash"),
        None,
    )
    assert lodash is not None
    assert lodash.pin_override is True, (
        "npm overrides target not flagged as pin_override"
    )
    assert lodash.pin_override_kind == "NPM_OVERRIDES"
