"""PR-2 red test — FR-205 resolved-version detection (npm). TA-226a."""
from __future__ import annotations

import json

import pytest


@pytest.mark.requirement("FR-205")
def test_npm_resolved_version_from_lockfile_root_install(tmp_path):
    """TA-226a — package-lock.json with overrides forcing lodash to
    4.17.21 records 4.17.21 as the resolved version for lodash."""
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
    (pkg_root / "package-lock.json").write_text(
        json.dumps({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "app",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.21"},
                },
                "node_modules/lodash": {"version": "4.17.21"},
            },
        })
    )
    resolved = _npm.resolve_versions_from_lockfile(str(pkg_root))
    assert resolved.get("lodash") == "4.17.21"
