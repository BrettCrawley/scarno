"""FR-110 — entry-point resolution from node_modules exports (Phase 5.1)."""
from __future__ import annotations

import json

import pytest

from scarno.analysers.javascript.source_analyser import (
    JS_AST_AVAILABLE,
    analyse_npm_sources,
)
from scarno.models import Dependency, DependencyStatus


@pytest.mark.skipif(
    not JS_AST_AVAILABLE, reason="tree-sitter JS/TS grammars unavailable"
)
class TestReq11EntryPointResolution:
    @pytest.mark.requirement("FR-110")
    def test_entry_points_from_node_modules_exports(self, tmp_path):
        """When ``node_modules/<pkg>/package.json`` has an ``exports``
        map, the analyser populates ``entry_points_used`` /
        ``entry_points_total`` on the dep."""
        # Set up node_modules/lodash with an exports map
        pkg_dir = tmp_path / "node_modules" / "lodash"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(
            json.dumps(
                {
                    "name": "lodash",
                    "version": "4.17.21",
                    "exports": {
                        ".": "./lodash.js",
                        "./merge": "./merge.js",
                        "./cloneDeep": "./cloneDeep.js",
                        "./isEmpty": "./isEmpty.js",
                    },
                }
            )
        )

        # Source imports only lodash root and lodash/merge
        (tmp_path / "app.js").write_text(
            'import lodash from "lodash";\n'
            'import merge from "lodash/merge";\n'
        )

        declared = Dependency(
            name="lodash",
            version="4.17.21",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            source="package.json:dependencies",
            ecosystem="npm",
        )
        deps, errors = analyse_npm_sources(str(tmp_path), [declared])
        dep = next(d for d in deps if d.name == "lodash")

        assert dep.status is DependencyStatus.IN_USE
        # 4 exports total, 2 used (root "." and "./merge")
        assert dep.entry_points_total == 4
        assert dep.entry_points_used == 2
        assert len(dep.entry_points) == 4

    @pytest.mark.requirement("FR-110")
    @pytest.mark.requirement("FR-150")
    def test_no_node_modules_falls_back_to_specifier_entry_points(self, tmp_path):
        """When ``node_modules`` is absent, the analyser must still surface
        the imports the project actually uses as entry points (FR-150).

        Without this fallback the user sees the dep name and version but
        none of the methods/specifiers in use — exactly the gap the
        original FR-150 ticket reports against the real-world output.
        """
        (tmp_path / "app.js").write_text('import lodash from "lodash";\n')
        declared = Dependency(
            name="lodash",
            version="4.17.21",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            source="package.json:dependencies",
            ecosystem="npm",
        )
        deps, _ = analyse_npm_sources(str(tmp_path), [declared])
        dep = next(d for d in deps if d.name == "lodash")
        # Synthetic entry point for the root specifier `lodash` itself.
        assert dep.entry_points_total >= 1
        assert dep.entry_points_used >= 1
        assert any(
            ep.usage_count > 0 for ep in dep.entry_points if ep.used
        )
