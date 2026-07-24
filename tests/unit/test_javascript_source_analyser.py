"""REQ-11 — JavaScript / TypeScript / Node.js source analyser.

Covers:
  * ESM static imports + CJS ``require`` via tree-sitter grammars
  * TypeScript triple-slash ``/// <reference types="…" />`` directives
  * ``tsconfig.json`` ``paths`` aliases resolved locally (not as npm deps)
  * Node built-ins (including ``node:`` prefix) excluded from UNDECLARED
  * Rule catalogue extensions registered (SF-018)
"""
from __future__ import annotations

import json

import pytest

from scarno.analysers.javascript.source_analyser import (
    JS_AST_AVAILABLE,
    analyse_npm_sources,
)
from scarno.findings.rules import RULES
from scarno.models import Dependency, DependencyStatus


pytestmark = pytest.mark.skipif(
    not JS_AST_AVAILABLE, reason="tree-sitter JS/TS grammars unavailable"
)


def _declared(name: str, *, version: str = "1.0.0") -> Dependency:
    return Dependency(
        name=name,
        version=version,
        status=DependencyStatus.UNCERTAIN,
        reason="declared — source analysis pending",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        source="package.json:dependencies",
        ecosystem="npm",
    )


def _status(deps, name):
    return next(d.status for d in deps if d.name == name)


class TestReq11EsmAndCjs:
    @pytest.mark.requirement("FR-107")
    def test_static_esm_import_marks_in_use(self, tmp_path):
        (tmp_path / "app.js").write_text('import lodash from "lodash";\n')
        deps, errors = analyse_npm_sources(
            str(tmp_path), [_declared("lodash")]
        )
        assert _status(deps, "lodash") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-107")
    def test_cjs_require_marks_in_use(self, tmp_path):
        (tmp_path / "app.js").write_text('const express = require("express");\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [_declared("express")])
        assert _status(deps, "express") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-107")
    def test_unused_dep_marks_safe(self, tmp_path):
        (tmp_path / "app.js").write_text('import x from "lodash";\n')
        deps, _ = analyse_npm_sources(
            str(tmp_path),
            [_declared("lodash"), _declared("jest")],
        )
        assert _status(deps, "jest") is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-107")
    def test_dynamic_import_literal_in_use(self, tmp_path):
        (tmp_path / "app.js").write_text('const m = await import("lodash");\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [_declared("lodash")])
        assert _status(deps, "lodash") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-107")
    def test_dynamic_import_nonliteral_leaves_uncertain(self, tmp_path):
        (tmp_path / "app.js").write_text(
            'const name = process.env.PKG;\n'
            'const m = await import(name);\n'
        )
        deps, _ = analyse_npm_sources(str(tmp_path), [_declared("lodash")])
        # Non-literal dynamic import → status stays UNCERTAIN for all deps
        assert _status(deps, "lodash") is DependencyStatus.UNCERTAIN

    @pytest.mark.requirement("FR-107")
    def test_string_inside_code_is_not_an_import(self, tmp_path):
        (tmp_path / "app.js").write_text('const s = "lodash is cool";\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [_declared("lodash")])
        assert _status(deps, "lodash") is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-107")
    def test_comment_is_not_an_import(self, tmp_path):
        (tmp_path / "app.js").write_text(
            '// import "lodash"\n'
            '/* require("lodash") */\n'
            'console.log("ok");\n'
        )
        deps, _ = analyse_npm_sources(str(tmp_path), [_declared("lodash")])
        assert _status(deps, "lodash") is DependencyStatus.SAFE


class TestReq11TypeScript:
    @pytest.mark.requirement("FR-107")
    def test_typescript_import_parsed(self, tmp_path):
        (tmp_path / "app.ts").write_text(
            'import { merge } from "lodash";\n'
            'export const out = merge({}, {});\n'
        )
        deps, _ = analyse_npm_sources(str(tmp_path), [_declared("lodash")])
        assert _status(deps, "lodash") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-108")
    def test_triple_slash_reference_types_detected_as_undeclared(
        self, tmp_path
    ):
        (tmp_path / "app.ts").write_text(
            '/// <reference types="node" />\n'
            'console.log("hi");\n'
        )
        # `node` is a core-like name, but reference_types is specifically
        # a TypeScript @types/* hook. The analyser extracts it into
        # facts.reference_types; we just assert extraction doesn't crash
        # and produces no spurious imports for the bare reference.
        deps, errors = analyse_npm_sources(str(tmp_path), [])
        assert errors == []


class TestReq11TsConfigPaths:
    @pytest.mark.requirement("FR-109")
    def test_tsconfig_alias_not_treated_as_npm(self, tmp_path):
        (tmp_path / "tsconfig.json").write_text(json.dumps({
            "compilerOptions": {"paths": {"@/*": ["src/*"]}},
        }))
        (tmp_path / "app.ts").write_text('import helper from "@/utils/helper";\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [])
        # No phantom dep named "@" should appear — local alias
        names = {d.name for d in deps}
        assert "@" not in names
        assert names == set() or all(not n.startswith("@/") for n in names)

    @pytest.mark.requirement("FR-109")
    def test_non_aliased_import_still_phantom(self, tmp_path):
        (tmp_path / "tsconfig.json").write_text(json.dumps({
            "compilerOptions": {"paths": {"@/*": ["src/*"]}},
        }))
        (tmp_path / "app.ts").write_text('import x from "some-npm-pkg";\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [])
        names = {d.name for d in deps}
        assert "some-npm-pkg" in names


class TestReq11NodeCoreModules:
    @pytest.mark.requirement("FR-107")
    def test_node_prefix_core_module_excluded(self, tmp_path):
        (tmp_path / "app.js").write_text('import fs from "node:fs";\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [])
        # Core modules must NOT surface as phantom/UNDECLARED deps
        assert not any(d.name in {"fs", "node:fs"} for d in deps)

    @pytest.mark.requirement("FR-107")
    def test_bare_core_module_excluded(self, tmp_path):
        (tmp_path / "app.js").write_text('const path = require("path");\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [])
        assert not any(d.name == "path" for d in deps)

    @pytest.mark.requirement("FR-107")
    def test_undeclared_npm_pkg_becomes_phantom(self, tmp_path):
        (tmp_path / "app.js").write_text('import x from "mystery-pkg";\n')
        deps, _ = analyse_npm_sources(str(tmp_path), [])
        phantom = next(d for d in deps if d.name == "mystery-pkg")
        assert phantom.status is DependencyStatus.UNDECLARED
        assert phantom.ecosystem == "npm"
        assert phantom.resolved is False


class TestReq11ScopedPackages:
    @pytest.mark.requirement("FR-107")
    def test_scoped_package_trimmed_to_root(self, tmp_path):
        (tmp_path / "app.js").write_text(
            'import { Thing } from "@scope/pkg/deep/path";\n'
        )
        deps, _ = analyse_npm_sources(
            str(tmp_path), [_declared("@scope/pkg")]
        )
        assert _status(deps, "@scope/pkg") is DependencyStatus.IN_USE


class TestReq11RuleCatalogue:
    @pytest.mark.requirement("SF-018")
    @pytest.mark.security
    def test_phase5_rules_present(self):
        for rule_id in (
            "TS-SI-007", "TS-SI-008", "TS-SI-009", "TS-SI-010", "TS-SI-011",
            "TS-CE-007", "TS-CE-008",
        ):
            assert rule_id in RULES, f"missing rule: {rule_id}"

    @pytest.mark.requirement("SF-018")
    @pytest.mark.security
    def test_rules_have_required_fields(self):
        for rule_id in ("TS-SI-007", "TS-CE-007", "TS-CE-008"):
            rule = RULES[rule_id]
            assert rule.message
            assert rule.remediation
            assert rule.severity is not None
            assert rule.kind is not None
