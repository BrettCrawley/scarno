"""REQ-10 — JavaScript / TypeScript / Node.js manifest + lock parsers.

Covers:
  * ``package.json`` sections (deps / dev / peer / optional)
  * ``package-lock.json`` both lockfileVersion 1 and 2/3
  * ``npm-shrinkwrap.json``
  * ``yarn.lock`` v1 (state-machine) + v2 Berry (YAML)
  * ``pnpm-lock.yaml`` (v6+ importers)
  * ``bun.lock`` (JSONC) + ``bun.lockb`` refusal (FR-106)
  * ``deno.json`` + ``deno.lock`` (npm:/jsr: specifiers)
  * ``.npmrc`` registry override → TS-SI-008
  * ``package.json`` lifecycle hooks → TS-SI-007
"""
from __future__ import annotations

import json

import pytest

from scarno.analysers.javascript.dep_file_parser import (
    parse_all_npm_dependency_files,
)


def _names(deps):
    return {d.name for d in deps}


def _version(deps, name):
    for d in deps:
        if d.name == name:
            return d.version
    return None


class TestReq10PackageJson:
    @pytest.mark.requirement("FR-103")
    def test_dependencies_section_parsed(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.21", "express": "^4.18.0"},
        }))
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert errors == []
        assert "lodash" in _names(deps)
        assert "express" in _names(deps)

    @pytest.mark.requirement("FR-103")
    def test_all_four_sections_parsed(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"a": "1.0.0"},
            "devDependencies": {"b": "1.0.0"},
            "peerDependencies": {"c": "1.0.0"},
            "optionalDependencies": {"d": "1.0.0"},
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert _names(deps) >= {"a", "b", "c", "d"}

    @pytest.mark.requirement("FR-103")
    def test_deps_tagged_ecosystem_npm(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.0.0"},
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert all(d.ecosystem == "npm" for d in deps)

    @pytest.mark.requirement("FR-103")
    def test_malformed_json_reports_error(self, tmp_path):
        (tmp_path / "package.json").write_text("{ not valid json")
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert deps == []
        assert any("package.json" in e for e in errors)


class TestReq10NpmLockfiles:
    @pytest.mark.requirement("FR-104")
    def test_package_lock_v2_packages_map(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"lodash": "^4.17.21"}},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/react": {"version": "18.2.0"},
                # nested: must be skipped
                "node_modules/react/node_modules/scheduler": {"version": "0.23"},
            },
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert "lodash" in _names(deps)
        assert "react" in _names(deps)
        assert "scheduler" not in _names(deps)
        assert _version(deps, "react") == "18.2.0"

    @pytest.mark.requirement("FR-104")
    def test_package_lock_v1_top_level_dependencies(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "express": {"version": "4.18.2"},
            },
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert _version(deps, "lodash") == "4.17.21"
        assert _version(deps, "express") == "4.18.2"

    @pytest.mark.requirement("FR-104")
    def test_npm_shrinkwrap_parsed(self, tmp_path):
        (tmp_path / "npm-shrinkwrap.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {"pkg": {"version": "1.2.3"}},
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert _version(deps, "pkg") == "1.2.3"

    @pytest.mark.requirement("FR-104")
    def test_yarn_v1_lock_parsed(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(
            '# yarn lockfile v1\n'
            '\n'
            'lodash@^4.17.21:\n'
            '  version "4.17.21"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
            '\n'
            '"@scope/pkg@^1.0.0":\n'
            '  version "1.2.3"\n'
        )
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert _version(deps, "lodash") == "4.17.21"
        assert _version(deps, "@scope/pkg") == "1.2.3"

    @pytest.mark.requirement("FR-104")
    def test_pnpm_lock_v6_importers(self, tmp_path):
        (tmp_path / "pnpm-lock.yaml").write_text(
            'lockfileVersion: "6.0"\n'
            'importers:\n'
            '  .:\n'
            '    dependencies:\n'
            '      lodash:\n'
            '        version: 4.17.21\n'
            '    devDependencies:\n'
            '      jest:\n'
            '        version: 29.7.0\n'
        )
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert _version(deps, "lodash") == "4.17.21"
        assert _version(deps, "jest") == "29.7.0"


class TestReq10DenoManifest:
    @pytest.mark.requirement("FR-105")
    def test_deno_json_npm_specifier(self, tmp_path):
        (tmp_path / "deno.json").write_text(json.dumps({
            "imports": {
                "lodash": "npm:lodash@^4.17.21",
                "std/fs": "jsr:@std/fs@^1.0.0",
            },
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert "lodash" in _names(deps)
        assert "@std/fs" in _names(deps)

    @pytest.mark.requirement("FR-105")
    def test_deno_jsonc_comments_stripped(self, tmp_path):
        (tmp_path / "deno.jsonc").write_text(
            '{\n'
            '  // comment\n'
            '  "imports": { "lodash": "npm:lodash@^4" }\n'
            '}\n'
        )
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert errors == []
        assert "lodash" in _names(deps)

    @pytest.mark.requirement("FR-105")
    def test_deno_lock_specifiers(self, tmp_path):
        (tmp_path / "deno.lock").write_text(json.dumps({
            "version": "3",
            "packages": {
                "specifiers": {
                    "npm:lodash@^4": "npm:lodash@4.17.21",
                    "jsr:@std/fs@^1": "jsr:@std/fs@1.0.0",
                },
            },
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert "lodash" in _names(deps)
        assert "@std/fs" in _names(deps)


class TestReq10BunLock:
    @pytest.mark.requirement("FR-106")
    def test_bun_lockb_binary_refused_with_warning(self, tmp_path):
        (tmp_path / "bun.lockb").write_bytes(b"\x00\x01\x02\x03BUNLOCK\xff")
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any("bun.lockb" in e for e in errors)

    @pytest.mark.requirement("FR-106")
    def test_bun_lockb_quiet_when_bun_lock_companion_present(self, tmp_path):
        (tmp_path / "bun.lockb").write_bytes(b"\x00binary")
        (tmp_path / "bun.lock").write_text(json.dumps({
            "packages": {"lodash": ["lodash@4.17.21"]},
        }))
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert not any("bun.lockb" in e for e in errors)
        assert _version(deps, "lodash") == "4.17.21"

    @pytest.mark.requirement("FR-106")
    def test_bun_lock_jsonc_comments_stripped(self, tmp_path):
        (tmp_path / "bun.lock").write_text(
            '{\n'
            '  // bun lock v0\n'
            '  "packages": { "lodash": ["lodash@4.17.21"] }\n'
            '}\n'
        )
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert errors == []
        assert _version(deps, "lodash") == "4.17.21"


class TestReq10SecurityFindings:
    @pytest.mark.requirement("SF-016")
    @pytest.mark.security
    def test_postinstall_script_emits_ts_si_007(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "scripts": {"postinstall": "node ./setup.js"},
        }))
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-007" for f in findings)

    @pytest.mark.requirement("SF-016")
    @pytest.mark.security
    def test_preinstall_and_prepare_also_fire(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "scripts": {
                "preinstall": "./hook.sh",
                "prepare": "husky install",
            },
        }))
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        ts_si_007 = [f for f in findings if f.rule_id == "TS-SI-007"]
        assert len(ts_si_007) == 2

    @pytest.mark.requirement("SF-016")
    @pytest.mark.security
    def test_non_install_script_does_not_fire(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "scripts": {"build": "webpack", "test": "jest"},
        }))
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert not any(f.rule_id == "TS-SI-007" for f in findings)

    @pytest.mark.requirement("SF-017")
    @pytest.mark.security
    def test_npmrc_custom_registry_emits_ts_si_008(self, tmp_path):
        (tmp_path / ".npmrc").write_text("registry=https://evil.example.com/\n")
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-008" for f in findings)

    @pytest.mark.requirement("SF-017")
    @pytest.mark.security
    def test_npmrc_default_registry_does_not_fire(self, tmp_path):
        (tmp_path / ".npmrc").write_text(
            "registry=https://registry.npmjs.org/\n"
        )
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert not any(f.rule_id == "TS-SI-008" for f in findings)

    @pytest.mark.requirement("SF-017")
    @pytest.mark.security
    def test_npmrc_scoped_registry_override_fires(self, tmp_path):
        (tmp_path / ".npmrc").write_text(
            "@acme:registry=https://nexus.acme.internal/\n"
        )
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-008" for f in findings)


class TestReq10Robustness:
    @pytest.mark.requirement("FR-103")
    def test_missing_directory_returns_empty(self, tmp_path):
        deps, errors, findings = parse_all_npm_dependency_files(
            str(tmp_path / "does-not-exist")
        )
        assert deps == []
        assert findings == []

    @pytest.mark.requirement("FR-103")
    def test_deep_json_rejected_as_bomb(self, tmp_path):
        # Hand-build a > _MAX_JSON_DEPTH (1000) deeply-nested payload —
        # can't use json.dumps here because it would itself overflow
        # Python's recursion limit on the construction side.
        depth = 1500
        raw = ("{" + '"n":') * depth + "1" + ("}" * depth)
        (tmp_path / "package.json").write_text(raw)
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert deps == []
        assert any("nesting" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-103")
    def test_dedup_prefers_lockfile_version_over_manifest(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.0.0"},
        }))
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/lodash": {"version": "4.17.21"}},
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        # Lockfile precedence beats manifest's loose range
        assert _version(deps, "lodash") == "4.17.21"
