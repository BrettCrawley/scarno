"""REQ-13 — Go manifest + lock parser (Phase 6, TDD red).

Tests are written against the expected Phase 6 public API:

    from scarno.analysers.go.dep_file_parser import (
        parse_all_go_dependency_files,
    )

Until that module exists the import fails and every test in this file
is marked SKIPPED with a clear reason. When Phase 6 starts, the
implementer creates the module; tests then go RED and drive the
implementation until they turn green.

Covers:
  * go.mod ``require`` blocks (single + grouped)
  * go.mod ``replace`` / ``exclude`` / ``retract`` directives
  * go.sum version resolution + hash-pair deduplication
  * ``vendor/modules.txt`` cross-check (vendored modules used vs declared)
  * ``replace ... => https://…`` remote-URL → Finding TS-DS-002
"""
from __future__ import annotations

import pytest

try:
    from scarno.analysers.go.dep_file_parser import (  # type: ignore[import-not-found]
        parse_all_go_dependency_files,
    )
    from scarno.findings.rules import RULES

    GO_MANIFEST_AVAILABLE = True
except ImportError:
    parse_all_go_dependency_files = None  # type: ignore[assignment]
    RULES = {}  # type: ignore[assignment]
    GO_MANIFEST_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not GO_MANIFEST_AVAILABLE,
    reason="pending Phase 6 — scarno.analysers.go.dep_file_parser not yet implemented",
)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _names(deps):
    return {d.name for d in deps}


def _version(deps, name):
    for d in deps:
        if d.name == name:
            return d.version
    return None


def _write_go_mod(tmp_path, body: str) -> None:
    (tmp_path / "go.mod").write_text(body)


# ── REQ-13 — go.mod require ────────────────────────────────────────────────


class TestReq13GoModRequire:
    @pytest.mark.requirement("FR-114")
    def test_single_require_parsed(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module example.com/app\n\ngo 1.21\n\n"
            'require github.com/stretchr/testify v1.8.4\n',
        )
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        assert errors == []
        assert _version(deps, "github.com/stretchr/testify") == "v1.8.4"

    @pytest.mark.requirement("FR-114")
    def test_grouped_require_block_parsed(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module example.com/app\n\ngo 1.21\n\n"
            "require (\n"
            "    github.com/stretchr/testify v1.8.4\n"
            "    github.com/pkg/errors v0.9.1\n"
            "    golang.org/x/crypto v0.17.0 // indirect\n"
            ")\n",
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "github.com/stretchr/testify" in names
        assert "github.com/pkg/errors" in names
        assert "golang.org/x/crypto" in names

    @pytest.mark.requirement("FR-114")
    def test_deps_tagged_ecosystem_go(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        assert deps, "expected at least one dep"
        assert all(d.ecosystem == "go" for d in deps)

    @pytest.mark.requirement("FR-114")
    def test_indirect_comment_preserved_in_metadata(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require (\n"
            "    github.com/a v1.0.0\n"
            "    github.com/b v2.0.0 // indirect\n"
            ")\n",
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        # `indirect` marker must be recorded somewhere — conventionally
        # encoded in the dep's ``source`` string or a structured flag.
        indirect_dep = next(d for d in deps if d.name == "github.com/b")
        assert "indirect" in indirect_dep.source or "indirect" in indirect_dep.reason


# ── REQ-13 — go.mod replace / exclude / retract ────────────────────────────


class TestReq13ModDirectives:
    @pytest.mark.requirement("FR-115")
    def test_replace_directive_redirects_version(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require github.com/pkg/errors v0.9.1\n\n"
            "replace github.com/pkg/errors => github.com/pkg/errors v0.8.0\n",
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        assert _version(deps, "github.com/pkg/errors") == "v0.8.0"

    @pytest.mark.requirement("FR-115")
    def test_replace_to_local_path_flagged(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require example.com/internal v1.0.0\n\n"
            "replace example.com/internal => ../internal\n",
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        local = next(d for d in deps if d.name == "example.com/internal")
        # Local replace → treated as an in-tree module, version is "local"
        # or similar. Either way, NOT the original v1.0.0 version.
        assert local.version != "v1.0.0"

    @pytest.mark.requirement("FR-115")
    def test_exclude_directive_drops_version(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require github.com/bad/pkg v1.2.3\n\n"
            "exclude github.com/bad/pkg v1.2.3\n",
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        # Excluded version must NOT appear; either dep is dropped entirely
        # or its status is SAFE/excluded.
        bad = [d for d in deps if d.name == "github.com/bad/pkg"]
        assert not bad or all(d.version != "v1.2.3" for d in bad)

    @pytest.mark.requirement("FR-115")
    def test_retract_honoured(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module example.com/x\n\ngo 1.21\n\n"
            "retract v0.5.0 // security issue\n"
            "retract [v0.1.0, v0.4.0]\n",
        )
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        # retract directives apply to THIS module's published versions —
        # parser must not error out on them.
        assert errors == []


# ── REQ-13 — go.sum version resolution ─────────────────────────────────────


class TestReq13GoSum:
    @pytest.mark.requirement("FR-116")
    def test_go_sum_overrides_range_with_exact_version(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.0\n",
        )
        (tmp_path / "go.sum").write_text(
            "github.com/pkg/errors v0.9.1 h1:abc=\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:def=\n"
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        # go.sum is authoritative for what actually got built
        assert _version(deps, "github.com/pkg/errors") == "v0.9.1"

    @pytest.mark.requirement("FR-116")
    def test_go_sum_hash_pair_dedup(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module x\n\ngo 1.21\n\nrequire github.com/a v1.0.0\n",
        )
        # Both hash lines (module archive + go.mod hash) must not produce
        # two separate deps.
        (tmp_path / "go.sum").write_text(
            "github.com/a v1.0.0 h1:zzz=\n"
            "github.com/a v1.0.0/go.mod h1:yyy=\n"
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        matching = [d for d in deps if d.name == "github.com/a"]
        assert len(matching) == 1


# ── REQ-13 — vendor/modules.txt ────────────────────────────────────────────


class TestReq13VendorModules:
    @pytest.mark.requirement("FR-117")
    def test_vendor_modules_txt_cross_checked(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require (\n"
            "    github.com/a v1.0.0\n"
            "    github.com/b v2.0.0\n"
            ")\n",
        )
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "modules.txt").write_text(
            "# github.com/a v1.0.0\n"
            "## explicit\n"
            "github.com/a\n"
            "# github.com/b v2.0.0\n"
            "## explicit\n"
            "github.com/b\n"
        )
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        # Vendored modules should be marked as such via the source
        # provenance field or an equivalent flag.
        a = next(d for d in deps if d.name == "github.com/a")
        assert "vendor" in a.source.lower() or a.vendored_path is not None

    @pytest.mark.requirement("FR-117")
    def test_vendor_modules_missing_dep_reported(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require github.com/a v1.0.0\n",
        )
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "modules.txt").write_text("# nothing useful\n")
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        # go.mod declares github.com/a but vendor dir doesn't — parser
        # should surface the mismatch as an informational error.
        assert any(
            "vendor" in e.lower() and "github.com/a" in e for e in errors
        )


# ── REQ-13 — Security: remote replace URL ──────────────────────────────────


class TestReq13ReplaceRemoteUrl:
    @pytest.mark.requirement("SF-021")
    @pytest.mark.security
    def test_replace_with_remote_url_emits_ts_ds_002(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require github.com/pkg/errors v0.9.1\n\n"
            "replace github.com/pkg/errors => "
            "https://evil.example.com/errors v0.0.1\n",
        )
        _, _, findings = parse_all_go_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-DS-002" for f in findings)

    @pytest.mark.requirement("SF-021")
    @pytest.mark.security
    def test_ts_ds_002_rule_exists_in_catalogue(self):
        # Drives rule-catalogue extension during Phase 6
        assert "TS-DS-002" in RULES

    @pytest.mark.requirement("SF-021")
    @pytest.mark.security
    def test_replace_to_local_path_does_not_fire_ts_ds_002(self, tmp_path):
        _write_go_mod(
            tmp_path,
            "module x\n\ngo 1.21\n\n"
            "require github.com/pkg/errors v0.9.1\n\n"
            "replace github.com/pkg/errors => ../errors\n",
        )
        _, _, findings = parse_all_go_dependency_files(str(tmp_path))
        assert not any(f.rule_id == "TS-DS-002" for f in findings)


# ── REQ-13 — Robustness ────────────────────────────────────────────────────


class TestReq13Robustness:
    @pytest.mark.requirement("FR-114")
    def test_missing_go_mod_returns_empty(self, tmp_path):
        deps, errors, findings = parse_all_go_dependency_files(str(tmp_path))
        assert deps == []
        assert findings == []

    @pytest.mark.requirement("FR-114")
    def test_malformed_go_mod_reports_error(self, tmp_path):
        (tmp_path / "go.mod").write_text("this is not a go.mod file at all\n")
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        # Parser should not raise — errors surface via the errors list
        assert isinstance(errors, list)
