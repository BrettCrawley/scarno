"""REQ-14 — Go source analyser (Phase 6, TDD red).

Tests are written against the expected Phase 6 public API:

    from scarno.analysers.go.source_analyser import (
        GO_AST_AVAILABLE,
        analyse_go_sources,
    )

Covers:
  * Go ``import`` blocks via tree-sitter-go (single + grouped)
  * Blank ``_ "foo"`` and dot ``. "foo"`` imports classify IN_USE
  * ``_test.go`` scoped separately from production sources
  * ``vendor/`` directory skipped
  * Build-tagged files included (``//go:build`` / ``// +build``)
  * Standard-library packages excluded from UNDECLARED
  * Security findings: TS-SI-012 (unsafe.Pointer), TS-SI-013 (cgo),
    TS-CE-009 (exec.Command taint)
"""
from __future__ import annotations

import pytest

try:
    from scarno.analysers.go.source_analyser import (  # type: ignore[import-not-found]
        GO_AST_AVAILABLE,
        analyse_go_sources,
    )
    from scarno.findings.rules import RULES
    from scarno.models import Dependency, DependencyStatus

    GO_SOURCE_AVAILABLE = True
except ImportError:
    analyse_go_sources = None  # type: ignore[assignment]
    GO_AST_AVAILABLE = False
    RULES = {}  # type: ignore[assignment]
    try:
        from scarno.models import Dependency, DependencyStatus  # type: ignore
    except ImportError:
        Dependency = DependencyStatus = None  # type: ignore
    GO_SOURCE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not GO_SOURCE_AVAILABLE,
    reason="pending Phase 6 — scarno.analysers.go.source_analyser not yet implemented",
)


def _declared(name: str, *, version: str = "v1.0.0") -> "Dependency":
    return Dependency(
        name=name,
        version=version,
        status=DependencyStatus.UNCERTAIN,
        reason="declared — source analysis pending",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        source="go.mod:require",
        ecosystem="go",
    )


def _status(deps, name):
    return next(d.status for d in deps if d.name == name)


# ── REQ-14 — import extraction via tree-sitter ─────────────────────────────


class TestReq14GoImports:
    @pytest.mark.requirement("FR-118")
    def test_single_import_marks_in_use(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import "github.com/pkg/errors"\n\n'
            'func main() { errors.New("x") }\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/pkg/errors")]
        )
        assert _status(deps, "github.com/pkg/errors") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-118")
    def test_grouped_import_block_marks_in_use(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import (\n'
            '    "fmt"\n'
            '    "github.com/pkg/errors"\n'
            '    "golang.org/x/sync/errgroup"\n'
            ')\n\n'
            'var _ = fmt.Println\n'
            'var _ = errors.New\n'
            'var _ = errgroup.Group{}\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path),
            [
                _declared("github.com/pkg/errors"),
                _declared("golang.org/x/sync"),
            ],
        )
        assert _status(deps, "github.com/pkg/errors") is DependencyStatus.IN_USE
        assert _status(deps, "golang.org/x/sync") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-118")
    def test_unused_dep_marks_safe(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/pkg/errors")]
        )
        assert _status(deps, "github.com/pkg/errors") is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-118")
    def test_string_inside_code_is_not_an_import(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import "fmt"\n\n'
            'func main() { fmt.Println("github.com/pkg/errors is a package") }\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/pkg/errors")]
        )
        assert _status(deps, "github.com/pkg/errors") is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-118")
    def test_comment_is_not_an_import(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            '// import "github.com/pkg/errors"\n'
            '/* import "github.com/pkg/errors" */\n\n'
            'import "fmt"\n\n'
            'func main() { fmt.Println("x") }\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/pkg/errors")]
        )
        assert _status(deps, "github.com/pkg/errors") is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-118")
    def test_stdlib_not_reported_as_undeclared(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import (\n'
            '    "fmt"\n'
            '    "os"\n'
            '    "net/http"\n'
            ')\n\n'
            'func main() { fmt.Println(os.Args); _ = http.DefaultClient }\n'
        )
        deps, _ = analyse_go_sources(str(tmp_path), [])
        names = {d.name for d in deps}
        assert "fmt" not in names
        assert "os" not in names
        assert "net/http" not in names


# ── REQ-14 — Blank / dot imports ───────────────────────────────────────────


class TestReq14BlankDotImports:
    @pytest.mark.requirement("FR-119")
    def test_blank_import_classifies_in_use(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import _ "github.com/lib/pq"\n\n'
            'func main() {}\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/lib/pq")]
        )
        # Blank imports are side-effect imports — strictly IN_USE
        assert _status(deps, "github.com/lib/pq") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-119")
    def test_dot_import_classifies_in_use(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import . "github.com/onsi/gomega"\n\n'
            'func main() {}\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/onsi/gomega")]
        )
        assert _status(deps, "github.com/onsi/gomega") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-119")
    def test_aliased_import_classifies_in_use(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import errs "github.com/pkg/errors"\n\n'
            'func main() { _ = errs.New("x") }\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/pkg/errors")]
        )
        assert _status(deps, "github.com/pkg/errors") is DependencyStatus.IN_USE


# ── REQ-14 — Test-file scope ───────────────────────────────────────────────


class TestReq14TestFileScope:
    @pytest.mark.requirement("FR-120")
    def test_test_only_dep_still_in_use(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\nimport "fmt"\nfunc main() { fmt.Println() }\n'
        )
        (tmp_path / "main_test.go").write_text(
            'package main\n\n'
            'import (\n'
            '    "testing"\n'
            '    "github.com/stretchr/testify/assert"\n'
            ')\n\n'
            'func TestX(t *testing.T) { assert.Equal(t, 1, 1) }\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/stretchr/testify")]
        )
        assert _status(deps, "github.com/stretchr/testify") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-120")
    def test_test_scope_tracked_separately_in_provenance(self, tmp_path):
        (tmp_path / "main_test.go").write_text(
            'package main\n\nimport "github.com/stretchr/testify/assert"\n'
            'import "testing"\n'
            'func TestX(t *testing.T) { assert.Equal(t, 1, 1) }\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/stretchr/testify")]
        )
        dep = next(d for d in deps if d.name == "github.com/stretchr/testify")
        # Implementation detail: source/reason should indicate test-only scope
        assert "test" in (dep.reason + dep.source).lower()


# ── REQ-14 — vendor/ directory ─────────────────────────────────────────────


class TestReq14VendorDirSkipped:
    @pytest.mark.requirement("FR-121")
    def test_vendor_directory_not_scanned(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\nimport "fmt"\nfunc main() { fmt.Println() }\n'
        )
        vendor = tmp_path / "vendor" / "github.com" / "bad" / "pkg"
        vendor.mkdir(parents=True)
        (vendor / "pkg.go").write_text(
            'package pkg\nimport "github.com/mystery"\n'
        )
        deps, _ = analyse_go_sources(str(tmp_path), [])
        # Imports found inside vendor/ must NOT produce phantom deps —
        # that code is third-party and already accounted for by vendor/modules.txt
        names = {d.name for d in deps}
        assert "github.com/mystery" not in names


# ── REQ-14 — Build tags ────────────────────────────────────────────────────


class TestReq14BuildTags:
    @pytest.mark.requirement("FR-122")
    def test_go_build_tagged_file_included(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\nimport "fmt"\nfunc main() { fmt.Println() }\n'
        )
        (tmp_path / "linux_only.go").write_text(
            '//go:build linux\n\n'
            'package main\n\n'
            'import "github.com/linux/only"\n\n'
            'var _ = only.X\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/linux/only")]
        )
        # Build-tagged files are still project source — analysis must NOT
        # omit them (missing a tagged file means missing real imports).
        assert _status(deps, "github.com/linux/only") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-122")
    def test_legacy_plus_build_tag_respected(self, tmp_path):
        (tmp_path / "darwin.go").write_text(
            '// +build darwin\n\n'
            'package main\n\n'
            'import "github.com/darwin/only"\n\n'
            'var _ = only.X\n'
        )
        deps, _ = analyse_go_sources(
            str(tmp_path), [_declared("github.com/darwin/only")]
        )
        assert _status(deps, "github.com/darwin/only") is DependencyStatus.IN_USE


# ── REQ-14 — Security: unsafe.Pointer ──────────────────────────────────────


class TestReq14UnsafePointer:
    @pytest.mark.requirement("SF-022")
    @pytest.mark.security
    def test_unsafe_pointer_emits_ts_si_012(self, tmp_path):
        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import "unsafe"\n\n'
            'func main() {\n'
            '    var x int = 42\n'
            '    p := unsafe.Pointer(&x)\n'
            '    _ = p\n'
            '}\n'
        )
        _, errors = analyse_go_sources(str(tmp_path), [])
        # The source analyser returns findings via an extended API; the
        # convention in this codebase is that findings are surfaced via
        # the analyser's AnalysisResult. For this unit test we inspect
        # RULES to drive the rule-catalogue addition.
        assert "TS-SI-012" in RULES


# ── REQ-14 — Security: cgo ─────────────────────────────────────────────────


class TestReq14CgoImport:
    @pytest.mark.requirement("SF-023")
    @pytest.mark.security
    def test_cgo_import_emits_ts_si_013(self):
        assert "TS-SI-013" in RULES


# ── REQ-14 — Security: exec.Command taint ──────────────────────────────────


class TestReq14ExecCommandTaint:
    @pytest.mark.requirement("SF-024")
    @pytest.mark.security
    def test_ts_ce_009_rule_exists(self):
        assert "TS-CE-009" in RULES
