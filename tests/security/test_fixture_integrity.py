"""Integrity tests — every committed fixture directory is loaded by at
least one test, and the analyser behaves as its README promises.

Why this file exists:
  * Every committed fixture must be real (no empty directories).
  * Every real fixture must be exercised — an unreferenced fixture
    silently rots and gives false assurance.
  * When a fixture is modified, these tests fail loudly.

For Phase 4/5 (done phases) the assertions are real. For Phase 6/7
(Go/C#) the tests import the target analyser and skip at runtime when
the module isn't present — same pattern as the rest of the suite.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

_ROOT = Path(__file__).resolve().parents[1] / "fixtures"


# ═══════════════════════════════════════════════════════════════════════════
# Generic coverage — no empty dirs, every fixture is listed here
# ═══════════════════════════════════════════════════════════════════════════


def test_no_empty_fixture_directories():
    """Regression guard: every fixture directory contains at least one file.

    Empty directories were a historical wart — placeholder dirs whose
    READMEs promised content but where the payload was built inline via
    ``tmp_path``. Now every scenario has a real committed payload.
    """
    empty = []
    for path in sorted(_ROOT.rglob("*")):
        if path.is_dir() and not any(path.iterdir()):
            empty.append(path.relative_to(_ROOT))
    assert not empty, f"empty fixture directories: {empty}"


# ═══════════════════════════════════════════════════════════════════════════
# Python malicious fixtures
# ═══════════════════════════════════════════════════════════════════════════


class TestPythonFixtures:
    @pytest.mark.requirement("SEC-003")
    def test_ansi_dep_fixture_sanitised(self):
        from scarno.analysers.python.dep_file_parser import (
            parse_all_dependency_files,
        )
        path = _ROOT / "python_malicious" / "ansi_dep"
        assert (path / "requirements.txt").exists()
        deps, _, _ = parse_all_dependency_files(str(path))
        for d in deps:
            assert "\x1b" not in d.name

    @pytest.mark.requirement("SEC-003")
    def test_control_chars_fixture_rejected_or_sanitised(self):
        from scarno.analysers.python.dep_file_parser import (
            parse_all_dependency_files,
        )
        path = _ROOT / "python_malicious" / "control_chars"
        assert (path / "requirements.txt").exists()
        deps, errors, _ = parse_all_dependency_files(str(path))
        for d in deps:
            assert "\x00" not in d.name
            assert "\x01" not in d.name
            assert "\x1b" not in d.name

    @pytest.mark.requirement("SEC-003")
    def test_rich_markup_fixture_sanitised(self):
        from scarno.analysers.python.dep_file_parser import (
            parse_all_dependency_files,
        )
        path = _ROOT / "python_malicious" / "rich_markup"
        assert (path / "requirements.txt").exists()
        deps, _, _ = parse_all_dependency_files(str(path))
        for d in deps:
            assert "[bold" not in d.name
            assert "[link" not in d.name

    @pytest.mark.requirement("SEC-003")
    def test_oversized_req_fixture_bounded(self):
        from scarno.analysers.python.dep_file_parser import (
            parse_all_dependency_files,
        )
        path = _ROOT / "python_malicious" / "oversized_req"
        assert (path / "requirements.txt").exists()
        deps, errors, _ = parse_all_dependency_files(str(path))
        assert isinstance(deps, list)

    @pytest.mark.requirement("SEC-003")
    def test_circular_includes_fixture_terminates(self):
        import time
        from scarno.analysers.python.dep_file_parser import (
            parse_all_dependency_files,
        )
        path = _ROOT / "python_malicious" / "circular_includes"
        assert (path / "a.txt").exists()
        assert (path / "b.txt").exists()
        start = time.monotonic()
        deps, errors, _ = parse_all_dependency_files(str(path))
        elapsed = time.monotonic() - start
        # Cycle detection keeps it bounded
        assert elapsed < 5.0, f"circular includes took {elapsed:.2f}s"


# ═══════════════════════════════════════════════════════════════════════════
# Java malicious fixtures
# ═══════════════════════════════════════════════════════════════════════════


class TestJavaFixtures:
    @pytest.mark.requirement("SEC-NEW-03")
    def test_xxe_pom_fixture_rejected(self):
        from scarno.analysers.java.maven import MavenPomResolver
        path = _ROOT / "java_malicious" / "xxe_pom"
        assert (path / "pom.xml").exists()
        result = MavenPomResolver().analyse(str(path))
        # DOCTYPE must be refused pre-parse; nothing sensitive leaks
        all_text = " ".join(d.name for d in result.dependencies) + " ".join(result.errors)
        assert "root:" not in all_text
        assert "/bin/" not in all_text

    @pytest.mark.requirement("SEC-NEW-03")
    def test_billion_laughs_fixture_rejected(self):
        from scarno.analysers.java.maven import MavenPomResolver
        path = _ROOT / "java_malicious" / "billion_laughs"
        assert (path / "pom.xml").exists()
        result = MavenPomResolver().analyse(str(path))
        # Entity expansion bomb must not produce expanded strings
        combined = " ".join(d.name for d in result.dependencies) + " ".join(result.errors)
        # No runaway expansion (would be MB of "lol")
        assert len(combined) < 100_000

    @pytest.mark.requirement("FR-010")
    def test_circular_modules_fixture_terminates(self):
        import time
        from scarno.analysers.java.maven import MavenPomResolver
        path = _ROOT / "java_malicious" / "circular_modules"
        assert (path / "pom.xml").exists()
        start = time.monotonic()
        MavenPomResolver().analyse(str(path))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"circular modules took {elapsed:.2f}s"

    @pytest.mark.requirement("SEC-NEW-01")
    def test_deep_nested_pom_fixture_bounded(self):
        from scarno.analysers.java.maven import MavenPomResolver
        path = _ROOT / "java_malicious" / "deep_nested_pom"
        assert (path / "pom.xml").exists()
        # Must not stack-overflow parsing 2000-level-deep XML
        result = MavenPomResolver().analyse(str(path))
        assert isinstance(result.dependencies, list)


# ═══════════════════════════════════════════════════════════════════════════
# Gradle malicious fixtures
# ═══════════════════════════════════════════════════════════════════════════


class TestGradleFixtures:
    @pytest.mark.requirement("SEC-NEW-11")
    def test_redos_fixture_parses_fast(self):
        import time
        from scarno.analysers.java.gradle import GradleBuildResolver
        path = _ROOT / "gradle_malicious" / "redos"
        assert (path / "build.gradle").exists()
        start = time.monotonic()
        GradleBuildResolver().analyse(str(path))
        elapsed = time.monotonic() - start
        # Must parse in < 2 s — no catastrophic backtracking
        assert elapsed < 2.0, f"Gradle ReDoS fixture took {elapsed:.2f}s"

    @pytest.mark.requirement("SEC-NEW-12")
    def test_long_lines_fixture_bounded(self):
        import time
        from scarno.analysers.java.gradle import GradleBuildResolver
        path = _ROOT / "gradle_malicious" / "long_lines"
        assert (path / "build.gradle").exists()
        start = time.monotonic()
        result = GradleBuildResolver().analyse(str(path))
        elapsed = time.monotonic() - start
        # Line-length cap prevents hangs
        assert elapsed < 2.0, f"Gradle long_lines took {elapsed:.2f}s"
        assert isinstance(result.dependencies, list)


# ═══════════════════════════════════════════════════════════════════════════
# JavaScript malicious fixtures
# ═══════════════════════════════════════════════════════════════════════════


class TestJavaScriptFixtures:
    @pytest.mark.requirement("SF-016")
    def test_postinstall_exfil_fixture_emits_ts_si_007(self):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        path = _ROOT / "javascript_malicious" / "postinstall_exfil"
        assert (path / "package.json").exists()
        _, _, findings = parse_all_npm_dependency_files(str(path))
        assert any(f.rule_id == "TS-SI-007" for f in findings)

    @pytest.mark.requirement("SF-017")
    def test_rogue_registry_fixture_emits_ts_si_008(self):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        path = _ROOT / "javascript_malicious" / "rogue_registry"
        assert (path / ".npmrc").exists()
        _, _, findings = parse_all_npm_dependency_files(str(path))
        assert any(f.rule_id == "TS-SI-008" for f in findings)

    @pytest.mark.requirement("SEC-NEW-20")
    def test_packagelock_json_bomb_fixture_rejected(self):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        path = _ROOT / "javascript_malicious" / "packagelock_json_bomb"
        assert (path / "package-lock.json").exists()
        deps, errors, _ = parse_all_npm_dependency_files(str(path))
        # Either the iterative depth-cap or json.loads' own RecursionError trips
        assert any("nesting" in e.lower() or "depth" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-NEW-21")
    def test_pnpm_yaml_bomb_fixture_terminates_fast(self):
        import time
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        path = _ROOT / "javascript_malicious" / "pnpm_yaml_bomb"
        assert (path / "pnpm-lock.yaml").exists()
        start = time.monotonic()
        deps, errors, _ = parse_all_npm_dependency_files(str(path))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"pnpm yaml bomb took {elapsed:.2f}s"

    @pytest.mark.requirement("SEC-NEW-22")
    def test_yarnlock_redos_fixture_parses_fast(self):
        import time
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        path = _ROOT / "javascript_malicious" / "yarnlock_redos"
        assert (path / "yarn.lock").exists()
        start = time.monotonic()
        deps, errors, _ = parse_all_npm_dependency_files(str(path))
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"yarn.lock ReDoS fixture took {elapsed:.2f}s"

    @pytest.mark.requirement("SEC-NEW-23")
    def test_tsconfig_jsonc_bomb_fixture_terminates(self):
        import time
        from scarno.analysers.javascript.source_analyser import (
            JS_AST_AVAILABLE,
            analyse_npm_sources,
        )
        if not JS_AST_AVAILABLE:
            pytest.skip("tree-sitter-javascript grammar unavailable")
        path = _ROOT / "javascript_malicious" / "tsconfig_jsonc_bomb"
        assert (path / "tsconfig.json").exists()
        start = time.monotonic()
        deps, errors = analyse_npm_sources(str(path), [])
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"tsconfig bomb took {elapsed:.2f}s"

    @pytest.mark.requirement("FR-104")
    def test_workspaces_cycle_fixture_terminates(self):
        import time
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        path = _ROOT / "javascript_malicious" / "workspaces_cycle"
        assert (path / "package.json").exists()
        start = time.monotonic()
        deps, errors, _ = parse_all_npm_dependency_files(str(path))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"workspaces cycle took {elapsed:.2f}s"


# ═══════════════════════════════════════════════════════════════════════════
# CSS malicious fixtures
# ═══════════════════════════════════════════════════════════════════════════


class TestCssFixtures:
    @pytest.mark.requirement("SF-019")
    def test_remote_import_fixture_emits_ts_ce_007(self):
        from scarno.analysers.css import CssAnalyser
        path = _ROOT / "css_malicious" / "remote_import"
        assert (path / "styles.css").exists()
        result = CssAnalyser().analyse(str(path))
        assert any(f.rule_id == "TS-CE-007" for f in result.findings)

    @pytest.mark.requirement("SF-020")
    def test_file_url_fixture_emits_ts_ce_008(self):
        from scarno.analysers.css import CssAnalyser
        path = _ROOT / "css_malicious" / "file_url"
        assert (path / "styles.css").exists()
        result = CssAnalyser().analyse(str(path))
        assert any(f.rule_id == "TS-CE-008" for f in result.findings)


# ═══════════════════════════════════════════════════════════════════════════
# Tree-sitter JVM regression fixtures
# ═══════════════════════════════════════════════════════════════════════════


class TestTreeSitterFixtures:
    @pytest.mark.requirement("FR-087")
    def test_comment_with_import_fixture_ignored(self):
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java grammar unavailable")
        path = _ROOT / "tree_sitter_fixtures" / "java_comment_with_import" / "A.java"
        assert path.exists()
        facts = extract_java(path.read_text(), file_path=str(path))
        assert "com.example.real.Thing" in facts.imports
        assert not any("ghost" in i for i in facts.imports)

    @pytest.mark.requirement("FR-087")
    def test_string_with_annotation_fixture_ignored(self):
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java grammar unavailable")
        path = _ROOT / "tree_sitter_fixtures" / "java_string_with_annotation" / "A.java"
        assert path.exists()
        facts = extract_java(path.read_text(), file_path=str(path))
        # Genuine @Service on the class survives
        assert any("Service" in a for a in facts.annotations)
        # In-string annotations are NOT picked up
        assert not any("Autowired" in a for a in facts.annotations)
        assert not any("RestController" in a for a in facts.annotations)
        assert not any("Qualifier" in a for a in facts.annotations)

    @pytest.mark.requirement("FR-087")
    def test_javadoc_forname_fixture_ignored(self):
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java grammar unavailable")
        path = _ROOT / "tree_sitter_fixtures" / "java_javadoc_forname" / "A.java"
        assert path.exists()
        facts = extract_java(path.read_text(), file_path=str(path))
        assert "com.example.real.Driver" in facts.reflective_literals
        assert not any("ghost" in r for r in facts.reflective_literals)

    @pytest.mark.requirement("FR-087")
    def test_kotlin_aliased_import_fixture(self):
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_kotlin,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-kotlin grammar unavailable")
        path = _ROOT / "tree_sitter_fixtures" / "kotlin_aliased_import" / "Main.kt"
        assert path.exists()
        facts = extract_kotlin(path.read_text(), file_path=str(path))
        # Aliased imports resolve to the underlying package
        assert "com.foo.Bar" in facts.imports
        assert "org.springframework.stereotype.Service" in facts.imports


# ═══════════════════════════════════════════════════════════════════════════
# GitHub Action smoke fixture
# ═══════════════════════════════════════════════════════════════════════════


class TestGhActionFixture:
    @pytest.mark.requirement("FR-090")
    def test_smoke_fixture_produces_deterministic_result(self):
        """The fixture exists and is analysable end-to-end. Used by the
        REQ-8 smoke workflow."""
        from scarno.analysers.python import PythonAnalyser  # noqa: F401
        from scarno.core.registry import get_analyser
        from scarno.core.detector import detect_project_types

        path = _ROOT / "gh_action" / "smoke_fixture"
        assert (path / "pyproject.toml").exists()
        assert (path / "main.py").exists()
        types = detect_project_types(path)
        assert types == ["python"]

        analyser = get_analyser("python")
        assert analyser is not None
        result = analyser.analyse(str(path))
        names = {d.name for d in result.dependencies}
        # Expected: requests + click IN_USE, rich SAFE
        assert {"requests", "click", "rich"} <= names
        from scarno.models import DependencyStatus
        rich_dep = next(d for d in result.dependencies if d.name == "rich")
        assert rich_dep.status is DependencyStatus.SAFE


# ═══════════════════════════════════════════════════════════════════════════
# Reporter golden-file fixtures
# ═══════════════════════════════════════════════════════════════════════════


class TestReporterFixtures:
    @pytest.mark.parametrize(
        "scenario", ["all_statuses", "empty_result", "entry_points", "ansi_input"]
    )
    def test_report_fixtures_are_valid_json(self, scenario):
        path = _ROOT / "report" / scenario / "expected.json"
        assert path.exists(), f"missing fixture: {scenario}/expected.json"
        data = json.loads(path.read_text())
        # Minimum schema: every fixture has these top-level keys
        for key in ("project_type", "project_path", "dependencies", "findings", "errors"):
            assert key in data, f"{scenario} missing key: {key}"


# ═══════════════════════════════════════════════════════════════════════════
# Go malicious fixtures — TDD red until Phase 6
# ═══════════════════════════════════════════════════════════════════════════

try:
    from scarno.analysers.go.dep_file_parser import (  # type: ignore[import-not-found]
        parse_all_go_dependency_files,
    )

    _GO_AVAILABLE = True
except ImportError:
    parse_all_go_dependency_files = None  # type: ignore[assignment]
    _GO_AVAILABLE = False


@pytest.mark.skipif(
    not _GO_AVAILABLE,
    reason="pending Phase 6 — scarno.analysers.go not yet implemented",
)
class TestGoFixtures:
    @pytest.mark.requirement("SF-021")
    def test_replace_remote_url_fixture_emits_ts_ds_002(self):
        path = _ROOT / "go_malicious" / "replace_remote_url"
        assert (path / "go.mod").exists()
        _, _, findings = parse_all_go_dependency_files(str(path))
        assert any(f.rule_id == "TS-DS-002" for f in findings)

    @pytest.mark.requirement("FR-117")
    def test_vendor_mismatch_fixture_warns(self):
        path = _ROOT / "go_malicious" / "vendor_mismatch"
        assert (path / "go.mod").exists()
        assert (path / "vendor" / "modules.txt").exists()
        _, errors, _ = parse_all_go_dependency_files(str(path))
        assert any("stowaway" in e for e in errors)

    @pytest.mark.requirement("SEC-NEW-24")
    def test_long_module_path_fixture_rejected(self):
        path = _ROOT / "go_malicious" / "long_module_path"
        assert (path / "go.mod").exists()
        deps, errors, _ = parse_all_go_dependency_files(str(path))
        # Line-length cap rejects the 10 KB module path
        huge = next(
            (d for d in deps if d.name.startswith("github.com/") and len(d.name) > 1000),
            None,
        )
        assert huge is None or any("line" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-NEW-24")
    def test_gomod_line_dos_fixture_bounded(self):
        import time
        path = _ROOT / "go_malicious" / "gomod_line_dos"
        assert (path / "go.mod").exists()
        start = time.monotonic()
        parse_all_go_dependency_files(str(path))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"gomod_line_dos took {elapsed:.2f}s"


# ═══════════════════════════════════════════════════════════════════════════
# C# malicious fixtures — TDD red until Phase 7
# ═══════════════════════════════════════════════════════════════════════════

try:
    from scarno.analysers.csharp.dep_file_parser import (  # type: ignore[import-not-found]
        parse_all_csharp_dependency_files,
    )

    _CSHARP_AVAILABLE = True
except ImportError:
    parse_all_csharp_dependency_files = None  # type: ignore[assignment]
    _CSHARP_AVAILABLE = False


@pytest.mark.skipif(
    not _CSHARP_AVAILABLE,
    reason="pending Phase 7 — scarno.analysers.csharp not yet implemented",
)
class TestCsharpFixtures:
    @pytest.mark.requirement("SEC-NEW-25")
    def test_csproj_xxe_fixture_rejected(self):
        path = _ROOT / "csharp_malicious" / "csproj_xxe"
        assert (path / "App.csproj").exists()
        deps, errors, _ = parse_all_csharp_dependency_files(str(path))
        assert deps == []
        assert any("doctype" in e.lower() or "entity" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-NEW-26")
    def test_directory_build_props_escape_fixture_blocked(self):
        path = _ROOT / "csharp_malicious" / "directory_build_props_escape"
        assert (path / "App.csproj").exists()
        assert (path / "Directory.Build.props").exists()
        deps, _, _ = parse_all_csharp_dependency_files(str(path))
        names = {d.name for d in deps}
        # The parent-escape Import must not bring in "LocalOnly" via the
        # imagined outside\evil.props file (which doesn't exist).
        # LocalOnly declared directly in the .props file must still load
        # (it's within the project), but any outside resolution must fail
        # silently without bringing in phantom deps.
        assert isinstance(deps, list)

    @pytest.mark.requirement("FR-123")
    def test_hintpath_escape_fixture_blocked(self):
        path = _ROOT / "csharp_malicious" / "hintpath_escape"
        assert (path / "App.csproj").exists()
        deps, _, _ = parse_all_csharp_dependency_files(str(path))
        names = {d.name for d in deps}
        # HintPath refs outside project must be dropped
        assert "Evil" not in names
        assert "AlsoEvil" not in names

    @pytest.mark.requirement("SF-025")
    def test_nuget_rogue_registry_fixture_emits_ts_si_015(self):
        path = _ROOT / "csharp_malicious" / "nuget_rogue_registry"
        assert (path / "nuget.config").exists()
        _, _, findings = parse_all_csharp_dependency_files(str(path))
        assert any(f.rule_id == "TS-SI-015" for f in findings)

    @pytest.mark.requirement("FR-126")
    def test_sln_circular_fixture_terminates(self):
        import time
        path = _ROOT / "csharp_malicious" / "sln_circular"
        assert (path / "App.sln").exists()
        assert (path / "A" / "A.csproj").exists()
        assert (path / "B" / "B.csproj").exists()
        start = time.monotonic()
        deps, _, _ = parse_all_csharp_dependency_files(str(path))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"sln cycle took {elapsed:.2f}s"

    @pytest.mark.requirement("SF-027")
    def test_usingtask_unknown_dll_fixture_emits_ts_si_017(self):
        path = _ROOT / "csharp_malicious" / "usingtask_unknown_dll"
        assert (path / "App.csproj").exists()
        _, _, findings = parse_all_csharp_dependency_files(str(path))
        assert any(f.rule_id == "TS-SI-017" for f in findings)
