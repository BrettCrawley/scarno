"""Resource bound tests — memory and time limits on realistic project sizes."""
from __future__ import annotations

import json
import resource
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.performance


# ═══════════════════════════════════════════════════════════════════════════
# Existing time-bound tests (Phase 0 → 2)
# ═══════════════════════════════════════════════════════════════════════════


class TestTimeBounds:
    @pytest.mark.requirement("PERF-001")
    def test_requirements_txt_100_deps_parses_fast(self, tmp_path):
        lines = "\n".join(f"package{i}==1.{i}.0" for i in range(100))
        (tmp_path / "requirements.txt").write_text(lines)
        from scarno.analysers.python.dep_file_parser import parse_all_dependency_files

        start = time.monotonic()
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"100-dep parse took {elapsed:.2f}s"
        assert len(deps) == 100

    @pytest.mark.requirement("PERF-002")
    @pytest.mark.requirement("SEC-012")
    def test_javap_timeout_respected(self, tmp_path):
        import shutil

        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        if shutil.which("javap") is None:
            pytest.skip("javap not available")
        analyser = JvmSourceAnalyser()
        start = time.monotonic()
        analyser._invoke_javap_safe(Path("/dev/null"), "com.example.NonExistent")
        elapsed = time.monotonic() - start
        assert elapsed < 11.0, f"javap invocation exceeded 11s: {elapsed:.1f}s"


# ═══════════════════════════════════════════════════════════════════════════
# Phase 5 — JS/TS/Node.js time bounds
# ═══════════════════════════════════════════════════════════════════════════


class TestJsTimeBounds:
    @pytest.mark.requirement("PERF-003")
    def test_package_lock_json_5000_deps_parses_fast(self, tmp_path):
        """A 5,000-dep ``package-lock.json`` must parse in < 2 s."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        packages = {"": {"dependencies": {}}}
        for i in range(5000):
            packages[f"node_modules/pkg{i}"] = {"version": f"1.{i}.0"}
        data = {"lockfileVersion": 3, "packages": packages}
        (tmp_path / "package-lock.json").write_text(json.dumps(data))

        start = time.monotonic()
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"5k-dep parse took {elapsed:.2f}s"
        assert len(deps) >= 4000  # some dedup may happen

    @pytest.mark.requirement("PERF-003")
    def test_yarn_lock_v1_large_parses_fast(self, tmp_path):
        """yarn v1 ``yarn.lock`` with 5,000 entries must parse in < 2 s."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        lines = ["# yarn lockfile v1\n"]
        for i in range(5000):
            lines.append(f'"pkg{i}@^1.0.0":\n  version "1.{i}.0"\n\n')
        (tmp_path / "yarn.lock").write_text("".join(lines))

        start = time.monotonic()
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"5k-entry yarn.lock took {elapsed:.2f}s"
        assert len(deps) >= 4000

    @pytest.mark.requirement("PERF-003")
    def test_pnpm_lock_yaml_large_parses_fast(self, tmp_path):
        """``pnpm-lock.yaml`` with 5,000 deps must parse in < 2 s."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        deps_section = {f"pkg{i}": f"1.{i}.0" for i in range(5000)}
        content = (
            'lockfileVersion: "6.0"\n'
            "importers:\n"
            "  .:\n"
            "    dependencies:\n"
        )
        for name, ver in list(deps_section.items())[:5000]:
            content += f"      {name}:\n        version: {ver}\n"
        (tmp_path / "pnpm-lock.yaml").write_text(content)

        start = time.monotonic()
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"5k-dep pnpm took {elapsed:.2f}s"
        assert len(deps) >= 4000


# ═══════════════════════════════════════════════════════════════════════════
# Phase 6 — Go time bounds
# ═══════════════════════════════════════════════════════════════════════════


class TestGoTimeBounds:
    @pytest.mark.requirement("PERF-004")
    def test_go_sum_10k_lines_parses_fast(self, tmp_path):
        """``go.sum`` with 10,000 module entries parses in < 1 s."""
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        lines = [f"module x\n\ngo 1.22\n\n"]
        (tmp_path / "go.mod").write_text(lines[0])
        sum_lines = []
        for i in range(10000):
            sum_lines.append(
                f"github.com/example/pkg{i} v1.{i}.0 h1:abc{i}=\n"
            )
        (tmp_path / "go.sum").write_text("".join(sum_lines))

        start = time.monotonic()
        parse_all_go_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"10k-line go.sum took {elapsed:.2f}s"

    @pytest.mark.requirement("PERF-004")
    def test_go_mod_500_require_parses_fast(self, tmp_path):
        """``go.mod`` with 500 ``require`` entries parses in < 0.5 s."""
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        requires = "\n".join(
            f"    github.com/example/pkg{i} v1.{i}.0"
            for i in range(500)
        )
        (tmp_path / "go.mod").write_text(
            f"module example.com/big\n\ngo 1.22\n\nrequire (\n{requires}\n)\n"
        )

        start = time.monotonic()
        deps, _, _ = parse_all_go_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, f"500-require go.mod took {elapsed:.2f}s"
        assert len(deps) == 500


# ═══════════════════════════════════════════════════════════════════════════
# Phase 7 — C# time bounds
# ═══════════════════════════════════════════════════════════════════════════


class TestCsharpTimeBounds:
    @pytest.mark.requirement("PERF-005")
    def test_sln_100_projects_parses_fast(self, tmp_path):
        """A 100-project ``*.sln`` parses in < 2 s."""
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        sln_lines = [
            "Microsoft Visual Studio Solution File, Format Version 12.00\n"
        ]
        for i in range(100):
            proj_dir = tmp_path / f"proj{i}"
            proj_dir.mkdir()
            (proj_dir / f"P{i}.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                "  <ItemGroup>\n"
                f'    <PackageReference Include="Pkg{i}" Version="1.0.{i}"/>\n'
                "  </ItemGroup>\n"
                "</Project>\n"
            )
            sln_lines.append(
                f'Project("{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}") = "P{i}", '
                f'"proj{i}\\P{i}.csproj", '
                f'"{{{i:08d}-0000-0000-0000-000000000000}}"\n'
                "EndProject\n"
            )
        (tmp_path / "App.sln").write_text("".join(sln_lines))

        start = time.monotonic()
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"100-project sln took {elapsed:.2f}s"
        assert len(deps) == 100

    @pytest.mark.requirement("PERF-005")
    def test_csproj_large_package_reference_parses_fast(self, tmp_path):
        """A ``*.csproj`` with 500 `<PackageReference>` entries parses in < 1 s."""
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        refs = "\n".join(
            f'    <PackageReference Include="Pkg{i}" Version="1.0.{i}"/>'
            for i in range(500)
        )
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            f"  <ItemGroup>\n{refs}\n  </ItemGroup>\n"
            "</Project>\n"
        )

        start = time.monotonic()
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"500-ref csproj took {elapsed:.2f}s"
        assert len(deps) == 500


# ═══════════════════════════════════════════════════════════════════════════
# Cross-language tree-sitter time bound
# ═══════════════════════════════════════════════════════════════════════════


class TestTreeSitterTimeBound:
    @pytest.mark.requirement("PERF-006")
    def test_tree_sitter_per_file_timeout(self, tmp_path):
        """A 200 KB source file must parse in < 10 s across all tree-sitter
        languages."""
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE as JAVA_AST,
            extract_java,
        )
        from scarno.analysers.javascript.source_analyser import (
            JS_AST_AVAILABLE,
            analyse_npm_sources,
        )
        from scarno.analysers.go.source_analyser import (
            GO_AST_AVAILABLE,
        )
        from scarno.analysers.csharp.source_analyser import (
            CSHARP_AST_AVAILABLE,
        )

        # Java
        if JAVA_AST:
            java_src = "package p;\n" + ("class C { int x; }\n" * 5000)
            start = time.monotonic()
            extract_java(java_src, "big.java")
            assert time.monotonic() - start < 10.0

        # JavaScript
        if JS_AST_AVAILABLE:
            js_src = 'const x = require("lodash");\n' * 5000
            (tmp_path / "big.js").write_text(js_src)
            start = time.monotonic()
            analyse_npm_sources(str(tmp_path), [])
            assert time.monotonic() - start < 10.0

        # Go
        if GO_AST_AVAILABLE:
            go_src = 'package main\nimport "fmt"\n' + (
                "func f() { fmt.Println() }\n" * 5000
            )
            go_dir = tmp_path / "gotest"
            go_dir.mkdir()
            (go_dir / "main.go").write_text(go_src)
            from scarno.analysers.go.source_analyser import analyse_go_sources
            start = time.monotonic()
            analyse_go_sources(str(go_dir), [])
            assert time.monotonic() - start < 10.0

        # C#
        if CSHARP_AST_AVAILABLE:
            cs_src = "using System;\n" + (
                "class C { void M() {} }\n" * 5000
            )
            cs_dir = tmp_path / "cstest"
            cs_dir.mkdir()
            (cs_dir / "Program.cs").write_text(cs_src)
            from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
            start = time.monotonic()
            analyse_csharp_sources(str(cs_dir), [])
            assert time.monotonic() - start < 10.0


# ═══════════════════════════════════════════════════════════════════════════
# REQ-17 — ASCII tree render perf bound
# ═══════════════════════════════════════════════════════════════════════════


class TestAsciiTreeRenderPerf:
    @pytest.mark.requirement("PERF-007")
    def test_ascii_tree_render_under_200ms_for_1k_deps(self):
        from scarno.models import (
            AnalysisResult,
            Dependency,
            DependencyStatus,
        )
        from scarno.reporters.markdown_reporter import MarkdownReporter

        # 1000 deps + a non-trivial dep_graph (each parent has 2 children).
        deps = [
            Dependency(
                name=f"d{i:04d}", version=None,
                status=(
                    DependencyStatus.SAFE if i % 3 == 0
                    else DependencyStatus.UNCERTAIN if i % 3 == 1
                    else DependencyStatus.IN_USE
                ),
                reason="perf", source="lock", ecosystem="pypi",
            )
            for i in range(1000)
        ]
        graph: dict[str, set[str]] = {}
        for i in range(0, 999, 2):
            graph[f"d{i:04d}"] = {f"d{i + 1:04d}", f"d{(i + 2) % 1000:04d}"}
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
            dep_graph=graph,
        )
        start = time.monotonic()
        out = MarkdownReporter().render(result)
        elapsed = time.monotonic() - start
        assert "```diff" in out
        # Strict ceiling per spec: < 200 ms.
        assert elapsed < 0.2, f"ascii tree render took {elapsed:.3f}s"


# ═══════════════════════════════════════════════════════════════════════════
# Memory bounds
# ═══════════════════════════════════════════════════════════════════════════


class TestMemoryBounds:
    @pytest.mark.requirement("D-04")
    def test_10mb_file_not_loaded_into_memory(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        huge = project / "huge.py"
        huge.write_bytes(b"x = 1\n" * (10 * 1024 * 1024 // 6 + 1))
        from scarno.analysers.python.source_analyser import analyse_source_files
        from scarno.models import Dependency, DependencyStatus

        deps = [
            Dependency(
                "requests", None, DependencyStatus.UNCERTAIN, "pending", [], 0, 0
            )
        ]
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        try:
            analyse_source_files(str(project), deps)
        except NotImplementedError:
            pytest.skip("analyser not yet implemented (Phase 0a stub)")
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        delta_mb = (after - before) / 1024
        assert delta_mb < 50, f"Memory increased by {delta_mb:.1f} MB"


class TestJsMemoryBounds:
    @pytest.mark.requirement("SEC-NEW-20")
    def test_large_package_lock_not_loaded_fully(self, tmp_path):
        """5k-dep ``package-lock.json`` must not balloon RSS by > 200 MB."""
        import sys
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        packages = {}
        for i in range(5000):
            packages[f"node_modules/pkg{i}"] = {"version": f"1.{i}.0"}
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3, "packages": packages})
        )
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        parse_all_npm_dependency_files(str(tmp_path))
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # macOS reports bytes; Linux reports KB
        divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
        delta_mb = (after - before) / divisor
        assert delta_mb < 200, f"Memory increased by {delta_mb:.1f} MB"


class TestGoMemoryBounds:
    @pytest.mark.requirement("SEC-NEW-24")
    def test_large_gomod_not_loaded_fully(self, tmp_path):
        """``go.mod`` with a 10 MB whitespace-bombed require block must
        be rejected at the size cap."""
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        from scarno.security import MAX_FILE_BYTES
        # Build a go.mod that exceeds MAX_FILE_BYTES
        content = "module x\n\ngo 1.22\n\nrequire (\n"
        content += "    github.com/a v1.0.0" + (" " * (MAX_FILE_BYTES + 100)) + "\n"
        content += ")\n"
        (tmp_path / "go.mod").write_text(content)
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        assert any("size" in e.lower() for e in errors)


class TestCsharpMemoryBounds:
    @pytest.mark.requirement("SEC-NEW-25")
    def test_deeply_nested_csproj_not_stack_overflow(self, tmp_path):
        """1000-level nested ``*.csproj`` must not cause RecursionError."""
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        depth = 1000
        inner = "<x>" * depth + "<PackageReference Include='A' Version='1'/>" + "</x>" * depth
        (tmp_path / "App.csproj").write_text(
            f'<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>{inner}</ItemGroup></Project>'
        )
        # Must not crash — XML parser handles deep nesting gracefully
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert isinstance(deps, list)
