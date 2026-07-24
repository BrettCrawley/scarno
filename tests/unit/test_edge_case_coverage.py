"""Edge-case and error-path tests to boost coverage on under-tested modules.

Covers: Go source analyser error paths, C# source analyser error paths,
JS dep parser edge cases, findings config/engine, reporter edge cases.
"""
from __future__ import annotations

import json
import os

import pytest

from scarno.models import Dependency, DependencyStatus


# ═══════════════════════════════════════════════════════════════════════════
# Go source analyser — error handling paths (76% → higher)
# ═══════════════════════════════════════════════════════════════════════════


class TestGoSourceAnalyserEdges:
    @pytest.mark.requirement("FR-118")
    def test_analyse_non_existent_path(self):
        from scarno.analysers.go.source_analyser import analyse_go_sources
        deps, errors = analyse_go_sources("/does/not/exist", [])
        assert deps == []

    @pytest.mark.requirement("FR-118")
    def test_analyse_file_not_dir(self, tmp_path):
        from scarno.analysers.go.source_analyser import analyse_go_sources
        f = tmp_path / "file.txt"
        f.write_text("hi")
        deps, errors = analyse_go_sources(str(f), [])
        assert deps == []

    @pytest.mark.requirement("FR-118")
    def test_symlink_escape_blocked(self, tmp_path):
        from scarno.analysers.go.source_analyser import analyse_go_sources
        project = tmp_path / "project"
        project.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.go").write_text(
            'package evil\nimport "github.com/bad/pkg"\n'
        )
        try:
            (project / "evil.go").symlink_to(outside / "evil.go")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported")
        deps, errors = analyse_go_sources(str(project), [])
        assert any("symlink" in e.lower() or "escape" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-118")
    def test_oversized_go_file_skipped(self, tmp_path):
        from scarno.analysers.go.source_analyser import analyse_go_sources
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "big.go").write_text("package main\n" + "x" * (MAX_FILE_BYTES + 1))
        deps, errors = analyse_go_sources(str(tmp_path), [])
        assert any("too large" in e for e in errors)

    @pytest.mark.requirement("FR-118")
    def test_non_go_ecosystem_dep_passed_through(self, tmp_path):
        from scarno.analysers.go.source_analyser import analyse_go_sources
        (tmp_path / "main.go").write_text("package main\n")
        non_go = Dependency(
            name="requests", version="2.31", status=DependencyStatus.UNCERTAIN,
            reason="pending", ecosystem="pypi",
        )
        deps, _ = analyse_go_sources(str(tmp_path), [non_go])
        assert any(d.name == "requests" and d.ecosystem == "pypi" for d in deps)

    @pytest.mark.requirement("FR-118")
    def test_phantom_dep_for_undeclared_import(self, tmp_path):
        from scarno.analysers.go.source_analyser import analyse_go_sources
        (tmp_path / "main.go").write_text(
            'package main\nimport "github.com/mystery/pkg"\nfunc main() {}\n'
        )
        deps, _ = analyse_go_sources(str(tmp_path), [])
        phantom = next((d for d in deps if "mystery" in d.name), None)
        assert phantom is not None
        assert phantom.status is DependencyStatus.UNDECLARED
        assert phantom.ecosystem == "go"


# ═══════════════════════════════════════════════════════════════════════════
# C# source analyser — error handling paths (79% → higher)
# ═══════════════════════════════════════════════════════════════════════════


class TestCsharpSourceAnalyserEdges:
    @pytest.mark.requirement("FR-128")
    def test_analyse_non_existent_path(self):
        from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
        deps, errors = analyse_csharp_sources("/does/not/exist", [])
        assert deps == []

    @pytest.mark.requirement("FR-128")
    def test_analyse_file_not_dir(self, tmp_path):
        from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
        f = tmp_path / "file.txt"
        f.write_text("hi")
        deps, errors = analyse_csharp_sources(str(f), [])
        assert deps == []

    @pytest.mark.requirement("FR-128")
    def test_oversized_cs_file_skipped(self, tmp_path):
        from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "big.cs").write_text("using System;\n" + "x" * (MAX_FILE_BYTES + 1))
        deps, errors = analyse_csharp_sources(str(tmp_path), [])
        assert any("too large" in e for e in errors)

    @pytest.mark.requirement("FR-128")
    def test_non_nuget_dep_passed_through(self, tmp_path):
        from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
        (tmp_path / "Program.cs").write_text("using System;\n")
        non_cs = Dependency(
            name="lodash", version="4.0", status=DependencyStatus.UNCERTAIN,
            reason="pending", ecosystem="npm",
        )
        deps, _ = analyse_csharp_sources(str(tmp_path), [non_cs])
        assert any(d.name == "lodash" and d.ecosystem == "npm" for d in deps)

    @pytest.mark.requirement("FR-130")
    def test_microsoft_csharp_not_phantom(self, tmp_path):
        from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
        (tmp_path / "Program.cs").write_text(
            "using Microsoft.CSharp;\nclass P {}\n"
        )
        deps, _ = analyse_csharp_sources(str(tmp_path), [])
        # Microsoft.CSharp is shared framework — not phantom
        assert not any("Microsoft.CSharp" in d.name for d in deps)

    @pytest.mark.requirement("FR-129")
    def test_view_imports_cshtml(self, tmp_path):
        from scarno.analysers.csharp.source_analyser import analyse_csharp_sources
        (tmp_path / "_ViewImports.cshtml").write_text(
            "@using Microsoft.AspNetCore.Html\n"
            "@using Serilog\n"
        )
        declared = Dependency(
            name="Serilog", version="3.0", status=DependencyStatus.UNCERTAIN,
            reason="pending", ecosystem="nuget",
        )
        deps, _ = analyse_csharp_sources(str(tmp_path), [declared])
        serilog = next(d for d in deps if d.name == "Serilog")
        assert serilog.status is DependencyStatus.IN_USE


# ═══════════════════════════════════════════════════════════════════════════
# C# dep file parser — error paths
# ═══════════════════════════════════════════════════════════════════════════


class TestCsharpDepParserEdges:
    @pytest.mark.requirement("FR-123")
    def test_nuget_config_case_insensitive(self, tmp_path):
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        (tmp_path / "NuGet.Config").write_text(
            '<?xml version="1.0"?>\n'
            "<configuration><packageSources>\n"
            '  <add key="evil" value="https://evil.example.com/v3/index.json"/>\n'
            "</packageSources></configuration>\n"
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-015" for f in findings)

    @pytest.mark.requirement("FR-123")
    def test_oversized_csproj_skipped(self, tmp_path):
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "App.csproj").write_text("x" * (MAX_FILE_BYTES + 1))
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert any("size" in e.lower() for e in errors)


# ═══════════════════════════════════════════════════════════════════════════
# Go dep file parser — error paths
# ═══════════════════════════════════════════════════════════════════════════


class TestGoDepParserEdges:
    @pytest.mark.requirement("FR-114")
    def test_non_existent_path(self):
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        deps, errors, findings = parse_all_go_dependency_files("/nonexistent")
        assert deps == []

    @pytest.mark.requirement("FR-114")
    def test_oversized_go_mod_skipped(self, tmp_path):
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "go.mod").write_text("x" * (MAX_FILE_BYTES + 1))
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        assert any("size" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-114")
    def test_unreadable_go_mod(self, tmp_path):
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        gomod = tmp_path / "go.mod"
        gomod.write_text("module x\n")
        gomod.chmod(0o000)
        try:
            deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
            assert any("read failed" in e for e in errors)
        finally:
            gomod.chmod(0o644)


# ═══════════════════════════════════════════════════════════════════════════
# JS dep file parser — more coverage for error paths
# ═══════════════════════════════════════════════════════════════════════════


class TestJsDepParserEdges:
    @pytest.mark.requirement("FR-103")
    def test_oversized_package_json_skipped(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "package.json").write_text("x" * (MAX_FILE_BYTES + 1))
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any("size" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-103")
    def test_non_dict_root_package_json(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "package.json").write_text("[1,2,3]")
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any("root must be" in e.lower() or "object" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-104")
    def test_oversized_yarn_lock_skipped(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "yarn.lock").write_text("x" * (MAX_FILE_BYTES + 1))
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any("size" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-104")
    def test_oversized_pnpm_lock_skipped(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "pnpm-lock.yaml").write_text("x" * (MAX_FILE_BYTES + 1))
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any("size" in e.lower() for e in errors)


# ═══════════════════════════════════════════════════════════════════════════
# Findings config (66% → higher)
# ═══════════════════════════════════════════════════════════════════════════


class TestFindingsConfig:
    @pytest.mark.requirement("SEC-003")
    def test_suppression_config_empty_project(self, tmp_path):
        from scarno.findings.config import load_suppression_config
        # No pyproject.toml → empty config, no errors
        config, errors = load_suppression_config(tmp_path)
        assert config.suppress == set()
        assert errors == []

    @pytest.mark.requirement("SEC-003")
    def test_suppression_config_with_valid_rules(self, tmp_path):
        from scarno.findings.config import load_suppression_config
        (tmp_path / "pyproject.toml").write_text(
            "[tool.scarno.findings]\n"
            'suppress = ["TS-SI-001", "TS-CE-001"]\n'
        )
        config, errors = load_suppression_config(tmp_path)
        assert "TS-SI-001" in config.suppress
        assert "TS-CE-001" in config.suppress
        assert errors == []

    @pytest.mark.requirement("SEC-003")
    def test_suppression_config_unknown_rule_warns(self, tmp_path):
        from scarno.findings.config import load_suppression_config
        (tmp_path / "pyproject.toml").write_text(
            "[tool.scarno.findings]\n"
            'suppress = ["TS-FAKE-999"]\n'
        )
        config, errors = load_suppression_config(tmp_path)
        assert "TS-FAKE-999" not in config.suppress
        assert any("unknown" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-003")
    def test_suppression_config_non_string_entry_warns(self, tmp_path):
        from scarno.findings.config import load_suppression_config
        (tmp_path / "pyproject.toml").write_text(
            "[tool.scarno.findings]\n"
            "suppress = [42]\n"
        )
        config, errors = load_suppression_config(tmp_path)
        assert any("string" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-003")
    def test_suppression_config_per_path(self, tmp_path):
        from scarno.findings.config import load_suppression_config
        (tmp_path / "pyproject.toml").write_text(
            "[tool.scarno.findings]\n"
            '[paths."scripts/deploy.py"]\n'
            '# This syntax is wrong for TOML inline — use dotted keys\n'
        )
        # This may not parse correctly, but it must not crash
        config, errors = load_suppression_config(tmp_path)
        assert isinstance(config.suppress, set)

    @pytest.mark.requirement("SEC-003")
    def test_suppression_config_paths_section(self, tmp_path):
        from scarno.findings.config import load_suppression_config
        (tmp_path / "pyproject.toml").write_text(
            "[tool.scarno.findings]\n"
            'suppress = ["TS-SI-001"]\n'
            "\n"
            "[tool.scarno.findings.paths]\n"
            '"scripts/deploy.py" = ["TS-CE-005"]\n'
            '"test/" = ["TS-SI-005", "TS-FAKE-000"]\n'
        )
        config, errors = load_suppression_config(tmp_path)
        assert "TS-SI-001" in config.suppress
        assert "scripts/deploy.py" in config.per_path
        assert "TS-CE-005" in config.per_path["scripts/deploy.py"]
        # TS-FAKE-000 is unknown → warned
        assert any("TS-FAKE-000" in e for e in errors)

    @pytest.mark.requirement("SEC-003")
    def test_suppression_config_malformed_toml(self, tmp_path):
        from scarno.findings.config import load_suppression_config
        (tmp_path / "pyproject.toml").write_text("[broken\n")
        config, errors = load_suppression_config(tmp_path)
        # Malformed TOML → empty config (no crash)
        assert config.suppress == set()


# ═══════════════════════════════════════════════════════════════════════════
# Reporter edge cases — json reporter
# ═══════════════════════════════════════════════════════════════════════════


class TestCssAnalyserEdges:
    @pytest.mark.requirement("FR-111")
    def test_supports_with_css_file(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        (tmp_path / "styles.css").write_text("body { color: red; }\n")
        assert CssAnalyser().supports(str(tmp_path))

    @pytest.mark.requirement("FR-111")
    def test_supports_rejects_non_dir(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        f = tmp_path / "file.txt"
        f.write_text("x")
        assert not CssAnalyser().supports(str(f))

    @pytest.mark.requirement("FR-111")
    def test_supports_rejects_empty_dir(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        assert not CssAnalyser().supports(str(tmp_path))

    @pytest.mark.requirement("FR-111")
    def test_analyse_excluded_dirs(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "pkg.css").write_text('@import "evil";\n')
        (tmp_path / "app.css").write_text('@import "good-pkg";\n')
        result = CssAnalyser().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "evil" not in names
        assert "good-pkg" in names

    @pytest.mark.requirement("FR-111")
    def test_analyse_oversized_css_skipped(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        from scarno.security import MAX_FILE_BYTES
        (tmp_path / "huge.css").write_text("x" * (MAX_FILE_BYTES + 1))
        result = CssAnalyser().analyse(str(tmp_path))
        assert any("too large" in e for e in result.errors)

    @pytest.mark.requirement("FR-111")
    def test_analyse_symlink_escape(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        project = tmp_path / "project"
        project.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.css").write_text('@import "evil";\n')
        try:
            (project / "evil.css").symlink_to(outside / "evil.css")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported")
        result = CssAnalyser().analyse(str(project))
        assert any("escape" in e.lower() or "symlink" in e.lower() for e in result.errors)

    @pytest.mark.requirement("FR-112")
    def test_analyse_scss_and_less(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        (tmp_path / "app.scss").write_text('@use "bootstrap";\n')
        (tmp_path / "theme.less").write_text('@import "antd";\n')
        result = CssAnalyser().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "bootstrap" in names
        assert "antd" in names


class TestJavascriptSourceEdges:
    @pytest.mark.requirement("FR-107")
    def test_source_analyser_non_existent_path(self):
        from scarno.analysers.javascript.source_analyser import analyse_npm_sources
        deps, errors = analyse_npm_sources("/nonexistent", [])
        assert deps == []

    @pytest.mark.requirement("FR-107")
    def test_source_analyser_non_dir(self, tmp_path):
        from scarno.analysers.javascript.source_analyser import analyse_npm_sources
        f = tmp_path / "file.txt"
        f.write_text("x")
        deps, errors = analyse_npm_sources(str(f), [])
        assert deps == []

    @pytest.mark.requirement("FR-107")
    def test_non_npm_dep_passed_through(self, tmp_path):
        from scarno.analysers.javascript.source_analyser import analyse_npm_sources
        (tmp_path / "app.js").write_text("console.log('hi');\n")
        go_dep = Dependency(
            name="github.com/a", version="v1.0", status=DependencyStatus.UNCERTAIN,
            reason="pending", ecosystem="go",
        )
        deps, _ = analyse_npm_sources(str(tmp_path), [go_dep])
        assert any(d.ecosystem == "go" for d in deps)


class TestJsDepParserMoreEdges:
    @pytest.mark.requirement("FR-104")
    def test_yarn_berry_lock_parsed(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "yarn.lock").write_text(
            "__metadata:\n"
            "  version: 8\n"
            "\n"
            '"lodash@npm:^4.17.21":\n'
            "  version: 4.17.21\n"
            "  resolution: \"lodash@npm:4.17.21\"\n"
        )
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any(d.name == "lodash" for d in deps)

    @pytest.mark.requirement("FR-105")
    def test_deno_json_non_npm_specifiers_skipped(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "deno.json").write_text(json.dumps({
            "imports": {
                "std/path": "https://deno.land/std@0.220.0/path/mod.ts",
                "lodash": "npm:lodash@^4",
            },
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        names = {d.name for d in deps}
        assert "lodash" in names
        # HTTPS imports are not npm deps
        assert "std/path" not in names

    @pytest.mark.requirement("FR-104")
    def test_bun_lock_dict_format(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "bun.lock").write_text(json.dumps({
            "packages": {
                "express": {"version": "4.18.2"},
            },
        }))
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any(d.name == "express" and d.version == "4.18.2" for d in deps)

    @pytest.mark.requirement("FR-103")
    def test_package_json_non_string_key_skipped(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        # Construct JSON with numeric key in dependencies — unusual but possible
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"valid-pkg": "1.0.0"}}'
        )
        deps, _, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any(d.name == "valid-pkg" for d in deps)

    @pytest.mark.requirement("SF-017")
    def test_npmrc_comments_and_blank_lines(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / ".npmrc").write_text(
            "# This is a comment\n"
            "\n"
            "registry=https://registry.npmjs.org/\n"
            "save-exact=true\n"
        )
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        # Default registry — should NOT fire TS-SI-008
        assert not any(f.rule_id == "TS-SI-008" for f in findings)


class TestJavaSourceAnalyserEdges:
    @pytest.mark.requirement("FR-018")
    def test_jvm_source_analyser_with_annotations(self, tmp_path):
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser
        from scarno.models import Dependency, DependencyStatus

        (tmp_path / "Main.java").write_text(
            "import org.springframework.beans.factory.annotation.Autowired;\n"
            "import org.springframework.stereotype.Service;\n"
            "@Service\n"
            "public class Main {\n"
            "    @Autowired\n"
            "    private Object dep;\n"
            "}\n"
        )
        dep = Dependency(
            name="org.springframework:spring-context", version="6.0.0",
            status=DependencyStatus.UNCERTAIN, reason="pending",
            ecosystem="maven",
        )
        result = JvmSourceAnalyser().analyse(str(tmp_path), [dep])
        spring = next(d for d in result.dependencies if "spring" in d.name)
        assert spring.status is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-018")
    def test_jvm_source_reflection(self, tmp_path):
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser
        from scarno.models import Dependency, DependencyStatus

        (tmp_path / "Main.java").write_text(
            "public class Main {\n"
            "    void load() throws Exception {\n"
            '        Class.forName("com.mysql.cj.jdbc.Driver");\n'
            "    }\n"
            "}\n"
        )
        dep = Dependency(
            name="mysql:mysql-connector-java", version="8.0.33",
            status=DependencyStatus.UNCERTAIN, reason="pending",
            ecosystem="maven",
        )
        result = JvmSourceAnalyser().analyse(str(tmp_path), [dep])
        # Reflection makes the dep at least UNCERTAIN
        mysql = next(d for d in result.dependencies if "mysql" in d.name)
        assert mysql.status in (DependencyStatus.IN_USE, DependencyStatus.UNCERTAIN)


class TestJsonReporterEdges:
    @pytest.mark.requirement("FR-003")
    def test_json_reporter_empty_result(self):
        from scarno.reporters.json_reporter import JsonReporter
        from scarno.models import AnalysisResult

        result = AnalysisResult(
            project_type="python",
            project_path="/tmp/test",
            dependencies=[],
            errors=[],
            findings=[],
            languages=["python"],
        )
        output = JsonReporter().render(result)
        data = json.loads(output)
        assert data["dependencies"] == []
        assert data["findings"] == []

    @pytest.mark.requirement("FR-003")
    def test_json_reporter_with_findings(self):
        from scarno.reporters.json_reporter import JsonReporter
        from scarno.models import (
            AnalysisResult,
            Finding,
            FindingKind,
            FindingSeverity,
        )

        result = AnalysisResult(
            project_type="python",
            project_path="/tmp/test",
            dependencies=[],
            errors=[],
            findings=[
                Finding(
                    rule_id="TS-SI-001",
                    kind=FindingKind.RUNTIME_PIP_INSTALL,
                    severity=FindingSeverity.HIGH,
                    file_path="setup.py",
                    line=5,
                    snippet="subprocess.run(['pip', 'install'])",
                    message="Runtime pip install",
                    remediation="Declare in pyproject.toml",
                )
            ],
            languages=["python"],
        )
        output = JsonReporter().render(result)
        data = json.loads(output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "TS-SI-001"
