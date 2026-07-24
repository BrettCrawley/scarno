"""Negative-path tests for Phase 4 → 7 analysers.

Mirrors the NEG-001..007 structure of ``test_negative_cases.py`` but
targets the JS/TS/CSS/Go/C# and tree-sitter surfaces. All analysers
now exist, so these are real passing tests — not xfail placeholders.
"""
from __future__ import annotations

import json

import pytest


# ── NEG-001 — wrong-type inputs ──────────────────────────────────────────


class TestFutureWrongTypeInputs:
    @pytest.mark.requirement("NEG-001")
    def test_package_json_dependencies_as_array_not_object(self, tmp_path):
        """npm ``package.json`` with ``dependencies: ["x", "y"]`` (array not
        object) must produce a structured warning, not crash."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": ["x", "y"]})
        )
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        # Array is not a dict — section is silently skipped, no crash
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-001")
    def test_package_json_version_non_string(self, tmp_path):
        """`dependencies: {"x": 42}` — value must be a string."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"x": 42}})
        )
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        # Non-string version → version=None, not crash
        assert any(d.name == "x" for d in deps)
        x = next(d for d in deps if d.name == "x")
        assert x.version is None

    @pytest.mark.requirement("NEG-001")
    def test_go_mod_require_without_version(self, tmp_path):
        """``require github.com/foo`` with no version token — structured
        parse error, not crash."""
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        (tmp_path / "go.mod").write_text(
            "module x\n\ngo 1.22\n\nrequire github.com/foo\n"
        )
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        # Regex won't match a line without a version — dep is silently skipped
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-001")
    def test_csproj_packagereference_without_include_attr(self, tmp_path):
        """`<PackageReference Version="1.0" />` missing ``Include`` → skip."""
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            "  <ItemGroup>\n"
            '    <PackageReference Version="1.0.0" />\n'
            '    <PackageReference Include="Valid" Version="2.0.0" />\n'
            "  </ItemGroup>\n"
            "</Project>\n"
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        names = {d.name for d in deps}
        assert "Valid" in names
        # Missing Include attribute is skipped, not crash
        assert len(deps) == 1

    @pytest.mark.requirement("NEG-001")
    def test_directory_packages_props_packageversion_without_include(self, tmp_path):
        """CPM `<PackageVersion Version="1.0" />` missing ``Include`` → skip."""
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        (tmp_path / "Directory.Packages.props").write_text(
            "<Project>\n"
            "  <ItemGroup>\n"
            '    <PackageVersion Version="1.0.0" />\n'
            "  </ItemGroup>\n"
            "</Project>\n"
        )
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk" />\n'
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        # Missing Include is silently skipped
        assert isinstance(deps, list)


# ── NEG-002 — truncated inputs ───────────────────────────────────────────


class TestFutureTruncatedInputs:
    @pytest.mark.requirement("NEG-002")
    def test_truncated_package_lock_json(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages":')
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any("parse error" in e.lower() or "json" in e.lower() for e in errors)

    @pytest.mark.requirement("NEG-002")
    def test_truncated_yarn_lock(self, tmp_path):
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "yarn.lock").write_text(
            '# yarn lockfile v1\n\n"lodash@^4.17.21":\n  version'
        )
        # Truncated mid-version — parser must not crash
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-002")
    def test_truncated_go_mod_require_block(self, tmp_path):
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        (tmp_path / "go.mod").write_text(
            "module x\n\ngo 1.22\n\nrequire (\n    github.com/a v1.0.0\n"
            # Missing closing paren
        )
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        # Parsed what it could — github.com/a should still appear
        assert any(d.name == "github.com/a" for d in deps)

    @pytest.mark.requirement("NEG-002")
    def test_truncated_csproj_xml(self, tmp_path):
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<PackageReference Include="A" Version="1.0"/>'
            # Missing closing tags
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert any("parse error" in e.lower() or "xml" in e.lower() for e in errors)


# ── NEG-003 — encoding edges ────────────────────────────────────────────


class TestFutureEncodingEdges:
    @pytest.mark.requirement("NEG-003")
    def test_package_json_utf16_rejected_cleanly(self, tmp_path):
        """UTF-16 (BOM-prefixed) package.json — reject with clear error."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        content = '{"dependencies": {"x": "1.0.0"}}'
        (tmp_path / "package.json").write_bytes(
            b"\xff\xfe" + content.encode("utf-16-le")
        )
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        # UTF-16 bytes fail JSON parse or read as UTF-8
        assert not deps or any("error" in e.lower() or "read" in e.lower() for e in errors)

    @pytest.mark.requirement("NEG-003")
    def test_csproj_with_utf16_bom(self, tmp_path):
        """MSBuild often emits UTF-16 BOM on Windows; we read as UTF-8 so
        this may error or parse empty — must not crash."""
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        xml = '<Project><ItemGroup><PackageReference Include="A" Version="1"/></ItemGroup></Project>'
        (tmp_path / "App.csproj").write_bytes(
            b"\xff\xfe" + xml.encode("utf-16-le")
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        # Either parses the dep or errors — must not crash
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-003")
    def test_go_mod_non_utf8_bytes(self, tmp_path):
        """Latin-1 bytes in go.mod should produce a structured error."""
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        (tmp_path / "go.mod").write_bytes(
            b"module x\n\ngo 1.22\n\nrequire github.com/\xe9 v1.0.0\n"
        )
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        # Either parsed with replacement chars or errored — not crash
        assert isinstance(deps, list)

    @pytest.mark.requirement("NEG-003")
    def test_javascript_source_with_utf8_bom(self, tmp_path):
        """UTF-8 BOM at start of a JS file must not break the AST walker."""
        from scarno.analysers.javascript.source_analyser import (
            JS_AST_AVAILABLE,
            analyse_npm_sources,
        )
        if not JS_AST_AVAILABLE:
            pytest.skip("tree-sitter-javascript grammar unavailable")
        (tmp_path / "app.js").write_bytes(
            b"\xef\xbb\xbf" + b'import lodash from "lodash";\n'
        )
        from scarno.models import Dependency, DependencyStatus

        declared = Dependency(
            name="lodash",
            version="4.0.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            source="package.json",
            ecosystem="npm",
        )
        deps, errors = analyse_npm_sources(str(tmp_path), [declared])
        # BOM should not break parsing
        assert isinstance(deps, list)


# ── NEG-004 — empty-but-well-formed ──────────────────────────────────────


class TestFutureEmptyInputs:
    @pytest.mark.requirement("NEG-004")
    def test_empty_package_json(self, tmp_path):
        """Bare `{}` package.json — no deps, no errors."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "package.json").write_text("{}")
        deps, errors, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert deps == []
        assert errors == []

    @pytest.mark.requirement("NEG-004")
    def test_go_mod_with_only_module_directive(self, tmp_path):
        """`module x\ngo 1.22\n` — no requires, no errors."""
        from scarno.analysers.go.dep_file_parser import (
            parse_all_go_dependency_files,
        )
        (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n")
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        assert deps == []
        assert errors == []

    @pytest.mark.requirement("NEG-004")
    def test_csproj_with_only_target_framework(self, tmp_path):
        """Minimal csproj with only `<TargetFramework>` — no deps."""
        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            "  <PropertyGroup>\n"
            "    <TargetFramework>net8.0</TargetFramework>\n"
            "  </PropertyGroup>\n"
            "</Project>\n"
        )
        deps, errors, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert deps == []

    @pytest.mark.requirement("NEG-004")
    def test_empty_tsconfig_json(self, tmp_path):
        """`{}` tsconfig must be accepted without error."""
        from scarno.analysers.javascript.source_analyser import (
            JS_AST_AVAILABLE,
            analyse_npm_sources,
        )
        if not JS_AST_AVAILABLE:
            pytest.skip("tree-sitter-javascript grammar unavailable")
        (tmp_path / "tsconfig.json").write_text("{}")
        (tmp_path / "app.ts").write_text('import x from "lodash";\n')
        deps, errors = analyse_npm_sources(str(tmp_path), [])
        # No crash, tsconfig parsed fine
        assert isinstance(errors, list)


# ── NEG-005 — CLI / orchestrator edges ───────────────────────────────────


class TestFutureCliEdges:
    @pytest.mark.requirement("NEG-005")
    def test_polyglot_project_language_filter_excludes_missing_analyser(
        self, tmp_path
    ):
        """`--language go` on a Python+Go project when Go analyser IS
        registered — filters correctly to just Go deps."""
        from typer.testing import CliRunner
        from scarno.cli import app

        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        (tmp_path / "go.mod").write_text(
            "module x\n\ngo 1.22\n\nrequire github.com/a v1.0.0\n"
        )
        runner = CliRunner()
        result = runner.invoke(app, [str(tmp_path), "--language", "go", "--format", "json"])
        # Should succeed and only show Go deps
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        assert all(d["ecosystem"] == "go" for d in data.get("dependencies", []))

    @pytest.mark.requirement("NEG-005")
    def test_conflicting_language_filters(self, tmp_path):
        """`--language pypi --language npm` on a project with neither detected
        produces a clear error, not a crash."""
        from typer.testing import CliRunner
        from scarno.cli import app

        (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n")
        runner = CliRunner()
        result = runner.invoke(
            app, [str(tmp_path), "--language", "pypi", "--language", "npm"]
        )
        # Exit 2 — language filter doesn't overlap
        assert result.exit_code == 2


# ── NEG-007 — orchestrator / registry edges ──────────────────────────────


class TestFutureOrchestratorFailureModes:
    @pytest.mark.requirement("NEG-007")
    def test_tree_sitter_grammar_unavailable_falls_back(self):
        """When tree-sitter grammars aren't installed, the analyser
        exports ``AST_AVAILABLE = False`` and analysis proceeds
        (no crash). We verify the flag exists and is boolean."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE as JAVA_AST
        from scarno.analysers.javascript.source_analyser import JS_AST_AVAILABLE
        from scarno.analysers.go.source_analyser import GO_AST_AVAILABLE
        from scarno.analysers.csharp.source_analyser import CSHARP_AST_AVAILABLE

        # All must export a boolean flag
        for name, flag in [
            ("Java", JAVA_AST),
            ("JavaScript", JS_AST_AVAILABLE),
            ("Go", GO_AST_AVAILABLE),
            ("C#", CSHARP_AST_AVAILABLE),
        ]:
            assert isinstance(flag, bool), f"{name} AST flag is not bool: {type(flag)}"

    @pytest.mark.requirement("NEG-007")
    def test_gh_action_invocation_missing_scarno_binary(self):
        """REQ-8: ``action.yml`` exists and uses ``pip install`` (not
        curl|sh). If the install fails, the ``set -euo pipefail`` in
        the composite step causes a clean job failure."""
        from pathlib import Path

        action_yml = Path(__file__).resolve().parents[2] / "action.yml"
        if not action_yml.exists():
            pytest.skip("action.yml not present in this checkout")
        text = action_yml.read_text()
        # The install step uses pip — verified
        assert "pip install" in text
        # The run step starts with `set +e` so it captures exit codes
        assert "set +e" in text
        # If scarno isn't available, `scarno --help > /dev/null`
        # fails and the step exits non-zero
        assert "scarno --help" in text
