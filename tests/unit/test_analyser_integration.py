"""Integration tests exercising each analyser's full ``analyse()`` path.

These cover the ``__init__.py`` wiring code for every language analyser,
which has been a major coverage gap because unit tests only exercised
the inner parsers directly.
"""
from __future__ import annotations

import json

import pytest

from scarno.models import DependencyStatus


# ═══════════════════════════════════════════════════════════════════════════
# Java analyser integration
# ═══════════════════════════════════════════════════════════════════════════


class TestJavaAnalyserIntegration:
    @pytest.mark.requirement("FR-010")
    def test_maven_project_analyse(self, tmp_path):
        from scarno.analysers.java import JavaAnalyser

        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>app</artifactId>\n"
            "  <version>1.0</version>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.slf4j</groupId>\n"
            "      <artifactId>slf4j-api</artifactId>\n"
            "      <version>2.0.9</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        analyser = JavaAnalyser()
        assert analyser.supports(str(tmp_path))
        result = analyser.analyse(str(tmp_path))
        assert result.project_type == "java"
        assert result.languages == ["java"]
        names = {d.name for d in result.dependencies}
        assert "org.slf4j:slf4j-api" in names

    @pytest.mark.requirement("FR-018")
    def test_gradle_project_analyse(self, tmp_path):
        from scarno.analysers.java import JavaAnalyser

        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n\n"
            "dependencies {\n"
            "    implementation 'com.google.guava:guava:32.1.2-jre'\n"
            "}\n"
        )
        analyser = JavaAnalyser()
        assert analyser.supports(str(tmp_path))
        result = analyser.analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "com.google.guava:guava" in names

    @pytest.mark.requirement("FR-010")
    def test_maven_and_gradle_merged(self, tmp_path):
        from scarno.analysers.java import JavaAnalyser

        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>app</artifactId>\n"
            "  <version>1.0</version>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>junit</groupId>\n"
            "      <artifactId>junit</artifactId>\n"
            "      <version>4.13.2</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n\n"
            "dependencies {\n"
            "    implementation 'junit:junit:4.13.2'\n"
            "}\n"
        )
        result = JavaAnalyser().analyse(str(tmp_path))
        # Dedup: same dep from both sources → one entry
        junit = [d for d in result.dependencies if d.name == "junit:junit"]
        assert len(junit) == 1

    @pytest.mark.requirement("FR-010")
    def test_no_build_files_reports_error(self, tmp_path):
        from scarno.analysers.java import JavaAnalyser

        (tmp_path / "README.md").write_text("not a java project\n")
        # supports() returns False, but if analyse() is called directly:
        result = JavaAnalyser().analyse(str(tmp_path))
        assert any("no pom.xml" in e.lower() for e in result.errors)

    @pytest.mark.requirement("FR-010")
    def test_supports_rejects_non_java(self, tmp_path):
        from scarno.analysers.java import JavaAnalyser

        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        assert not JavaAnalyser().supports(str(tmp_path))

    @pytest.mark.requirement("FR-010")
    def test_supports_rejects_non_dir(self, tmp_path):
        from scarno.analysers.java import JavaAnalyser

        f = tmp_path / "not_a_dir.txt"
        f.write_text("hi")
        assert not JavaAnalyser().supports(str(f))

    @pytest.mark.requirement("FR-010")
    def test_dedup_maven_wins_over_gradle_version(self, tmp_path):
        """When both Maven and Gradle declare the same dep, Maven version wins."""
        from scarno.analysers.java import JavaAnalyser

        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>app</artifactId>\n"
            "  <version>1.0</version>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>com.a</groupId>\n"
            "      <artifactId>b</artifactId>\n"
            "      <version>2.0.0</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n"
            "dependencies { implementation 'com.a:b:1.0.0' }\n"
        )
        result = JavaAnalyser().analyse(str(tmp_path))
        dep = next(d for d in result.dependencies if d.name == "com.a:b")
        assert dep.version == "2.0.0"  # Maven wins


# ═══════════════════════════════════════════════════════════════════════════
# JavaScript analyser integration
# ═══════════════════════════════════════════════════════════════════════════


class TestJavascriptAnalyserIntegration:
    @pytest.mark.requirement("FR-103")
    def test_npm_project_analyse(self, tmp_path):
        from scarno.analysers.javascript import JavascriptAnalyser

        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        (tmp_path / "app.js").write_text('import lodash from "lodash";\n')

        analyser = JavascriptAnalyser()
        assert analyser.supports(str(tmp_path))
        result = analyser.analyse(str(tmp_path))
        assert result.project_type == "javascript"
        assert result.languages == ["javascript"]

        names = {d.name for d in result.dependencies}
        assert "lodash" in names
        assert "jest" in names

        lodash = next(d for d in result.dependencies if d.name == "lodash")
        jest = next(d for d in result.dependencies if d.name == "jest")
        assert lodash.status is DependencyStatus.IN_USE
        assert jest.status is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-103")
    def test_supports_rejects_non_js(self, tmp_path):
        from scarno.analysers.javascript import JavascriptAnalyser

        (tmp_path / "pyproject.toml").write_text("[project]\n")
        assert not JavascriptAnalyser().supports(str(tmp_path))

    @pytest.mark.requirement("FR-103")
    def test_supports_rejects_non_dir(self, tmp_path):
        from scarno.analysers.javascript import JavascriptAnalyser

        f = tmp_path / "file.txt"
        f.write_text("x")
        assert not JavascriptAnalyser().supports(str(f))


# ═══════════════════════════════════════════════════════════════════════════
# C# analyser integration
# ═══════════════════════════════════════════════════════════════════════════


class TestCsharpAnalyserIntegration:
    @pytest.mark.requirement("FR-123")
    def test_csharp_project_analyse(self, tmp_path):
        from scarno.analysers.csharp import CsharpAnalyser

        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            "  <ItemGroup>\n"
            '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3"/>\n'
            '    <PackageReference Include="Serilog" Version="3.1.1"/>\n'
            "  </ItemGroup>\n"
            "</Project>\n"
        )
        (tmp_path / "Program.cs").write_text(
            "using Serilog;\nclass P { static void Main() {} }\n"
        )

        analyser = CsharpAnalyser()
        assert analyser.supports(str(tmp_path))
        result = analyser.analyse(str(tmp_path))
        assert result.project_type == "csharp"
        assert result.languages == ["csharp"]

        serilog = next(d for d in result.dependencies if d.name == "Serilog")
        newtonsoft = next(d for d in result.dependencies if d.name == "Newtonsoft.Json")
        assert serilog.status is DependencyStatus.IN_USE
        assert newtonsoft.status is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-123")
    def test_supports_via_global_json(self, tmp_path):
        from scarno.analysers.csharp import CsharpAnalyser

        (tmp_path / "global.json").write_text('{"sdk":{"version":"8.0.100"}}\n')
        assert CsharpAnalyser().supports(str(tmp_path))

    @pytest.mark.requirement("FR-123")
    def test_supports_rejects_non_csharp(self, tmp_path):
        from scarno.analysers.csharp import CsharpAnalyser

        (tmp_path / "pyproject.toml").write_text("[project]\n")
        assert not CsharpAnalyser().supports(str(tmp_path))

    @pytest.mark.requirement("FR-123")
    def test_supports_rejects_non_dir(self, tmp_path):
        from scarno.analysers.csharp import CsharpAnalyser

        f = tmp_path / "file.txt"
        f.write_text("x")
        assert not CsharpAnalyser().supports(str(f))


# ═══════════════════════════════════════════════════════════════════════════
# Go analyser integration
# ═══════════════════════════════════════════════════════════════════════════


class TestGoAnalyserIntegration:
    @pytest.mark.requirement("FR-114")
    def test_go_project_analyse(self, tmp_path):
        from scarno.analysers.go import GoAnalyser

        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\ngo 1.22\n\n"
            "require github.com/pkg/errors v0.9.1\n"
        )
        (tmp_path / "main.go").write_text(
            'package main\nimport "github.com/pkg/errors"\n'
            "func main() { _ = errors.New(\"x\") }\n"
        )

        analyser = GoAnalyser()
        assert analyser.supports(str(tmp_path))
        result = analyser.analyse(str(tmp_path))
        assert result.project_type == "go"
        dep = next(d for d in result.dependencies if d.name == "github.com/pkg/errors")
        assert dep.status is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-114")
    def test_supports_rejects_non_go(self, tmp_path):
        from scarno.analysers.go import GoAnalyser

        (tmp_path / "pyproject.toml").write_text("[project]\n")
        assert not GoAnalyser().supports(str(tmp_path))


# ═══════════════════════════════════════════════════════════════════════════
# Python analyser integration
# ═══════════════════════════════════════════════════════════════════════════


class TestPythonAnalyserIntegration:
    @pytest.mark.requirement("FR-001")
    def test_python_project_analyse(self, tmp_path):
        from scarno.analysers.python import PythonAnalyser

        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = ['requests>=2.31', 'click>=8.0']\n"
        )
        (tmp_path / "main.py").write_text("import requests\n")

        analyser = PythonAnalyser()
        assert analyser.supports(str(tmp_path))
        result = analyser.analyse(str(tmp_path))
        assert result.project_type == "python"
        names = {d.name for d in result.dependencies}
        assert "requests" in names
        assert "click" in names

    @pytest.mark.requirement("FR-001")
    def test_supports_rejects_non_python(self, tmp_path):
        from scarno.analysers.python import PythonAnalyser

        (tmp_path / "go.mod").write_text("module x\ngo 1.22\n")
        assert not PythonAnalyser().supports(str(tmp_path))
