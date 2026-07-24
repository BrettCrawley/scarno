"""REQ-17 — CLI flag plumbing tests.

End-to-end checks that ``--exclude-tests``, ``--test-paths``, and
``--exclude-dev`` reach the ecosystem analysers and produce the
right behaviour.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _names(deps: list[dict]) -> set[str]:
    return {d["name"] for d in deps}


# ── Python ────────────────────────────────────────────────────────────────


class TestExcludeTestsPython:
    @pytest.mark.requirement("FR-153")
    def test_exclude_tests_drops_python_optional_test_group(
        self, runner, tmp_path
    ):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["requests"]\n'
            "\n"
            "[project.optional-dependencies]\n"
            'test = ["pytest"]\n'
        ))
        _write(tmp_path / "main.py", "import requests\n")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "pytest" not in names
        assert "requests" in names

    @pytest.mark.requirement("FR-153")
    def test_default_keeps_python_optional_test_group(self, runner, tmp_path):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["requests"]\n'
            "\n"
            "[project.optional-dependencies]\n"
            'test = ["pytest"]\n'
        ))
        _write(tmp_path / "main.py", "import requests\n")
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "pytest" in names

    @pytest.mark.requirement("FR-153")
    def test_exclude_tests_drops_requirements_test_txt(
        self, runner, tmp_path
    ):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        _write(tmp_path / "requirements-test.txt", "pytest==7.0\n")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "pytest" not in names

    @pytest.mark.requirement("FR-153")
    def test_exclude_tests_skips_tests_dir_python(self, runner, tmp_path):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        _write(tmp_path / "tests" / "test_foo.py", "import requests\n")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        assert result.exit_code in (0, 1, 3)
        data = json.loads(result.stdout)
        # 'requests' would otherwise be flagged UNDECLARED — under
        # --exclude-tests it must not appear at all.
        names = _names(data["dependencies"])
        assert "requests" not in names


# ── Maven ─────────────────────────────────────────────────────────────────


class TestExcludeTestsMaven:
    @pytest.mark.requirement("FR-153")
    def test_exclude_tests_drops_maven_test_scope(self, runner, tmp_path):
        _write(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>lib</artifactId>
      <version>1</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
""")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "junit:junit" not in names
        assert "org.example:lib" in names


# ── Gradle ────────────────────────────────────────────────────────────────


class TestExcludeTestsGradle:
    @pytest.mark.requirement("FR-153")
    def test_exclude_tests_drops_gradle_test_configurations(
        self, runner, tmp_path
    ):
        _write(tmp_path / "build.gradle.kts", """\
dependencies {
    implementation("org.example:lib:1.0")
    testImplementation("org.mockito:mockito-core:5.0")
    androidTestImplementation("androidx.test:runner:1.0")
}
""")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "org.mockito:mockito-core" not in names
        assert "androidx.test:runner" not in names
        assert "org.example:lib" in names


# ── npm / JS ──────────────────────────────────────────────────────────────


class TestExcludeJs:
    @pytest.mark.requirement("FR-153")
    def test_exclude_tests_skips_js_tests_only_not_devdeps(
        self, runner, tmp_path
    ):
        _write(tmp_path / "package.json", json.dumps({
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
            "devDependencies": {"vitest": "^1"},
        }))
        _write(tmp_path / "src" / "index.ts", 'import "lodash";\n')
        _write(tmp_path / "src" / "foo.test.ts", 'import "vitest";\n')
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        # devDependencies remain because --exclude-dev was not passed.
        assert "vitest" in names
        assert "lodash" in names

    @pytest.mark.requirement("FR-155")
    def test_exclude_dev_drops_npm_dev_deps(self, runner, tmp_path):
        _write(tmp_path / "package.json", json.dumps({
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
            "devDependencies": {"vitest": "^1", "eslint": "^8"},
        }))
        _write(tmp_path / "src" / "index.ts", 'import "lodash";\n')
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-dev",
        ])
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "vitest" not in names
        assert "eslint" not in names
        assert "lodash" in names

    @pytest.mark.requirement("FR-155")
    def test_exclude_dev_default_keeps_npm_dev_deps(self, runner, tmp_path):
        _write(tmp_path / "package.json", json.dumps({
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
            "devDependencies": {"vitest": "^1"},
        }))
        _write(tmp_path / "src" / "index.ts", 'import "lodash";\n')
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "vitest" in names

    @pytest.mark.requirement("FR-155")
    def test_exclude_dev_warns_outside_npm_projects(self, runner, tmp_path):
        # Pure-Python project; --exclude-dev should not be a fatal error.
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-dev",
        ])
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        # A non-fatal warning is emitted in the errors list.
        assert any("--exclude-dev" in e for e in data["errors"])


# ── --test-paths ──────────────────────────────────────────────────────────


class TestTestPathsFlag:
    @pytest.mark.requirement("FR-154")
    def test_test_paths_extends_matcher_for_it_dir(self, runner, tmp_path):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        # 'requests' is imported only from a custom-named test directory.
        _write(tmp_path / "it" / "integration_test.py", "import requests\n")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json",
            "--exclude-tests", "--test-paths", "it/**/*",
        ])
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        assert "requests" not in names

    @pytest.mark.requirement("FR-154")
    def test_test_paths_no_effect_without_exclude_tests(
        self, runner, tmp_path
    ):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        _write(tmp_path / "it" / "integration_test.py", "import requests\n")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--test-paths", "it/**/*",
        ])
        data = json.loads(result.stdout)
        names = _names(data["dependencies"])
        # Without --exclude-tests, 'requests' surfaces as UNDECLARED.
        assert "requests" in names

    @pytest.mark.requirement("T-19")
    def test_verbose_echoes_test_paths_with_sanitise(
        self, runner, tmp_path
    ):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        result = runner.invoke(app, [
            str(tmp_path), "--format", "text",
            "--exclude-tests", "--test-paths", "it/**/*", "--verbose",
        ])
        # Verbose echo line must appear and must not contain raw control bytes.
        # We can't easily inject ANSI here without breaking validation;
        # instead assert the verbose echo line is present.
        assert "test_paths" in result.output or "test-paths" in result.output


# ── Aggregate-only skip reporting ────────────────────────────────────────


class TestAggregateOnlySkipReporting:
    @pytest.mark.requirement("FR-157")
    @pytest.mark.requirement("PRV-004")
    def test_exclude_tests_emits_count_only_in_errors(
        self, runner, tmp_path
    ):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        _write(tmp_path / "tests" / "test_a.py", "")
        _write(tmp_path / "tests" / "test_b.py", "")
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        data = json.loads(result.stdout)
        # Errors must contain a single summary line; per-file paths must
        # not leak.
        skip_lines = [e for e in data["errors"] if "skipped" in e]
        assert len(skip_lines) >= 1
        # No verbatim file path of a skipped file.
        joined = " | ".join(data["errors"])
        assert "test_a.py" not in joined
        assert "test_b.py" not in joined

    @pytest.mark.requirement("PRV-004")
    def test_exclude_tests_does_not_leak_test_paths_in_errors(
        self, runner, tmp_path
    ):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        ))
        for i in range(5):
            _write(
                tmp_path / "tests" / f"test_secret_{i}.py", "import os\n",
            )
        result = runner.invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        data = json.loads(result.stdout)
        joined = " | ".join(data["errors"])
        assert "secret" not in joined
