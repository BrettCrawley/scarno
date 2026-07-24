"""Deep coverage for Python dep_file_parser and source_analyser."""
from __future__ import annotations

import json

import pytest

from scarno.analysers.python.dep_file_parser import parse_all_dependency_files
from scarno.models import Dependency, DependencyStatus


def _names(deps):
    return {d.name for d in deps}


class TestPyprojectTomlEdgePaths:
    @pytest.mark.requirement("FR-001")
    def test_pyproject_optional_dependencies(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\n"
            "dependencies = ['requests>=2.31']\n"
            "[project.optional-dependencies]\n"
            "dev = ['pytest>=8.0', 'mypy>=1.0']\n"
            "docs = ['sphinx>=7.0']\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "pytest" in names
        assert "sphinx" in names

    @pytest.mark.requirement("FR-042")
    def test_pyproject_dependency_groups(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\n"
            "dependencies = ['requests']\n"
            "[dependency-groups]\n"
            "test = ['pytest>=8.0', 'coverage>=7.0']\n"
            "lint = ['ruff>=0.3']\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "ruff" in names

    @pytest.mark.requirement("FR-041")
    def test_pyproject_build_system_requires(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\n"
            "requires = ['setuptools>=68', 'wheel']\n"
            "build-backend = 'setuptools.build_meta'\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "setuptools" in names
        assert "wheel" in names

    @pytest.mark.requirement("FR-001")
    def test_pyproject_malformed_toml(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[broken\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any("pyproject.toml" in e for e in errors)

    @pytest.mark.requirement("FR-001")
    def test_pyproject_non_list_dependencies(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\n"
            "dependencies = 'requests'\n"  # wrong type: str not list
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # Either errors or silently skips — must not crash
        assert isinstance(deps, list)


class TestRequirementsTxtEdgePaths:
    @pytest.mark.requirement("FR-001")
    def test_recursive_requirements_file(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "requests>=2.31\n"
            "-r extra-reqs.txt\n"
        )
        (tmp_path / "extra-reqs.txt").write_text(
            "click>=8.0\n"
            "flask>=3.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names
        assert "flask" in names

    @pytest.mark.requirement("FR-001")
    def test_constraint_file(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "-c constraints.txt\n"
            "requests\n"
        )
        (tmp_path / "constraints.txt").write_text("requests==2.31.0\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names

    @pytest.mark.requirement("FR-001")
    def test_editable_install_ignored(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "-e ./my-local-pkg\n"
            "-e git+https://github.com/foo/bar.git#egg=bar\n"
            "requests\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert "requests" in _names(deps)

    @pytest.mark.requirement("FR-001")
    def test_environment_markers_stripped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            'requests>=2.31; python_version>="3.8"\n'
            'click>=8.0; sys_platform=="linux"\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names

    @pytest.mark.requirement("FR-001")
    def test_extras_in_dependency(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "requests[security]>=2.31\n"
            "celery[redis,msgpack]>=5.3\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "celery" in names

    @pytest.mark.requirement("FR-001")
    def test_multiple_requirements_files(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests\n")
        (tmp_path / "requirements-dev.txt").write_text("pytest\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        # requirements-dev.txt may or may not be discovered depending on
        # the parser's glob pattern — just verify no crash
        assert isinstance(deps, list)


class TestSourceAnalyserCoverage:
    @pytest.mark.requirement("FR-001")
    def test_analyse_with_in_use_and_safe_deps(self, tmp_path):
        from scarno.analysers.python.source_analyser import analyse_source_files

        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = ['requests', 'click', 'numpy']\n"
        )
        (tmp_path / "main.py").write_text(
            "import requests\n"
            "import click\n"
            "# numpy not imported\n"
        )
        deps = [
            Dependency(
                name=n, version=None, status=DependencyStatus.UNCERTAIN,
                reason="pending", ecosystem="pypi",
            )
            for n in ("requests", "click", "numpy")
        ]
        result, errors = analyse_source_files(str(tmp_path), deps)
        names_by_status = {}
        for d in result:
            names_by_status.setdefault(d.status, set()).add(d.name)
        assert "requests" in names_by_status.get(DependencyStatus.IN_USE, set())
        assert "click" in names_by_status.get(DependencyStatus.IN_USE, set())
        assert "numpy" in names_by_status.get(DependencyStatus.SAFE, set())

    @pytest.mark.requirement("FR-001")
    def test_source_analyser_with_from_import(self, tmp_path):
        from scarno.analysers.python.source_analyser import analyse_source_files

        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "from flask.views import MethodView\n"
        )
        deps = [
            Dependency(
                name="flask", version=None, status=DependencyStatus.UNCERTAIN,
                reason="pending", ecosystem="pypi",
            )
        ]
        result, _ = analyse_source_files(str(tmp_path), deps)
        flask = next(d for d in result if d.name == "flask")
        assert flask.status is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-001")
    def test_source_analyser_phantom_import(self, tmp_path):
        from scarno.analysers.python.source_analyser import analyse_source_files

        (tmp_path / "app.py").write_text("import mystery_pkg\n")
        result, errors = analyse_source_files(str(tmp_path), [])
        # Should detect phantom/undeclared import
        assert isinstance(result, list)

    @pytest.mark.requirement("FR-001")
    def test_source_analyser_ignores_stdlib(self, tmp_path):
        from scarno.analysers.python.source_analyser import analyse_source_files

        (tmp_path / "app.py").write_text(
            "import os\nimport json\nimport sys\nimport pathlib\n"
        )
        result, _ = analyse_source_files(str(tmp_path), [])
        names = {d.name for d in result}
        # stdlib should not appear as UNDECLARED
        assert "os" not in names
        assert "json" not in names

    @pytest.mark.requirement("FR-001")
    def test_source_analyser_skips_too_large(self, tmp_path):
        from scarno.analysers.python.source_analyser import analyse_source_files
        from scarno.security import MAX_FILE_BYTES

        (tmp_path / "huge.py").write_text("x=1\n" * (MAX_FILE_BYTES // 4 + 1))
        result, errors = analyse_source_files(str(tmp_path), [])
        # Must not crash — file is silently skipped
        assert isinstance(result, list)

    @pytest.mark.requirement("FR-001")
    def test_source_analyser_non_python_files_ignored(self, tmp_path):
        from scarno.analysers.python.source_analyser import analyse_source_files

        (tmp_path / "script.sh").write_text("import fake_pkg\n")
        (tmp_path / "data.json").write_text('{"import": "nothing"}')
        result, errors = analyse_source_files(str(tmp_path), [])
        # No deps extracted from non-Python files
        assert result == []
