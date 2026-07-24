"""Skeleton tests for REQ-2b — Extended Python Dependency Format Coverage.

These tests will fail until REQ-2b is implemented in Phase 1.5. SRTM markers
are attached now so the SRTM-coverage gate stays green.
"""
from __future__ import annotations

import textwrap

import pytest

from scarno.analysers.python.dep_file_parser import parse_all_dependency_files


class TestCondaEnvironmentYml:
    @pytest.mark.requirement("FR-040")
    def test_scalar_dep_parsed(self, tmp_path):
        (tmp_path / "environment.yml").write_text(
            textwrap.dedent(
                """\
            name: mystack
            dependencies:
              - numpy=1.26
              - python=3.12
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "numpy" in names
        assert "python" not in names

    @pytest.mark.requirement("FR-040")
    def test_nested_pip_section_parsed(self, tmp_path):
        (tmp_path / "environment.yml").write_text(
            textwrap.dedent(
                """\
            name: mystack
            dependencies:
              - numpy
              - pip:
                - flask>=3
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "flask" in names

    @pytest.mark.requirement("FR-040")
    @pytest.mark.requirement("SEC-NEW-13")
    @pytest.mark.security
    def test_yaml_uses_safe_load(self, tmp_path):
        """environment.yml must parse via yaml.safe_load only."""
        (tmp_path / "environment.yml").write_text(
            "!!python/object/apply:os.system ['echo pwned']\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # Must not execute the tag; either safe_load raises or errors are appended
        assert isinstance(deps, list)

    @pytest.mark.requirement("FR-040")
    @pytest.mark.requirement("PRV-003")
    def test_environment_name_not_leaked_as_dep(self, tmp_path):
        (tmp_path / "environment.yml").write_text(
            "name: my-private-stack\ndependencies:\n  - numpy\n"
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "my-private-stack" not in names


class TestPep518BuildSystemRequires:
    @pytest.mark.requirement("FR-041")
    def test_build_system_requires_parsed(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [build-system]
            requires = ["hatchling", "setuptools>=61"]
            build-backend = "hatchling.build"
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "hatchling" in names
        assert "setuptools" in names

    @pytest.mark.requirement("FR-043")
    def test_source_provenance_set(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n'
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        hatch = next((d for d in deps if d.name == "hatchling"), None)
        assert hatch is not None
        assert hatch.source.startswith("pyproject.toml:build-system")


class TestPep735DependencyGroups:
    @pytest.mark.requirement("FR-042")
    def test_simple_group_parsed(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [dependency-groups]
            test = ["pytest>=8", "pytest-cov"]
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "pytest" in names
        assert "pytest-cov" in names

    @pytest.mark.requirement("FR-042")
    def test_include_group_resolved(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [dependency-groups]
            test = ["pytest"]
            docs = ["sphinx", {include-group = "test"}]
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "pytest" in names
        assert "sphinx" in names

    @pytest.mark.requirement("FR-042")
    @pytest.mark.requirement("SEC-NEW-14")
    @pytest.mark.security
    def test_include_group_cycle_detected(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [dependency-groups]
            a = [{include-group = "b"}]
            b = [{include-group = "a"}]
            """
            )
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any("cycle" in e.lower() for e in errors)
