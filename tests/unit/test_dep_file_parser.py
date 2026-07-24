"""Tests for all Python dependency format parsers."""
from __future__ import annotations

import textwrap

import pytest

from scarno.analysers.python.dep_file_parser import parse_all_dependency_files


class TestRequirementsTxt:
    @pytest.mark.requirement("FR-005")
    def test_simple_pinned_dep_parsed(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "requests" in names
        assert errors == []

    @pytest.mark.requirement("FR-005")
    def test_comment_lines_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "# a comment\nrequests==2.31.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert len(deps) == 1
        assert deps[0].name == "requests"

    @pytest.mark.requirement("FR-005")
    def test_env_marker_stripped_dep_retained(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            'requests>=2.0; python_version >= "3.8"\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(d.name == "requests" for d in deps)

    @pytest.mark.requirement("FR-005")
    def test_editable_install_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "-e .\n-e git+https://github.com/example/repo.git\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert deps == []

    @pytest.mark.requirement("FR-005")
    def test_url_dep_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "https://example.com/pkg.tar.gz\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert deps == []

    @pytest.mark.requirement("FR-005")
    def test_malformed_line_appends_error_not_crash(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("@@@notapackage@@@\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert len(errors) >= 1

    @pytest.mark.requirement("FR-005")
    @pytest.mark.security
    def test_r_include_within_project_root_followed(self, tmp_path):
        sub = tmp_path / "deps"
        sub.mkdir()
        (sub / "core.txt").write_text("flask==3.0.0\n")
        (tmp_path / "requirements.txt").write_text("-r deps/core.txt\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(d.name == "flask" for d in deps)

    @pytest.mark.requirement("FR-005")
    @pytest.mark.requirement("SEC-002")
    @pytest.mark.security
    def test_r_include_escaping_root_is_blocked(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("-r ../../../../etc/passwd\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(
            "escape" in e.lower() or "outside" in e.lower() or "confined" in e.lower()
            for e in errors
        )
        assert not any(d.name for d in deps if "/" in d.name)

    @pytest.mark.requirement("FR-005")
    @pytest.mark.requirement("D-01")
    @pytest.mark.requirement("SEC-009")
    @pytest.mark.security
    def test_circular_r_include_detected_not_infinite(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("-r b.txt\n")
        b.write_text("-r a.txt\n")
        (tmp_path / "requirements.txt").write_text("-r a.txt\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(
            "cycle" in e.lower() or "circular" in e.lower() or "depth" in e.lower()
            for e in errors
        )

    @pytest.mark.requirement("FR-005")
    @pytest.mark.requirement("SEC-009")
    @pytest.mark.requirement("PERF-001")
    @pytest.mark.security
    def test_r_include_max_depth_respected(self, tmp_path):
        for i in range(12, -1, -1):
            fname = f"level{i}.txt"
            content = f"-r level{i + 1}.txt\n" if i < 12 else "flask==3.0.0\n"
            (tmp_path / fname).write_text(content)
        (tmp_path / "requirements.txt").write_text("-r level0.txt\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any("depth" in e.lower() or "max" in e.lower() for e in errors)


class TestPyprojectToml:
    @pytest.mark.requirement("FR-006")
    def test_pep621_dependencies_parsed(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [project]
            name = "myapp"
            dependencies = ["requests>=2.0", "flask==3.0.0"]
        """
            )
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names

    @pytest.mark.requirement("FR-006")
    def test_poetry_dependencies_parsed(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [tool.poetry.dependencies]
            python = "^3.12"
            requests = "^2.31"
            flask = "^3.0"
        """
            )
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "python" not in names

    @pytest.mark.requirement("PRV-003")
    @pytest.mark.security
    def test_author_fields_not_extracted(self, tmp_path):
        """Author/maintainer PII from pyproject.toml must not appear in Dependency objects."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
            [project]
            name = "myapp"
            authors = [{name = "Alice Smith", email = "alice@example.com"}]
            dependencies = ["requests>=2.0"]
        """
            )
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        all_dep_text = " ".join(d.name + (d.reason or "") for d in deps)
        assert "Alice Smith" not in all_dep_text
        assert "alice@example.com" not in all_dep_text


class TestSetupPy:
    @pytest.mark.requirement("FR-007")
    @pytest.mark.requirement("SEC-008")
    @pytest.mark.requirement("SEC-001")
    @pytest.mark.security
    def test_setup_py_ast_only_never_executed(self, tmp_path):
        """setup.py must be parsed via AST, not executed."""
        import os

        (tmp_path / "setup.py").write_text(
            textwrap.dedent(
                """\
            import os
            os.system("touch /tmp/scarno_executed_setup_py")
            from setuptools import setup
            setup(install_requires=["requests==2.31.0"])
        """
            )
        )
        parse_all_dependency_files(str(tmp_path))
        assert not os.path.exists("/tmp/scarno_executed_setup_py")

    @pytest.mark.requirement("FR-007")
    def test_setup_py_valid_parses_deps(self, tmp_path):
        (tmp_path / "setup.py").write_text(
            textwrap.dedent(
                """\
            from setuptools import setup
            setup(install_requires=["requests>=2.0", "flask"])
        """
            )
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "requests" in names

    @pytest.mark.requirement("FR-007")
    def test_setup_py_syntax_error_produces_error_not_crash(self, tmp_path):
        (tmp_path / "setup.py").write_text("def broken((:")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert len(errors) >= 1


class TestDeduplicationAndNormalisation:
    @pytest.mark.requirement("FR-010")
    def test_duplicate_deps_deduplicated(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\nRequests==2.31.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert names.count("requests") == 1

    @pytest.mark.requirement("FR-009")
    def test_pep503_normalisation_applied(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "My_Package==1.0\nmy-package==1.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert len(deps) == 1

    @pytest.mark.requirement("S-02")
    @pytest.mark.security
    def test_stdlib_module_not_included_as_dependency(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("os==1.0\nrequests==2.31.0\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "os" not in names or len(errors) >= 1
