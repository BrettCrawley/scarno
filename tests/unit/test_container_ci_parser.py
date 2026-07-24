"""Coverage tests for container & CI dependency extractor (REQ-2c).

Exercises Dockerfile, GitHub Actions workflow, GitLab CI, tox.ini,
and noxfile.py parsers in ``container_ci_parser.py``.
"""
from __future__ import annotations

import pytest

from scarno.analysers.python.container_ci_parser import (
    parse_container_and_ci_deps,
)


def _names(deps):
    return {d.name for d in deps}


class TestDockerfileParsing:
    @pytest.mark.requirement("FR-040")
    def test_pip_install_in_dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "RUN pip install requests==2.31.0 click\n"
            "RUN pip install --no-cache-dir flask>=3.0\n"
        )
        deps, errors = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names
        assert "flask" in names

    @pytest.mark.requirement("FR-040")
    def test_pip3_install_in_dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "RUN pip3 install numpy pandas\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "numpy" in names
        assert "pandas" in names

    @pytest.mark.requirement("FR-040")
    def test_python_m_pip_in_dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "RUN python -m pip install torch\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        assert "torch" in _names(deps)

    @pytest.mark.requirement("FR-040")
    def test_multiline_continuation(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "RUN pip install \\\n"
            "    requests \\\n"
            "    click \\\n"
            "    flask\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names
        assert "flask" in names

    @pytest.mark.requirement("FR-040")
    def test_containerfile_also_scanned(self, tmp_path):
        (tmp_path / "Containerfile").write_text(
            "FROM python:3.12\n"
            "RUN pip install gunicorn\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        assert "gunicorn" in _names(deps)


class TestGitHubWorkflows:
    @pytest.mark.requirement("FR-041")
    def test_github_workflow_pip_install(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "name: CI\n"
            "on: push\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: pip install pytest coverage\n"
            "      - run: pip install -e .\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "coverage" in names


class TestGitLabCI:
    @pytest.mark.requirement("FR-042")
    def test_gitlab_ci_pip_install(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages:\n"
            "  - test\n"
            "\n"
            "test:\n"
            "  stage: test\n"
            "  script:\n"
            "    - pip install pytest mypy\n"
            "    - pytest\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "mypy" in names


class TestToxIni:
    @pytest.mark.requirement("FR-043")
    def test_tox_ini_deps(self, tmp_path):
        (tmp_path / "tox.ini").write_text(
            "[tox]\nenvlist = py312\n\n"
            "[testenv]\n"
            "deps =\n"
            "    pytest>=8.0\n"
            "    coverage>=7.0\n"
            "commands = pytest\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "coverage" in names


class TestNoxfile:
    @pytest.mark.requirement("FR-043")
    def test_noxfile_session_install(self, tmp_path):
        (tmp_path / "noxfile.py").write_text(
            "import nox\n\n"
            "@nox.session\n"
            "def tests(session):\n"
            "    session.install('pytest', 'coverage')\n"
            "    session.run('pytest')\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "coverage" in names


class TestToxIniAdvanced:
    @pytest.mark.requirement("FR-043")
    def test_tox_ini_named_testenv(self, tmp_path):
        (tmp_path / "tox.ini").write_text(
            "[tox]\nenvlist = py312, lint\n\n"
            "[testenv]\n"
            "deps = pytest>=8.0\n"
            "commands = pytest\n\n"
            "[testenv:lint]\n"
            "deps =\n"
            "    ruff>=0.3\n"
            "    mypy>=1.0\n"
            "commands = ruff check\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "ruff" in names
        assert "mypy" in names

    @pytest.mark.requirement("FR-043")
    def test_tox_ini_interpolation_resolved(self, tmp_path):
        (tmp_path / "tox.ini").write_text(
            "[base]\n"
            "deps = requests>=2.31\n\n"
            "[testenv]\n"
            "deps = {[base]deps}\n"
            "commands = python -c 'import requests'\n"
        )
        deps, errors = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "requests" in names

    @pytest.mark.requirement("FR-043")
    def test_tox_ini_malformed(self, tmp_path):
        (tmp_path / "tox.ini").write_text("[broken\n")
        deps, errors = parse_container_and_ci_deps(str(tmp_path))
        assert any("tox.ini" in e for e in errors)


class TestNoxfileAdvanced:
    @pytest.mark.requirement("FR-043")
    def test_noxfile_multiple_sessions(self, tmp_path):
        (tmp_path / "noxfile.py").write_text(
            "import nox\n\n"
            "@nox.session\n"
            "def tests(session):\n"
            "    session.install('pytest', 'coverage')\n"
            "    session.run('pytest')\n\n"
            "@nox.session\n"
            "def lint(session):\n"
            "    session.install('ruff', 'mypy')\n"
            "    session.run('ruff', 'check', '.')\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "ruff" in names

    @pytest.mark.requirement("FR-043")
    def test_noxfile_dot_install(self, tmp_path):
        (tmp_path / "noxfile.py").write_text(
            "import nox\n\n"
            "@nox.session\n"
            "def tests(session):\n"
            "    session.install('.')\n"
            "    session.install('pytest')\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        # "." is a self-install — should not appear as a dep
        assert "." not in names
        assert "pytest" in names

    @pytest.mark.requirement("FR-043")
    def test_noxfile_syntax_error(self, tmp_path):
        (tmp_path / "noxfile.py").write_text(
            "def broken(\n"  # syntax error
        )
        deps, errors = parse_container_and_ci_deps(str(tmp_path))
        # Must not crash — syntax errors are caught
        assert isinstance(deps, list)


class TestGitLabCIAdvanced:
    @pytest.mark.requirement("FR-042")
    def test_gitlab_ci_before_script(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "test:\n"
            "  before_script:\n"
            "    - pip install tox\n"
            "  script:\n"
            "    - tox\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        assert "tox" in _names(deps)

    @pytest.mark.requirement("FR-042")
    def test_gitlab_ci_pip3_install(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "build:\n"
            "  script:\n"
            "    - pip3 install sphinx\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        assert "sphinx" in _names(deps)

    @pytest.mark.requirement("FR-042")
    def test_gitlab_ci_malformed_yaml(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "---\n- broken: [unclosed\n"
        )
        deps, errors = parse_container_and_ci_deps(str(tmp_path))
        assert isinstance(deps, list)


class TestDockerfileAdvanced:
    @pytest.mark.requirement("FR-040")
    def test_dockerfile_with_arg_env(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "ARG PIP_INDEX_URL=https://pypi.org/simple\n"
            "RUN pip install --index-url $PIP_INDEX_URL flask gunicorn\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        assert "flask" in names
        assert "gunicorn" in names

    @pytest.mark.requirement("FR-040")
    def test_dockerfile_with_run_prefix(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "COPY . .\n"
            "RUN set -ex && pip install numpy && python -c 'import numpy'\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        assert "numpy" in _names(deps)


class TestRobustness:
    @pytest.mark.requirement("FR-040")
    def test_empty_project_no_errors(self, tmp_path):
        deps, errors = parse_container_and_ci_deps(str(tmp_path))
        assert deps == []
        assert errors == []

    @pytest.mark.requirement("FR-040")
    def test_non_existent_path(self):
        deps, errors = parse_container_and_ci_deps("/nonexistent/path")
        assert deps == []

    @pytest.mark.requirement("FR-040")
    def test_pip_flags_not_treated_as_packages(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "RUN pip install --no-cache-dir --upgrade -q requests\n"
        )
        deps, _ = parse_container_and_ci_deps(str(tmp_path))
        names = _names(deps)
        # Flags like --no-cache-dir should not appear as package names
        assert not any(n.startswith("--") for n in names)
        assert "requests" in names
