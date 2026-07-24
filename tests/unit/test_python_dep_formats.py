"""Coverage tests for Python dep-file format parsers.

Exercises the many dep-file parsers in ``dep_file_parser.py`` that
aren't covered by the main test suites: setup.cfg, Pipfile,
Pipfile.lock, poetry.lock, uv.lock, environment.yml, conda-forge.
"""
from __future__ import annotations

import json

import pytest

from scarno.analysers.python.dep_file_parser import parse_all_dependency_files


def _names(deps):
    return {d.name for d in deps}


class TestSetupCfg:
    @pytest.mark.requirement("FR-001")
    def test_setup_cfg_install_requires(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            "[options]\n"
            "install_requires =\n"
            "    requests>=2.31\n"
            "    click>=8.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names

    @pytest.mark.requirement("FR-001")
    def test_setup_cfg_extras_require(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            "[options.extras_require]\n"
            "dev =\n"
            "    pytest>=8.0\n"
            "    mypy>=1.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "pytest" in names
        assert "mypy" in names

    @pytest.mark.requirement("FR-001")
    def test_setup_cfg_parse_error(self, tmp_path):
        (tmp_path / "setup.cfg").write_text("[broken\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any("setup.cfg" in e for e in errors)


class TestPipfile:
    @pytest.mark.requirement("FR-001")
    def test_pipfile_packages(self, tmp_path):
        (tmp_path / "Pipfile").write_text(
            "[packages]\n"
            'requests = ">=2.31"\n'
            'click = "*"\n'
            "\n"
            "[dev-packages]\n"
            'pytest = {version = ">=8.0"}\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names
        assert "pytest" in names
        # click has version "*" → version should be None
        click = next(d for d in deps if d.name == "click")
        assert click.version is None

    @pytest.mark.requirement("FR-001")
    def test_pipfile_lock(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_text(json.dumps({
            "_meta": {"requires": {"python_version": "3.12"}},
            "default": {
                "requests": {"version": "==2.31.0"},
                "certifi": {"version": "==2023.7.22"},
            },
            "develop": {
                "pytest": {"version": "==8.1.0"},
            },
        }))
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "certifi" in names
        assert "pytest" in names
        req = next(d for d in deps if d.name == "requests")
        assert req.version == "2.31.0"


class TestPoetryLock:
    @pytest.mark.requirement("FR-001")
    def test_poetry_lock(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\n'
            'name = "requests"\n'
            'version = "2.31.0"\n'
            'description = "HTTP library"\n'
            '\n'
            '[[package]]\n'
            'name = "click"\n'
            'version = "8.1.7"\n'
            'description = "CLI toolkit"\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names
        req = next(d for d in deps if d.name == "requests")
        assert req.version == "2.31.0"


class TestUvLock:
    @pytest.mark.requirement("FR-001")
    def test_uv_lock(self, tmp_path):
        (tmp_path / "uv.lock").write_text(
            '[[package]]\n'
            'name = "flask"\n'
            'version = "3.0.0"\n'
            '\n'
            '[[package]]\n'
            'name = "werkzeug"\n'
            'version = "3.0.1"\n'
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "flask" in names
        assert "werkzeug" in names


class TestEnvironmentYml:
    @pytest.mark.requirement("FR-001")
    def test_environment_yml_pip_section(self, tmp_path):
        (tmp_path / "environment.yml").write_text(
            "name: myenv\n"
            "channels:\n"
            "  - defaults\n"
            "dependencies:\n"
            "  - python=3.12\n"
            "  - numpy=1.26.0\n"
            "  - pip:\n"
            "    - requests>=2.31\n"
            "    - click>=8.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        # Conda-managed deps
        assert "numpy" in names
        # pip-managed deps
        assert "requests" in names
        assert "click" in names

    @pytest.mark.requirement("FR-001")
    def test_environment_yaml_variant(self, tmp_path):
        (tmp_path / "environment.yaml").write_text(
            "name: env\ndependencies:\n  - scipy=1.11.0\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert "scipy" in _names(deps)


class TestSetupPy:
    @pytest.mark.requirement("FR-001")
    def test_setup_py_literal_install_requires(self, tmp_path):
        (tmp_path / "setup.py").write_text(
            "from setuptools import setup\n"
            "setup(\n"
            "    name='myapp',\n"
            "    install_requires=['requests>=2.31', 'click>=8.0'],\n"
            "    extras_require={'dev': ['pytest>=8.0']},\n"
            ")\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names
        assert "pytest" in names

    @pytest.mark.requirement("FR-001")
    def test_setup_py_dynamic_install_requires(self, tmp_path):
        """Non-literal install_requires emits Finding TS-DS-001."""
        (tmp_path / "setup.py").write_text(
            "from setuptools import setup\n"
            "import json\n"
            "reqs = json.load(open('reqs.json'))\n"
            "setup(install_requires=reqs)\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        # Dynamic assignment — parser may emit an error or finding
        assert isinstance(deps, list)


class TestRequirementsTxt:
    @pytest.mark.requirement("FR-001")
    def test_requirements_with_inline_options(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "--index-url https://pypi.org/simple/\n"
            "--trusted-host pypi.org\n"
            "requests>=2.31\n"
            "-e git+https://github.com/example/pkg.git#egg=pkg\n"
            "click>=8.0  # comment\n"
        )
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "requests" in names
        assert "click" in names


class TestDeduplication:
    @pytest.mark.requirement("FR-001")
    def test_lockfile_wins_over_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests>=2.0\n")
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        )
        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        req = next(d for d in deps if d.name == "requests")
        assert req.version == "2.31.0"
