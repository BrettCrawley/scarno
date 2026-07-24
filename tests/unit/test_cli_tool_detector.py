"""Tests for ``scarno.analysers.python.cli_tool_detector``.

Covers the five detection sources (Dockerfiles, Procfile, shell scripts,
pyproject scripts, config files) plus their helpers.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scarno.analysers.python.cli_tool_detector import (
    CLI_TOOL_TO_PACKAGE,
    _detect_from_config_files,
    _detect_from_dockerfiles,
    _detect_from_procfile,
    _detect_from_pyproject_scripts,
    _detect_from_shell_scripts,
    _extract_command_word,
    _read_text_safe,
    detect_cli_tool_usage,
)


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


class TestExtractCommandWord:
    @pytest.mark.requirement("FR-001")
    def test_json_array_form(self):
        assert _extract_command_word('["gunicorn", "app:app"]') == "gunicorn"

    @pytest.mark.requirement("FR-001")
    def test_invalid_json_falls_back_to_shell(self):
        assert _extract_command_word("[bad json gunicorn app:app") == "[bad"

    @pytest.mark.requirement("FR-001")
    def test_shell_form_strips_path_prefix(self):
        assert _extract_command_word("/usr/local/bin/gunicorn app") == "gunicorn"

    @pytest.mark.requirement("FR-001")
    def test_strips_exec_wrapper(self):
        assert _extract_command_word("exec gunicorn app:app") == "gunicorn"

    @pytest.mark.requirement("FR-001")
    def test_strips_sudo_env_nohup(self):
        assert _extract_command_word("sudo env nohup uvicorn x") == "uvicorn"

    @pytest.mark.requirement("FR-001")
    def test_blank_returns_none(self):
        assert _extract_command_word("") is None
        assert _extract_command_word("   ") is None

    @pytest.mark.requirement("FR-001")
    def test_only_wrappers_returns_none(self):
        assert _extract_command_word("exec sudo env") is None


class TestReadTextSafe:
    @pytest.mark.requirement("SEC-NEW-04")
    def test_oversized_returns_none(self, tmp_path, monkeypatch):
        from scarno.analysers.python import cli_tool_detector as mod
        monkeypatch.setattr(mod, "MAX_FILE_BYTES", 10)
        big = tmp_path / "big.txt"
        big.write_text("x" * 100)
        assert _read_text_safe(big) is None

    @pytest.mark.requirement("FR-001")
    def test_missing_file_returns_none(self, tmp_path):
        assert _read_text_safe(tmp_path / "nope") is None

    @pytest.mark.requirement("FR-001")
    def test_normal_read(self, tmp_path):
        p = tmp_path / "ok.txt"
        p.write_text("hello")
        assert _read_text_safe(p) == "hello"


class TestDockerfileDetection:
    @pytest.mark.requirement("FR-001")
    def test_dockerfile_cmd_shell_form(self, tmp_path):
        _write(tmp_path / "Dockerfile",
               "FROM python:3\nCMD gunicorn app:app\n")
        tools = _detect_from_dockerfiles(tmp_path)
        assert "gunicorn" in tools

    @pytest.mark.requirement("FR-001")
    def test_dockerfile_entrypoint_json(self, tmp_path):
        _write(tmp_path / "Dockerfile",
               'FROM python:3\nENTRYPOINT ["uvicorn", "app:app"]\n')
        tools = _detect_from_dockerfiles(tmp_path)
        assert "uvicorn" in tools

    @pytest.mark.requirement("FR-001")
    def test_dockerfile_in_docker_subdir(self, tmp_path):
        _write(tmp_path / "docker" / "Dockerfile.api",
               "CMD celery -A app worker\n")
        tools = _detect_from_dockerfiles(tmp_path)
        assert "celery" in tools

    @pytest.mark.requirement("FR-001")
    def test_dockerfile_unknown_command_skipped(self, tmp_path):
        _write(tmp_path / "Dockerfile", "CMD some-other-binary\n")
        tools = _detect_from_dockerfiles(tmp_path)
        assert tools == set()

    @pytest.mark.requirement("FR-001")
    def test_no_dockerfile_returns_empty(self, tmp_path):
        assert _detect_from_dockerfiles(tmp_path) == set()


class TestProcfileDetection:
    @pytest.mark.requirement("FR-001")
    def test_procfile_basic(self, tmp_path):
        _write(tmp_path / "Procfile", "web: gunicorn app:app\n")
        assert "gunicorn" in _detect_from_procfile(tmp_path)

    @pytest.mark.requirement("FR-001")
    def test_procfile_skips_comments_and_blanks(self, tmp_path):
        _write(tmp_path / "Procfile",
               "# top comment\n\nweb: uvicorn app\nworker: celery -A app\n")
        tools = _detect_from_procfile(tmp_path)
        assert "uvicorn" in tools
        assert "celery" in tools

    @pytest.mark.requirement("FR-001")
    def test_procfile_no_colon_skipped(self, tmp_path):
        _write(tmp_path / "Procfile", "this line has no colon\n")
        assert _detect_from_procfile(tmp_path) == set()

    @pytest.mark.requirement("FR-001")
    def test_procfile_missing(self, tmp_path):
        assert _detect_from_procfile(tmp_path) == set()


class TestShellScriptDetection:
    @pytest.mark.requirement("FR-001")
    def test_root_sh_script(self, tmp_path):
        _write(tmp_path / "run.sh", "#!/bin/sh\ngunicorn app:app\n")
        assert "gunicorn" in _detect_from_shell_scripts(tmp_path)

    @pytest.mark.requirement("FR-001")
    def test_docker_dir_sh(self, tmp_path):
        _write(tmp_path / "docker" / "start.sh", "uvicorn app\n")
        assert "uvicorn" in _detect_from_shell_scripts(tmp_path)

    @pytest.mark.requirement("FR-001")
    def test_scripts_dir_sh(self, tmp_path):
        _write(tmp_path / "scripts" / "go.sh", "celery worker\n")
        assert "celery" in _detect_from_shell_scripts(tmp_path)

    @pytest.mark.requirement("FR-001")
    def test_named_entrypoint_at_root(self, tmp_path):
        _write(tmp_path / "entrypoint.sh", "alembic upgrade head\n")
        assert "alembic" in _detect_from_shell_scripts(tmp_path)


class TestPyprojectScripts:
    @pytest.mark.requirement("FR-001")
    def test_console_scripts_pulled(self, tmp_path):
        _write(tmp_path / "pyproject.toml",
               "[project]\nname='x'\nversion='0'\n"
               "[project.scripts]\n"
               'mycli = "alpha.cli:main"\n'
               'other = "beta_pkg.app:run"\n')
        tools = _detect_from_pyproject_scripts(tmp_path)
        assert "alpha" in tools
        assert "beta-pkg" in tools

    @pytest.mark.requirement("FR-001")
    def test_no_pyproject(self, tmp_path):
        assert _detect_from_pyproject_scripts(tmp_path) == set()

    @pytest.mark.requirement("FR-001")
    def test_invalid_toml_returns_empty(self, tmp_path):
        _write(tmp_path / "pyproject.toml", "this is { not toml")
        assert _detect_from_pyproject_scripts(tmp_path) == set()

    @pytest.mark.requirement("FR-001")
    def test_no_scripts_section(self, tmp_path):
        _write(tmp_path / "pyproject.toml",
               "[project]\nname='x'\nversion='0'\n")
        assert _detect_from_pyproject_scripts(tmp_path) == set()


class TestConfigFileDetection:
    @pytest.mark.requirement("FR-001")
    def test_config_file_present(self, tmp_path):
        _write(tmp_path / "alembic.ini", "[alembic]\n")
        assert "alembic" in _detect_from_config_files(tmp_path)

    @pytest.mark.requirement("FR-001")
    def test_alembic_dir(self, tmp_path):
        (tmp_path / "alembic").mkdir()
        assert "alembic" in _detect_from_config_files(tmp_path)

    @pytest.mark.requirement("FR-001")
    def test_migrations_env_py(self, tmp_path):
        _write(tmp_path / "migrations" / "env.py", "")
        assert "alembic" in _detect_from_config_files(tmp_path)

    @pytest.mark.requirement("FR-001")
    def test_no_config_files(self, tmp_path):
        assert _detect_from_config_files(tmp_path) == set()


class TestDetectCliToolUsage:
    @pytest.mark.requirement("FR-001")
    def test_full_pipeline(self, tmp_path):
        _write(tmp_path / "Dockerfile", "CMD gunicorn app:app\n")
        _write(tmp_path / "Procfile", "web: uvicorn x\n")
        _write(tmp_path / "alembic.ini", "[alembic]\n")
        tools, errors = detect_cli_tool_usage(str(tmp_path))
        assert {"gunicorn", "uvicorn", "alembic"}.issubset(tools)
        assert errors == []

    @pytest.mark.requirement("FR-001")
    def test_returns_canonical_names(self, tmp_path):
        # py.test → pytest (alias normalisation)
        _write(tmp_path / "Procfile", "test: py.test\n")
        tools, _ = detect_cli_tool_usage(str(tmp_path))
        assert "pytest" in tools


class TestCanonicalAliases:
    @pytest.mark.requirement("FR-001")
    def test_known_aliases_present(self):
        assert CLI_TOOL_TO_PACKAGE["py.test"] == "pytest"
        assert CLI_TOOL_TO_PACKAGE["django-admin"] == "django"
        assert CLI_TOOL_TO_PACKAGE["sphinx-build"] == "sphinx"
