"""Tests for the project-type auto-detector."""
from __future__ import annotations

import pytest

from scarno.core.detector import detect_project_type


class TestDetector:
    @pytest.mark.requirement("FR-001")
    def test_pom_xml_detected_as_java(self, tmp_path):
        (tmp_path / "pom.xml").touch()
        assert detect_project_type(tmp_path) == "java"

    @pytest.mark.requirement("FR-001")
    def test_build_gradle_detected_as_java(self, tmp_path):
        (tmp_path / "build.gradle").touch()
        assert detect_project_type(tmp_path) == "java"

    @pytest.mark.requirement("FR-001")
    def test_build_gradle_kts_detected_as_java(self, tmp_path):
        (tmp_path / "build.gradle.kts").touch()
        assert detect_project_type(tmp_path) == "java"

    @pytest.mark.requirement("FR-001")
    def test_pyproject_toml_detected_as_python(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        assert detect_project_type(tmp_path) == "python"

    @pytest.mark.requirement("FR-001")
    def test_requirements_txt_detected_as_python(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        assert detect_project_type(tmp_path) == "python"

    @pytest.mark.requirement("FR-001")
    def test_both_indicators_java_wins(self, tmp_path, capsys):
        """Java takes precedence when both sets are present; a warning is emitted."""
        (tmp_path / "pom.xml").touch()
        (tmp_path / "pyproject.toml").touch()
        result = detect_project_type(tmp_path)
        assert result == "java"
        captured = capsys.readouterr()
        assert "warning" in captured.err.lower() or "both" in captured.err.lower()

    @pytest.mark.requirement("FR-001")
    @pytest.mark.requirement("FR-002")
    def test_no_indicators_returns_none(self, tmp_path):
        assert detect_project_type(tmp_path) is None

    @pytest.mark.requirement("FR-001")
    def test_setup_py_detected_as_python(self, tmp_path):
        (tmp_path / "setup.py").touch()
        assert detect_project_type(tmp_path) == "python"

    @pytest.mark.requirement("FR-001")
    def test_pipfile_detected_as_python(self, tmp_path):
        (tmp_path / "Pipfile").touch()
        assert detect_project_type(tmp_path) == "python"

    @pytest.mark.requirement("FR-001")
    def test_uv_lock_detected_as_python(self, tmp_path):
        (tmp_path / "uv.lock").touch()
        assert detect_project_type(tmp_path) == "python"
