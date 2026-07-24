"""Tests for multi-language project detection (REQ-9 / FR-097)."""
from __future__ import annotations

import pytest

from scarno.core import detector


class TestDetectProjectTypes:
    @pytest.mark.requirement("FR-097")
    def test_returns_list(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        result = detector.detect_project_types(tmp_path)
        assert isinstance(result, list)
        assert result == ["python"]

    @pytest.mark.requirement("FR-097")
    def test_python_and_java_both_detected(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "pom.xml").touch()
        result = detector.detect_project_types(tmp_path)
        assert "python" in result
        assert "java" in result

    @pytest.mark.requirement("FR-097")
    def test_empty_directory_returns_empty_list(self, tmp_path):
        assert detector.detect_project_types(tmp_path) == []

    @pytest.mark.requirement("FR-097")
    def test_javascript_detected_via_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        assert "javascript" in detector.detect_project_types(tmp_path)

    @pytest.mark.requirement("FR-097")
    def test_go_detected_via_go_mod(self, tmp_path):
        (tmp_path / "go.mod").write_text("module x\n")
        assert "go" in detector.detect_project_types(tmp_path)

    @pytest.mark.requirement("FR-097")
    def test_csharp_detected_via_csproj_glob(self, tmp_path):
        (tmp_path / "App.csproj").write_text("<Project />")
        assert "csharp" in detector.detect_project_types(tmp_path)

    @pytest.mark.requirement("FR-097")
    def test_css_detected_alongside_js_when_stylesheets_present(self, tmp_path):
        """REQ-12 (post-Phase 5): CSS analysis runs alongside JS, not
        exclusive of it — CSS-side Findings (TS-CE-007 / TS-CE-008)
        must fire even when a JS package.json is the primary indicator.
        The original REQ-9 draft made these mutually exclusive; Phase 5
        relaxed that.
        """
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "styles.css").write_text("")
        result = detector.detect_project_types(tmp_path)
        assert "javascript" in result
        assert "css" in result

    @pytest.mark.requirement("FR-097")
    def test_css_detected_standalone(self, tmp_path):
        (tmp_path / "styles.css").write_text("")
        result = detector.detect_project_types(tmp_path)
        assert "css" in result

    @pytest.mark.requirement("FR-097")
    def test_polyglot_deterministic_order(self, tmp_path):
        """java first, then python (REQ-1 smoke test relies on this)."""
        (tmp_path / "pom.xml").touch()
        (tmp_path / "pyproject.toml").touch()
        result = detector.detect_project_types(tmp_path)
        assert result == ["java", "python"]


class TestLegacyDetectProjectType:
    @pytest.mark.requirement("FR-097")
    def test_returns_first_detected(self, tmp_path):
        (tmp_path / "pom.xml").touch()
        (tmp_path / "pyproject.toml").touch()
        assert detector.detect_project_type(tmp_path) == "java"

    @pytest.mark.requirement("FR-097")
    def test_returns_none_for_empty_directory(self, tmp_path):
        assert detector.detect_project_type(tmp_path) is None
