"""Tests for the analyser registry (REQ-9 / FR-102)."""
from __future__ import annotations

import pytest

from scarno.core import registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.models import AnalysisResult


class _NullAnalyser(BaseAnalyser):
    """Stand-in analyser for registry tests."""

    def supports(self, project_path: str) -> bool:
        return True

    def analyse(self, project_path: str) -> AnalysisResult:
        return AnalysisResult(
            project_type="null",
            project_path=project_path,
            dependencies=[],
            errors=[],
            findings=[],
            languages=[],
        )


class TestRegister:
    @pytest.mark.requirement("FR-102")
    def test_register_and_lookup(self):
        registry.register("null_test_lang", _NullAnalyser)
        try:
            analyser = registry.get_analyser("null_test_lang")
            assert analyser is not None
            assert isinstance(analyser, _NullAnalyser)
        finally:
            # Clean up by replacing with a no-op (clear() would nuke the real
            # python/java registrations done at import time).
            registry._REGISTRY.pop("null_test_lang", None)

    @pytest.mark.requirement("FR-102")
    def test_get_unknown_returns_none(self):
        assert registry.get_analyser("nonexistent_language_12345") is None

    @pytest.mark.requirement("FR-102")
    def test_registered_languages_sorted(self):
        langs = registry.registered_languages()
        assert langs == sorted(langs)

    @pytest.mark.requirement("FR-102")
    def test_registering_same_language_replaces(self):
        class _Other(_NullAnalyser):
            pass

        registry.register("replace_test", _NullAnalyser)
        registry.register("replace_test", _Other)
        try:
            analyser = registry.get_analyser("replace_test")
            assert isinstance(analyser, _Other)
        finally:
            registry._REGISTRY.pop("replace_test", None)


class TestAnalysersFor:
    @pytest.mark.requirement("FR-102")
    def test_returns_instances_for_known_languages(self):
        instances = registry.analysers_for(["python", "java"])
        assert len(instances) == 2

    @pytest.mark.requirement("FR-102")
    def test_unknown_languages_silently_skipped(self):
        instances = registry.analysers_for(["python", "nonexistent"])
        assert len(instances) == 1


class TestBootstrapRegistration:
    @pytest.mark.requirement("FR-102")
    def test_python_registered_on_import(self):
        # Importing scarno.analysers.python side-effect-registers.
        import scarno.analysers.python  # noqa: F401

        assert registry.get_analyser("python") is not None

    @pytest.mark.requirement("FR-102")
    def test_java_registered_on_import(self):
        import scarno.analysers.java  # noqa: F401

        assert registry.get_analyser("java") is not None
