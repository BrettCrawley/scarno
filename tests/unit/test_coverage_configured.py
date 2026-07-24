"""Self-check: coverage reporting is configured for every pytest run.

Maps to FR-085 — the project commitment that running ``pytest`` at any
time produces a coverage report, so developers and CI both see the
same data.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def pyproject() -> dict[str, object]:
    with (_REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


class TestCoverageConfiguredOnEveryRun:
    @pytest.mark.requirement("FR-085")
    def test_pytest_addopts_includes_coverage(self, pyproject):
        """pyproject.toml must include ``--cov=src/scarno`` in pytest addopts."""
        pytest_cfg = pyproject["tool"]["pytest"]["ini_options"]
        addopts = pytest_cfg.get("addopts", "")
        assert "--cov=src/scarno" in addopts, (
            "pytest addopts must include --cov=src/scarno so every "
            "invocation produces a coverage report (FR-085)"
        )

    @pytest.mark.requirement("FR-085")
    def test_coverage_reports_include_html_and_xml(self, pyproject):
        """HTML + XML reports are required so CI can publish artefacts."""
        addopts = pyproject["tool"]["pytest"]["ini_options"]["addopts"]
        assert "--cov-report=xml" in addopts
        assert "--cov-report=html" in addopts
        assert "--cov-report=term-missing" in addopts

    @pytest.mark.requirement("FR-085")
    def test_coverage_fail_under_threshold_enforced(self, pyproject):
        """Coverage must fail under a non-trivial threshold.

        The threshold ramps per PLAN.md phase:
          * ≥ 75 today (Phases 0a → 1.5)
          * ≥ 85 once Phase 2 (Maven + JVM) green
          * ≥ 90 once Phase 3 (Gradle) green

        Keep the *floor* test strict — if someone tries to silently drop
        the threshold to 0, the gate fails.
        """
        report = pyproject["tool"]["coverage"]["report"]
        assert isinstance(report.get("fail_under"), (int, float))
        assert report["fail_under"] >= 75, (
            "fail_under must be at or above 75% to be meaningful at this phase"
        )

    @pytest.mark.requirement("FR-085")
    def test_coverage_source_is_src_package(self, pyproject):
        """Coverage must be measured against src/scarno, not tests/."""
        run_cfg = pyproject["tool"]["coverage"]["run"]
        sources = run_cfg.get("source") or []
        assert sources == ["src/scarno"]
        omit = run_cfg.get("omit") or []
        assert any("tests" in o for o in omit)


class TestCoverageArtefactsProduced:
    """These tests run AFTER pytest has begun — since addopts forces
    ``--cov``, coverage.py is actively recording. We verify the files
    appear at the end of the run by checking the config that names them."""

    @pytest.mark.requirement("FR-085")
    def test_xml_report_path_is_predictable(self, pyproject):
        # coverage.py writes to ``coverage.xml`` in cwd by default; we do
        # not override that, so the CI ``Upload coverage XML`` step can
        # find it deterministically.
        report = pyproject["tool"]["coverage"]["report"]
        # No explicit output path override → default is used, which is
        # fine for CI. Assert there's no surprise override.
        assert "output" not in report

    @pytest.mark.requirement("FR-085")
    def test_html_output_dir_is_default_htmlcov(self, pyproject):
        html_cfg = pyproject["tool"]["coverage"].get("html", {})
        # Default html output dir is ``htmlcov/``; don't override.
        if "directory" in html_cfg:
            assert html_cfg["directory"] == "htmlcov"
