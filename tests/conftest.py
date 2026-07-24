"""Shared pytest fixtures for the Scarno test suite."""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    EntryPoint,
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Return a temporary project directory (safe, confined)."""
    p = tmp_path / "project"
    p.mkdir(exist_ok=True)
    return p


@pytest.fixture
def simple_python_project(fixtures_dir: Path) -> Path:
    return fixtures_dir / "simple_python"


@pytest.fixture
def make_result():
    """Factory for AnalysisResult objects in tests."""

    def _make(
        deps: list[Dependency] | None = None,
        errors: list[str] | None = None,
        project_type: str = "python",
        project_path: str = "/tmp/test",
    ) -> AnalysisResult:
        return AnalysisResult(
            project_type=project_type,
            project_path=project_path,
            dependencies=deps or [],
            errors=errors or [],
        )

    return _make


@pytest.fixture
def safe_dep() -> Dependency:
    return Dependency(
        name="requests",
        version="2.31.0",
        status=DependencyStatus.SAFE,
        reason="No import or usage found in source files",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


@pytest.fixture
def in_use_dep() -> Dependency:
    return Dependency(
        name="flask",
        version="3.0.0",
        status=DependencyStatus.IN_USE,
        reason="Imported in src/app.py",
        entry_points=[
            EntryPoint(name="flask.Flask", kind="class", used=True),
            EntryPoint(name="flask.request", kind="constant", used=False),
        ],
        entry_points_used=1,
        entry_points_total=2,
    )


@pytest.fixture
def uncertain_dep() -> Dependency:
    return Dependency(
        name="boto3",
        version="1.26.0",
        status=DependencyStatus.UNCERTAIN,
        reason="Referenced via importlib.import_module() — manual review required",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


@pytest.fixture
def app_cli():
    """Re-export the Typer app so tests needing it can request a fixture."""
    return app
