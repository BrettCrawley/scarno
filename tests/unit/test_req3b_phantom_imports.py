"""Skeleton tests for REQ-3b — Phantom & Undeclared Import Reporter."""
from __future__ import annotations

import textwrap

import pytest

from scarno.analysers.python.source_analyser import analyse_source_files
from scarno.models import Dependency, DependencyStatus


def _declared(name: str) -> Dependency:
    return Dependency(
        name=name,
        version=None,
        status=DependencyStatus.UNCERTAIN,
        reason="declared — source analysis pending",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


class TestUndeclaredStatus:
    @pytest.mark.requirement("FR-060")
    def test_undeclared_enum_exists(self):
        assert DependencyStatus.UNDECLARED.value == "UNDECLARED"


class TestPhantomImport:
    @pytest.mark.requirement("FR-061")
    def test_phantom_import_surfaced(self, tmp_path):
        (tmp_path / "main.py").write_text(
            "import requests\nimport yaml  # pyyaml undeclared\n"
        )
        updated, _ = analyse_source_files(str(tmp_path), [_declared("requests")])
        # Expect a new dep for pyyaml (resolved) OR yaml (unresolved)
        names = {d.name for d in updated}
        assert any(
            d.status == DependencyStatus.UNDECLARED for d in updated
        ), f"No UNDECLARED dep emitted; got {names}"

    @pytest.mark.requirement("FR-061")
    def test_undeclared_unresolved_import(self, tmp_path):
        (tmp_path / "main.py").write_text("import nonexistent_module_xyz\n")
        updated, _ = analyse_source_files(str(tmp_path), [])
        missing = next(
            (d for d in updated if d.name == "nonexistent_module_xyz"), None
        )
        assert missing is not None
        assert missing.status == DependencyStatus.UNDECLARED
        assert missing.resolved is False

    @pytest.mark.requirement("FR-061")
    def test_stdlib_not_flagged_as_undeclared(self, tmp_path):
        (tmp_path / "main.py").write_text("import json\nimport os\n")
        updated, _ = analyse_source_files(str(tmp_path), [])
        names = {d.name for d in updated}
        assert "json" not in names
        assert "os" not in names


class TestVendoredDetection:
    @pytest.mark.requirement("FR-062")
    def test_vendored_overlap_emits_finding(self, tmp_path):
        (tmp_path / "main.py").write_text("import requests\n")
        vendor = tmp_path / "vendor" / "requests"
        vendor.mkdir(parents=True)
        (vendor / "__init__.py").write_text("# vendored\n")
        updated, errors = analyse_source_files(
            str(tmp_path), [_declared("requests")]
        )
        # Vendored path should be recorded on the declared dep
        req = next((d for d in updated if d.name == "requests"), None)
        assert req is not None
        # Either vendored_path populated OR a finding/error mentions vendored
        assert (req.vendored_path is not None) or any(
            "vendor" in e.lower() for e in errors
        )


class TestNotebookCells:
    @pytest.mark.requirement("FR-063")
    def test_ipynb_cell_import_detected(self, tmp_path):
        import json

        notebook = {
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["import pandas\n"],
                    "metadata": {},
                    "outputs": [],
                    "execution_count": None,
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        (tmp_path / "analysis.ipynb").write_text(json.dumps(notebook))
        updated, _ = analyse_source_files(str(tmp_path), [])
        names = {d.name for d in updated}
        assert "pandas" in names or any(
            d.status == DependencyStatus.UNDECLARED for d in updated
        )

    @pytest.mark.requirement("FR-063")
    def test_malformed_ipynb_handled_gracefully(self, tmp_path):
        (tmp_path / "broken.ipynb").write_text("{not valid json")
        _, errors = analyse_source_files(str(tmp_path), [])
        assert any("notebook" in e.lower() or "json" in e.lower() for e in errors)
