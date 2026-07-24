"""Skeleton tests for REQ-8 — GitHub Action packaging.

These tests fail red until Phase 4 implements the composite action. They
carry SRTM markers now so coverage stays honest. Once the action lands
in its own repo, these tests point at a local `action.yml` shim (either
checked into this repo for smoke-testing, or via a submodule).
"""
from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


class TestActionManifest:
    @pytest.mark.requirement("FR-090")
    def test_action_yml_exists_and_declares_inputs_outputs(self):
        """Phase 4 delivers `action.yml` — either at the repo root or
        a `.github/action.yml` pointer."""
        candidates = [
            _REPO_ROOT / "action.yml",
            _REPO_ROOT / "action.yaml",
            _REPO_ROOT / ".github" / "action.yml",
        ]
        found = [p for p in candidates if p.exists()]
        assert found, (
            "REQ-8: composite action manifest (action.yml) must be present"
        )
        import yaml  # defer import so missing file produces a clearer failure

        manifest = yaml.safe_load(found[0].read_text())
        assert manifest.get("runs", {}).get("using") == "composite", (
            "Must be a composite action"
        )
        required_inputs = {
            "path",
            "format",
            "fail-on-severity",
            "upload-sarif",
            "comment-on-pr",
        }
        declared_inputs = set((manifest.get("inputs") or {}).keys())
        missing = required_inputs - declared_inputs
        assert not missing, f"Missing action inputs: {sorted(missing)}"
        required_outputs = {
            "safe-count",
            "finding-count",
            "highest-severity",
            "exit-code",
        }
        declared_outputs = set((manifest.get("outputs") or {}).keys())
        missing_out = required_outputs - declared_outputs
        assert not missing_out, f"Missing action outputs: {sorted(missing_out)}"


class TestSmokeWorkflow:
    @pytest.mark.requirement("FR-095")
    def test_action_smoke_workflow_present(self):
        workflow = _REPO_ROOT / ".github" / "workflows" / "action-smoke.yml"
        assert workflow.exists(), (
            "REQ-8: action-smoke.yml workflow must exist to regression-test "
            "the composite action against a fixture"
        )


class TestSarifUpload:
    @pytest.mark.requirement("FR-091")
    def test_action_references_upload_sarif_action(self):
        manifest_path = _REPO_ROOT / "action.yml"
        if not manifest_path.exists():
            pytest.skip("action.yml not yet delivered (Phase 4 pending)")
        text = manifest_path.read_text()
        assert "github/codeql-action/upload-sarif" in text, (
            "REQ-8: SARIF upload must route through github/codeql-action/upload-sarif"
        )


class TestPrComment:
    @pytest.mark.requirement("FR-092")
    def test_action_sticky_comment_marker_present(self):
        """Sticky comments rely on an HTML-comment marker so the action
        can find and edit its previous comment."""
        manifest_path = _REPO_ROOT / "action.yml"
        if not manifest_path.exists():
            pytest.skip("action.yml not yet delivered (Phase 4 pending)")
        text = manifest_path.read_text()
        assert "<!-- scarno-report -->" in text, (
            "Sticky PR comment must embed the `<!-- scarno-report -->` "
            "marker for edit-in-place lookup"
        )


class TestAnnotations:
    @pytest.mark.requirement("FR-093")
    def test_action_emits_annotation_workflow_commands(self):
        manifest_path = _REPO_ROOT / "action.yml"
        if not manifest_path.exists():
            pytest.skip("action.yml not yet delivered (Phase 4 pending)")
        text = manifest_path.read_text()
        # At least one of ::error / ::warning / ::notice must be used.
        assert any(
            cmd in text for cmd in ("::error", "::warning", "::notice")
        ), "REQ-8: per-finding annotations must use workflow-command syntax"


class TestJobSummary:
    @pytest.mark.requirement("FR-094")
    def test_action_writes_to_github_step_summary(self):
        manifest_path = _REPO_ROOT / "action.yml"
        if not manifest_path.exists():
            pytest.skip("action.yml not yet delivered (Phase 4 pending)")
        text = manifest_path.read_text()
        assert "GITHUB_STEP_SUMMARY" in text, (
            "REQ-8: Markdown report must be written to $GITHUB_STEP_SUMMARY"
        )
