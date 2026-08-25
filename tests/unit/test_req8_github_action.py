"""Skeleton tests for REQ-8 — GitHub Action packaging.

These tests fail red until Phase 4 implements the composite action. They
carry SRTM markers now so coverage stays honest. Once the action lands
in its own repo, these tests point at a local `action.yml` shim (either
checked into this repo for smoke-testing, or via a submodule).
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _extract_collect_script(manifest_text: str) -> str:
    """Pull the inline Python heredoc out of the ``collect`` step so it can
    be executed directly (the runner feeds it to ``python -``)."""
    lines = manifest_text.splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.strip() == "python - <<'PY'"]
    assert starts, "action.yml must run the collect step via a `python - <<'PY'` heredoc"
    start = starts[0]
    ends = [i for i in range(start + 1, len(lines)) if lines[i].strip() == "PY"]
    assert ends, "unterminated `PY` heredoc in action.yml"
    return textwrap.dedent("\n".join(lines[start + 1 : ends[0]])) + "\n"


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

    @pytest.mark.requirement("FR-093")
    def test_annotation_fields_are_escaped_against_command_injection(self, tmp_path):
        """A scanned repo controls ``file_path`` / ``rule_id`` (paths may
        contain any byte but NUL and '/'). Every interpolated field must be
        escaped, or a path holding an LF starts a workflow command of the
        attacker's choosing — ``::stop-commands::`` hides all later findings.
        """
        manifest_path = _REPO_ROOT / "action.yml"
        if not manifest_path.exists():
            pytest.skip("action.yml not yet delivered (Phase 4 pending)")
        script = _extract_collect_script(manifest_path.read_text())

        report = {
            "dependencies": [],
            "findings": [
                {
                    "severity": "HIGH",
                    "file_path": "src/a\n::stop-commands::deadbeef\nevil.py",
                    "line": "1\n::error::forged",
                    "rule_id": "TS-SI-001\n::notice::forged",
                    "message": "bad\n::warning::forged",
                },
            ],
        }
        (tmp_path / "scarno.json").write_text(json.dumps(report))

        proc = subprocess.run(
            [sys.executable, "-"],
            input=script,
            cwd=tmp_path,
            env={
                "PATH": "/usr/bin:/bin",
                "GITHUB_OUTPUT": str(tmp_path / "github_output"),
                "TS_ANNOTATE": "true",
            },
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr

        # One finding may only ever produce one line: the runner parses a
        # workflow command at the start of a line, so a second line would be
        # an attacker-authored command.
        emitted = proc.stdout.splitlines()
        assert len(emitted) == 1, (
            f"one finding must emit exactly one workflow command, got: {emitted!r}"
        )
        head, sep, body = emitted[0][2:].partition("::")
        assert sep, emitted[0]
        cmd, _, props = head.partition(" ")
        assert cmd == "error", emitted[0]
        # ':' terminates the property list and ',' separates properties, so
        # neither may survive from a finding field.
        assert ":" not in props, props
        assert props.count(",") == 2, props
        assert props.startswith("file="), props
        assert "%0A" in props and "%3A" in props, props
        assert "%0A" in body, body


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
