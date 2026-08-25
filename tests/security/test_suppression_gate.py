"""Suppression must not silently clear the CI gate.

Both suppression routes are read out of the tree being analysed — a
``# scarno: allow`` comment in the source, and ``[tool.scarno.findings]``
in the project's own ``pyproject.toml``. When that tree is untrusted, a
pull request that adds a finding can add its own suppression in the same
change and the build stays green.

``--fail-on-suppressed-severity`` is the opt-in for scanning a tree you
do not control. It deliberately has no per-route mode: treating the
config route as "the operator's own configuration" is exactly what made
an earlier attempt at this bypassable, since that config is a file in the
scanned repository like any other.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scarno.cli import _exit_code_for
from scarno.models import (
    AnalysisResult,
    Finding,
    FindingKind,
    FindingSeverity,
)

pytestmark = pytest.mark.security


def _finding(*, suppressed: bool, by: str | None = None) -> Finding:
    return Finding(
        rule_id="TS-CE-001",
        kind=FindingKind.REMOTE_CODE_EXEC,
        severity=FindingSeverity.CRITICAL,
        file_path="evil.py",
        line=1,
        snippet="",
        message="remote code execution",
        remediation="",
        suppressed=suppressed,
        suppressed_by=by,
    )


def _result(finding: Finding) -> AnalysisResult:
    return AnalysisResult(
        project_type="python", project_path="/tmp", findings=[finding],
    )


class TestGateDefaults:
    @pytest.mark.requirement("FR-093")
    def test_unsuppressed_finding_still_gates(self):
        assert _exit_code_for(
            _result(_finding(suppressed=False)), FindingSeverity.HIGH,
        ) == 3

    @pytest.mark.requirement("FR-093")
    def test_suppression_still_silences_by_default(self):
        """Default behaviour is unchanged: suppression is how an operator
        silences a finding in their own repository."""
        assert _exit_code_for(
            _result(_finding(suppressed=True, by="inline")),
            FindingSeverity.HIGH,
        ) == 0


class TestOptInGateCoversBothRoutes:
    """The bypass the earlier attempt left open was a mode that trusted
    one of the two routes. Neither is trustworthy on an untrusted tree,
    so both must gate."""

    @pytest.mark.requirement("FR-093")
    @pytest.mark.parametrize("route", ["inline", "config", None])
    def test_every_suppression_route_gates_when_opted_in(self, route):
        assert _exit_code_for(
            _result(_finding(suppressed=True, by=route)),
            FindingSeverity.HIGH,
            fail_on_suppressed_severity=True,
        ) == 3

    @pytest.mark.requirement("FR-093")
    def test_below_threshold_suppressed_finding_does_not_gate(self):
        """The opt-in escalates suppressed findings into --fail-on-severity;
        it does not lower the threshold."""
        low = _finding(suppressed=True, by="config")
        low = Finding(**{**low.__dict__, "severity": FindingSeverity.LOW})
        assert _exit_code_for(
            _result(low),
            FindingSeverity.HIGH,
            fail_on_suppressed_severity=True,
        ) == 0


class TestSuppressionOriginIsRecorded:
    @pytest.mark.requirement("FR-093")
    def test_inline_directive_tags_the_finding(self, tmp_path):
        import ast

        from scarno.findings.engine import apply_rules

        source = (
            "import subprocess\n"
            "subprocess.run(['pip', 'install', 'x'])  # scarno: allow TS-SI-001\n"
        )
        findings = apply_rules("m.py", source, ast.parse(source))
        tagged = [f for f in findings if f.suppressed]
        assert tagged, "expected the inline directive to suppress"
        assert all(f.suppressed_by == "inline" for f in tagged)

    @pytest.mark.requirement("FR-093")
    def test_report_names_where_a_suppression_came_from(self):
        """A reviewer has to be able to see that the scanned tree chose
        this, not the operator."""
        from scarno.reporters.markdown_reporter import _render_findings

        lines = _render_findings([_finding(suppressed=True, by="config")])
        body = "\n".join(lines)
        assert "Suppressed findings (1)" in body
        assert "via config" in body, body
