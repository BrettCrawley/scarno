"""TA-336 — REQ-24 / FR-266 — top-of-report banner appears in every
reporter when the analysis was network-augmented (any artefact
fetched OR any provenance="remote" finding).

Banner is absent for analyses with no remote activity (the pre-REQ-24
default path). The four reporters render it differently:

* text — leading "⚠ " line right after the header.
* markdown — blockquote near the top.
* json — structured ``remote_provenance`` object on the payload.
* sarif — ``runs[0].properties.remoteProvenance`` object.
"""
from __future__ import annotations

import json

import pytest

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
    FindingKind,
    FindingSeverity,
)
from scarno.reporters.json_reporter import JsonReporter
from scarno.reporters.markdown_reporter import MarkdownReporter
from scarno.reporters.sarif_reporter import SarifReporter
from scarno.reporters.text_reporter import TextReporter


def _result_with_remote_activity() -> AnalysisResult:
    return AnalysisResult(
        project_type="java",
        project_path="/tmp/p",
        dependencies=[
            Dependency(
                name="com.example:lib", version="1.0",
                status=DependencyStatus.IN_USE, reason="",
                ecosystem="maven",
            ),
        ],
        findings=[
            Finding(
                rule_id="TS-ABI-DRIFT",
                kind=FindingKind.ABI_DRIFT,
                severity=FindingSeverity.MEDIUM,
                file_path="", line=0, snippet="",
                message="m", remediation="r",
                provenance="remote",
            ),
        ],
        errors=[
            "req24-fetch: REMOTE FETCH ENABLED — about to query 1 host",
            "req24-fetch: fetched com.example:lib@1.0 from https://repo.example/m2",
        ],
    )


def _result_local_only() -> AnalysisResult:
    return AnalysisResult(
        project_type="java",
        project_path="/tmp/p",
        dependencies=[
            Dependency(
                name="com.example:lib", version="1.0",
                status=DependencyStatus.IN_USE, reason="",
            ),
        ],
        findings=[
            Finding(
                rule_id="TS-ABI-DRIFT",
                kind=FindingKind.ABI_DRIFT,
                severity=FindingSeverity.MEDIUM,
                file_path="", line=0, snippet="",
                message="m", remediation="r",
                provenance="local",
            ),
        ],
    )


# ── present when remote activity occurred ──────────────────────────────────


class TestBannerPresent:
    @pytest.mark.requirement("FR-266")
    def test_text_banner_visible_in_header_area(self):
        rendered = TextReporter().render(_result_with_remote_activity())
        # Banner appears within the first few lines (after project_path /
        # project_type lines).
        head = "\n".join(rendered.splitlines()[:6])
        assert "⚠" in head
        assert "fetched 1 artefact" in head
        assert "1 finding(s) have provenance=remote" in head
        assert "--fail-on-remote-severity" in head

    @pytest.mark.requirement("FR-266")
    def test_markdown_banner_blockquote(self):
        rendered = MarkdownReporter().render(_result_with_remote_activity())
        head = "\n".join(rendered.splitlines()[:10])
        assert "Remote-fetch active" in head
        # Blockquote prefix.
        assert any(l.startswith("> ") for l in rendered.splitlines()[:10])

    @pytest.mark.requirement("FR-266")
    def test_json_remote_provenance_object(self):
        payload = json.loads(
            JsonReporter().render(_result_with_remote_activity())
        )
        rp = payload["remote_provenance"]
        assert rp["active"] is True
        assert rp["fetch_count"] == 1
        assert rp["remote_finding_count"] == 1

    @pytest.mark.requirement("FR-266")
    def test_sarif_remote_provenance_property(self):
        sarif = json.loads(
            SarifReporter().render(_result_with_remote_activity())
        )
        rp = sarif["runs"][0]["properties"]["remoteProvenance"]
        assert rp["active"] is True
        assert rp["fetchCount"] == 1
        assert rp["remoteFindingCount"] == 1


# ── absent when there is no remote activity ────────────────────────────────


class TestBannerAbsent:
    @pytest.mark.requirement("FR-266")
    def test_text_no_banner_for_local_only(self):
        rendered = TextReporter().render(_result_local_only())
        assert "⚠" not in rendered
        assert "Remote-fetch" not in rendered

    @pytest.mark.requirement("FR-266")
    def test_markdown_no_banner_for_local_only(self):
        rendered = MarkdownReporter().render(_result_local_only())
        assert "Remote-fetch" not in rendered

    @pytest.mark.requirement("FR-266")
    def test_json_remote_provenance_inactive_for_local_only(self):
        payload = json.loads(JsonReporter().render(_result_local_only()))
        rp = payload["remote_provenance"]
        assert rp["active"] is False
        assert rp["fetch_count"] == 0
        assert rp["remote_finding_count"] == 0

    @pytest.mark.requirement("FR-266")
    def test_sarif_remote_provenance_inactive_for_local_only(self):
        sarif = json.loads(SarifReporter().render(_result_local_only()))
        rp = sarif["runs"][0]["properties"]["remoteProvenance"]
        assert rp["active"] is False
