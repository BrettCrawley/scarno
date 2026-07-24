"""Tests for :class:`SarifReporter` (REQ-7 extension)."""
from __future__ import annotations

import json

import pytest

from scarno.findings.rules import RULES
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
    FindingKind,
    FindingSeverity,
)
from scarno.reporters.sarif_reporter import SarifReporter


@pytest.fixture
def reporter() -> SarifReporter:
    return SarifReporter()


@pytest.fixture
def mixed_result() -> AnalysisResult:
    return AnalysisResult(
        project_type="python",
        project_path="/tmp/demo",
        dependencies=[
            Dependency(
                "boto3",
                "1.26.0",
                DependencyStatus.SAFE,
                "No import or usage found in source files",
                [],
                0,
                0,
                source="pyproject.toml:project",
            ),
            Dependency(
                "requests",
                "2.31.0",
                DependencyStatus.IN_USE,
                "imported as 'requests' in project source",
                [],
                0,
                0,
            ),
            Dependency(
                "pandas",
                None,
                DependencyStatus.UNDECLARED,
                "imported but not declared in any dependency file",
                [],
                0,
                0,
                source="detected:pandas",
            ),
        ],
        errors=["sample warning"],
        findings=[
            Finding(
                rule_id="TS-SI-001",
                kind=FindingKind.RUNTIME_PIP_INSTALL,
                severity=FindingSeverity.HIGH,
                file_path="main.py",
                line=6,
                snippet='subprocess.run(["pip", "install", "foo"])',
                message="Runtime pip install via subprocess",
                remediation="Declare the package in pyproject.toml",
            ),
            Finding(
                rule_id="TS-CE-001",
                kind=FindingKind.REMOTE_CODE_EXEC,
                severity=FindingSeverity.CRITICAL,
                file_path="main.py",
                line=10,
                snippet="exec(requests.get(url).text)",
                message="exec() applied to a network response",
                remediation="Never execute untrusted remote content",
            ),
        ],
    )


class TestSchema:
    @pytest.mark.requirement("FR-081")
    def test_output_is_valid_json(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        assert isinstance(data, dict)

    @pytest.mark.requirement("FR-081")
    def test_schema_and_version(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        assert data["version"] == "2.1.0"
        assert data["$schema"].endswith("sarif-2.1.0.json")

    @pytest.mark.requirement("FR-081")
    def test_single_run(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        assert isinstance(data["runs"], list)
        assert len(data["runs"]) == 1

    @pytest.mark.requirement("FR-081")
    def test_tool_driver_name_is_scarno(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "scarno"
        assert "version" in driver
        assert "informationUri" in driver


class TestRuleCatalogue:
    @pytest.mark.requirement("FR-083")
    def test_every_req3c_rule_id_present_in_driver_rules(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        for ts_rule in RULES.keys():
            assert ts_rule in rule_ids, f"SARIF driver rules missing {ts_rule}"

    @pytest.mark.requirement("FR-083")
    def test_dep_status_rules_included(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        assert "TS-DEP-SAFE" in rule_ids
        assert "TS-DEP-UNCERTAIN" in rule_ids
        assert "TS-DEP-UNDECLARED" in rule_ids


class TestResults:
    @pytest.mark.requirement("FR-081")
    def test_finding_becomes_result(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        results = data["runs"][0]["results"]
        rule_ids = {r["ruleId"] for r in results}
        assert "TS-SI-001" in rule_ids
        assert "TS-CE-001" in rule_ids

    @pytest.mark.requirement("FR-084")
    def test_severity_mapped_to_level(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        results = data["runs"][0]["results"]
        by_rule = {r["ruleId"]: r for r in results}
        assert by_rule["TS-SI-001"]["level"] == "error"     # HIGH → error
        assert by_rule["TS-CE-001"]["level"] == "error"     # CRITICAL → error

    @pytest.mark.requirement("FR-081")
    def test_finding_location_includes_line(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        results = data["runs"][0]["results"]
        ts_si = next(r for r in results if r["ruleId"] == "TS-SI-001")
        locs = ts_si["locations"]
        assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "main.py"
        assert locs[0]["physicalLocation"]["region"]["startLine"] == 6

    @pytest.mark.requirement("FR-081")
    def test_safe_dep_becomes_note_level_result(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        results = data["runs"][0]["results"]
        safe = next(r for r in results if r["ruleId"] == "TS-DEP-SAFE")
        assert safe["level"] == "note"
        assert "boto3" in safe["message"]["text"]

    @pytest.mark.requirement("FR-081")
    def test_undeclared_dep_becomes_warning_level_result(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        results = data["runs"][0]["results"]
        und = next(r for r in results if r["ruleId"] == "TS-DEP-UNDECLARED")
        assert und["level"] == "warning"
        assert "pandas" in und["message"]["text"]

    @pytest.mark.requirement("FR-081")
    def test_in_use_deps_not_emitted_as_results(self, reporter, mixed_result):
        data = json.loads(reporter.render(mixed_result))
        results = data["runs"][0]["results"]
        for r in results:
            assert "requests" not in r.get("message", {}).get("text", "") or (
                r["ruleId"] in {"TS-SI-001", "TS-CE-001"}  # finding mentioning requests.get is fine
            )


class TestSuppressions:
    @pytest.mark.requirement("FR-081")
    def test_suppressed_finding_has_suppressions_node(self, reporter):
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[],
            errors=[],
            findings=[
                Finding(
                    rule_id="TS-SI-001",
                    kind=FindingKind.RUNTIME_PIP_INSTALL,
                    severity=FindingSeverity.HIGH,
                    file_path="main.py",
                    line=1,
                    snippet="subprocess.run(...)",
                    message="m",
                    remediation="r",
                    suppressed=True,
                )
            ],
        )
        data = json.loads(reporter.render(result))
        sarif_result = data["runs"][0]["results"][0]
        assert "suppressions" in sarif_result


class TestSanitisation:
    @pytest.mark.requirement("FR-081")
    @pytest.mark.requirement("SEC-NEW-03")
    @pytest.mark.security
    def test_control_chars_stripped_from_messages(self, reporter):
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[],
            errors=[],
            findings=[
                Finding(
                    rule_id="TS-SI-001",
                    kind=FindingKind.RUNTIME_PIP_INSTALL,
                    severity=FindingSeverity.HIGH,
                    file_path="evil\x00.py",
                    line=1,
                    snippet="payload\x00",
                    message="msg\x00with control",
                    remediation="rem\x1b[31m",
                )
            ],
        )
        raw = reporter.render(result)
        assert "\x00" not in raw
        assert "\x1b" not in raw
        # Output must still be valid JSON after stripping.
        json.loads(raw)


class TestInjectionPrevention:
    """SF-014 — adversarial dep names and findings must not break JSON shape."""

    @pytest.mark.requirement("SF-014")
    @pytest.mark.requirement("SEC-004")
    @pytest.mark.security
    def test_json_injection_via_dep_name_blocked(self, reporter):
        """A dep name containing JSON syntax must be carried as a string
        value, not interpreted as structure."""
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[
                Dependency(
                    '{"injected": true, "rootKey": "pwned"}',
                    "1.0",
                    DependencyStatus.SAFE,
                    "no usage",
                    [],
                    0,
                    0,
                )
            ],
            errors=[],
            findings=[],
        )
        data = json.loads(reporter.render(result))
        # The injected JSON must NOT appear as a top-level key.
        assert "injected" not in data
        assert "rootKey" not in data
        # It must appear as the string value of properties.package.
        safe = next(
            r
            for r in data["runs"][0]["results"]
            if r["ruleId"] == "TS-DEP-SAFE"
        )
        assert isinstance(safe["properties"]["package"], str)
        assert "injected" in safe["properties"]["package"]

    @pytest.mark.requirement("SF-014")
    @pytest.mark.requirement("SEC-003")
    @pytest.mark.security
    def test_ansi_escape_in_finding_message_stripped(self, reporter):
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[],
            errors=[],
            findings=[
                Finding(
                    rule_id="TS-SI-001",
                    kind=FindingKind.RUNTIME_PIP_INSTALL,
                    severity=FindingSeverity.HIGH,
                    file_path="m.py",
                    line=1,
                    snippet="s",
                    message="\x1b[31mdanger\x1b[0m",
                    remediation="r",
                )
            ],
        )
        data = json.loads(reporter.render(result))
        msg = data["runs"][0]["results"][0]["message"]["text"]
        assert "\x1b" not in msg
        assert "danger" in msg

    @pytest.mark.requirement("SF-014")
    @pytest.mark.security
    def test_quotes_in_dep_name_escaped_correctly(self, reporter):
        """A dep name with embedded quotes must not escape the JSON string."""
        result = AnalysisResult(
            project_type="python",
            project_path="/tmp",
            dependencies=[
                Dependency(
                    'evil"}, "injected": ["x"], "fake":"',
                    "1.0",
                    DependencyStatus.SAFE,
                    "no usage",
                    [],
                    0,
                    0,
                )
            ],
            errors=[],
            findings=[],
        )
        data = json.loads(reporter.render(result))
        # No top-level keys from the adversarial string.
        assert "injected" not in data
        assert "fake" not in data
        # The dep-level properties should contain the literal string.
        safe = next(
            r
            for r in data["runs"][0]["results"]
            if r["ruleId"] == "TS-DEP-SAFE"
        )
        assert "injected" in safe["properties"]["package"]


class TestRuleCatalogueConsistency:
    """SF-015 — SARIF rules must stay in lockstep with findings/rules.py."""

    @pytest.mark.requirement("SF-015")
    @pytest.mark.requirement("FR-083")
    def test_every_sarif_rule_id_is_either_in_rules_dict_or_dep_synth(
        self, reporter
    ):
        data = json.loads(
            reporter.render(AnalysisResult("python", "/tmp", [], [], []))
        )
        rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        dep_synth = {
            "TS-DEP-SAFE",
            "TS-DEP-UNCERTAIN",
            "TS-DEP-UNDECLARED",
            # REQ-17 — IN_USE deps with usage_count carried in properties.
            "TS-DEP-INUSE",
            # REQ-20 / FR-207 — coordinate present at >1 declared version.
            "TS-DEP-MULTI-VERSION",
            # REQ-21 / FR-215 — Maven pin-override.
            "TS-DEP-PIN-OVERRIDE-MAVEN",
            # REQ-23 / FR-246 — npm pin-override.
            "TS-DEP-PIN-OVERRIDE-NPM",
            # REQ-21b / FR-225 — Gradle pin-override.
            "TS-DEP-PIN-OVERRIDE-GRADLE",
        }
        for rid in rule_ids:
            assert rid in RULES or rid in dep_synth, (
                f"SARIF driver rule '{rid}' is neither in RULES nor a "
                f"synthesised dep rule — catalogue drift"
            )

    @pytest.mark.requirement("SF-015")
    def test_no_rules_missing_from_sarif(self, reporter):
        data = json.loads(
            reporter.render(AnalysisResult("python", "/tmp", [], [], []))
        )
        rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        missing = set(RULES.keys()) - rule_ids
        assert not missing, (
            f"Rules present in findings/rules.py but missing from SARIF: "
            f"{sorted(missing)}"
        )
