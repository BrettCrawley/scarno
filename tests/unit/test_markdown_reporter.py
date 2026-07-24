"""Tests for :class:`MarkdownReporter` (REQ-7 extension)."""
from __future__ import annotations

import pytest

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    EntryPoint,
    Finding,
    FindingKind,
    FindingSeverity,
)
from scarno.reporters.markdown_reporter import MarkdownReporter


@pytest.fixture
def reporter() -> MarkdownReporter:
    return MarkdownReporter()


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
            ),
            Dependency(
                "requests",
                "2.31.0",
                DependencyStatus.IN_USE,
                "imported as 'requests' in project source",
                [
                    EntryPoint("requests.get", "function", True),
                    EntryPoint("requests.post", "function", False),
                ],
                1,
                2,
            ),
            Dependency(
                "pandas",
                None,
                DependencyStatus.UNDECLARED,
                "imported as 'pandas' but not declared in any dependency file",
                [],
                0,
                0,
            ),
            Dependency(
                "dotenv",
                None,
                DependencyStatus.UNCERTAIN,
                "dynamic import with non-literal module name",
                [],
                0,
                0,
            ),
        ],
        errors=["pyproject.toml: TOML parse warning"],
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


class TestSections:
    @pytest.mark.requirement("FR-080")
    def test_header_present(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        assert output.startswith("# Scarno analysis")
        assert "/tmp/demo" in output

    @pytest.mark.requirement("FR-080")
    def test_safe_section_has_unticked_checkboxes(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        assert "## Suggested removals (SAFE)" in output
        assert "- [ ] `boto3==1.26.0`" in output

    @pytest.mark.requirement("FR-080")
    def test_undeclared_section_has_unticked_checkboxes(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        assert "## Undeclared imports" in output
        assert "- [ ] `pandas`" in output

    @pytest.mark.requirement("FR-080")
    def test_uncertain_section_has_unticked_checkboxes(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        assert "## Manual review required (UNCERTAIN)" in output
        assert "- [ ] `dotenv`" in output

    @pytest.mark.requirement("FR-080")
    def test_in_use_section_lists_entry_points(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        assert "## In use" in output
        assert "`requests==2.31.0`" in output
        assert "1 / 2 entry points used" in output
        assert "`requests.get`" in output
        # unused entry points should NOT appear
        assert "requests.post" not in output

    @pytest.mark.requirement("FR-080")
    def test_findings_section_with_severity(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        assert "## Security findings" in output
        assert "**[HIGH]**" in output
        assert "**[CRITICAL]**" in output
        assert "`TS-SI-001`" in output
        assert "`TS-CE-001`" in output
        assert "`main.py:6`" in output
        assert "**Remediation:**" in output

    @pytest.mark.requirement("FR-080")
    def test_findings_sorted_by_severity_desc(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        crit_pos = output.index("[CRITICAL]")
        high_pos = output.index("[HIGH]")
        assert crit_pos < high_pos

    @pytest.mark.requirement("FR-080")
    def test_warnings_section_rendered(self, reporter, mixed_result):
        output = reporter.render(mixed_result)
        assert "## Warnings" in output
        assert "pyproject.toml: TOML parse warning" in output

    @pytest.mark.requirement("FR-080")
    def test_empty_result_valid(self, reporter):
        result = AnalysisResult("python", "/tmp/empty", [], [], [])
        output = reporter.render(result)
        assert output.startswith("# Scarno analysis")


class TestSanitisation:
    @pytest.mark.requirement("FR-080")
    @pytest.mark.requirement("SEC-003")
    @pytest.mark.security
    def test_ansi_escape_in_dep_name_stripped(self, reporter):
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "\x1b[2Jevil",
                    "1.0",
                    DependencyStatus.SAFE,
                    "no usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
            [],
        )
        output = reporter.render(result)
        assert "\x1b" not in output

    @pytest.mark.requirement("FR-080")
    @pytest.mark.security
    def test_markdown_special_chars_escaped(self, reporter):
        """Pipes, backticks and asterisks must be escaped to prevent table /
        code-block / emphasis injection via dep name."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "evil|name`with*markup[link](x)",
                    "1.0",
                    DependencyStatus.SAFE,
                    "pipes | in | reason",
                    [],
                    0,
                    0,
                )
            ],
            [],
            [],
        )
        output = reporter.render(result)
        # The raw pipe / backtick / asterisk must be escaped
        assert "\\|" in output or "|" not in output.split("## Suggested")[1].split("## ")[0]
        assert "\\`" in output or "`evil" in output


class TestInjectionPrevention:
    """SF-013 — adversarial dep names must not break markdown structure."""

    @pytest.mark.requirement("SF-013")
    @pytest.mark.security
    def test_heading_injection_blocked(self, reporter):
        """A dep name starting with ``# `` must not produce a new heading."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "# Malicious Heading",
                    "1.0",
                    DependencyStatus.SAFE,
                    "no usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
            [],
        )
        output = reporter.render(result)
        # Only the legitimate Scarno / section headings should exist.
        headings = [
            line
            for line in output.splitlines()
            if line.startswith("#") and not line.startswith("##")
        ]
        assert len(headings) == 1
        assert headings[0].startswith("# Scarno analysis")
        section_headings = [
            line for line in output.splitlines() if line.startswith("## ")
        ]
        for h in section_headings:
            assert "Malicious Heading" not in h

    @pytest.mark.requirement("SF-013")
    @pytest.mark.security
    def test_code_block_injection_blocked(self, reporter):
        """A reason containing a fenced code block must not open a new block."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "evil",
                    "1.0",
                    DependencyStatus.SAFE,
                    "reason\n```bash\nrm -rf /\n```",
                    [],
                    0,
                    0,
                )
            ],
            [],
            [],
        )
        output = reporter.render(result)
        # The legitimate diff (ASCII tree) fence is allowed; the
        # injected ```bash code block must NOT open — backticks are
        # escaped at the dep label.
        assert "```bash" not in output
        # The only fenced blocks are the legitimate ones — currently
        # one ```diff (opener + closer = 2 occurrences of ```).
        assert output.count("```") == 2

    @pytest.mark.requirement("SF-013")
    @pytest.mark.security
    def test_html_tag_injection_blocked(self, reporter):
        """``<script>…</script>`` in a dep name must not survive."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "<script>alert(1)</script>",
                    "1.0",
                    DependencyStatus.SAFE,
                    "no usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
            [],
        )
        output = reporter.render(result)
        assert "<script>" not in output
        assert "</script>" not in output

    @pytest.mark.requirement("SF-013")
    @pytest.mark.security
    def test_link_injection_escaped(self, reporter):
        """`[click](evil.com)` in a dep name must not render as a link."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "name[click](https://evil.com)",
                    "1.0",
                    DependencyStatus.SAFE,
                    "no usage",
                    [],
                    0,
                    0,
                )
            ],
            [],
            [],
        )
        output = reporter.render(result)
        # Either brackets are escaped, or the literal url string appears
        # without being a clickable markdown link (i.e. `[click]` remains
        # visible as text). Verify the brackets are escaped:
        assert "\\[click\\]" in output

    @pytest.mark.requirement("SF-013")
    @pytest.mark.security
    def test_control_chars_in_dep_name_stripped(self, reporter):
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    "pkg\x00\x01\r",
                    "1.0",
                    DependencyStatus.SAFE,
                    "reason\x00",
                    [],
                    0,
                    0,
                )
            ],
            [],
            [],
        )
        output = reporter.render(result)
        assert "\x00" not in output
        assert "\x01" not in output

    @pytest.mark.requirement("SF-013")
    @pytest.mark.security
    def test_rich_markup_in_finding_message_escaped(self, reporter):
        """Backticks / brackets in a finding message must not open
        code-spans or markdown links in the rendered report."""
        result = AnalysisResult(
            "python",
            "/tmp",
            [],
            [],
            [
                Finding(
                    rule_id="TS-SI-001",
                    kind=FindingKind.RUNTIME_PIP_INSTALL,
                    severity=FindingSeverity.HIGH,
                    file_path="m.py",
                    line=1,
                    snippet="s",
                    message="foo `evil` [click](x)",
                    remediation="do this",
                )
            ],
        )
        output = reporter.render(result)
        # Message content must appear only in escaped form
        assert "\\`evil\\`" in output
        assert "\\[click\\]" in output
