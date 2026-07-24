"""TDD red tests for gap remediation (GAP-A, GAP-B, GAP-C).

These tests are written BEFORE the implementation. They must FAIL now
and pass once the gaps are addressed. Each test traces to the gap ID
in ``docs/gap-remediation-plan.md``.
"""
from __future__ import annotations

import pytest


# ═══════════════════════════════════════════════════════════════════════════
# GAP-A: HTML scanner should emit Finding objects for remote CDN scripts
#
# The HTML scanner discovers <script src="https://cdn..."> and
# <link rel="stylesheet" href="https://cdn..."> but currently does NOT
# emit Finding objects. It should — just like the CSS analyser emits
# TS-CE-007 for remote @import.
# ═══════════════════════════════════════════════════════════════════════════


class TestGapA_HtmlScannerFindings:
    @pytest.mark.requirement("SF-019")
    def test_remote_script_src_emits_finding(self, tmp_path):
        """A <script src="https://cdn..."> in an HTML file must emit a
        Finding object (not just a dependency) so it surfaces in the
        security findings section of the report."""
        from scarno.analysers.html_scanner import scan_html_templates

        (tmp_path / "index.html").write_text(
            '<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        # Must have a findings attribute with at least one Finding
        assert hasattr(result, "findings"), (
            "HtmlScanResult must have a 'findings' field"
        )
        assert any(
            f.rule_id == "TS-CE-012" for f in result.findings
        ), "remote <script src> should emit Finding TS-CE-012"

    @pytest.mark.requirement("SF-019")
    def test_remote_stylesheet_emits_finding(self, tmp_path):
        """A <link rel="stylesheet" href="https://cdn..."> must also
        emit a Finding."""
        from scarno.analysers.html_scanner import scan_html_templates

        (tmp_path / "index.html").write_text(
            '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css">\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert hasattr(result, "findings")
        # Could be TS-CE-012 or TS-CE-007 (reuse CSS remote import rule) —
        # either is acceptable as long as a finding fires.
        assert any(
            f.rule_id in ("TS-CE-012", "TS-CE-007") for f in result.findings
        ), "remote <link stylesheet> should emit a security Finding"

    @pytest.mark.requirement("SF-019")
    def test_local_script_does_not_emit_finding(self, tmp_path):
        """Local script sources must NOT emit a security finding."""
        from scarno.analysers.html_scanner import scan_html_templates

        (tmp_path / "index.html").write_text(
            '<script src="./js/app.js"></script>\n'
            '<script src="/static/vendor.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        if hasattr(result, "findings"):
            assert result.findings == [], (
                "local <script src> must not emit findings"
            )

    @pytest.mark.requirement("SF-019")
    def test_inline_script_module_import_from_cdn_emits_finding(self, tmp_path):
        """An ESM import from a CDN inside <script type="module"> should
        emit a finding."""
        from scarno.analysers.html_scanner import scan_html_templates

        (tmp_path / "index.html").write_text(
            '<script type="module">\n'
            '  import vue from "https://cdn.jsdelivr.net/npm/vue@3/dist/vue.esm-browser.js";\n'
            "</script>\n"
        )
        result = scan_html_templates(str(tmp_path))
        assert hasattr(result, "findings")
        assert len(result.findings) >= 1, (
            "CDN ESM import should emit a Finding"
        )

    @pytest.mark.requirement("SF-019")
    def test_rule_ts_ce_012_exists_in_catalogue(self):
        """The rule catalogue must contain TS-CE-012."""
        from scarno.findings.rules import RULES

        assert "TS-CE-012" in RULES, (
            "TS-CE-012 (remote script in HTML) must be in the rule catalogue"
        )
        rule = RULES["TS-CE-012"]
        assert rule.severity is not None
        assert rule.message
        assert rule.remediation

    @pytest.mark.requirement("SF-019")
    def test_html_findings_merged_into_cli_output(self, tmp_path):
        """HTML scanner findings must appear in the CLI's merged
        AnalysisResult alongside other findings."""
        from typer.testing import CliRunner
        from scarno.cli import app
        import json

        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = ['requests']\n"
        )
        (tmp_path / "templates").mkdir()
        (tmp_path / "templates" / "base.html").write_text(
            '<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.js"></script>\n'
        )

        runner = CliRunner()
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.stdout)
        findings = data.get("findings", [])
        assert any(
            f.get("rule_id") == "TS-CE-012" for f in findings
        ), "TS-CE-012 finding must appear in CLI JSON output"


# ═══════════════════════════════════════════════════════════════════════════
# GAP-B: Tree-sitter grammar wheel hash pinning
#
# pyproject.toml uses >= ranges for tree-sitter deps. They should use
# == exact pins to prevent a compromised wheel from loading malicious
# native code in-process.
# ═══════════════════════════════════════════════════════════════════════════


class TestGapB_TreeSitterPinning:
    @pytest.mark.requirement("SEC-003")
    def test_tree_sitter_deps_use_exact_pins(self):
        """Every tree-sitter-* dependency in pyproject.toml must use
        an exact version pin (==), not a range (>=)."""
        import tomllib
        from pathlib import Path

        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())

        # Scope strictly to the runtime dependency array — not keywords,
        # comments, or other strings elsewhere in the file.
        ts_deps = [
            dep
            for dep in data["project"]["dependencies"]
            if dep.startswith("tree-sitter")
        ]
        assert ts_deps, "no tree-sitter deps found in pyproject.toml"

        for dep in ts_deps:
            assert ">=" not in dep, (
                f"tree-sitter dep uses >= range (must be == exact pin): {dep}"
            )
            assert "==" in dep, (
                f"tree-sitter dep missing == exact pin: {dep}"
            )


# ═══════════════════════════════════════════════════════════════════════════
# GAP-C: CDN URLs must not appear in error messages
#
# If the HTML scanner encounters an error, the error string must
# contain only file paths — never the CDN URLs extracted from the file.
# ═══════════════════════════════════════════════════════════════════════════


class TestGapC_CdnUrlsNotInErrors:
    @pytest.mark.requirement("SEC-003")
    def test_error_messages_do_not_contain_cdn_urls(self, tmp_path):
        """When the HTML scanner encounters a read error, the error
        message must NOT contain any CDN URL from the file."""
        from scarno.analysers.html_scanner import scan_html_templates

        # Create a template with CDN URLs, then make it unreadable
        html = tmp_path / "broken.html"
        html.write_text(
            '<script src="https://cdn.jsdelivr.net/npm/evil@1/evil.js"></script>\n'
        )
        html.chmod(0o000)
        try:
            result = scan_html_templates(str(tmp_path))
            for error in result.errors:
                assert "cdn.jsdelivr.net" not in error, (
                    f"CDN URL leaked into error message: {error}"
                )
                assert "evil.js" not in error, (
                    f"CDN filename leaked into error message: {error}"
                )
        finally:
            html.chmod(0o644)

    @pytest.mark.requirement("SEC-003")
    def test_oversized_html_error_does_not_contain_urls(self, tmp_path):
        """When an HTML file is skipped for being too large, the error
        must not mention any URL from the file."""
        from scarno.analysers.html_scanner import scan_html_templates
        from scarno.security import MAX_FILE_BYTES

        html = tmp_path / "huge.html"
        html.write_text(
            '<script src="https://cdn.jsdelivr.net/npm/secret-internal-pkg@1/app.js"></script>\n'
            + "x" * (MAX_FILE_BYTES + 1)
        )
        result = scan_html_templates(str(tmp_path))
        for error in result.errors:
            assert "secret-internal-pkg" not in error
            assert "cdn.jsdelivr.net" not in error
