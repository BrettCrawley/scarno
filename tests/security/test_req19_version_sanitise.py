"""PR-1 red tests — SEC-NEW-38 (and the SEC-NEW-54 extension) version-string
sanitisation.

The sanitiser is the single trust transition between attacker-controlled
manifest content and every reporter. It must:
  * strip control characters,
  * strip Mermaid-active tokens (REQ-17 SEC-NEW-32 surface),
  * strip Markdown-table-breaking and inline-code-breaking characters
    (SEC-NEW-54 per-destination extension),
  * ensure JSON-encodeability,
  * cap length at 64 bytes.
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.security


def _sanitise(value):
    """Lazy-import wrapper so the module collects on pre-Phase-9 code."""
    from scarno.security import sanitise_declared_version
    return sanitise_declared_version(value)


# ── TA-211 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-38")
def test_version_string_strips_control_chars():
    """TA-211 — ANSI + C0/C1 control bytes are removed."""
    poisoned = "1.0\x1b[31mEVIL\x1b[0m\x07\x00"
    result = _sanitise(poisoned)
    # Control + ANSI bytes gone; the inert "EVIL" text remains (as ordinary
    # version-string characters — sanitiser strips bytes, not semantic words).
    assert result is not None
    assert "\x1b" not in result
    assert "\x07" not in result
    assert "\x00" not in result
    assert "\x1b[" not in result


# ── TA-212 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-38")
def test_version_string_strips_mermaid_active_chars():
    """TA-212 — Mermaid-active tokens (], [, newline, click directive)
    are stripped or rendered inert.
    """
    poisoned = '1.0]; click n_0 "javascript:alert(1)"\n'
    result = _sanitise(poisoned)
    assert result is not None
    # Mermaid label cannot be broken by a stray ].
    assert "]" not in result
    # No "click " substring may reach a renderer.
    assert "click" not in result.lower()
    # Newlines must be stripped or replaced with space.
    assert "\n" not in result


# ── TA-213 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-38")
def test_version_string_capped_at_64_chars():
    """TA-213 — 200-char input is capped to ≤ 64 chars."""
    poisoned = "A" * 200
    result = _sanitise(poisoned)
    assert result is not None
    assert len(result) <= 64, (
        f"version string length {len(result)} exceeds 64-byte cap"
    )


# ── TA-214 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-38")
def test_version_string_safe_for_markdown_table():
    """TA-214 — A ``|`` in the version must not break the rendered
    "Multiple versions detected" table (SEC-NEW-54 extension).
    """
    poisoned = "1.0|alpha"
    result = _sanitise(poisoned)
    assert result is not None
    # Either the pipe is stripped or it is escaped (\\|). Either makes the
    # GFM table row parse correctly. We accept both shapes here.
    assert "|" not in result or "\\|" in result, (
        "raw '|' in sanitised version string would break the markdown table"
    )


# ── TA-215 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-38")
def test_version_string_safe_for_markdown_inline_code():
    """TA-215 — A backtick in the version cannot open inline code or break
    the rendered row.
    """
    poisoned = "1.0`bad`"
    result = _sanitise(poisoned)
    assert result is not None
    assert "`" not in result, (
        "raw backtick in sanitised version string would open inline code"
    )


# ── TA-216 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-38")
def test_version_string_json_encodeable():
    """TA-216 — Adversarial version string round-trips through json.dumps
    without raising and survives a json.loads of the result.
    """
    poisoned = '1.0\x00"weird\\\x1b[31m'
    cleaned = _sanitise(poisoned)
    assert cleaned is not None
    encoded = json.dumps(cleaned)
    decoded = json.loads(encoded)
    assert decoded == cleaned


# ── TA-219 (lives in this file alongside the sanitiser tests) ───────────────


@pytest.mark.requirement("SEC-NEW-38")
def test_pom_xml_with_adversarial_version_no_breakage(tmp_path, monkeypatch):
    """TA-219 — Adversarial <version> field in a pom.xml flows through the
    Maven walker → sanitise_declared_version → markdown reporter without
    introducing a ``click `` substring or a stray newline that would break
    the diff-fence tree block.
    """
    from scarno.analysers.java import maven as _maven
    from scarno.reporters.markdown_reporter import MarkdownReporter

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pom.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>poisoned</artifactId>
      <version>1.0]; click n_0 "javascript:alert(1)"</version>
    </dependency>
  </dependencies>
</project>
"""
    )
    monkeypatch.setattr(_maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2")

    result = _maven.MavenPomResolver().analyse(str(project_root))
    rendered = MarkdownReporter().render(result)

    # The rendered output must not contain the click directive substring
    # nor split the diff-fence block by a stray newline.
    assert "click " not in rendered.lower(), (
        "Mermaid click directive smuggled into rendered output"
    )
    # The diff-fence block must remain a contiguous block.
    diff_open_count = rendered.count("```diff")
    diff_close_count = rendered.count("```\n") + (
        1 if rendered.rstrip().endswith("```") else 0
    )
    # We assert openings and closings are balanced (well-formed).
    assert diff_open_count <= diff_close_count
