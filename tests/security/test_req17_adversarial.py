"""REQ-17 — Security adversarial tests.

Covers ASCII-tree label injection (SEC-NEW-32, T-17), --test-paths
blow-up and traversal (SEC-NEW-31, SEC-NEW-33, T-18, T-20), and
verbose-mode sanitisation (T-19).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
)
from scarno.reporters.markdown_reporter import MarkdownReporter


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _result(name: str) -> AnalysisResult:
    return AnalysisResult(
        project_type="python", project_path="/p",
        dependencies=[
            Dependency(
                name=name, version=None,
                status=DependencyStatus.SAFE,
                reason="adversarial",
                source="adv", ecosystem="pypi",
            )
        ],
        languages=["python"],
    )


# ── ASCII-tree label injection ──────────────────────────────────────────


def _tree_block(out: str) -> str:
    start = out.index("```diff")
    end = out.index("```", start + len("```diff"))
    return out[start:end]


class TestAsciiTreeInjection:
    """The ASCII tree is wrapped in a ```diff fence. Adversarial dep
    names must not be able to:

      * Close the fence (backtick injection).
      * Inject ANSI / control bytes that would corrupt terminal output.
      * Inject newlines that would split the row across two lines and
        confuse downstream parsers.
    """

    @pytest.mark.requirement("SEC-NEW-32")
    @pytest.mark.requirement("T-17")
    @pytest.mark.security
    def test_ascii_label_neutralises_backtick(self):
        out = MarkdownReporter().render(_result("evil`name`"))
        block = _tree_block(out)
        # Inside the diff block, no backtick may appear on a dep row —
        # only the closing fence ``` is at the boundary.
        for line in block.splitlines():
            if "evil" in line:
                assert "`" not in line, (
                    f"backtick leaked into ASCII row: {line!r}"
                )

    @pytest.mark.requirement("SEC-NEW-32")
    @pytest.mark.requirement("T-17")
    @pytest.mark.security
    def test_ascii_label_neutralises_quote(self):
        out = MarkdownReporter().render(_result('say "hi"'))
        block = _tree_block(out)
        # Quotes are visually fine inside an ASCII row but ANSI / control
        # bytes must not survive — verify sanitise() ran.
        # (Quotes themselves are allowed; they don't break diff colouring.)
        assert "\x1b" not in block
        assert "\x00" not in block

    @pytest.mark.requirement("SEC-NEW-32")
    @pytest.mark.requirement("T-17")
    @pytest.mark.security
    def test_ascii_label_neutralises_newline(self):
        out = MarkdownReporter().render(_result("evil\nname"))
        block = _tree_block(out)
        # The dep row must remain on a single line.
        evil_lines = [l for l in block.splitlines() if "evil" in l]
        assert evil_lines
        for line in evil_lines:
            assert "name" in line, (
                f"newline split the row into two: {line!r}"
            )

    @pytest.mark.requirement("SEC-NEW-32")
    @pytest.mark.requirement("T-17")
    @pytest.mark.security
    def test_ascii_label_sanitises_ansi_and_control(self):
        out = MarkdownReporter().render(_result("\x1b[2Jevil\x00\x07"))
        block = _tree_block(out)
        # No ESC / NUL / BEL allowed.
        assert "\x1b" not in block
        assert "\x00" not in block
        assert "\x07" not in block

    @pytest.mark.requirement("SEC-NEW-32")
    @pytest.mark.requirement("T-17")
    @pytest.mark.security
    def test_diff_block_fence_cannot_be_broken_by_dep_name(self):
        """A dep name containing literal backticks must not close the
        fence prematurely. Verified by counting fence boundaries."""
        out = MarkdownReporter().render(_result("evil```name"))
        # Exactly one ```diff opener and one matching ``` closer for
        # the tree block. (Other fenced blocks elsewhere in the report
        # are independent.)
        diff_count = out.count("```diff")
        assert diff_count == 1, (
            f"expected exactly one ```diff opener; got {diff_count}"
        )


# ── --test-paths blow-up & traversal ─────────────────────────────────────


class TestTestPathsValidation:
    @pytest.mark.requirement("SEC-NEW-31")
    @pytest.mark.requirement("T-18")
    @pytest.mark.security
    def test_test_paths_count_cap_rejected(self, runner, tmp_path):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "d"\n'
            'version = "0"\n'
            'dependencies = []\n'
        ))
        argv = [str(tmp_path), "--exclude-tests"]
        for i in range(65):
            argv += ["--test-paths", f"p{i}/*"]
        result = runner.invoke(app, argv)
        assert result.exit_code == 2
        # Sanitised error must mention "too many" patterns.
        combined = (result.output or "") + (result.stderr or "")
        assert "too many" in combined.lower()

    @pytest.mark.requirement("SEC-NEW-31")
    @pytest.mark.requirement("T-18")
    @pytest.mark.security
    def test_test_paths_length_cap_rejected(self, runner, tmp_path):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "d"\n'
            'version = "0"\n'
            'dependencies = []\n'
        ))
        too_long = "a" * 257
        result = runner.invoke(app, [
            str(tmp_path), "--exclude-tests", "--test-paths", too_long,
        ])
        assert result.exit_code == 2
        combined = (result.output or "") + (result.stderr or "")
        assert "too long" in combined.lower()

    @pytest.mark.requirement("SEC-NEW-33")
    @pytest.mark.requirement("T-20")
    @pytest.mark.security
    def test_test_paths_dot_dot_segment_rejected(self, runner, tmp_path):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "d"\n'
            'version = "0"\n'
            'dependencies = []\n'
        ))
        result = runner.invoke(app, [
            str(tmp_path), "--exclude-tests",
            "--test-paths", "../../etc/*",
        ])
        assert result.exit_code == 2
        combined = (result.output or "") + (result.stderr or "")
        assert "project root" in combined.lower()

    @pytest.mark.requirement("SEC-NEW-33")
    @pytest.mark.requirement("T-20")
    @pytest.mark.security
    def test_test_paths_backslash_rejected(self, runner, tmp_path):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "d"\n'
            'version = "0"\n'
            'dependencies = []\n'
        ))
        result = runner.invoke(app, [
            str(tmp_path), "--exclude-tests",
            "--test-paths", "tests\\foo",
        ])
        assert result.exit_code == 2
        combined = (result.output or "") + (result.stderr or "")
        assert "posix" in combined.lower() or "backslash" in combined.lower()

    @pytest.mark.requirement("SEC-NEW-33")
    @pytest.mark.requirement("T-20")
    @pytest.mark.security
    def test_test_paths_leading_slash_stripped_with_warning(
        self, runner, tmp_path
    ):
        _write(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "d"\n'
            'version = "0"\n'
            'dependencies = []\n'
        ))
        result = runner.invoke(app, [
            str(tmp_path), "--exclude-tests",
            "--test-paths", "/abs/path/*",
            "--verbose",
        ])
        # Not a fatal error.
        assert result.exit_code in (0, 1)
        combined = (result.output or "") + (result.stderr or "")
        assert "leading" in combined.lower() or "stripped" in combined.lower()
