"""REQ-17 — Markdown reporter ASCII dependency-tree tests.

The Mermaid renderer was replaced with a vertical Unix-style ASCII
tree wrapped in a ```diff fenced block (FR-152). These tests pin
the structural shape of the new output: placement before checklists,
status-derived diff prefixes for colour, branch glyphs, cycle
handling, truncation, and the directly-used-transitive promote row.
"""
from __future__ import annotations

import pytest

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    EntryPoint,
)
from scarno.reporters.markdown_reporter import MarkdownReporter


def _dep(
    name: str,
    status: DependencyStatus,
    *,
    transitive: bool = False,
    imported_directly: bool = False,
    ecosystem: str = "pypi",
) -> Dependency:
    return Dependency(
        name=name,
        version=None,
        status=status,
        reason=f"{status.value}",
        source=ecosystem,
        ecosystem=ecosystem,
        is_transitive=transitive,
        imported_directly=imported_directly,
    )


def _extract_diff_block(markdown: str) -> str:
    start = markdown.index("```diff")
    end = markdown.index("```", start + len("```diff"))
    return markdown[start:end]


class TestAsciiTreeShape:
    @pytest.mark.requirement("FR-152")
    def test_diff_fenced_block_appears_before_checklists(self):
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[_dep("alpha", DependencyStatus.SAFE)],
            languages=["python"],
        )
        out = MarkdownReporter().render(result)
        assert "```diff" in out
        diff_idx = out.index("```diff")
        first_h2 = out.find("\n## ")
        assert diff_idx < first_h2

    @pytest.mark.requirement("FR-152")
    def test_project_root_row_present(self):
        result = AnalysisResult(
            project_type="python", project_path="/p/my-project",
            dependencies=[_dep("alpha", DependencyStatus.SAFE)],
            languages=["python"],
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        # Project root row carries the project_path string with a
        # neutral two-space marker.
        assert "/p/my-project" in block

    @pytest.mark.requirement("FR-152")
    def test_safe_dep_uses_dash_diff_prefix(self):
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[_dep("alpha", DependencyStatus.SAFE)],
            languages=["python"],
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        # SAFE deps render with a leading ``- `` — coloured red by
        # diff-aware viewers.
        safe_lines = [
            l for l in block.splitlines()
            if l.startswith("- ") and "alpha" in l
        ]
        assert safe_lines, (
            f"expected `- ` prefix on SAFE dep alpha; got block:\n{block}"
        )

    @pytest.mark.requirement("FR-152")
    def test_uncertain_dep_uses_bang_diff_prefix(self):
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[_dep("beta", DependencyStatus.UNCERTAIN)],
            languages=["python"],
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        bang_lines = [
            l for l in block.splitlines()
            if l.startswith("! ") and "beta" in l
        ]
        assert bang_lines

    @pytest.mark.requirement("FR-152")
    def test_in_use_dep_neutral_prefix(self):
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=[_dep("gamma", DependencyStatus.IN_USE)],
            languages=["python"],
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        # IN_USE: leading two spaces, no diff colour marker.
        in_use_lines = [
            l for l in block.splitlines()
            if "gamma" in l
        ]
        assert in_use_lines
        # No `-` or `!` first character on the in-use row.
        for line in in_use_lines:
            assert not line.startswith("- ")
            assert not line.startswith("! ")

    @pytest.mark.requirement("FR-152")
    def test_directly_used_transitive_renders_neutral(self):
        """Transitive + imported_directly stays neutral (used) regardless
        of parent's status."""
        deps = [
            _dep("parent", DependencyStatus.SAFE),
            _dep("trans", DependencyStatus.IN_USE,
                 transitive=True, imported_directly=True),
        ]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
            dep_graph={"parent": {"trans"}},
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        trans_lines = [l for l in block.splitlines() if "trans" in l]
        assert trans_lines
        # The trans row must NOT carry the `- ` (red) marker even
        # though its parent is SAFE.
        for line in trans_lines:
            assert not line.startswith("- "), (
                f"directly-used transitive falsely red: {line!r}"
            )


class TestAsciiTreeBranches:
    @pytest.mark.requirement("FR-152")
    def test_unicode_branch_chars_used(self):
        deps = [
            _dep("a", DependencyStatus.IN_USE),
            _dep("b", DependencyStatus.IN_USE, transitive=True),
            _dep("c", DependencyStatus.IN_USE, transitive=True),
        ]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
            dep_graph={"a": {"b", "c"}},
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        # Tree must use unicode branch chars.
        assert "├──" in block or "└──" in block
        assert "│" in block or "└──" in block

    @pytest.mark.requirement("FR-152")
    def test_transitive_nested_under_parent(self):
        deps = [
            _dep("alpha", DependencyStatus.IN_USE),
            _dep("beta", DependencyStatus.IN_USE, transitive=True),
            _dep("gamma", DependencyStatus.IN_USE, transitive=True),
        ]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
            dep_graph={"alpha": {"beta"}, "beta": {"gamma"}},
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        lines = block.splitlines()
        alpha_idx = next(i for i, l in enumerate(lines) if "alpha" in l)
        beta_idx = next(i for i, l in enumerate(lines) if "beta" in l)
        gamma_idx = next(i for i, l in enumerate(lines) if "gamma" in l)
        # Order: alpha, beta, gamma (DFS pre-order).
        assert alpha_idx < beta_idx < gamma_idx
        # Indentation increases with depth.
        assert lines[gamma_idx].index("gamma") > lines[beta_idx].index("beta")
        assert lines[beta_idx].index("beta") > lines[alpha_idx].index("alpha")

    @pytest.mark.requirement("FR-152")
    def test_cycle_in_dep_graph_does_not_recurse_forever(self):
        """A → B → A cycle must terminate."""
        deps = [
            _dep("a", DependencyStatus.IN_USE),
            _dep("b", DependencyStatus.IN_USE, transitive=True),
        ]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
            dep_graph={"a": {"b"}, "b": {"a"}},
        )
        # Should return without raising or hanging.
        block = _extract_diff_block(MarkdownReporter().render(result))
        assert block.count("\n") < 100, (
            "tree appears to have recursed past sane bounds"
        )


class TestAsciiTreeTruncation:
    @pytest.mark.requirement("FR-152")
    def test_node_cap_emits_truncation_notice(self):
        """Pin the cap behaviour without hard-coding 500/1000 — probes
        ``_TREE_NODE_CAP`` directly so a future bump (or revert)
        doesn't silently break the assertion. Generates ``cap + 100``
        deps so truncation is guaranteed to fire."""
        from scarno.reporters.markdown_reporter import _TREE_NODE_CAP

        deps = [
            _dep(f"d{i:04d}", DependencyStatus.SAFE)
            for i in range(_TREE_NODE_CAP + 100)
        ]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        assert "tree truncated" in block.lower()
        # No more than ``_TREE_NODE_CAP`` dep rows rendered.
        dep_rows = [l for l in block.splitlines() if "d0" in l]
        assert len(dep_rows) <= _TREE_NODE_CAP


class TestPromoteSubsection:
    @pytest.mark.requirement("FR-156")
    def test_promote_subsection_present_when_directly_used_transitive_exists(self):
        deps = [
            _dep("regular", DependencyStatus.IN_USE),
            _dep("promote-me", DependencyStatus.IN_USE,
                 transitive=True, imported_directly=True),
        ]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
        )
        out = MarkdownReporter().render(result)
        assert "imported directly" in out.lower()

    @pytest.mark.requirement("FR-156")
    def test_promote_subsection_above_in_use_section(self):
        deps = [
            _dep("regular", DependencyStatus.IN_USE),
            _dep("promote-me", DependencyStatus.IN_USE,
                 transitive=True, imported_directly=True),
        ]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
        )
        out = MarkdownReporter().render(result)
        promote_idx = out.lower().find("imported directly")
        in_use_idx = out.find("## In use")
        assert promote_idx != -1 and in_use_idx != -1
        assert promote_idx < in_use_idx

    @pytest.mark.requirement("FR-156")
    def test_promote_subsection_absent_when_no_directly_used_transitive(self):
        deps = [_dep("regular", DependencyStatus.IN_USE)]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
        )
        out = MarkdownReporter().render(result)
        # The phrase must NOT appear (neither in tree nor in checklist).
        # Loose check: "imported directly" in tree label appears only
        # when at least one dep has `imported_directly=True`.
        assert "imported directly" not in out.lower()


class TestAsciiLabelHelpers:
    @pytest.mark.requirement("SEC-NEW-32")
    def test_label_truncated_at_max(self):
        from scarno.reporters.markdown_reporter import _ascii_label
        long = "a" * 500
        assert len(_ascii_label(long)) <= 200

    @pytest.mark.requirement("SEC-NEW-32")
    def test_label_neutralises_backtick(self):
        """Backtick must not survive — would close the surrounding fence."""
        from scarno.reporters.markdown_reporter import _ascii_label
        assert "`" not in _ascii_label("evil`name`")

    @pytest.mark.requirement("SEC-NEW-32")
    def test_label_neutralises_newline(self):
        from scarno.reporters.markdown_reporter import _ascii_label
        out = _ascii_label("line1\nline2")
        assert "\n" not in out
        assert "\r" not in out
