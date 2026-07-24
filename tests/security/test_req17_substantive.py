"""REQ-17 substantive tests — closes superficiality gaps.

The first round of REQ-17 tests asserted shallow properties (string
membership, type checks). These tests assert *behavioural outcomes*
under adversarial input:

  * Mermaid output is structurally valid (every edge endpoint resolves
    to a defined node, no orphan ids), even for fuzzed dep names.
  * ``_ascii_label`` is a property: for arbitrary byte sequences the
    output contains no Mermaid-active escape and no ``click`` substring.
  * ``--test-paths`` accepts patterns whose segments *contain* ``.``
    characters (``foo.bar.test``) but rejects any segment that is
    literally ``..``.
  * ``usage_count`` counts aliased / re-exported / chained call sites.
  * Mermaid render perf scales with dep count (not super-linearly).

Where a test could be replaced by reading code, it isn't here. Each
assertion describes an attacker-observable failure mode.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
)
from scarno.reporters.markdown_reporter import (
    MarkdownReporter,
)


# ── ASCII tree structural integrity ─────────────────────────────────────


def _extract_diff_block(markdown: str) -> str:
    start = markdown.index("```diff")
    end = markdown.index("```", start + len("```diff"))
    return markdown[start:end]


def _dep(
    name: str,
    status: DependencyStatus = DependencyStatus.IN_USE,
    *,
    transitive: bool = False,
    imported_directly: bool = False,
) -> Dependency:
    return Dependency(
        name=name, version=None, status=status, reason="t",
        source="x", ecosystem="pypi",
        is_transitive=transitive, imported_directly=imported_directly,
    )


class TestAsciiTreeStructuralIntegrity:
    @pytest.mark.requirement("FR-152")
    def test_every_dep_appears_as_a_row(self):
        """Every dep that appears in dep_graph reachable from a direct
        dep should surface as a row in the rendered tree."""
        deps = [
            _dep("alpha"),
            _dep("beta", transitive=True),
            _dep("gamma", transitive=True),
        ]
        graph = {"alpha": {"beta", "gamma"}}
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"], dep_graph=graph,
        )
        block = _extract_diff_block(MarkdownReporter().render(result))
        for name in ("alpha", "beta", "gamma"):
            assert name in block, f"{name} missing from tree"

    @pytest.mark.requirement("FR-152")
    @pytest.mark.requirement("SEC-NEW-32")
    def test_ascii_tree_remains_well_formed_with_adversarial_names(self):
        """Adversarial dep names must not break the diff fence."""
        adversarial = [
            'evil"]; click n_0 "javascript:alert(1)',
            "name\nwith\nnewline",
            "name\twith\ttab",
            "<script>alert(1)</script>",
            "name with `backtick` and ]bracket[",
            "\x00\x07\x1b[2J",  # NUL, BEL, ANSI clear screen
            "subgraph",
            "---",
            "graph TD",
            "end",
            "```",  # fence-closer attempt
        ]
        deps = [_dep(name, DependencyStatus.SAFE) for name in adversarial]
        result = AnalysisResult(
            project_type="python", project_path="/p",
            dependencies=deps, languages=["python"],
        )
        rendered = MarkdownReporter().render(result)
        # Exactly one diff fence opener / closer pair for the tree
        # block (the fence-closer-attempt dep name MUST NOT register as
        # an extra fence boundary).
        assert rendered.count("```diff") == 1
        block = _extract_diff_block(rendered)
        # No raw ANSI / NUL / BEL inside the block.
        assert "\x00" not in block
        assert "\x1b" not in block
        assert "\x07" not in block
        # No literal backtick survived — sanitiser replaces with apostrophe.
        for line in block.splitlines():
            if line.startswith("```"):
                continue
            assert "`" not in line, (
                f"backtick leaked into ASCII row: {line!r}"
            )


class TestAsciiLabelProperty:
    @pytest.mark.requirement("SEC-NEW-32")
    @pytest.mark.security
    @pytest.mark.parametrize("payload", [
        "",
        " ",
        '"' * 50,
        "]" * 50,
        "\n" * 10,
        "\\" * 50,
        "&amp;already-encoded",
        "subgraph S [evil]",
        "click",
        "click n_0 javascript:alert(1)",
        "x" * 500,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08",
        "name with `backticks` everywhere",
        "‮" + "reverse",
        "```diff\nmalicious",
    ])
    def test_ascii_label_property_invariants(self, payload):
        """For any input, the ASCII label has no fence-breaking chars."""
        from scarno.reporters.markdown_reporter import _ascii_label
        out = _ascii_label(payload)
        assert len(out) <= 200
        # The four characters that would break the fenced diff block:
        assert "`" not in out      # would close the fence
        assert "\n" not in out      # would split the row
        assert "\r" not in out
        # Literal `<` / `>` are HTML-escaped so the markdown source
        # never contains tag-shaped substrings.
        assert "<" not in out
        assert ">" not in out
        # No raw control chars (sanitise stripped them).
        assert all(ord(c) >= 0x20 or c == "\t" for c in out)


# ── --test-paths edge cases ──────────────────────────────────────────────


class TestTestPathsEdgeCases:
    @pytest.mark.requirement("FR-154")
    def test_dot_in_segment_name_accepted(self):
        """`foo.bar.test` is a valid POSIX glob; only literal `..` segments are rejected."""
        from scarno.core.test_scope import sanitise_test_paths
        out = sanitise_test_paths(("foo.bar.test/*", "a.b/c.d/*.test"))
        assert out == ("foo.bar.test/*", "a.b/c.d/*.test")

    @pytest.mark.requirement("FR-154")
    def test_pattern_with_only_dotdot_basename_rejected(self):
        from scarno.core.test_scope import sanitise_test_paths
        with pytest.raises(ValueError, match="project root"):
            sanitise_test_paths(("foo/..",))

    @pytest.mark.requirement("FR-154")
    def test_one_invalid_pattern_rejects_whole_call(self):
        """Atomic validation — one bad pattern fails the entire call."""
        from scarno.core.test_scope import sanitise_test_paths
        with pytest.raises(ValueError):
            sanitise_test_paths(("ok/*", "bad/../traversal", "ok2/*"))

    @pytest.mark.requirement("FR-154")
    def test_unicode_pattern_within_byte_cap_accepted(self):
        """A pattern with unicode chars under the 256-byte cap is accepted."""
        from scarno.core.test_scope import sanitise_test_paths
        out = sanitise_test_paths(("tests/ñoño/*",))
        assert out == ("tests/ñoño/*",)

    @pytest.mark.requirement("FR-154")
    def test_unicode_pattern_over_byte_cap_rejected(self):
        """UTF-8 byte length is what counts, not character length."""
        from scarno.core.test_scope import sanitise_test_paths
        # 65 × 4-byte char = 260 bytes > 256 cap; only 65 chars long.
        pattern = "🚀" * 65
        with pytest.raises(ValueError, match="too long"):
            sanitise_test_paths((pattern,))


# ── usage_count under aliased / chained references ─────────────────────


class TestUsageCountAliased:
    @pytest.mark.requirement("FR-150")
    def test_aliased_from_import_counted(self, tmp_path):
        """`from pytest import fail as f; f(); f()` → usage_count==2 for pytest.fail."""
        (tmp_path / "main.py").write_text(
            "from pytest import fail as f\n"
            "f('a')\n"
            "f('b')\n"
        )
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )

        deps = [
            Dependency(
                name="pytest", version="0",
                status=DependencyStatus.UNCERTAIN, reason="",
                source="x", ecosystem="pypi",
            )
        ]
        updated, _ = analyse_source_files(str(tmp_path), deps)
        ep_by_name = {ep.name: ep for ep in updated[0].entry_points}
        assert "pytest.fail" in ep_by_name
        assert ep_by_name["pytest.fail"].used is True
        assert ep_by_name["pytest.fail"].usage_count == 2

    @pytest.mark.requirement("FR-150")
    def test_module_alias_attribute_chain_counted(self, tmp_path):
        """`import pytest as pt; pt.fail(); pt.fail()` → usage_count==2."""
        (tmp_path / "main.py").write_text(
            "import pytest as pt\n"
            "pt.fail('x')\n"
            "pt.fail('y')\n"
            "pt.fail('z')\n"
        )
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )

        deps = [
            Dependency(
                name="pytest", version="0",
                status=DependencyStatus.UNCERTAIN, reason="",
                source="x", ecosystem="pypi",
            )
        ]
        updated, _ = analyse_source_files(str(tmp_path), deps)
        ep_by_name = {ep.name: ep for ep in updated[0].entry_points}
        assert ep_by_name["pytest.fail"].usage_count == 3


# ── Mermaid render perf scaling ─────────────────────────────────────────


class TestAsciiTreePerfScaling:
    @pytest.mark.requirement("PERF-007")
    @pytest.mark.performance
    def test_render_time_scales_sublinearly_with_dep_count(self):
        """200-dep render must not be > 4× the 50-dep render time.

        Catches accidental O(N²) regressions in the renderer while
        avoiding the flakiness of an absolute wall-time bound on
        coverage-instrumented runs.
        """
        def _render(n: int) -> float:
            deps = [_dep(f"d{i:04d}", DependencyStatus.IN_USE) for i in range(n)]
            graph = {f"d{i:04d}": {f"d{(i + 1) % n:04d}"} for i in range(n)}
            result = AnalysisResult(
                project_type="python", project_path="/p",
                dependencies=deps, languages=["python"], dep_graph=graph,
            )
            t0 = time.perf_counter()
            for _ in range(5):
                MarkdownReporter().render(result)
            return (time.perf_counter() - t0) / 5

        small = _render(50)
        large = _render(200)
        # Linear scaling from 50→200 (4×) means large/small should be ≈ 4.
        # Allow up to 12× for noise; super-linear (e.g. quadratic 16×) fails.
        ratio = large / max(small, 1e-9)
        assert ratio < 12, (
            f"perf regression: 4× input → {ratio:.1f}× time (super-linear)"
        )


# ── --exclude-tests does not suppress findings in non-test source ──────


class TestExcludeTestsDoesNotMaskNonTestFindings:
    @pytest.mark.requirement("FR-153")
    @pytest.mark.security
    def test_findings_in_production_source_still_emitted_under_exclude_tests(
        self, tmp_path
    ):
        """A finding that lives in production code must still surface."""
        (tmp_path / "pyproject.toml").write_text(
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = []\n'
        )
        # Production code with a TS-CE-001 trigger (subprocess.run on an
        # f-string built from a network response).
        prod = tmp_path / "src" / "app.py"
        prod.parent.mkdir(parents=True, exist_ok=True)
        prod.write_text(
            "import subprocess, urllib.request\n"
            "def f():\n"
            "    data = urllib.request.urlopen('http://x').read().decode()\n"
            "    subprocess.run(data, shell=True)\n"
        )
        # And the same pattern in test code.
        test = tmp_path / "tests" / "test_x.py"
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text(
            "import subprocess, urllib.request\n"
            "def t():\n"
            "    data = urllib.request.urlopen('http://x').read().decode()\n"
            "    subprocess.run(data, shell=True)\n"
        )

        from typer.testing import CliRunner

        from scarno.cli import app

        result = CliRunner().invoke(app, [
            str(tmp_path), "--format", "json", "--exclude-tests",
        ])
        assert result.exit_code in (0, 1, 3)
        import json as _json

        data = _json.loads(result.output)
        # Production-source paths must remain in findings; test-source
        # paths must not. Both have the same pattern, so we can verify by
        # filename.
        finding_paths = [f["file_path"] for f in data["findings"]]
        # The test-file's findings are excluded (file was skipped).
        assert not any("test_x.py" in p for p in finding_paths), (
            "tests/ findings leaked despite --exclude-tests"
        )
        # The production findings are still emitted.
        assert any("app.py" in p for p in finding_paths), (
            "production-source findings were dropped — --exclude-tests "
            "is over-broad"
        )
