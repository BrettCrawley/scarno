"""PR-1 red tests — PERF-010 tree render perf + 8 MiB lockfile parse perf.

Budgets are absolute (the pre-Phase-9 codebase has no REQ-17 perf baseline
to compare against). They are deliberately generous — the goal is to
catch pathological regressions, not to enforce sub-millisecond timing.
"""
from __future__ import annotations

import json
import time

import pytest

pytestmark = pytest.mark.performance


# ── TA-226 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("PERF-010")
def test_tree_render_1000_deps_5000_edges_under_absolute_budget():
    """TA-226 — Markdown tree render with 1000 deps + 5000 edges completes
    under 1.0 s wall clock on developer-grade hardware.

    The budget is generous on purpose; this catches accidental O(n²) and
    n-times-fork regressions, not micro-perf drift.
    """
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
    )
    from scarno.reporters.markdown_reporter import MarkdownReporter

    deps = [
        Dependency(
            name=f"pkg{i}",
            version="1.0",
            status=DependencyStatus.IN_USE,
            reason="",
            is_transitive=(i > 100),
        )
        for i in range(1000)
    ]
    edges = []
    for i in range(1000):
        # Each pkg has up to 5 outgoing edges, totalling ≤ 5000.
        for j in range(min(5, 1000 - i - 1)):
            edges.append(
                DepEdge(
                    parent=f"pkg{i}",
                    child=f"pkg{i + j + 1}",
                    declared_version=f"1.{j}",
                )
            )
    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/perf",
        dependencies=deps,
        dep_edges=edges,
    )
    start = time.monotonic()
    MarkdownReporter().render(result)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f"tree render took {elapsed:.2f}s (budget 1.0s)"


# ── TA-227 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("PERF-010")
def test_npm_lockfile_8MiB_parse_under_500ms(tmp_path):
    """TA-227 — A near-cap (~7.5 MiB) realistic-shape package-lock.json
    parses in under 500 ms AND the parser populates dep_edges within
    the same budget.

    Target sits just under the SEC-NEW-37 cap (8 MiB) so the test
    exercises the at-cap-but-not-over path; oversized lockfiles
    are rejected by their own test (TA-217) and don't belong here.
    """
    from scarno.analysers.javascript.dep_file_parser import (
        parse_all_npm_dependency_files,
    )

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "package.json").write_text(
        json.dumps({"name": "app", "version": "1.0.0"})
    )
    # Build a realistic-shape lockfile under the 8 MiB cap.
    packages = {"": {"name": "app", "version": "1.0.0", "dependencies": {}}}
    i = 0
    target_bytes = int(7.5 * 1024 * 1024)
    while True:
        packages[f"node_modules/pkg{i}"] = {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/pkg{i}/-/pkg{i}-1.0.0.tgz",
            "integrity": "sha512-" + "A" * 80,
            "dependencies": {f"pkg{i + 1}": "1.0.0"},
        }
        i += 1
        if i % 200 == 0:
            current = len(json.dumps({"packages": packages}))
            if current >= target_bytes:
                break
    (project_root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": packages,
            }
        )
    )

    start = time.monotonic()
    result = parse_all_npm_dependency_files(str(project_root))
    elapsed = time.monotonic() - start
    assert elapsed < 0.5, (
        f"8 MiB lockfile parse took {elapsed:.2f}s (budget 0.5s)"
    )
    # REQ-19 contract: the parser must populate dep_edges within the same
    # budget. Without this assertion, the test passes on the pre-Phase-9
    # codebase that doesn't emit edges at all — defeating TDD red discipline.
    edges = getattr(result, "edges", None)
    assert edges is not None and len(edges) > 0, (
        "REQ-19 dep_edges not populated by lockfile parse; perf budget alone "
        "is insufficient evidence that the new API ran."
    )
