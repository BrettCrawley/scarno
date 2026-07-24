"""PR-4 red tests — PERF-014 / PERF-015: deep-inspection runtime budget +
diff scaling (TA-290 + TA-291)."""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.performance


@pytest.mark.requirement("PERF-014")
def test_deep_inspection_5x2_jars_under_60s(tmp_path):
    """TA-290 — 5 multi-version coordinates × 2 versions each = 10
    cached jars. Total deep-inspection time < 60 s wall clock."""
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        VersionedNode,
    )

    def fake_javap(jar_path, class_name):
        # Cheap signature surface so the test is bound by orchestration
        # cost, not by parser cost.
        return f"public class com.example.{class_name} {{\n  public void m();\n}}\n"

    m2 = tmp_path / "m2"
    coords = [f"com.example:lib{i}" for i in range(5)]
    for c in coords:
        _g, _a = c.split(":")
        for ver in ("1.0", "2.0"):
            d = m2 / _g.replace(".", "/") / _a / ver
            d.mkdir(parents=True)
            (d / f"{_a}-{ver}.jar").write_bytes(b"")

    deps = [
        Dependency(name=c, version="2.0", status=DependencyStatus.IN_USE,
                   reason="", ecosystem="maven")
        for c in coords
    ]
    edges = []
    vnodes = []
    for c in coords:
        for ver in ("1.0", "2.0"):
            edges.append(DepEdge(parent="", child=c, declared_version=ver))
            vnodes.append(
                VersionedNode(canonical=c, declared_version=ver,
                              status=DependencyStatus.IN_USE,
                              is_resolved=(ver == "2.0")),
            )
    result = AnalysisResult(
        project_type="java", project_path="/tmp",
        dependencies=deps, dep_edges=edges,
        versioned_nodes=vnodes, multi_version_coords=coords,
    )
    differ = CrossVersionAbiDiffer(m2_root=m2, invoke_javap=fake_javap)
    start = time.monotonic()
    differ.diff_all(result, source_symbols={})
    elapsed = time.monotonic() - start
    assert elapsed < 60.0, (
        f"deep-inspection took {elapsed:.1f}s (budget 60s)"
    )


@pytest.mark.requirement("PERF-015")
def test_signature_diff_no_quadratic_blowup():
    """TA-291 — A diff of two 5000-signature sets completes quickly
    (O(n log n) at worst). Catches accidental O(n²) regressions."""
    from scarno.analysers.java.abi_diff import signature_diff
    from scarno.models import JavaSignature

    def _make(n: int, suffix: str) -> set[JavaSignature]:
        return {
            JavaSignature(
                fqcn="com.example.Big",
                member_kind="method",
                member_name=f"m{i}",
                descriptor=f"()V{suffix}",
                modifiers=frozenset({"public"}),
            )
            for i in range(n)
        }

    declared = _make(5000, "")
    resolved = _make(5000, "2")  # different descriptor → all "changed"
    start = time.monotonic()
    signature_diff(declared=declared, resolved=resolved)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, (
        f"signature_diff on 5000 sigs took {elapsed:.2f}s — likely O(n²)"
    )
