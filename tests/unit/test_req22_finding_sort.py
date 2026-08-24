"""PR-4 red tests — R-Phase9-01: deterministic finding sort
(TA-285 + TA-286).

Extended for FR-274 (TA-365 + TA-366). Once ``signature_diff`` reports
per-overload, two overloads of one member reach ``_emit_findings``
together; if the message omits the descriptor they produce identical
``_finding_sort_key`` values and ``list.sort`` falls back to input
order — which is set-iteration order. R-Phase9-01 then holds only by
accident. See ``docs/SCARNO-BUG-signature-diff.md``.
"""
from __future__ import annotations

import pytest


def _differ(tmp_path):
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer

    return CrossVersionAbiDiffer(
        m2_root=tmp_path, invoke_javap=lambda jar, cls: None,
    )


def _overload_diff():
    """Two deleted overloads of one member, plus a third that is only
    a modifier shift — the shapes that collide on message text."""
    from scarno.analysers.java.abi_diff import AbiDiffResult
    from scarno.models import JavaSignature

    def sig(descriptor: str) -> JavaSignature:
        return JavaSignature(
            fqcn="org.eclipse.jetty.util.URIUtil",
            member_kind="method",
            member_name="encodePath",
            descriptor=descriptor,
            modifiers=frozenset({"public", "static"}),
        )

    return AbiDiffResult(
        added=frozenset(),
        removed=frozenset({
            sig("(java.lang.StringBuilder, java.lang.String)"),
            sig("(java.lang.String, int, int)"),
        }),
        changed=frozenset(),
    )


@pytest.mark.requirement("FR-274")
def test_findings_name_the_overload(tmp_path):
    """TA-365 — each Finding carries its own descriptor, so a reader
    can tell which overload vanished and the two are distinguishable
    in SARIF."""
    findings = _differ(tmp_path)._emit_findings(
        coord="org.eclipse.jetty:jetty-util",
        declared_version="9.4.51.v20230217",
        resolved_version="12.0.22",
        diff=_overload_diff(),
        source_symbols={"org.eclipse.jetty.util.URIUtil.encodePath"},
    )
    assert len(findings) == 2
    messages = [f.message for f in findings]
    assert len(set(messages)) == 2, f"messages collide: {messages}"
    assert any("java.lang.StringBuilder" in m for m in messages)
    assert any("(java.lang.String, int, int)" in m for m in messages)


@pytest.mark.requirement("FR-274")
def test_finding_sort_total_for_overloads(tmp_path):
    """TA-366 — the sort key discriminates between overloads of one
    member, so ordering does not depend on input order."""
    from scarno.analysers.java.abi_diff import _finding_sort_key

    findings = _differ(tmp_path)._emit_findings(
        coord="org.eclipse.jetty:jetty-util",
        declared_version="9.4.51.v20230217",
        resolved_version="12.0.22",
        diff=_overload_diff(),
        source_symbols={"org.eclipse.jetty.util.URIUtil.encodePath"},
    )
    keys = [_finding_sort_key(f) for f in findings]
    assert len(set(keys)) == len(keys), "sort key is not total"
    reordered = list(reversed(findings))
    forward = sorted(findings, key=_finding_sort_key)
    backward = sorted(reordered, key=_finding_sort_key)
    assert [f.message for f in forward] == [f.message for f in backward]


@pytest.mark.requirement("FR-234")
def test_finding_sort_key_severity_desc():
    """TA-286 — Mixed-severity findings sorted by the differ's
    canonical sort key: CRITICAL before HIGH before MEDIUM before LOW.
    """
    from scarno.analysers.java.abi_diff import _finding_sort_key
    from scarno.models import Finding, FindingKind, FindingSeverity

    severities = [
        FindingSeverity.LOW,
        FindingSeverity.CRITICAL,
        FindingSeverity.MEDIUM,
        FindingSeverity.HIGH,
    ]
    findings = [
        Finding(
            rule_id=f"R{i}",
            kind=FindingKind.ABI_DRIFT,
            severity=s,
            file_path="x",
            line=1,
            snippet="",
            message=str(i),
            remediation="",
        )
        for i, s in enumerate(severities)
    ]
    findings.sort(key=_finding_sort_key)
    assert findings[0].severity is FindingSeverity.CRITICAL
    assert findings[1].severity is FindingSeverity.HIGH
    assert findings[2].severity is FindingSeverity.MEDIUM
    assert findings[3].severity is FindingSeverity.LOW


@pytest.mark.requirement("FR-234")
def test_findings_sorted_after_diff_all(tmp_path):
    """TA-285 — Running diff_all twice against the same fixture
    produces byte-identical finding order. Deterministic across runs.
    """
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        VersionedNode,
    )

    def fake_javap(jar_path, class_name):
        if "1.2.0" in str(jar_path):
            return (
                "public class com.thirdparty.Helper {\n"
                "  public int methodA(int);\n"
                "  public int methodB(int);\n"
                "  public int methodC(int);\n"
                "}\n"
            )
        return "public class com.thirdparty.Helper {\n}\n"

    m2 = tmp_path / "m2"
    for ver in ("1.2.0", "1.5.0"):
        jd = m2 / "com" / "thirdparty" / "helper" / ver
        jd.mkdir(parents=True)
        (jd / f"helper-{ver}.jar").write_bytes(b"")

    def run() -> list[str]:
        differ = CrossVersionAbiDiffer(m2_root=m2, invoke_javap=fake_javap)
        result = AnalysisResult(
            project_type="java",
            project_path="/tmp",
            dependencies=[
                Dependency(name="com.thirdparty:helper", version="1.5.0",
                           status=DependencyStatus.IN_USE, reason="",
                           ecosystem="maven"),
            ],
            dep_edges=[
                DepEdge(parent="", child="com.thirdparty:helper",
                        declared_version="1.2.0"),
                DepEdge(parent="", child="com.thirdparty:helper",
                        declared_version="1.5.0"),
            ],
            versioned_nodes=[
                VersionedNode(canonical="com.thirdparty:helper",
                              declared_version="1.2.0",
                              status=DependencyStatus.IN_USE),
                VersionedNode(canonical="com.thirdparty:helper",
                              declared_version="1.5.0",
                              status=DependencyStatus.IN_USE,
                              is_resolved=True),
            ],
            multi_version_coords=["com.thirdparty:helper"],
        )
        findings = differ.diff_all(result, source_symbols={})
        return [f.message for f in findings]

    a = run()
    b = run()
    assert a == b, "diff_all is not deterministic across runs"
