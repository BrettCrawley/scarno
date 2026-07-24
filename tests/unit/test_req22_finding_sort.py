"""PR-4 red tests — R-Phase9-01: deterministic finding sort
(TA-285 + TA-286)."""
from __future__ import annotations

import pytest


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
