"""PR-4 red tests — REQ-22 / FR-234 / COMP-004: RUNTIME_RISK Findings
(TA-270 + TA-271)."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-234")
@pytest.mark.requirement("COMP-004")
def test_runtime_risk_finding_for_source_referenced_removed_method():
    """TA-270 — A method called by project source AND removed in the
    resolved version produces exactly one Finding(severity=HIGH,
    kind=ABI_RUNTIME_RISK) referencing the call site, the symbol,
    declared 1.2.0, and resolved 1.5.0.

    This is the CRA-relevant compliance signal (COMP-004): SARIF
    consumers downstream of Scarno treat this as a strong
    runtime-risk indicator distinct from a vulnerability scan.
    """
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        FindingKind,
        FindingSeverity,
        JavaSignature,
        VersionedNode,
    )

    # Stub the injected invoke_javap: returns canned stdout based on
    # which JAR path is queried.
    def fake_javap(jar_path, class_name):
        if "1.2.0" in str(jar_path):
            return (
                "public class com.thirdparty.Helper {\n"
                "  public int utilityMethod(java.lang.String);\n"
                "}\n"
            )
        if "1.5.0" in str(jar_path):
            # utilityMethod REMOVED in 1.5.0
            return (
                "public class com.thirdparty.Helper {\n"
                "  public int newMethod(int);\n"
                "}\n"
            )
        return None

    from pathlib import Path
    import tempfile

    # Construct a tmp m2 with both JARs cached.
    with tempfile.TemporaryDirectory() as td:
        m2_root = Path(td) / "m2"
        for ver in ("1.2.0", "1.5.0"):
            jar_dir = (
                m2_root / "com" / "thirdparty" / "helper" / ver
            )
            jar_dir.mkdir(parents=True)
            (jar_dir / f"helper-{ver}.jar").write_bytes(b"")  # placeholder

        differ = CrossVersionAbiDiffer(
            m2_root=m2_root,
            invoke_javap=fake_javap,
        )
        result = AnalysisResult(
            project_type="java",
            project_path="/tmp/test",
            dependencies=[
                Dependency(
                    name="com.thirdparty:helper",
                    version="1.5.0",
                    status=DependencyStatus.IN_USE,
                    reason="",
                    ecosystem="maven",
                    imported_directly=True,
                ),
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
        source_symbols = {
            "com.thirdparty:helper": {"com.thirdparty.Helper.utilityMethod"}
        }
        findings = differ.diff_all(result, source_symbols)

    risk_findings = [
        f for f in findings if f.kind is FindingKind.ABI_RUNTIME_RISK
    ]
    assert len(risk_findings) == 1
    assert risk_findings[0].severity is FindingSeverity.HIGH
    msg = risk_findings[0].message.lower()
    assert "utilitymethod" in msg or "utility" in msg


@pytest.mark.requirement("FR-234")
def test_abi_drift_finding_for_unreferenced_change():
    """TA-271 — A method that changed/removed but is NOT in the source
    call set produces a Finding(severity=MEDIUM, kind=ABI_DRIFT)."""
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
    from scarno.models import (
        AnalysisResult,
        Dependency,
        DependencyStatus,
        DepEdge,
        FindingKind,
        FindingSeverity,
        VersionedNode,
    )
    from pathlib import Path
    import tempfile

    def fake_javap(jar_path, class_name):
        if "1.2.0" in str(jar_path):
            return (
                "public class com.thirdparty.Helper {\n"
                "  public int internalMethod(int);\n"
                "}\n"
            )
        if "1.5.0" in str(jar_path):
            return "public class com.thirdparty.Helper {\n}\n"
        return None

    with tempfile.TemporaryDirectory() as td:
        m2_root = Path(td) / "m2"
        for ver in ("1.2.0", "1.5.0"):
            jar_dir = m2_root / "com" / "thirdparty" / "helper" / ver
            jar_dir.mkdir(parents=True)
            (jar_dir / f"helper-{ver}.jar").write_bytes(b"")
        differ = CrossVersionAbiDiffer(m2_root=m2_root, invoke_javap=fake_javap)
        result = AnalysisResult(
            project_type="java",
            project_path="/tmp/test",
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
        # No source call set for the removed method.
        findings = differ.diff_all(result, source_symbols={})

    drift = [
        f for f in findings if f.kind is FindingKind.ABI_DRIFT
    ]
    assert drift, "unreferenced ABI changes must emit ABI_DRIFT findings"
    assert drift[0].severity is FindingSeverity.MEDIUM
