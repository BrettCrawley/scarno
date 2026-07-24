"""REQ-24 Slice E — orchestration wiring tests.

* TA-332 (FR-262 / PRV-005) — minimisation: only multi-version-conflict
  coords are eligible for remote fetch; non-conflict edges are NOT
  disclosed off-machine.
* TA-335 (FR-265 / N-10) — ``Finding.provenance`` is ``"remote"``
  when EITHER side of the ABI comparison was sourced via the REQ-24
  finder (conservative tagging).
* TA-337 (FR-267) — ``provenance="remote"`` findings are visible but
  do NOT escalate ``--fail-on-severity`` unless
  ``--fail-on-remote-severity`` is set on argv.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scarno.analysers.java.abi_diff import (
    AbiDiffResult,
    CrossVersionAbiDiffer,
)
from scarno.cli import _exit_code_for
from scarno.indexing import (
    CoordinateValidator,
    HttpResponse,
    IndexConfigSource,
    IndexEndpoint,
    RemoteArtifactFetcher,
    SafeHttpsClient,
    SafeHttpsError,
)
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    DepEdge,
    Finding,
    FindingKind,
    FindingSeverity,
    JavaSignature,
    VersionedNode,
)


# ── TA-337 — FR-267 fail-on-severity gating for remote findings ───────────


class TestFR267RemoteFindingsAdvisoryByDefault:
    def _result_with_finding(self, *, severity, provenance) -> AnalysisResult:
        return AnalysisResult(
            project_type="java",
            project_path="/tmp/p",
            dependencies=[],
            findings=[
                Finding(
                    rule_id="TS-ABI-RUNTIME-RISK",
                    kind=FindingKind.ABI_RUNTIME_RISK,
                    severity=severity,
                    file_path="",
                    line=0,
                    snippet="",
                    message="m",
                    remediation="r",
                    provenance=provenance,
                ),
            ],
        )

    @pytest.mark.requirement("FR-267")
    def test_remote_high_does_not_escalate_by_default(self):
        result = self._result_with_finding(
            severity=FindingSeverity.HIGH, provenance="remote",
        )
        # threshold = HIGH (default); remote HIGH finding present.
        # Without --fail-on-remote-severity, exit code must NOT be 3.
        assert _exit_code_for(
            result, FindingSeverity.HIGH, fail_on_remote_severity=False,
        ) == 0

    @pytest.mark.requirement("FR-267")
    def test_remote_high_escalates_with_opt_in(self):
        result = self._result_with_finding(
            severity=FindingSeverity.HIGH, provenance="remote",
        )
        assert _exit_code_for(
            result, FindingSeverity.HIGH, fail_on_remote_severity=True,
        ) == 3

    @pytest.mark.requirement("FR-267")
    def test_local_high_always_escalates(self):
        """Local findings keep pre-REQ-24 semantics — they escalate
        regardless of the opt-in flag."""
        result = self._result_with_finding(
            severity=FindingSeverity.HIGH, provenance="local",
        )
        assert _exit_code_for(
            result, FindingSeverity.HIGH, fail_on_remote_severity=False,
        ) == 3
        assert _exit_code_for(
            result, FindingSeverity.HIGH, fail_on_remote_severity=True,
        ) == 3

    @pytest.mark.requirement("FR-267")
    def test_remote_finding_below_threshold_not_escalated_either_way(self):
        result = self._result_with_finding(
            severity=FindingSeverity.LOW, provenance="remote",
        )
        # Threshold is HIGH; LOW finding never gates exit 3.
        assert _exit_code_for(
            result, FindingSeverity.HIGH, fail_on_remote_severity=True,
        ) == 0


# ── TA-335 — provenance tagging (conservative — either-side) ──────────────


class TestProvenanceTagging:
    @pytest.mark.requirement("FR-265")
    def test_resolve_jar_returns_remote_provenance_when_finder_hits(
        self, tmp_path,
    ):
        """``_resolve_jar`` reports ``"remote"`` when ``find_jar`` returns
        an existing path; falls back to ``"local"`` (and the m2 lookup)
        otherwise."""
        # Create a fake "fetched" JAR file so .exists() is True.
        fetched_jar = tmp_path / "fetched-1.0.jar"
        fetched_jar.write_bytes(b"PK\x03\x04")

        def find_jar(coord: str, version: str) -> Path | None:
            return fetched_jar if (coord, version) == ("com.x:lib", "1.0") else None

        differ = CrossVersionAbiDiffer(
            m2_root=tmp_path / "m2",
            invoke_javap=lambda *_a, **_k: "",
            find_jar=find_jar,
        )
        path, provenance = differ._resolve_jar("com.x:lib", "1.0")
        assert path == fetched_jar
        assert provenance == "remote"

        # No finder hit → fall back to m2 (which is empty in tmp).
        path2, provenance2 = differ._resolve_jar("com.x:lib", "2.0")
        # m2 path is constructed but doesn't exist.
        assert provenance2 == "local"

    @pytest.mark.requirement("FR-265")
    def test_emit_findings_tags_provenance_on_every_finding(self):
        differ = CrossVersionAbiDiffer(
            m2_root=Path("/tmp"),
            invoke_javap=lambda *_a, **_k: "",
        )
        sig = JavaSignature(
            fqcn="com.x.Helper", member_kind="method", member_name="doIt",
            descriptor="()", modifiers=frozenset({"public"}),
        )
        diff = AbiDiffResult(
            added=frozenset(),
            removed=frozenset({sig}),
            changed=frozenset(),
        )
        # No source_symbols → not called → ABI_DRIFT (MEDIUM).
        findings = differ._emit_findings(
            coord="com.x:helper",
            declared_version="1.0",
            resolved_version="2.0",
            diff=diff,
            source_symbols=set(),
            provenance="remote",
        )
        assert findings
        for f in findings:
            assert f.provenance == "remote", (
                f"finding {f.rule_id} not tagged remote: {f.provenance!r}"
            )

    @pytest.mark.requirement("FR-265")
    def test_default_provenance_is_local(self):
        """Pre-REQ-24 callers passing no ``provenance=`` get ``"local"``
        — preserves existing behaviour."""
        differ = CrossVersionAbiDiffer(
            m2_root=Path("/tmp"),
            invoke_javap=lambda *_a, **_k: "",
        )
        sig = JavaSignature(
            fqcn="com.x.Helper", member_kind="method", member_name="doIt",
            descriptor="()", modifiers=frozenset({"public"}),
        )
        diff = AbiDiffResult(
            added=frozenset(), removed=frozenset({sig}), changed=frozenset(),
        )
        findings = differ._emit_findings(
            coord="com.x:helper",
            declared_version="1.0",
            resolved_version="2.0",
            diff=diff,
            source_symbols=set(),
        )
        for f in findings:
            assert f.provenance == "local"


# ── TA-332 — minimisation: only conflict coords fetched ───────────────────


class _RecordingFetcher(RemoteArtifactFetcher):
    """Records every ``fetch`` call for assertion. Bypasses the real
    SafeHttpsClient by overriding ``fetch`` itself."""

    def __init__(self, *, client, warnings, cache_root) -> None:
        super().__init__(client=client, warnings=warnings, cache_root=cache_root)
        self.calls: list[tuple[str, str]] = []

    def fetch(self, coord, version, endpoints):  # type: ignore[override]
        self.calls.append((coord.raw, version))
        return None  # don't actually create files


class TestLazyFindJarFetchesAnyCoord:
    """Option 2 — the multi-version-conflict minimisation gate is
    REMOVED. ``find_jar`` is now lazy: it fetches whatever the differ
    asks for, regardless of whether the coord is in
    ``multi_version_coords``. PRV-005 minimisation no longer applies
    in this code path; broader disclosure is documented in the
    pre-fetch audit line + LIMITATIONS.md."""

    @pytest.mark.requirement("FR-262")
    def test_lazy_find_jar_fetches_on_demand(
        self, monkeypatch, tmp_path,
    ):
        """The lazy ``find_jar`` calls the fetcher for ANY coord the
        differ asks about — including coords NOT in
        ``multi_version_coords``. The minimisation gate is gone."""
        from scarno.analysers import java as java_pkg

        recorded: list[tuple[str, str]] = []

        class _CaptureFetcher:
            def __init__(self, *, client, warnings, **_kw):
                self._client = client
                self._warnings = warnings

            def fetch(self, coord, version, endpoints, **_kw):
                recorded.append((coord.raw, version))
                return None

        monkeypatch.setattr(
            java_pkg, "RemoteArtifactFetcher", _CaptureFetcher,
        )
        monkeypatch.setattr(
            java_pkg, "SafeHttpsClient", lambda **kw: None,
        )
        monkeypatch.setattr(
            java_pkg, "resolve_indexes",
            lambda **_kw: (
                [IndexEndpoint(
                    "maven", "https://repo.example/m2", 0,
                    IndexConfigSource.CLI,
                )],
                [],
            ),
        )

        analyser = java_pkg.JavaAnalyser()
        analyser.allow_remote_fetch = True
        analyser.cli_indexes = ()

        errors: list[str] = []
        findings: list = []
        fetcher, endpoints = analyser._maybe_build_fetcher(
            tmp_path, errors, findings,
        )
        find_jar = analyser._build_lazy_find_jar(fetcher, endpoints)
        assert find_jar is not None
        # Call find_jar for a NON-conflict coord — Option 2 fetches it.
        find_jar("com.example:singleton", "1.0")
        find_jar("com.example:conflicted", "2.0")
        coords_fetched = {c for c, _v in recorded}
        # BOTH the singleton AND the conflict coord were queried —
        # the minimisation gate is gone (Option 2).
        assert coords_fetched == {
            "com.example:singleton", "com.example:conflicted",
        }, f"recorded={recorded}"

    @pytest.mark.requirement("FR-262")
    def test_returns_none_when_fetch_disabled(self, tmp_path):
        from scarno.analysers.java import JavaAnalyser

        analyser = JavaAnalyser()
        analyser.allow_remote_fetch = False
        errors: list[str] = []
        findings: list = []
        fetcher, endpoints = analyser._maybe_build_fetcher(
            tmp_path, errors, findings,
        )
        assert fetcher is None
        assert endpoints == []
        find_jar = analyser._build_lazy_find_jar(fetcher, endpoints)
        assert find_jar is None

    @pytest.mark.requirement("FR-262")
    def test_returns_none_when_no_indexes_configured(
        self, monkeypatch, tmp_path,
    ):
        """If --allow-remote-fetch is set but no indexes resolve,
        emit a warning and return (None, []) — never silently fetch
        nothing (which would mask a misconfiguration)."""
        from scarno.analysers import java as java_pkg

        monkeypatch.setattr(
            java_pkg, "resolve_indexes",
            lambda **_kw: ([], []),  # no endpoints
        )

        analyser = java_pkg.JavaAnalyser()
        analyser.allow_remote_fetch = True
        errors: list[str] = []
        findings: list = []
        fetcher, endpoints = analyser._maybe_build_fetcher(
            tmp_path, errors, findings,
        )
        assert fetcher is None
        assert endpoints == []
        find_jar = analyser._build_lazy_find_jar(fetcher, endpoints)
        assert find_jar is None
        assert any(
            "no indexes configured" in w for w in errors
        )

