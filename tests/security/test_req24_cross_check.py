"""TA-331 + TA-354 — REQ-24 / SEC-NEW-71 / SEC-NEW-74 — cross-check
fetch orchestration.

Scenarios covered:

* Two indexes returning identical bytes → cached, no finding.
* Two indexes returning different bytes, retry agrees → cached,
  audit notes transient drift, no finding (T-43 mitigation).
* Two indexes returning different bytes, retry persists → reject,
  emit ``TS-INTEGRITY-MISMATCH`` (HIGH) finding.
* Secondary unreachable → degrade to single-source with audit (the
  operator who enabled cross-check still gets an analysis result).
* Cross-check off → standard single-source path (existing behaviour
  preserved exactly).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from scarno.indexing import (
    CoordinateValidator,
    HttpResponse,
    IndexConfigSource,
    IndexEndpoint,
    RemoteArtifactFetcher,
    SafeHttpsClient,
    SafeHttpsError,
)
from scarno.models import Finding, FindingKind, FindingSeverity

pytestmark = pytest.mark.security


_GUAVA = CoordinateValidator.validate("maven", "com.google.guava:guava")
_PRIMARY_URL = "https://nexus.corp/repo"
_SECONDARY_URL = "https://repo1.maven.org/maven2"


class _ScriptedClient(SafeHttpsClient):
    """Returns canned HttpResponse / raises canned exceptions per URL."""

    def __init__(self, script: list[Any], **kw: Any) -> None:
        super().__init__(**kw)
        # script is consumed in order on each get() call so the test
        # can model "first call returns X, second call returns Y".
        self._script = list(script)
        self.calls: list[str] = []

    def get(self, url: str) -> HttpResponse:  # type: ignore[override]
        self.calls.append(url)
        if not self._script:
            raise SafeHttpsError(f"unscripted call: {url}")
        outcome = self._script.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _ok(body: bytes) -> HttpResponse:
    return HttpResponse(
        status=200, headers={}, body=body,
        final_url="", pinned_ip="8.8.8.8",
    )


def _checksum(body: bytes) -> HttpResponse:
    return _ok(hashlib.sha256(body).hexdigest().encode("ascii"))


def _endpoints() -> list[IndexEndpoint]:
    return [
        IndexEndpoint(
            "maven", _PRIMARY_URL, 0, IndexConfigSource.CLI,
        ),
        IndexEndpoint(
            "maven", _SECONDARY_URL, 1, IndexConfigSource.CLI,
        ),
    ]


def _fetcher(
    tmp_path: Path,
    client: SafeHttpsClient,
    *,
    cross_check: bool = True,
    findings: list[Finding] | None = None,
) -> tuple[RemoteArtifactFetcher, list[str]]:
    warnings: list[str] = []
    return (
        RemoteArtifactFetcher(
            client=client,
            warnings=warnings,
            cross_check=cross_check,
            findings=findings,
            cache_root=tmp_path / "fetched",
        ),
        warnings,
    )


# ── Scenario: agreement → cached, no finding ──────────────────────────────


class TestUnanimousAgreement:
    @pytest.mark.requirement("FR-261")
    def test_matching_bytes_cached_no_finding(self, tmp_path):
        body = b"PK\x03\x04matching"
        client = _ScriptedClient([
            _ok(body),  # primary fetch
            _ok(body),  # secondary fetch
        ])
        findings: list[Finding] = []
        fetcher, warnings = _fetcher(tmp_path, client, findings=findings)
        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())
        assert result is not None
        assert result.read_bytes() == body
        assert findings == []
        assert any("fetched com.google.guava:guava" in w for w in warnings)
        # No mismatch audit.
        assert not any("TS-INTEGRITY-MISMATCH" in w for w in warnings)


# ── Scenario: transient drift, retry agrees → cached, no finding ──────────


class TestTransientDriftRetryRecovers:
    @pytest.mark.requirement("SEC-NEW-74")
    @pytest.mark.requirement("T-43")
    def test_retry_agrees_no_finding_audited_as_transient(self, tmp_path):
        body = b"PK\x03\x04agreed"
        client = _ScriptedClient([
            _ok(body),               # primary
            _ok(b"PK\x03\x04drift"),  # secondary (initially disagrees)
            _ok(body),               # secondary retry (now agrees)
        ])
        findings: list[Finding] = []
        fetcher, warnings = _fetcher(tmp_path, client, findings=findings)
        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())
        assert result is not None
        assert result.read_bytes() == body
        assert findings == []
        assert any("transient drift resolved on retry" in w for w in warnings)


# ── Scenario: persistent disagreement → finding ──────────────────────────


class TestPersistentMismatch:
    @pytest.mark.requirement("SEC-NEW-71")
    @pytest.mark.requirement("SEC-NEW-74")
    @pytest.mark.requirement("T-40")
    def test_persistent_mismatch_emits_high_finding_and_rejects(
        self, tmp_path,
    ):
        primary_body = b"PK\x03\x04good"
        secondary_body = b"PK\x03\x04evil"
        retry_body = b"PK\x03\x04still-evil"
        client = _ScriptedClient([
            _ok(primary_body),    # primary
            _ok(secondary_body),  # secondary (disagrees)
            _ok(retry_body),      # secondary retry (still disagrees)
        ])
        findings: list[Finding] = []
        fetcher, warnings = _fetcher(tmp_path, client, findings=findings)

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is None, "mismatched artefact must NOT be cached"
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "TS-INTEGRITY-MISMATCH"
        assert f.kind is FindingKind.ABI_INTEGRITY_MISMATCH
        assert f.severity is FindingSeverity.HIGH
        assert f.provenance == "remote"
        assert "different bytes" in f.message
        # Both index URLs named in the audit so the operator can
        # investigate.
        assert any(
            "TS-INTEGRITY-MISMATCH" in w
            and _PRIMARY_URL in w
            and _SECONDARY_URL in w
            for w in warnings
        )

    @pytest.mark.requirement("SEC-NEW-74")
    def test_findings_optional_audit_only_when_no_sink(self, tmp_path):
        """When ``findings=None`` (e.g. fetcher tested in isolation),
        the mismatch is audited but no Finding is constructed —
        callers without a findings sink still see the mismatch."""
        body = b"PK\x03\x04a"
        client = _ScriptedClient([
            _ok(body),
            _ok(b"PK\x03\x04b"),
            _ok(b"PK\x03\x04c"),
        ])
        fetcher, warnings = _fetcher(
            tmp_path, client, findings=None,
        )
        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())
        assert result is None
        assert any("TS-INTEGRITY-MISMATCH" in w for w in warnings)


# ── Scenario: secondary unreachable → degrade to single-source ────────────


class TestSecondaryUnreachable:
    @pytest.mark.requirement("FR-261")
    def test_secondary_failure_degrades_to_primary_with_audit(self, tmp_path):
        """If the operator enabled cross-check but the secondary is
        down, the analysis still proceeds with a clear audit note —
        better than a silent "fetch failed"."""
        body = b"PK\x03\x04primary"
        client = _ScriptedClient([
            _ok(body),                                 # primary
            SafeHttpsError("secondary connect refused"),  # secondary down
        ])
        findings: list[Finding] = []
        fetcher, warnings = _fetcher(tmp_path, client, findings=findings)

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is not None
        assert result.read_bytes() == body
        assert findings == []
        assert any(
            "degraded to single-source" in w for w in warnings
        )


# ── Scenario: cross_check OFF → identical to pre-F2 behaviour ─────────────


class TestCrossCheckOffPreservesBehaviour:
    @pytest.mark.requirement("FR-261")
    def test_off_uses_single_source_path(self, tmp_path):
        body = b"PK\x03\x04solo"
        # When cross-check is off, only the primary is queried; the
        # standard single-source path also requests a checksum URL,
        # so script that too.
        client = _ScriptedClient([
            _ok(body),
            _ok(hashlib.sha512(body).hexdigest().encode("ascii")),
        ])
        findings: list[Finding] = []
        fetcher, warnings = _fetcher(
            tmp_path, client, cross_check=False, findings=findings,
        )
        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())
        assert result is not None
        assert result.read_bytes() == body
        # No cross-check artefacts in the audit.
        assert not any("transient drift" in w for w in warnings)
        assert not any("TS-INTEGRITY-MISMATCH" in w for w in warnings)
        assert not any("degraded to single-source" in w for w in warnings)
