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
* Primary answers 4xx → NO secondary request (SEC-NEW-61 / T-44
  holds on the cross-check path too), while 5xx/connection-level
  failures still fall through.
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


def _status(code: int, body: bytes = b"") -> HttpResponse:
    return HttpResponse(
        status=code, headers={}, body=body,
        final_url="", pinned_ip="8.8.8.8",
    )


def _artefact_url(index_url: str) -> str:
    return f"{index_url}/com/google/guava/guava/1.0/guava-1.0.jar"


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


# ── Scenario: primary 4xx → no secondary request (SEC-NEW-61) ─────────────


class TestNoFallthroughOn4xxUnderCrossCheck:
    """``--integrity-cross-check`` is advertised as an integrity
    *strengthening* flag; it must not weaken SEC-NEW-61. A 4xx from
    the operator's authoritative (priority-0) index is final: the
    lower-priority index is never asked, so the coordinate can't leak
    (T-44) and a public index can't substitute an artefact the primary
    says does not exist (dependency confusion)."""

    @pytest.mark.requirement("SEC-NEW-61")
    @pytest.mark.requirement("T-44")
    def test_primary_404_does_not_query_secondary(self, tmp_path):
        evil = b"PK\x03\x04attacker-published"
        client = _ScriptedClient([
            _status(404),   # primary: corp Nexus denies the coordinate
            # Scripted so a regression would *succeed* in fetching the
            # attacker's artefact rather than merely erroring out.
            _ok(evil),
            _ok(hashlib.sha512(evil).hexdigest().encode("ascii")),
        ])
        findings: list[Finding] = []
        fetcher, warnings = _fetcher(tmp_path, client, findings=findings)

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is None
        assert client.calls == [_artefact_url(_PRIMARY_URL)], (
            f"cross-check fell through on 4xx and leaked the "
            f"coordinate: {client.calls}"
        )
        assert findings == []
        assert any("NOT falling through" in w for w in warnings)
        assert any("would leak coord" in w for w in warnings)

    @pytest.mark.requirement("SEC-NEW-61")
    def test_primary_403_does_not_query_secondary(self, tmp_path):
        """401/403 are authoritative too — an index that refuses to
        answer must not hand the coordinate to the next one."""
        client = _ScriptedClient([
            _status(403),
            _ok(b"PK\x03\x04should-never-be-requested"),
        ])
        fetcher, warnings = _fetcher(tmp_path, client)

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is None
        assert client.calls == [_artefact_url(_PRIMARY_URL)]

    @pytest.mark.requirement("SEC-NEW-61")
    def test_primary_503_still_falls_through(self, tmp_path):
        """Connection-level failures (502/503/504) remain a legitimate
        fall-through trigger — the fix must not turn cross-check into
        a hard single-source path."""
        body = b"PK\x03\x04from-secondary"
        client = _ScriptedClient([
            _status(503),  # primary is down, not answering "no"
            _ok(body),     # secondary serves it
            _ok(hashlib.sha512(body).hexdigest().encode("ascii")),
        ])
        fetcher, warnings = _fetcher(tmp_path, client)

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is not None
        assert result.read_bytes() == body
        assert _artefact_url(_SECONDARY_URL) in client.calls

    @pytest.mark.requirement("SEC-NEW-61")
    def test_primary_connection_failure_still_falls_through(self, tmp_path):
        body = b"PK\x03\x04from-secondary"
        client = _ScriptedClient([
            SafeHttpsError("primary connect refused"),
            _ok(body),
            _ok(hashlib.sha512(body).hexdigest().encode("ascii")),
        ])
        fetcher, warnings = _fetcher(tmp_path, client)

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is not None
        assert result.read_bytes() == body
        assert _artefact_url(_SECONDARY_URL) in client.calls


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


class TestNonFallthroughOutcomesUnderCrossCheck:
    """The remaining two authoritative outcomes on the cross-check
    fetch path. Both changed shape when F9 threaded ``_Outcome`` back
    out of ``_fetch_artefact_bytes``, and neither is reached by the 4xx
    tests above, so each is pinned here: an authoritative answer must
    end the fetch without the secondary ever being asked.
    """

    @pytest.mark.requirement("SEC-NEW-61")
    def test_unexpected_status_does_not_query_secondary(self, tmp_path):
        """A non-4xx, non-200 reply (a redirect the client surfaced, a
        201, ...) is treated as authoritative, not as a connection
        failure — so it must not fall through either."""
        client = _ScriptedClient([
            _status(301),
            _ok(b"PK\x03\x04should-never-be-requested"),
        ])
        fetcher, warnings = _fetcher(tmp_path, client)

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is None
        assert client.calls == [_artefact_url(_PRIMARY_URL)], (
            f"unexpected status fell through and leaked the "
            f"coordinate: {client.calls}"
        )
        assert any("NOT falling through" in w for w in warnings)

    @pytest.mark.requirement("SEC-NEW-61")
    def test_oversize_primary_body_does_not_query_secondary(self, tmp_path):
        """An over-cap body from the primary is a refusal by policy, not
        a transport failure. Falling through would let a lower-priority
        index answer for a coordinate the primary actually served."""
        client = _ScriptedClient([
            _ok(b"PK\x03\x04" + b"A" * 4096),
            _ok(b"PK\x03\x04should-never-be-requested"),
        ])
        warnings: list[str] = []
        fetcher = RemoteArtifactFetcher(
            client=client,
            warnings=warnings,
            cross_check=True,
            cache_root=tmp_path / "fetched",
            per_artefact_max_bytes=64,
        )

        result = fetcher.fetch(_GUAVA, "1.0", _endpoints())

        assert result is None
        assert client.calls == [_artefact_url(_PRIMARY_URL)], (
            f"over-cap body fell through: {client.calls}"
        )
        assert any("exceeds per-artefact cap" in w for w in warnings)
