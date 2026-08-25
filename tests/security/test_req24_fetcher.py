"""TA-344, TA-346, TA-347, TA-350, TA-351, TA-353, TA-355 — REQ-24
:class:`RemoteArtifactFetcher` security invariants:

* TA-344 (SEC-NEW-61) — HTTP 4xx is authoritative; no fallthrough.
* TA-346 (SEC-NEW-64) — quarantined cache root mode 0700.
* TA-347 (SEC-NEW-65) — cache writes confined to cache root.
* TA-350 (SEC-NEW-68) — per-artefact size cap.
* TA-351 (SEC-NEW-69) — per-run fetch count + time-budget caps.
* TA-353 (SEC-NEW-73) — fetched JARs run through ``safe_jar_entries``
  on read (decompression-bomb caps applied).
* TA-355 (PRV-006) — pre-fetch disclosure names hosts AND explicitly
  mentions IP visibility.

Every test uses a scripted ``SafeHttpsClient`` subclass — the fetcher
sees a normal client interface, the test controls the responses.
"""
from __future__ import annotations

import hashlib
import io
import zipfile
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
from scarno.security import safe_jar_entries

pytestmark = pytest.mark.security


# ── Helpers ────────────────────────────────────────────────────────────────


class _ScriptedClient(SafeHttpsClient):
    """SafeHttpsClient subclass that returns canned responses keyed
    by URL. Production code path (DNS / TLS / sockets) is bypassed."""

    def __init__(self, script: dict[str, Any], **kw: Any) -> None:
        super().__init__(**kw)
        # script[url] is either an HttpResponse OR an exception to raise.
        self._script = script
        self.requests: list[str] = []

    def get(self, url: str) -> HttpResponse:  # type: ignore[override]
        self.requests.append(url)
        if url not in self._script:
            raise SafeHttpsError(f"unscripted URL: {url}")
        outcome = self._script[url]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _resp(
    status: int = 200, body: bytes = b"", headers: dict[str, str] | None = None,
) -> HttpResponse:
    return HttpResponse(
        status=status,
        headers=headers or {},
        body=body,
        final_url="",
        pinned_ip="8.8.8.8",
    )


def _checksum_resp(body: bytes, algo: str) -> HttpResponse:
    return _resp(
        status=200,
        body=hashlib.new(algo, body).hexdigest().encode("ascii"),
    )


_GUAVA = CoordinateValidator.validate("maven", "com.google.guava:guava")


def _make_endpoint(url: str = "https://repo1.example/m2") -> IndexEndpoint:
    return IndexEndpoint(
        ecosystem="maven", url=url, priority=0,
        source=IndexConfigSource.CLI,
    )


def _make_fetcher(
    tmp_path: Path,
    client: SafeHttpsClient,
    warnings: list[str],
    **kw: Any,
) -> RemoteArtifactFetcher:
    return RemoteArtifactFetcher(
        client=client,
        warnings=warnings,
        cache_root=tmp_path / "fetched",
        **kw,
    )


# ── TA-344 — no fallthrough on HTTP 4xx ────────────────────────────────────


class TestNoFallthroughOn4xx:
    @pytest.mark.requirement("SEC-NEW-61")
    @pytest.mark.requirement("T-44")
    def test_404_does_not_query_secondary_index(self, tmp_path):
        """SEC-NEW-61: the keystone confidentiality control. A 404 on
        the corp Nexus must NOT cause scarno to query Maven Central
        with the same coordinate (would leak the internal name)."""
        primary_url = (
            "https://nexus.corp/repo/com/google/guava/guava/"
            "1.0/guava-1.0.jar"
        )
        secondary_url = (
            "https://repo1.maven.org/maven2/com/google/guava/guava/"
            "1.0/guava-1.0.jar"
        )
        client = _ScriptedClient({
            primary_url: _resp(status=404),
            # If the fetcher DOES query the secondary, the test will
            # pick up a different request count.
            secondary_url: _resp(status=200, body=b"oops"),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)

        result = fetcher.fetch(
            _GUAVA, "1.0",
            endpoints=[
                IndexEndpoint(
                    "maven", "https://nexus.corp/repo", 0,
                    IndexConfigSource.CLI,
                ),
                IndexEndpoint(
                    "maven", "https://repo1.maven.org/maven2", 1,
                    IndexConfigSource.CLI,
                ),
            ],
        )

        assert result is None
        # Only ONE request — the 404 on the primary. Secondary never queried.
        assert client.requests == [primary_url], (
            f"fallthrough on 4xx leaked the coordinate: {client.requests}"
        )
        assert any("NOT falling through" in w for w in warnings)
        assert any("would leak coord" in w for w in warnings)

    @pytest.mark.requirement("SEC-NEW-61")
    def test_502_does_fall_through(self, tmp_path):
        """Connection-level failures (502/503/504) ARE a legitimate
        fallthrough trigger."""
        primary = "https://nexus.corp/repo"
        secondary = "https://repo1.maven.org/maven2"
        primary_url = (
            f"{primary}/com/google/guava/guava/1.0/guava-1.0.jar"
        )
        secondary_url = (
            f"{secondary}/com/google/guava/guava/1.0/guava-1.0.jar"
        )
        artefact_body = b"PK\x03\x04fakejar"
        client = _ScriptedClient({
            primary_url: _resp(status=503),
            secondary_url: _resp(status=200, body=artefact_body),
            f"{secondary_url}.sha512": _checksum_resp(artefact_body, "sha512"),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)
        result = fetcher.fetch(
            _GUAVA, "1.0",
            endpoints=[
                IndexEndpoint("maven", primary, 0, IndexConfigSource.CLI),
                IndexEndpoint("maven", secondary, 1, IndexConfigSource.CLI),
            ],
        )
        assert result is not None
        assert result.read_bytes() == artefact_body


# ── TA-346 — cache root mode 0700 ─────────────────────────────────────────


class TestCacheRootMode0700:
    @pytest.mark.requirement("SEC-NEW-64")
    @pytest.mark.requirement("T-42")
    def test_cache_root_chmod_0700_after_first_fetch(self, tmp_path):
        artefact = b"PK\x03\x04bytes"
        url = (
            "https://repo.example/m2/com/google/guava/guava/"
            "1.0/guava-1.0.jar"
        )
        client = _ScriptedClient({
            url: _resp(status=200, body=artefact),
            url + ".sha512": _checksum_resp(artefact, "sha512"),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)
        fetcher.fetch(_GUAVA, "1.0", endpoints=[
            _make_endpoint("https://repo.example/m2"),
        ])
        cache_root = tmp_path / "fetched"
        assert cache_root.exists()
        # Mode bits — only the lower 9 are interesting.
        mode = cache_root.stat().st_mode & 0o777
        assert mode == 0o700, f"cache root mode {oct(mode)} != 0700"


# ── TA-347 — confined writes ──────────────────────────────────────────────


class TestCacheConfined:
    @pytest.mark.requirement("SEC-NEW-65")
    def test_write_stays_inside_cache_root(self, tmp_path):
        """Successful fetch writes the file under the cache root and
        nowhere else. The ValidatedCoordinate type prevents any
        coordinate-based traversal at construction time, so this test
        verifies the write side: ``resolve_and_confine`` is applied."""
        artefact = b"PK\x03\x04"
        url = (
            "https://repo.example/m2/com/google/guava/guava/"
            "1.0/guava-1.0.jar"
        )
        client = _ScriptedClient({
            url: _resp(status=200, body=artefact),
            url + ".sha512": _checksum_resp(artefact, "sha512"),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)
        result = fetcher.fetch(_GUAVA, "1.0", endpoints=[
            _make_endpoint("https://repo.example/m2"),
        ])
        assert result is not None
        cache_root = (tmp_path / "fetched").resolve()
        assert result.resolve().is_relative_to(cache_root), (
            f"fetched path {result} escaped cache root {cache_root}"
        )
        # And nothing landed outside.
        for p in tmp_path.rglob("*"):
            if p.is_file():
                assert p.resolve().is_relative_to(cache_root), (
                    f"file {p} written outside cache root"
                )


# ── TA-350 — per-artefact size cap ────────────────────────────────────────


class TestPerArtefactSizeCap:
    @pytest.mark.requirement("SEC-NEW-68")
    def test_oversized_artefact_rejected(self, tmp_path):
        url = (
            "https://repo.example/m2/com/google/guava/guava/"
            "1.0/guava-1.0.jar"
        )
        oversized = b"x" * (1024 + 1)  # 1 KiB cap below
        client = _ScriptedClient({
            url: _resp(status=200, body=oversized),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(
            tmp_path, client, warnings,
            per_artefact_max_bytes=1024,
        )
        result = fetcher.fetch(_GUAVA, "1.0", endpoints=[
            _make_endpoint("https://repo.example/m2"),
        ])
        assert result is None
        assert any("exceeds per-artefact cap" in w for w in warnings)


# ── TA-351 — per-run fetch count + time-budget caps ───────────────────────


class TestFetchCaps:
    @pytest.mark.requirement("SEC-NEW-69")
    def test_per_run_fetch_count_cap(self, tmp_path):
        """Once the per-run cap is hit, further fetches return None
        immediately without any network call."""
        artefact = b"PK\x03\x04"
        endpoint = _make_endpoint("https://repo.example/m2")
        # Build script for two distinct coords; cap is 1.
        urls = {
            f"https://repo.example/m2/com/google/guava/guava/"
            f"1.{i}/guava-1.{i}.jar": _resp(status=200, body=artefact)
            for i in range(3)
        }
        for u in list(urls):
            urls[u + ".sha512"] = _checksum_resp(artefact, "sha512")
        client = _ScriptedClient(urls)
        warnings: list[str] = []
        fetcher = _make_fetcher(
            tmp_path, client, warnings, max_fetches_per_run=1,
        )
        # First fetch consumes the slot.
        ok = fetcher.fetch(_GUAVA, "1.0", endpoints=[endpoint])
        assert ok is not None
        # Second fetch hits the cap.
        denied = fetcher.fetch(_GUAVA, "1.1", endpoints=[endpoint])
        assert denied is None
        assert any("per-run fetch cap" in w for w in warnings)

    @pytest.mark.requirement("SEC-NEW-69")
    def test_time_budget_exhausted(self, tmp_path, monkeypatch):
        client = _ScriptedClient({})
        warnings: list[str] = []
        fetcher = _make_fetcher(
            tmp_path, client, warnings,
            total_time_budget_s=0.01,
        )
        # Fast-forward monotonic so the budget is past on the first attempt.
        import time as _t
        start = _t.monotonic()
        monkeypatch.setattr(_t, "monotonic", lambda: start + 60.0)
        # Need to also set the fetcher's own start clock to before the
        # forwarded time — it captured monotonic() in __init__.
        denied = fetcher.fetch(_GUAVA, "1.0", endpoints=[
            _make_endpoint(),
        ])
        assert denied is None
        assert any("fetch-time budget" in w for w in warnings)


# ── TA-353 — decompression-bomb cap (read path) ───────────────────────────


class TestDecompressionBombGuards:
    @pytest.mark.requirement("SEC-NEW-73")
    def test_safe_jar_entries_rejects_oversized_jar(self, tmp_path):
        """SEC-NEW-73 is satisfied by reusing the existing
        ``safe_jar_entries`` guard on JARs scarno reads —
        whether they came from ~/.m2 or the quarantined cache.
        Synthesise a JAR whose declared uncompressed entry size
        exceeds ``MAX_JAR_ENTRY_BYTES``; verify rejection."""
        from scarno.security import MAX_JAR_ENTRY_BYTES

        jar_path = tmp_path / "evil.jar"
        # Build a real-looking ZIP whose central directory claims a
        # huge file_size for one entry. zipfile sets file_size from
        # the actual write, so we shrink the cap by patching MAX
        # via the test instead — easier than crafting a false-header zip.
        with zipfile.ZipFile(jar_path, "w") as zf:
            zf.writestr("Foo.class", b"x" * (1024 * 1024))
        # Patch the cap downward to trigger.
        import scarno.security as sec
        orig = sec.MAX_JAR_ENTRY_BYTES
        sec.MAX_JAR_ENTRY_BYTES = 1024  # 1 KiB
        try:
            with pytest.raises(ValueError, match="declares uncompressed size"):
                safe_jar_entries(jar_path)
        finally:
            sec.MAX_JAR_ENTRY_BYTES = orig


# ── TA-355 — pre-fetch disclosure includes IP visibility (PRV-006) ────────


class TestDisclosureMessage:
    @pytest.mark.requirement("PRV-006")
    @pytest.mark.requirement("FR-263")
    @pytest.mark.requirement("PRV-005")
    def test_pre_fetch_disclosure_names_hosts_and_ip_exposure(self, tmp_path):
        artefact = b"PK\x03\x04"
        url = (
            "https://nexus.corp.example/repo/com/google/guava/guava/"
            "1.0/guava-1.0.jar"
        )
        client = _ScriptedClient({
            url: _resp(status=200, body=artefact),
            url + ".sha512": _checksum_resp(artefact, "sha512"),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)
        fetcher.fetch(_GUAVA, "1.0", endpoints=[
            _make_endpoint("https://nexus.corp.example/repo"),
        ])
        disclosures = [w for w in warnings if "REMOTE FETCH ENABLED" in w]
        assert len(disclosures) == 1, disclosures
        d = disclosures[0]
        # PRV-006 — explicit IP visibility wording.
        assert "IP address will be visible" in d
        # Host named.
        assert "nexus.corp.example" in d

    @pytest.mark.requirement("FR-264")
    def test_per_attempt_audit_line(self, tmp_path):
        artefact = b"PK\x03\x04"
        url = (
            "https://repo.example/m2/com/google/guava/guava/"
            "1.0/guava-1.0.jar"
        )
        client = _ScriptedClient({
            url: _resp(status=200, body=artefact),
            url + ".sha512": _checksum_resp(artefact, "sha512"),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)
        fetcher.fetch(_GUAVA, "1.0", endpoints=[
            _make_endpoint("https://repo.example/m2"),
        ])
        # One success audit line.
        success = [w for w in warnings if "fetched com.google.guava:guava" in w]
        assert len(success) == 1
        assert "provenance=remote" in success[0]


# ── SEC-NEW-59 — repo-derived version allow-list at the fetch entry ───────


class TestVersionAllowList:
    """The ``<version>`` comes from the analysed repo and is templated
    into the outbound index URL. ``sanitise_declared_version`` is a
    report-rendering sanitiser and leaves ``/ .. ? # % & :`` intact, so
    the fetch entry point applies a strict allow-list — otherwise a
    hostile pom.xml steers scarno's GET to an arbitrary path or query
    on the operator's (possibly internal) index host."""

    @pytest.mark.requirement("SEC-NEW-59")
    @pytest.mark.parametrize("version", [
        "1.0?leak=1",             # query injection
        "1.0#frag",               # fragment injection
        "1.0&x=y",
        "1.0/../../admin",        # path traversal on the index host
        "../1.0",
        "..",
        "1.0%2f..%2fadmin",       # percent-escaped traversal
        "1.0:8080",
        "1.0@evil.example",       # userinfo synthesis
        "1.0 2.0",
    ])
    def test_hostile_version_never_reaches_the_network(
        self, tmp_path, version,
    ):
        client = _ScriptedClient({})
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)

        result = fetcher.fetch(
            _GUAVA, version, endpoints=[_make_endpoint()],
        )

        assert result is None
        assert client.requests == [], (
            f"hostile version {version!r} reached the index: "
            f"{client.requests}"
        )
        assert any("rejecting unsafe version" in w for w in warnings), warnings

    @pytest.mark.requirement("SEC-NEW-59")
    @pytest.mark.parametrize("version", [
        "1.0",
        "2.0-SNAPSHOT",
        "1.0-20230101.120000-1",
        "5.3.20.RELEASE",
        "1.0.0.Final",
        "31.1-jre",
        "2.0.0-rc.1",
        "1.0.0+build.5",
        "20030203.000550",
        "r08",
        "1.0_01",
    ])
    def test_real_world_versions_still_fetch(self, tmp_path, version):
        """The allow-list must not reject any published Maven version
        shape — SNAPSHOT timestamps, qualifiers, classifier-ish
        suffixes, semver build metadata, date versions."""
        artefact = b"PK\x03\x04"
        url = (
            f"https://repo.example/m2/com/google/guava/guava/"
            f"{version}/guava-{version}.jar"
        )
        client = _ScriptedClient({
            url: _resp(status=200, body=artefact),
            url + ".sha512": _checksum_resp(artefact, "sha512"),
        })
        warnings: list[str] = []
        fetcher = _make_fetcher(tmp_path, client, warnings)

        result = fetcher.fetch(_GUAVA, version, endpoints=[
            _make_endpoint("https://repo.example/m2"),
        ])

        assert result is not None, warnings
        assert client.requests[0] == url


class TestVersionAllowListEdges:
    """Coverage for the two rejection branches the F8 patch added that
    its own tests do not reach: the length/empty guard in
    :func:`is_valid_fetch_version`, and the defence-in-depth re-check at
    the URL sink."""

    @pytest.mark.requirement("SEC-NEW-59")
    @pytest.mark.parametrize("version", ["", "9" * 257])
    def test_empty_and_overlong_versions_rejected(self, version):
        """Empty and over-cap versions fail closed before the character
        allow-list is consulted."""
        from scarno.indexing.validator import is_valid_fetch_version

        assert is_valid_fetch_version(version) is False

    @pytest.mark.requirement("SEC-NEW-59")
    def test_boundary_length_version_accepted(self):
        """The cap itself is inclusive — a 256-character version is
        still a valid path segment, so the guard must not be off by one.
        """
        from scarno.indexing.validator import is_valid_fetch_version

        assert is_valid_fetch_version("9" * 256) is True

    @pytest.mark.requirement("SEC-NEW-59")
    def test_artefact_url_rejects_unvalidated_version_at_the_sink(
        self, tmp_path,
    ):
        """``fetch`` gates the version, but ``_artefact_url`` re-asserts
        the allow-list so a future call path cannot template a
        repo-derived version straight into the request URL. Calling the
        sink directly is the only way to exercise that guard.
        """
        fetcher = _make_fetcher(tmp_path, _ScriptedClient({}), [])

        with pytest.raises(ValueError, match="not a valid index segment|not a valid index path segment"):
            fetcher._artefact_url(
                _make_endpoint(), _GUAVA, "1.0/../../admin", "jar",
            )
