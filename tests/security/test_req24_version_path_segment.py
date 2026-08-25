"""REQ-24 — a declared version can never choose the request path.

The group/artifact halves of an artefact URL are pinned by the
``ValidatedCoordinate`` regex; the version comes straight from the
analysed project's pom.xml. These tests hold the line that the version
is percent-encoded into exactly ONE path segment at both sinks — the
artefact URL (and therefore the ``.sha512`` / ``.sha256`` / ``.sha1``
URLs derived from it) and the quarantined-cache path — while ordinary
Maven versions, including the ``1.20.1+build.10`` build-metadata family,
still travel the wire and land on disk unchanged.
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
from scarno.indexing.fetcher import _cache_relative_path

pytestmark = pytest.mark.security


_GUAVA = CoordinateValidator.validate("maven", "com.google.guava:guava")
_INDEX = "https://repo1.example/m2"
_COORD_DIR = f"{_INDEX}/com/google/guava/guava/"


class _ScriptedClient(SafeHttpsClient):
    """Records every requested URL; answers from a canned script."""

    def __init__(self, script: dict[str, Any], **kw: Any) -> None:
        super().__init__(**kw)
        self._script = script
        self.requests: list[str] = []

    def get(self, url: str) -> HttpResponse:  # type: ignore[override]
        self.requests.append(url)
        if url not in self._script:
            raise SafeHttpsError(f"unscripted URL: {url}")
        return self._script[url]


def _resp(status: int = 200, body: bytes = b"") -> HttpResponse:
    return HttpResponse(
        status=status, headers={}, body=body, final_url="",
        pinned_ip="8.8.8.8",
    )


def _endpoint() -> IndexEndpoint:
    return IndexEndpoint(
        ecosystem="maven", url=_INDEX, priority=0,
        source=IndexConfigSource.CLI,
    )


def _fetcher(
    tmp_path: Path, client: SafeHttpsClient, warnings: list[str],
) -> RemoteArtifactFetcher:
    return RemoteArtifactFetcher(
        client=client, warnings=warnings, cache_root=tmp_path / "fetched",
    )


# ── The version cannot shape the request path ──────────────────────────────


class TestVersionCannotShapeUrl:
    @pytest.mark.requirement("SEC-NEW-38")
    def test_traversal_version_is_rejected_before_any_request(
        self, tmp_path,
    ):
        """``1.0/../../../evil`` never reaches the network at all.

        The F20 patch made such a version encode to a single segment;
        the F8 allow-list, applied first, refuses it outright instead —
        a strictly stronger outcome, so this asserts the stronger one.
        The encoding remains at both sinks as defence in depth.
        """
        client = _ScriptedClient({})
        warnings: list[str] = []
        result = _fetcher(tmp_path, client, warnings).fetch(
            _GUAVA, "1.0/../../../evil", [_endpoint()],
        )

        assert result is None
        assert client.requests == [], client.requests
        assert any("rejecting unsafe version" in w for w in warnings), warnings

    @pytest.mark.requirement("SEC-NEW-38")
    def test_encoder_keeps_a_traversal_version_in_one_segment(self):
        """The sink encoder is what would contain such a version if one
        ever reached it. ``fetch`` rejects it first, so the guarantee is
        pinned on the encoder directly rather than over the wire.
        """
        from scarno.indexing.fetcher import _path_segment

        encoded = _path_segment("1.0/../../../evil")
        assert "/" not in encoded, encoded
        assert encoded == "1.0%2F..%2F..%2F..%2Fevil", encoded

    @pytest.mark.requirement("SEC-NEW-38")
    @pytest.mark.parametrize("version", [
        ".", "..", "...", "1.0/./x", "a/../b", "%2e%2e", "%2E%2E",
        "..%2f", "1.0?x=1", "1.0#frag",
    ])
    def test_adversarial_versions_never_reach_the_network(
        self, tmp_path, version,
    ):
        """Dot-only segments, encoded separators, query and fragment
        introducers are all refused by the allow-list before a request
        is made. The encoder still neutralises each of them at the sink,
        asserted separately below.
        """
        client = _ScriptedClient({})
        warnings: list[str] = []
        result = _fetcher(tmp_path, client, warnings).fetch(
            _GUAVA, version, [_endpoint()],
        )

        assert result is None
        assert client.requests == [], client.requests

    @pytest.mark.requirement("SEC-NEW-38")
    @pytest.mark.parametrize("version", [
        ".", "..", "...", "1.0/./x", "a/../b", "%2e%2e", "%2E%2E",
        "..%2f", "1.0?x=1", "1.0#frag",
    ])
    def test_encoder_neutralises_adversarial_versions(self, version):
        """Defence in depth: whatever the entry-point gate does, the
        encoder alone must keep each of these to one inert segment, with
        ``%`` encoded so ``..%2f`` cannot round-trip into a separator.
        """
        from scarno.indexing.fetcher import _path_segment

        segment = _path_segment(version)
        # Nothing structural survives literally...
        assert "/" not in segment, segment
        assert "?" not in segment, segment
        assert "#" not in segment, segment
        # ...and the result is never a dot-segment, which would still be
        # traversal even without a separator of its own.
        assert segment.strip(".") != "" or segment == "", segment
        assert segment not in {".", "..", "..."}, segment
        # A literal '%' is itself encoded, so an already-encoded
        # separator cannot round-trip back into one.
        if "%" in version:
            assert "%25" in segment, segment


# ── The cache path is a leaf under the coordinate dir ──────────────────────


class TestVersionCannotShapeCachePath:
    @pytest.mark.requirement("SEC-NEW-65")
    def test_traversal_version_cache_path_has_no_dot_segments(self):
        rel = _cache_relative_path(_GUAVA, "1.0/../../../evil")
        assert rel.parts[:5] == (
            "maven", "com", "google", "guava", "guava",
        )
        # <version> dir + filename and nothing else.
        assert len(rel.parts) == 7, rel.parts
        assert ".." not in rel.parts
        assert "." not in rel.parts

    @pytest.mark.requirement("SEC-NEW-65")
    @pytest.mark.parametrize("version", [".", "..", "..."])
    def test_dot_only_versions_survive_as_a_real_directory(self, version):
        rel = _cache_relative_path(_GUAVA, version)
        assert len(rel.parts) == 7, rel.parts
        assert rel.parts[5] not in {".", ".."}

    @pytest.mark.requirement("SEC-NEW-65")
    def test_distinct_versions_never_share_a_cache_entry(self):
        """Injectivity. ``1.0/./x`` and ``1.0/x`` collided before the
        fix — pathlib drops a ``.`` component — so one poisoned fetch
        could be served for a different declared version."""
        versions = [
            "1.0", "1.0/x", "1.0/./x", "1.0/../x", ".", "..", "...",
            "%2e%2e", "..%2f", "1.0?x=1", "1.0#frag", "1.20.1+build.10",
        ]
        paths = {str(_cache_relative_path(_GUAVA, v)) for v in versions}
        assert len(paths) == len(versions)


# ── Legitimate versions are untouched ──────────────────────────────────────


class TestLegitimateVersionsUnchanged:
    @pytest.mark.requirement("SEC-NEW-38")
    @pytest.mark.parametrize("version", [
        "33.0.0-jre",          # ordinary release
        "1.0-SNAPSHOT",        # snapshot
        "1.20.1+build.10",     # Fabric-style build metadata — '+' is a
                               # legal path character and must stay literal
        "2.0.0-rc1_final",
        "1.0~beta",
    ])
    def test_wire_and_cache_layout_are_byte_for_byte_unchanged(
        self, tmp_path, version,
    ):
        client = _ScriptedClient({})
        warnings: list[str] = []
        _fetcher(tmp_path, client, warnings).fetch(
            _GUAVA, version, [_endpoint()],
        )

        assert client.requests == [
            f"{_COORD_DIR}{version}/guava-{version}.jar"
        ]
        rel = _cache_relative_path(_GUAVA, version)
        assert rel.parts[5] == version
        assert rel.name == f"guava-{version}.jar"

    @pytest.mark.requirement("SEC-NEW-38")
    @pytest.mark.parametrize("version", [
        "33.0.0-jre", "1.20.1+build.10", "1.0-SNAPSHOT",
    ])
    def test_no_structural_character_warning_for_legitimate_versions(
        self, tmp_path, version,
    ):
        """The audit line is gated on the characters that really are
        structural, so a Fabric-style ``+`` version does not put a
        spurious entry in the report's Warnings section."""
        client = _ScriptedClient({})
        warnings: list[str] = []
        _fetcher(tmp_path, client, warnings).fetch(
            _GUAVA, version, [_endpoint()],
        )

        assert not [w for w in warnings if "structural" in w]

    @pytest.mark.requirement("SEC-NEW-38")
    def test_structural_version_is_audited(self, tmp_path):
        """A version carrying URL/path structure must leave a trace in
        the audit channel rather than failing silently.

        The F20 patch worded that line around encoding the version and
        fetching it anyway; with the F8 allow-list applied first the
        version is refused outright, so the audit line is the rejection.
        The requirement — the operator can see what happened to it — is
        unchanged.
        """
        client = _ScriptedClient({})
        warnings: list[str] = []
        result = _fetcher(tmp_path, client, warnings).fetch(
            _GUAVA, "1.0/../evil", [_endpoint()],
        )

        assert result is None
        assert client.requests == [], client.requests
        assert [w for w in warnings if "rejecting unsafe version" in w], warnings


class TestNonMavenCachePath:
    """The non-Maven branch of the cache path is unreachable through
    ``fetch`` in v1 — the fetcher short-circuits every ecosystem but
    Maven — yet it templates the version just the same. Exercised
    directly so the encoding there is not left unproven until the npm
    fetch path lands.
    """

    @pytest.mark.requirement("SEC-NEW-38")
    def test_npm_cache_path_encodes_the_version(self):
        from scarno.indexing.fetcher import _cache_relative_path
        from scarno.indexing.validator import CoordinateValidator

        coord = CoordinateValidator.validate("npm", "left-pad")
        assert _cache_relative_path(coord, "1.0.0") == Path(
            "npm/left-pad/1.0.0/artefact"
        )

    @pytest.mark.requirement("SEC-NEW-38")
    def test_npm_cache_path_cannot_gain_a_segment(self):
        from scarno.indexing.fetcher import _cache_relative_path
        from scarno.indexing.validator import CoordinateValidator

        coord = CoordinateValidator.validate("npm", "left-pad")
        relpath = _cache_relative_path(coord, "1.0/../../etc")
        assert ".." not in relpath.parts, relpath
        # ecosystem / name / version / "artefact" — no extra segments.
        assert len(relpath.parts) == 4, relpath
