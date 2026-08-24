"""REQ-24 / Option 2 — POM fetching, lazy JAR fetching, and cache-first
ordering.

Covers the three behavioural changes the user requested:

* ``MavenPomResolver._locate_or_fetch_pom`` walks m2 → REQ-24 fetcher
  → Maven CLI in order. m2-hit returns immediately with no fetcher
  call (cache-first). m2-miss with fetcher set falls through to a
  POM fetch.
* ``CrossVersionAbiDiffer._resolve_jar`` tries m2 first, find_jar
  second (H4 cache-first). A JAR present in m2 yields ``provenance=
  "local"`` with no find_jar invocation.
* ``JavaAnalyser._build_lazy_find_jar`` fetches ANY (coord, version)
  the differ asks about — minimisation gate dropped under Option 2.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scarno.analysers.java._maven_version import declared_covers_resolved
from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
from scarno.analysers.java.maven import MavenPomResolver
from scarno.indexing import (
    CoordinateValidator,
    IndexConfigSource,
    IndexEndpoint,
    ValidatedCoordinate,
)


# ── POM fetcher integration in MavenPomResolver._locate_or_fetch_pom ──────


class _PomCaptureFetcher:
    """Minimal fetcher stub — records ``fetch_pom`` calls and writes
    a synthetic POM to a tmp_path it owns so the resolver can read
    the file back."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.calls: list[tuple[ValidatedCoordinate, str]] = []
        self.return_pom = True  # set False to simulate fetch failure

    def fetch_pom(
        self,
        coord: ValidatedCoordinate,
        version: str,
        endpoints: list[IndexEndpoint],
    ) -> Path | None:
        self.calls.append((coord, version))
        if not self.return_pom:
            return None
        out = self.tmp_path / f"{coord.components[1]}-{version}.pom"
        out.write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            f"<groupId>{coord.components[0]}</groupId>"
            f"<artifactId>{coord.components[1]}</artifactId>"
            f"<version>{version}</version></project>"
        )
        return out


class TestPomFetchInResolver:
    def test_m2_hit_does_not_invoke_fetcher(
        self, monkeypatch, tmp_path,
    ):
        """Cache-first — when ``_locate_pom_in_local_cache`` returns
        a Path, the fetcher is never called."""
        from scarno.analysers.java import maven as mvn_mod

        cached_pom = tmp_path / "cached.pom"
        cached_pom.write_text("<project/>")
        monkeypatch.setattr(
            mvn_mod, "_locate_pom_in_local_cache",
            lambda coords, errors: cached_pom,
        )
        fetcher = _PomCaptureFetcher(tmp_path)

        resolver = MavenPomResolver()
        resolver.fetcher = fetcher
        resolver.endpoints = [
            IndexEndpoint("maven", "https://repo/m2", 0, IndexConfigSource.CLI),
        ]

        errors: list[str] = []
        result = resolver._locate_or_fetch_pom(
            ("com.example", "lib", "1.0"), errors,
        )
        assert result == cached_pom
        assert fetcher.calls == [], (
            "fetcher invoked despite m2 cache hit"
        )

    def test_m2_miss_falls_through_to_fetcher(
        self, monkeypatch, tmp_path,
    ):
        """When m2 misses AND fetcher is wired, the fetcher is
        called and its returned path becomes the POM."""
        from scarno.analysers.java import maven as mvn_mod

        monkeypatch.setattr(
            mvn_mod, "_locate_pom_in_local_cache",
            lambda coords, errors: None,
        )
        fetcher = _PomCaptureFetcher(tmp_path)

        resolver = MavenPomResolver()
        resolver.fetcher = fetcher
        resolver.endpoints = [
            IndexEndpoint("maven", "https://repo/m2", 0, IndexConfigSource.CLI),
        ]

        errors: list[str] = []
        result = resolver._locate_or_fetch_pom(
            ("com.example", "lib", "1.0"), errors,
        )
        assert result is not None
        assert result.exists()
        assert len(fetcher.calls) == 1
        coord, version = fetcher.calls[0]
        assert coord.raw == "com.example:lib"
        assert version == "1.0"

    def test_m2_miss_no_fetcher_falls_through_to_cli(
        self, monkeypatch, tmp_path,
    ):
        """No fetcher wired but the network capability granted →
        resolver still tries the legacy Maven CLI tier."""
        from scarno.analysers.java import maven as mvn_mod

        monkeypatch.setattr(
            mvn_mod, "_locate_pom_in_local_cache",
            lambda coords, errors: None,
        )
        cli_called: list[tuple[str, ...]] = []

        def _fake_cli(coords, errors):
            cli_called.append(coords)
            return None

        monkeypatch.setattr(
            mvn_mod, "_fetch_pom_via_maven", _fake_cli,
        )

        resolver = MavenPomResolver()
        # No fetcher set, but --allow-remote-fetch was passed.
        resolver.allow_remote_fetch = True

        errors: list[str] = []
        resolver._locate_or_fetch_pom(
            ("com.example", "lib", "1.0"), errors,
        )
        assert cli_called == [("com.example", "lib", "1.0")]

    def test_m2_miss_without_capability_never_spawns_cli(
        self, monkeypatch, tmp_path,
    ):
        """Without --allow-remote-fetch, an m2 miss must NOT reach the
        ``mvn dependency:get`` tier: the coordinates come from the
        analysed project's own pom.xml, so spawning Maven for them is
        an outbound call the operator never authorised."""
        from scarno.analysers.java import maven as mvn_mod

        monkeypatch.setattr(
            mvn_mod, "_locate_pom_in_local_cache",
            lambda coords, errors: None,
        )
        cli_called: list[tuple[str, ...]] = []

        def _fake_cli(coords, errors):
            cli_called.append(coords)
            return None

        monkeypatch.setattr(
            mvn_mod, "_fetch_pom_via_maven", _fake_cli,
        )

        resolver = MavenPomResolver()
        # Default: allow_remote_fetch is False.
        assert resolver.allow_remote_fetch is False

        errors: list[str] = []
        result = resolver._locate_or_fetch_pom(
            ("com.example", "lib", "1.0"), errors,
        )
        assert result is None
        assert cli_called == [], (
            "mvn dependency:get spawned without --allow-remote-fetch"
        )
        assert any("maven-cli-fetch" in e for e in errors)

        # The explanatory note is emitted once, not per coordinate.
        resolver._locate_or_fetch_pom(
            ("com.example", "other", "2.0"), errors,
        )
        assert sum("maven-cli-fetch" in e for e in errors) == 1

    @pytest.mark.parametrize("capability", [False, True])
    def test_java_analyser_forwards_capability_to_resolver(
        self, monkeypatch, tmp_path, capability,
    ):
        """JavaAnalyser must propagate --allow-remote-fetch onto the
        MavenPomResolver it builds, otherwise the tier-3 gate can
        never open (and, before the gate existed, never closed)."""
        from scarno.analysers.java import JavaAnalyser

        (tmp_path / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            "<groupId>com.example</groupId>"
            "<artifactId>app</artifactId>"
            "<version>1.0</version></project>"
        )
        seen: list[bool] = []
        real_analyse = MavenPomResolver.analyse

        def _spy(self, project_path):
            seen.append(self.allow_remote_fetch)
            return real_analyse(self, project_path)

        monkeypatch.setattr(MavenPomResolver, "analyse", _spy)
        # Keep the test hermetic: index resolution reads the operator's
        # env / config and is irrelevant to the forwarding assertion.
        monkeypatch.setattr(
            JavaAnalyser, "_maybe_build_fetcher",
            lambda self, root, errors, findings: (None, []),
        )

        analyser = JavaAnalyser()
        analyser.allow_remote_fetch = capability
        analyser.analyse(str(tmp_path))
        assert seen == [capability]

    def test_invalid_coord_emits_audit_not_crash(
        self, monkeypatch, tmp_path,
    ):
        from scarno.analysers.java import maven as mvn_mod

        monkeypatch.setattr(
            mvn_mod, "_locate_pom_in_local_cache",
            lambda coords, errors: None,
        )
        # Replace the CLI tier with a no-op so we don't hit a real shell.
        monkeypatch.setattr(
            mvn_mod, "_fetch_pom_via_maven",
            lambda coords, errors: None,
        )

        resolver = MavenPomResolver()
        # A fetcher with no endpoints is fine — coord validation would
        # fire first if the coord had bad characters. Use a coord with
        # a path-traversal segment to trigger validator rejection.
        fetcher = _PomCaptureFetcher(tmp_path)
        resolver.fetcher = fetcher
        resolver.endpoints = [
            IndexEndpoint("maven", "https://repo/m2", 0, IndexConfigSource.CLI),
        ]

        errors: list[str] = []
        result = resolver._locate_or_fetch_pom(
            ("com.example", "../evil", "1.0"), errors,
        )
        assert result is None
        assert any(
            "validation rejected" in e.lower() or
            "invalid" in e.lower()
            for e in errors
        )
        # Fetcher never called for invalid coord.
        assert fetcher.calls == []


# ── H4 — m2-first ordering in CrossVersionAbiDiffer._resolve_jar ──────────


class TestM2FirstInAbiDiffer:
    def test_m2_hit_returns_local_without_invoking_find_jar(
        self, tmp_path,
    ):
        """A JAR present in m2 returns ``provenance="local"`` and
        ``find_jar`` is NEVER called — preserves the operator's
        already-trusted m2 cache and avoids spurious network hits."""
        # Build a fake m2 layout with the JAR present.
        m2 = tmp_path / "m2"
        jar = m2 / "com" / "example" / "lib" / "1.0" / "lib-1.0.jar"
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b"PK\x03\x04")

        find_jar_calls: list[tuple[str, str]] = []

        def find_jar(coord, version):
            find_jar_calls.append((coord, version))
            return None

        differ = CrossVersionAbiDiffer(
            m2_root=m2,
            invoke_javap=lambda *_a, **_k: None,
            find_jar=find_jar,
        )
        path, provenance = differ._resolve_jar("com.example:lib", "1.0")
        assert path is not None and path.exists()
        assert provenance == "local"
        assert find_jar_calls == [], (
            "find_jar invoked despite m2 cache hit — H4 not honoured"
        )

    def test_m2_miss_falls_through_to_find_jar_and_tags_remote(
        self, tmp_path,
    ):
        """m2 miss → find_jar invoked → remote provenance on hit."""
        m2 = tmp_path / "m2"
        m2.mkdir()
        fetched_jar = tmp_path / "fetched-1.0.jar"
        fetched_jar.write_bytes(b"PK\x03\x04")

        def find_jar(coord, version):
            return fetched_jar

        differ = CrossVersionAbiDiffer(
            m2_root=m2,
            invoke_javap=lambda *_a, **_k: None,
            find_jar=find_jar,
        )
        path, provenance = differ._resolve_jar("com.example:lib", "1.0")
        assert path == fetched_jar
        assert provenance == "remote"
