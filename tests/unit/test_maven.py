"""Tests for the Maven POM resolver — REQ-4."""
from __future__ import annotations

import os
import signal
import subprocess
import textwrap

import pytest

from scarno.analysers.java import maven as maven_mod
from scarno.analysers.java.maven import (
    MavenPomResolver,
    _fetch_pom_via_maven,
    _gav_to_pom_path,
    _is_valid_gav_component,
    _locate_pom_in_local_cache,
    _resolve_mvn_binary,
    _validate_gav,
)


@pytest.fixture
def resolver() -> MavenPomResolver:
    return MavenPomResolver()


class TestBasicParsing:
    @pytest.mark.requirement("FR-018")
    def test_single_module_deps_parsed(self, tmp_path, resolver):
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <groupId>com.example</groupId>
              <artifactId>myapp</artifactId>
              <version>1.0</version>
              <dependencies>
                <dependency>
                  <groupId>org.springframework</groupId>
                  <artifactId>spring-core</artifactId>
                  <version>6.0.0</version>
                </dependency>
              </dependencies>
            </project>
        """
            )
        )
        result = resolver.analyse(str(tmp_path))
        names = [d.name for d in result.dependencies]
        assert any("spring-core" in n for n in names)

    @pytest.mark.requirement("FR-019")
    def test_parent_pom_version_inherited(self, tmp_path, resolver):
        parent_dir = tmp_path / "parent"
        parent_dir.mkdir()
        child_dir = tmp_path / "child"
        child_dir.mkdir()
        (parent_dir / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <groupId>com.example</groupId>
              <artifactId>parent</artifactId>
              <version>2.0</version>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>com.google.guava</groupId>
                    <artifactId>guava</artifactId>
                    <version>32.1.2-jre</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
        """
            )
        )
        (child_dir / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <parent>
                <groupId>com.example</groupId>
                <artifactId>parent</artifactId>
                <version>2.0</version>
                <relativePath>../parent/pom.xml</relativePath>
              </parent>
              <artifactId>child</artifactId>
              <dependencies>
                <dependency>
                  <groupId>com.google.guava</groupId>
                  <artifactId>guava</artifactId>
                </dependency>
              </dependencies>
            </project>
        """
            )
        )
        result = resolver.analyse(str(child_dir))
        guava = next((d for d in result.dependencies if "guava" in d.name), None)
        assert guava is not None
        assert guava.version == "32.1.2-jre"


class TestXXEPrevention:
    @pytest.mark.requirement("SEC-010")
    @pytest.mark.requirement("SEC-NEW-01")
    @pytest.mark.requirement("T-02")
    @pytest.mark.security
    def test_xxe_entity_reference_blocked(self, tmp_path, resolver):
        """A pom.xml with XXE payload must not read the referenced file."""
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <!DOCTYPE project [
              <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <project>
              <groupId>com.example</groupId>
              <artifactId>&xxe;</artifactId>
              <version>1.0</version>
            </project>
        """
            )
        )
        sentinel = tmp_path / "sentinel.txt"
        sentinel.write_text("sentinel_content_12345")
        try:
            result = resolver.analyse(str(tmp_path))
            all_text = " ".join(d.name for d in result.dependencies)
            all_text += " ".join(result.errors)
        except Exception:
            all_text = ""
        assert "root:" not in all_text
        assert "sentinel_content_12345" not in all_text

    @pytest.mark.requirement("SEC-NEW-01")
    @pytest.mark.security
    def test_exclusions_augmentation_rejects_doctype(self, tmp_path):
        """Defence-in-depth: the ``<exclusions>`` re-parse path
        (``_augment_pom_with_exclusions``) must refuse a DOCTYPE-bearing
        POM before it reaches the stdlib XML parser. This path re-reads
        the file independently of the main parser, so without its own
        DOCTYPE guard it would be an unguarded XXE sink."""
        clean = tmp_path / "clean-pom.xml"
        clean.write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            "<groupId>g</groupId><artifactId>a</artifactId><version>1</version>"
            "<dependencies><dependency><groupId>x</groupId>"
            "<artifactId>y</artifactId><version>1</version></dependency>"
            "</dependencies></project>"
        )
        pom = maven_mod._parse_pom_file(clean, [])
        assert pom is not None

        sentinel = tmp_path / "sentinel.txt"
        sentinel.write_text("sentinel_content_54321")
        malicious = tmp_path / "evil-pom.xml"
        malicious.write_text(
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE project [\n"
            f'  <!ENTITY xxe SYSTEM "file://{sentinel}">\n'
            "]>\n"
            "<project><dependencies><dependency>"
            "<groupId>&xxe;</groupId><artifactId>y</artifactId>"
            "<exclusions><exclusion><groupId>e</groupId>"
            "<artifactId>ex</artifactId></exclusion></exclusions>"
            "</dependency></dependencies></project>"
        )
        # Returns without raising and without reading the sentinel file.
        maven_mod._augment_pom_with_exclusions(malicious, pom)
        blob = repr(pom.dependencies)
        assert "sentinel_content_54321" not in blob
        assert "root:" not in blob

    @pytest.mark.requirement("SEC-010")
    @pytest.mark.requirement("SEC-NEW-01")
    @pytest.mark.requirement("D-02")
    @pytest.mark.security
    def test_billion_laughs_does_not_exhaust_memory(self, tmp_path, resolver):
        """Billion laughs attack must be blocked before memory exhaustion."""
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <!DOCTYPE project [
              <!ENTITY lol "lol">
              <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
              <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
            ]>
            <project>
              <artifactId>&lol3;</artifactId>
            </project>
        """
            )
        )

        def timeout_handler(signum, frame):
            pytest.fail("XML parsing took too long — billion laughs not blocked")

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)
        try:
            resolver.analyse(str(tmp_path))
        except Exception:
            pass
        finally:
            signal.alarm(0)


class TestPathTraversal:
    @pytest.mark.requirement("T-07")
    @pytest.mark.requirement("FR-019")
    @pytest.mark.security
    def test_parent_pom_relative_path_traversal_blocked(self, tmp_path, resolver):
        project = tmp_path / "project"
        project.mkdir()
        (project / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <parent>
                <groupId>com.example</groupId>
                <artifactId>evil-parent</artifactId>
                <version>1.0</version>
                <relativePath>../../../../etc/passwd</relativePath>
              </parent>
              <artifactId>child</artifactId>
            </project>
        """
            )
        )
        result = resolver.analyse(str(project))
        assert any(
            "not found" in e.lower() or "escape" in e.lower() or "outside" in e.lower()
            for e in result.errors
        )

    @pytest.mark.requirement("SEC-NEW-08")
    @pytest.mark.requirement("D-06")
    @pytest.mark.security
    def test_circular_module_reference_detected(self, tmp_path, resolver):
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <groupId>com.example</groupId>
              <artifactId>root</artifactId>
              <version>1.0</version>
              <modules>
                <module>.</module>
              </modules>
            </project>
        """
            )
        )

        def timeout_handler(signum, frame):
            pytest.fail("Circular module traversal did not terminate")

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)
        try:
            result = resolver.analyse(str(tmp_path))
            assert any(
                "cycle" in e.lower() or "circular" in e.lower()
                for e in result.errors
            )
        finally:
            signal.alarm(0)


# ── GAV validation ────���─────────────────────────────────────────────────────


class TestGavValidation:
    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_valid_gav_accepted(self):
        assert _validate_gav(
            ("org.springframework.boot", "spring-boot-starter-parent", "3.2.0")
        )

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_empty_component_rejected(self):
        assert not _is_valid_gav_component("")

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_path_traversal_in_group_id_rejected(self):
        assert not _validate_gav(("../../../etc", "passwd", "1.0"))

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_shell_metachar_in_artifact_rejected(self):
        assert not _is_valid_gav_component("foo;rm -rf /")

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_nul_byte_in_version_rejected(self):
        assert not _is_valid_gav_component("1.0\x00")

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_dot_dot_in_component_rejected(self):
        assert not _is_valid_gav_component("..")

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_slash_in_component_rejected(self):
        assert not _is_valid_gav_component("foo/bar")

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_backslash_in_component_rejected(self):
        assert not _is_valid_gav_component("foo\\bar")


# ── Tier 1: local cache resolution ────���────────────────────────────────────


def _write_cached_pom(
    repo_root, group_id, artifact_id, version, pom_content
):
    """Helper: write a POM file into the mock .m2 layout."""
    pom_path = _gav_to_pom_path(repo_root, group_id, artifact_id, version)
    pom_path.parent.mkdir(parents=True, exist_ok=True)
    pom_path.write_text(pom_content)
    return pom_path


class TestLocalCacheResolution:
    @pytest.mark.requirement("FR-131")
    def test_pom_found_in_m2_cache(self, tmp_path, monkeypatch):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        _write_cached_pom(
            repo,
            "com.example",
            "parent",
            "1.0",
            '<?xml version="1.0"?><project><groupId>com.example</groupId>'
            "<artifactId>parent</artifactId><version>1.0</version></project>",
        )
        errors: list[str] = []
        result = _locate_pom_in_local_cache(
            ("com.example", "parent", "1.0"), errors
        )
        assert result is not None
        assert result.name == "parent-1.0.pom"
        assert not errors

    @pytest.mark.requirement("FR-131")
    def test_m2_directory_missing_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            maven_mod, "_m2_repo_path", lambda: tmp_path / "nonexistent"
        )
        errors: list[str] = []
        result = _locate_pom_in_local_cache(
            ("com.example", "parent", "1.0"), errors
        )
        assert result is None
        assert not errors  # Not an error — just no cache

    @pytest.mark.requirement("FR-131")
    def test_pom_file_missing_returns_none(self, tmp_path, monkeypatch):
        repo = tmp_path / ".m2" / "repository"
        repo.mkdir(parents=True)
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        errors: list[str] = []
        result = _locate_pom_in_local_cache(
            ("com.example", "parent", "1.0"), errors
        )
        assert result is None

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_symlink_escape_blocked(self, tmp_path, monkeypatch):
        """A symlink inside .m2/repository pointing outside must be caught."""
        repo = tmp_path / ".m2" / "repository"
        pom_path = _gav_to_pom_path(repo, "com.example", "evil", "1.0")
        pom_path.parent.mkdir(parents=True, exist_ok=True)
        # Create a symlink pointing outside the repository
        target = tmp_path / "outside" / "secret.pom"
        target.parent.mkdir(parents=True)
        target.write_text("secret")
        pom_path.symlink_to(target)
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        errors: list[str] = []
        result = _locate_pom_in_local_cache(
            ("com.example", "evil", "1.0"), errors
        )
        assert result is None
        assert any("escapes" in e.lower() or "outside" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-131")
    def test_oversized_pom_skipped(self, tmp_path, monkeypatch):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        pom_path = _gav_to_pom_path(repo, "com.example", "big", "1.0")
        pom_path.parent.mkdir(parents=True, exist_ok=True)
        # Write a file exceeding MAX_FILE_BYTES (10 MiB)
        pom_path.write_bytes(b"x" * (10 * 1024 * 1024 + 1))
        errors: list[str] = []
        result = _locate_pom_in_local_cache(
            ("com.example", "big", "1.0"), errors
        )
        assert result is None
        assert any("size limit" in e for e in errors)

    @pytest.mark.requirement("FR-131")
    def test_parent_resolved_from_cache_when_relativepath_fails(
        self, tmp_path, monkeypatch, resolver
    ):
        """End-to-end: child references a parent not on the filesystem,
        but the parent POM is in the mock .m2 cache."""
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        # Block mvn so only cache is used
        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: None)

        project = tmp_path / "project"
        project.mkdir()
        (project / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>3.2.0</version>
                <relativePath/>
              </parent>
              <artifactId>myapp</artifactId>
              <dependencies>
                <dependency>
                  <groupId>org.springframework</groupId>
                  <artifactId>spring-web</artifactId>
                </dependency>
              </dependencies>
            </project>
        """
            )
        )
        _write_cached_pom(
            repo,
            "org.springframework.boot",
            "spring-boot-starter-parent",
            "3.2.0",
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <groupId>org.springframework.boot</groupId>
              <artifactId>spring-boot-starter-parent</artifactId>
              <version>3.2.0</version>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.springframework</groupId>
                    <artifactId>spring-web</artifactId>
                    <version>6.1.1</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
        """
            ),
        )
        result = resolver.analyse(str(project))
        spring_web = next(
            (d for d in result.dependencies if "spring-web" in d.name), None
        )
        assert spring_web is not None
        assert spring_web.version == "6.1.1"


# ─��� Tier 2: Maven CLI fallback ─────────────────────────────────────────────


class TestMavenCliFallback:
    @pytest.mark.requirement("SEC-NEW-28")
    @pytest.mark.security
    def test_mvn_binary_resolved_from_maven_home(self, tmp_path, monkeypatch):
        mvn_bin = tmp_path / "maven" / "bin" / "mvn"
        mvn_bin.parent.mkdir(parents=True)
        mvn_bin.write_text("#!/bin/sh\n")
        mvn_bin.chmod(0o755)
        monkeypatch.setenv("MAVEN_HOME", str(tmp_path / "maven"))
        monkeypatch.delenv("M2_HOME", raising=False)
        result = _resolve_mvn_binary()
        assert result is not None
        assert "mvn" in result

    @pytest.mark.requirement("SEC-NEW-28")
    @pytest.mark.security
    def test_mvn_binary_resolved_from_m2_home(self, tmp_path, monkeypatch):
        mvn_bin = tmp_path / "m2" / "bin" / "mvn"
        mvn_bin.parent.mkdir(parents=True)
        mvn_bin.write_text("#!/bin/sh\n")
        mvn_bin.chmod(0o755)
        monkeypatch.delenv("MAVEN_HOME", raising=False)
        monkeypatch.setenv("M2_HOME", str(tmp_path / "m2"))
        result = _resolve_mvn_binary()
        assert result is not None
        assert "mvn" in result

    @pytest.mark.requirement("FR-132")
    def test_mvn_binary_resolved_from_path(self, monkeypatch):
        monkeypatch.delenv("MAVEN_HOME", raising=False)
        monkeypatch.delenv("M2_HOME", raising=False)
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/mvn")
        result = _resolve_mvn_binary()
        assert result == "/usr/bin/mvn"

    @pytest.mark.requirement("FR-132")
    def test_mvn_not_found_returns_none(self, monkeypatch):
        monkeypatch.delenv("MAVEN_HOME", raising=False)
        monkeypatch.delenv("M2_HOME", raising=False)
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        result = _resolve_mvn_binary()
        assert result is None

    @pytest.mark.requirement("FR-132")
    def test_mvn_fetch_succeeds_and_reads_from_cache(
        self, tmp_path, monkeypatch
    ):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        coords = ("com.example", "fetched-parent", "2.0")

        # Mock subprocess.run to simulate mvn success, then write the POM
        # to the cache so the subsequent _locate_pom_in_local_cache finds it.
        def mock_run(*args, **kwargs):
            _write_cached_pom(
                repo,
                *coords,
                '<?xml version="1.0"?><project>'
                "<groupId>com.example</groupId>"
                "<artifactId>fetched-parent</artifactId>"
                "<version>2.0</version></project>",
            )
            return subprocess.CompletedProcess(args=args, returncode=0)

        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: "/usr/bin/mvn")
        monkeypatch.setattr(subprocess, "run", mock_run)
        errors: list[str] = []
        result = _fetch_pom_via_maven(
            coords, errors, allow_remote_fetch=True
        )
        assert result is not None
        assert result.name == "fetched-parent-2.0.pom"

    @pytest.mark.requirement("FR-132")
    def test_mvn_fetch_timeout_returns_none(self, monkeypatch):
        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: "/usr/bin/mvn")
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="mvn", timeout=60)
            ),
        )
        errors: list[str] = []
        result = _fetch_pom_via_maven(
            ("com.example", "slow", "1.0"), errors,
            allow_remote_fetch=True,
        )
        assert result is None
        assert any("timeout" in e.lower() or "os error" in e.lower() for e in errors)

    @pytest.mark.requirement("FR-132")
    def test_mvn_fetch_nonzero_exit_returns_none(self, monkeypatch):
        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: "/usr/bin/mvn")
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(args=a, returncode=1),
        )
        errors: list[str] = []
        result = _fetch_pom_via_maven(
            ("com.example", "missing", "1.0"), errors,
            allow_remote_fetch=True,
        )
        assert result is None
        assert any("exited with code 1" in e for e in errors)

    @pytest.mark.requirement("FR-132")
    def test_mvn_fetch_oserror_returns_none(self, monkeypatch):
        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: "/usr/bin/mvn")

        def raise_oserror(*a, **kw):
            raise OSError("permission denied")

        monkeypatch.setattr(subprocess, "run", raise_oserror)
        errors: list[str] = []
        result = _fetch_pom_via_maven(
            ("com.example", "broken", "1.0"), errors,
            allow_remote_fetch=True,
        )
        assert result is None

    @pytest.mark.requirement("SEC-NEW-27")
    @pytest.mark.security
    def test_invalid_gav_not_passed_to_subprocess(self, monkeypatch):
        """Invalid GAV coordinates must never reach subprocess."""
        called = []
        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: "/usr/bin/mvn")
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: called.append("called"),
        )
        errors: list[str] = []
        _fetch_pom_via_maven(
            ("../../../etc", "passwd", "1.0"), errors,
            allow_remote_fetch=True,
        )
        assert called == []

    @pytest.mark.requirement("FR-260")
    @pytest.mark.requirement("SEC-NEW-72")
    @pytest.mark.security
    def test_no_spawn_without_allow_remote_fetch(self, monkeypatch):
        """The CLI tier fails closed without the operator's consent.

        ``mvn dependency:get`` is outbound network access driven by
        coordinates from the analysed repo. With ``allow_remote_fetch``
        False it must not resolve a binary, spawn a process, or emit a
        packet — even for perfectly valid GAV coordinates.
        """
        spawned: list[object] = []
        monkeypatch.setattr(
            maven_mod,
            "_resolve_mvn_binary",
            lambda: pytest.fail(
                "mvn binary resolved without --allow-remote-fetch"
            ),
        )
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **kw: spawned.append(a),
        )
        errors: list[str] = []
        result = _fetch_pom_via_maven(
            ("com.example", "lib", "1.0"), errors,
            allow_remote_fetch=False,
        )
        assert result is None
        assert spawned == []


# ── BOM resolution ─���────────────────────────���──────────────────────────────


class TestBomResolution:
    @pytest.mark.requirement("FR-133")
    def test_bom_managed_deps_merged(self, tmp_path, monkeypatch, resolver):
        """A BOM POM in the cache should provide managed dependency versions."""
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: None)

        _write_cached_pom(
            repo,
            "com.example",
            "bom",
            "1.0",
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <groupId>com.example</groupId>
              <artifactId>bom</artifactId>
              <version>1.0</version>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                    <version>3.14.0</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
        """
            ),
        )
        project = tmp_path / "project"
        project.mkdir()
        (project / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <groupId>com.example</groupId>
              <artifactId>myapp</artifactId>
              <version>1.0</version>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>com.example</groupId>
                    <artifactId>bom</artifactId>
                    <version>1.0</version>
                    <type>pom</type>
                    <scope>import</scope>
                  </dependency>
                </dependencies>
              </dependencyManagement>
              <dependencies>
                <dependency>
                  <groupId>org.apache.commons</groupId>
                  <artifactId>commons-lang3</artifactId>
                </dependency>
              </dependencies>
            </project>
        """
            )
        )
        result = resolver.analyse(str(project))
        lang3 = next(
            (d for d in result.dependencies if "commons-lang3" in d.name), None
        )
        assert lang3 is not None
        assert lang3.version == "3.14.0"

    @pytest.mark.requirement("FR-133")
    def test_bom_not_found_emits_warning(self, tmp_path, monkeypatch, resolver):
        """When a BOM cannot be resolved, a warning should be emitted."""
        repo = tmp_path / ".m2" / "repository"
        repo.mkdir(parents=True)
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(maven_mod, "_resolve_mvn_binary", lambda: None)

        project = tmp_path / "project"
        project.mkdir()
        (project / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <project>
              <groupId>com.example</groupId>
              <artifactId>myapp</artifactId>
              <version>1.0</version>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>com.example</groupId>
                    <artifactId>missing-bom</artifactId>
                    <version>1.0</version>
                    <type>pom</type>
                    <scope>import</scope>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
        """
            )
        )
        result = resolver.analyse(str(project))
        assert any("missing-bom" in e and "not resolved" in e for e in result.errors)
