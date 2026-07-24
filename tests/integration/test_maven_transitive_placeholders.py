"""Regression tests for placeholder resolution inside cached POMs read
by ``_build_transitive_graph`` (FR-165).

A cached POM frequently declares its sibling artefacts via
``${project.version}`` (so all artifacts in a multi-module release
move together) or via a property like ``${commons.version}``. When
the transitive walker reads such a POM raw and hands the literal
placeholder to ``_locate_pom_in_local_cache``, ``_validate_gav``
rejects it with an "Invalid GAV coordinates" warning — surfaced to
the user as a noisy "${project.version} not resolvable" message.

These tests fix that by resolving against the cached POM's own
``<properties>`` plus its ``project.*`` reserved keys before passing
coords to the cache lookup.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app


def _w(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _project_pom(directory: Path) -> None:
    """A toy project that depends on a cached package whose POM uses
    ``${project.version}``."""
    _w(directory / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.example.lib</groupId>
      <artifactId>lib-core</artifactId>
      <version>2.5.0</version>
    </dependency>
  </dependencies>
</project>
""")


def _cached_pom_with_self_referenced_version(repo_root: Path) -> None:
    """`com.example.lib:lib-core:2.5.0` declares ``lib-utils`` sibling
    using ``${project.version}``."""
    pom = (
        repo_root / "com" / "example" / "lib" / "lib-core" / "2.5.0"
        / "lib-core-2.5.0.pom"
    )
    pom.parent.mkdir(parents=True)
    pom.write_text("""\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.lib</groupId>
  <artifactId>lib-core</artifactId>
  <version>2.5.0</version>
  <properties>
    <commons.version>3.12.0</commons.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.example.lib</groupId>
      <artifactId>lib-utils</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>${commons.version}</version>
    </dependency>
  </dependencies>
</project>
""")


class TestMavenTransitivePlaceholderResolution:
    @pytest.mark.requirement("FR-165")
    def test_project_version_in_cached_pom_resolves(self, tmp_path, monkeypatch):
        """A cached POM's ``${project.version}`` must resolve against its
        own version when the transitive walker reads it."""
        fake_m2 = tmp_path / "fake-m2" / "repository"
        fake_m2.mkdir(parents=True)
        _cached_pom_with_self_referenced_version(fake_m2)

        from scarno.analysers.java import maven as _maven
        monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

        project = tmp_path / "project"
        _project_pom(project)
        result = CliRunner().invoke(app, [str(project), "--format", "json"])
        data = json.loads(result.output)

        graph = data.get("dep_graph") or {}
        assert "com.example.lib:lib-core" in graph, (
            "lib-core not in dep_graph"
        )
        # The placeholder resolved → child label looks normal.
        assert "com.example.lib:lib-utils" in graph["com.example.lib:lib-core"]
        # And no "Invalid GAV coordinates" / "Unresolvable placeholder"
        # warning surfaces with the literal ``${project.version}`` text.
        offending = [
            e for e in data["errors"]
            if "${project.version}" in e or "${commons.version}" in e
        ]
        assert not offending, (
            f"placeholder warnings still surfaced:\n  "
            + "\n  ".join(offending)
        )

    @pytest.mark.requirement("FR-165")
    def test_property_in_cached_pom_resolves(self, tmp_path, monkeypatch):
        """A cached POM's own ``<properties>`` are honoured during
        transitive resolution (e.g. ``${commons.version}``)."""
        fake_m2 = tmp_path / "fake-m2" / "repository"
        fake_m2.mkdir(parents=True)
        _cached_pom_with_self_referenced_version(fake_m2)

        from scarno.analysers.java import maven as _maven
        monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

        project = tmp_path / "project"
        _project_pom(project)
        result = CliRunner().invoke(app, [str(project), "--format", "json"])
        data = json.loads(result.output)
        graph = data.get("dep_graph") or {}
        assert "org.apache.commons:commons-lang3" in graph.get(
            "com.example.lib:lib-core", []
        ), (
            "commons-lang3 not in lib-core's children — "
            "${commons.version} probably failed to resolve"
        )

    @pytest.mark.requirement("FR-165")
    def test_unresolvable_placeholder_in_cached_pom_skipped_silently(
        self, tmp_path, monkeypatch
    ):
        """When a cached POM uses ``${revision}`` but doesn't define
        ``revision`` (and we don't walk its parent), we skip the dep
        rather than emitting a noisy warning the user can't act on."""
        fake_m2 = tmp_path / "fake-m2" / "repository"
        pom = (
            fake_m2 / "com" / "x" / "x-core" / "1.0" / "x-core-1.0.pom"
        )
        pom.parent.mkdir(parents=True)
        pom.write_text("""\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.x</groupId>
  <artifactId>x-core</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.x</groupId>
      <artifactId>x-other</artifactId>
      <version>${revision}</version>
    </dependency>
  </dependencies>
</project>
""")

        from scarno.analysers.java import maven as _maven
        monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

        project = tmp_path / "project"
        _w(project / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.x</groupId>
      <artifactId>x-core</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>
""")
        result = CliRunner().invoke(app, [str(project), "--format", "json"])
        data = json.loads(result.output)
        # No warnings should mention the literal ${revision} text.
        offending = [e for e in data["errors"] if "${revision}" in e]
        assert not offending, (
            f"unresolvable transitive placeholder leaked into errors:\n  "
            + "\n  ".join(offending)
        )
