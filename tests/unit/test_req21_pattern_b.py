"""PR-3 red tests — REQ-21 / FR-213 + SUC-46: pattern (b)
<dependencyManagement> pin detection (TA-252 + TA-253)."""
from __future__ import annotations

from pathlib import Path

import pytest


def _write_pom(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


@pytest.mark.requirement("FR-213")
def test_pattern_b_dependency_management_pin(tmp_path, monkeypatch):
    """TA-252 — Root POM <dependencyManagement> pins jackson-databind to a
    specific version; jackson-databind reached transitively (no source
    use). The dep gets pin_override=True with kind=DEPENDENCY_MANAGEMENT.
    """
    from scarno.analysers.java import maven as _maven

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pom.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.3</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
    <dependency>
      <groupId>com.thirdparty</groupId>
      <artifactId>other</artifactId>
      <version>4.0</version>
    </dependency>
  </dependencies>
</project>
"""
    )
    # Cached transitive: other → jackson-databind 2.15.0 (DM should override).
    m2 = tmp_path / "m2"
    _write_pom(
        m2 / "com/thirdparty/other/4.0/other-4.0.pom",
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.thirdparty</groupId>
  <artifactId>other</artifactId>
  <version>4.0</version>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.0</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    monkeypatch.setattr(_maven, "_m2_repo_path", lambda: m2)

    result = _maven.MavenPomResolver().analyse(str(project_root))

    jackson = next(
        (d for d in result.dependencies
         if d.name == "com.fasterxml.jackson.core:jackson-databind"),
        None,
    )
    assert jackson is not None
    assert jackson.pin_override is True
    assert jackson.pin_override_kind == "DEPENDENCY_MANAGEMENT"


@pytest.mark.requirement("FR-213")
def test_pattern_b_dm_not_reached_no_pin(tmp_path, monkeypatch):
    """TA-253 — DM pins jackson-databind but no transitive reaches it.
    No false pin-override flag; the DM entry is harmless documentation.
    """
    from scarno.analysers.java import maven as _maven

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pom.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.3</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>only-thing</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>
"""
    )
    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )
    # First, prove the DM detector actually ran by verifying it
    # produced a non-empty index for jackson-databind. Without this
    # the test would pass vacuously on the pre-PR-3 codebase where
    # no detector exists.
    dm_index = _maven._collect_dependency_management(
        project_root, errors=[]
    )
    assert (
        ("com.fasterxml.jackson.core", "jackson-databind") in dm_index
    ), "DM detector did not parse the jackson-databind entry"

    result = _maven.MavenPomResolver().analyse(str(project_root))
    # jackson-databind not in deps at all (DM alone doesn't add a dep).
    jackson_deps = [
        d for d in result.dependencies
        if d.name == "com.fasterxml.jackson.core:jackson-databind"
    ]
    if jackson_deps:
        assert jackson_deps[0].pin_override is False, (
            "DM-only pin without transitive reach must NOT flag"
        )
