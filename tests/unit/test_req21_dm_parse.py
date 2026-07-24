"""PR-3 red tests — REQ-21 / FR-212: <dependencyManagement> parsed after
property resolution (TA-254)."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-212")
def test_dm_parsed_after_property_resolution(tmp_path, monkeypatch):
    """TA-254 — DM entry uses ${jackson.version}; the placeholder MUST be
    resolved against the POM's <properties> before the DM index is
    populated. Otherwise pin-override pattern (b) misses the match.
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
  <properties>
    <jackson.version>2.15.3</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""
    )
    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )
    dm_index = _maven._collect_dependency_management(
        project_root, errors=[]
    )
    val = dm_index.get(("com.fasterxml.jackson.core", "jackson-databind"))
    assert val == "2.15.3", (
        f"property must be resolved before DM index; got {val!r}"
    )
