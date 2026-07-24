"""PR-3 red tests — REQ-21 / FR-210: Maven <exclusions> index. TA-250."""
from __future__ import annotations

from pathlib import Path

import pytest


def _write_pom(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


@pytest.mark.requirement("FR-210")
def test_collect_exclusions_indexes_by_ga(tmp_path, monkeypatch):
    """TA-250 — Walked POMs containing <exclusion> blocks index by
    (group, artifact). The index value records which transitive POM
    declared each exclusion so pin-override (pattern a) can name the
    substitution target in its reason text.
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
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib-y</artifactId>
      <version>2.0</version>
      <exclusions>
        <exclusion>
          <groupId>com.example</groupId>
          <artifactId>vulnerable-x</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
  </dependencies>
</project>
"""
    )
    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )
    resolver = _maven.MavenPomResolver()
    result = resolver.analyse(str(project_root))

    # New REQ-21 contract: result exposes the exclusions index OR the
    # resolver provides a public helper that returns it. We probe both.
    exclusions = getattr(result, "maven_exclusions", None)
    if exclusions is None:
        exclusions = _maven._collect_exclusions_from_walked_poms(
            project_root, errors=[]
        )
    # Expect (group, artifact) of the excluded transitive in the index.
    keys = {(g, a) for (g, a, *_rest) in exclusions} if isinstance(exclusions, list) else set(exclusions.keys())
    assert ("com.example", "vulnerable-x") in keys, (
        f"<exclusion> not indexed; got {keys}"
    )
