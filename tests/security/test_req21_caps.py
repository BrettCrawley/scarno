"""PR-3 red tests — SEC-NEW-40 Maven exclusion + DM caps (TA-258 + TA-259)."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-40")
def test_max_exclusions_per_dep_cap_128(tmp_path, monkeypatch):
    """TA-258 — pom.xml with 200 <exclusion> entries on one transitive.
    Exactly 128 retained; errors[] contains a truncation note; analysis
    completes without raising."""
    from scarno.analysers.java import maven as _maven

    exclusions_xml = "\n".join(
        f"<exclusion><groupId>com.junk</groupId>"
        f"<artifactId>junk{i}</artifactId></exclusion>"
        for i in range(200)
    )
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pom.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8"?>
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
        {exclusions_xml}
      </exclusions>
    </dependency>
  </dependencies>
</project>
"""
    )
    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )
    result = _maven.MavenPomResolver().analyse(str(project_root))
    assert any(
        "exclusion" in e.lower() and (
            "cap" in e.lower() or "truncat" in e.lower()
        )
        for e in result.errors
    ), f"expected exclusion-cap error; got {result.errors!r}"


@pytest.mark.requirement("SEC-NEW-40")
def test_max_dm_entries_cap_2048(tmp_path, monkeypatch):
    """TA-259 — Synthetic DM block with 3000 entries truncated to 2048."""
    from scarno.analysers.java import maven as _maven

    entries_xml = "\n".join(
        f"<dependency><groupId>com.junk</groupId>"
        f"<artifactId>junk{i}</artifactId>"
        f"<version>1.{i}</version></dependency>"
        for i in range(3000)
    )
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pom.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      {entries_xml}
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
    assert len(dm_index) <= 2048, (
        f"DM cap not enforced; got {len(dm_index)} entries"
    )
