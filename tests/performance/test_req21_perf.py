"""PR-3 red test — PERF-012 Maven pin-detection scaling (TA-264)."""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.performance


@pytest.mark.requirement("PERF-012")
def test_pin_detection_perf_spring_boot_style(tmp_path, monkeypatch):
    """TA-264 — Spring-Boot-style fixture: ~1500 DM entries + ~30 direct
    deps. Pin-override detection completes in < 50 ms.

    Catches accidental O(direct × DM) blowup; the algorithm should be
    O(direct) via dictionary lookup against the DM index.
    """
    from scarno.analysers.java import maven as _maven

    dm_xml = "\n".join(
        f"<dependency><groupId>com.example</groupId>"
        f"<artifactId>lib{i}</artifactId>"
        f"<version>1.{i}</version></dependency>"
        for i in range(1500)
    )
    direct_xml = "\n".join(
        f"<dependency><groupId>com.example</groupId>"
        f"<artifactId>lib{i}</artifactId></dependency>"
        for i in range(30)
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
      {dm_xml}
    </dependencies>
  </dependencyManagement>
  <dependencies>
    {direct_xml}
  </dependencies>
</project>
"""
    )
    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )

    # Measure the pin-detection path only (not full analysis).
    from scarno.models import Dependency, DependencyStatus, DepEdge
    dm_index = _maven._collect_dependency_management(
        project_root, errors=[]
    )
    deps_by_key = {
        ("com.example", f"lib{i}"): Dependency(
            name=f"com.example:lib{i}",
            version=f"1.{i}",
            status=DependencyStatus.SAFE,
            reason="",
            ecosystem="maven",
        )
        for i in range(30)
    }
    # Reach every direct dep via a synthetic root edge so pattern (b)
    # has the chance to fire — that's where the perf cost lives.
    edges = [
        DepEdge(
            parent="", child=f"com.example:lib{i}",
            declared_version=f"1.{i}",
        )
        for i in range(30)
    ]

    start = time.monotonic()
    _maven._detect_pin_overrides(
        deps_by_key=deps_by_key,
        exclusions=[],
        dm_index=dm_index,
        edges=edges,
        errors=[],
    )
    elapsed = time.monotonic() - start
    assert elapsed < 0.05, (
        f"pin detection took {elapsed * 1000:.1f}ms (budget 50ms)"
    )
