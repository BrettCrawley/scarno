"""PR-3 red tests — REQ-21 / FR-211 + SUC-45: pattern (a) exclusion-override
detection (TA-251 + TA-260)."""
from __future__ import annotations

from pathlib import Path

import pytest


def _make_project_with_exclusion_pin(tmp_path: Path) -> Path:
    """Project layout: lib-y excludes vulnerable-x; direct patched-x at
    the same GA coordinate (no source uses it). The classic substitution
    pattern."""
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
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>vulnerable-x</artifactId>
      <version>1.5</version>
    </dependency>
  </dependencies>
</project>
"""
    )
    return project_root


@pytest.mark.requirement("FR-211")
def test_pattern_a_direct_dep_substituting_excluded_transitive(
    tmp_path, monkeypatch
):
    """TA-251 — A direct <dependency> at the same GA as another transitive's
    <exclusion> target gets pin_override=True with kind=EXCLUSION.
    """
    from scarno.analysers.java import maven as _maven

    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )
    project_root = _make_project_with_exclusion_pin(tmp_path)
    result = _maven.MavenPomResolver().analyse(str(project_root))

    patched = next(
        (d for d in result.dependencies
         if d.name == "com.example:vulnerable-x"),
        None,
    )
    assert patched is not None
    assert patched.pin_override is True, (
        "patched-x at same GA as excluded transitive must flag pin_override"
    )
    assert patched.pin_override_kind == "EXCLUSION"
    assert patched.pin_override_target  # non-empty narrative


@pytest.mark.requirement("FR-211")
def test_pin_override_pattern_a_reason_mentions_coincidence(
    tmp_path, monkeypatch
):
    """TA-260 (T-Phase9-02) — Pattern (a) reason text must include
    "manual review recommended" + "coincidental GA match is possible"
    so the developer is warned the flag may be a false positive when
    the GA coincidence is unrelated to the substitution intent.
    """
    from scarno.analysers.java import maven as _maven

    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )
    project_root = _make_project_with_exclusion_pin(tmp_path)
    result = _maven.MavenPomResolver().analyse(str(project_root))
    patched = next(
        d for d in result.dependencies
        if d.name == "com.example:vulnerable-x"
    )
    target = (patched.pin_override_target or "").lower()
    reason = (patched.reason or "").lower()
    text = f"{target} {reason}"
    assert "manual review" in text, (
        "pattern (a) must warn about manual-review need"
    )
    assert "coincidental" in text or "ga match" in text, (
        "pattern (a) must call out the GA-match coincidence risk"
    )
