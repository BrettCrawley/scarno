"""PR-3 red test — TA-261: pin_override and manifest_redundant detectors
must coordinate so a single dep never has both flags True. Defends the
NEW-ARCH-007 invariant against detector-ordering bugs."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.requirement("FR-251")
def test_pin_override_and_manifest_redundant_never_both_set_by_detectors(
    tmp_path, monkeypatch
):
    """TA-261 — Run the Maven analyser against a fixture where BOTH
    detectors COULD apply (a direct dep that is excluded by another
    transitive AND reachable transitively by an IN_USE parent). The
    pin-override detector must defer to manifest-redundant OR vice
    versa; whichever wins, NO Dependency ends up with both True
    (which would raise ValueError in __post_init__)."""
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
      <artifactId>excluder</artifactId>
      <version>2.0</version>
      <exclusions>
        <exclusion>
          <groupId>com.example</groupId>
          <artifactId>contested</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>contested</artifactId>
      <version>1.5</version>
    </dependency>
  </dependencies>
</project>
"""
    )
    monkeypatch.setattr(
        _maven, "_m2_repo_path", lambda: tmp_path / "no-such-m2"
    )
    # If either detector violates the invariant the analyser will raise
    # in Dependency.__post_init__; the analyse() call must complete
    # without exception.
    result = _maven.MavenPomResolver().analyse(str(project_root))
    # First, prove a detector actually ran — pre-PR-3 the test would
    # pass vacuously (no detector means no flag means trivially no
    # mutex violation). The contested fixture above is engineered so
    # at least one detector should fire; if neither fires, the test
    # is meaningless and must fail red.
    contested = next(
        d for d in result.dependencies
        if d.name == "com.example:contested"
    )
    assert contested.pin_override or contested.manifest_redundant, (
        "neither pin_override nor manifest_redundant set on contested — "
        "the relevant detector did not run, so this test is vacuous"
    )
    for dep in result.dependencies:
        assert not (dep.pin_override and dep.manifest_redundant), (
            f"{dep.name}: detectors set both pin_override and "
            f"manifest_redundant — NEW-ARCH-007 invariant violated"
        )
