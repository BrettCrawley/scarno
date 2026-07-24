"""PR-6 red test — REQ-21b / PERF-013: Gradle pin detection < 100 ms
per project. TA-324."""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.performance


@pytest.mark.requirement("PERF-013")
def test_gradle_pin_detection_per_project_under_100ms(tmp_path):
    """TA-324 — Typical project: < 10 build files × 50 directives.
    pin-detection completes in under 100 ms.
    """
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    forces = "\n".join(
        f'  force("com.example:lib{i}:1.{i}")' for i in range(50)
    )
    (project / "build.gradle.kts").write_text(
        f"""
plugins {{ id("java") }}
configurations.all {{
    resolutionStrategy {{
{forces}
    }}
}}
"""
    )
    start = time.monotonic()
    _dsl.parse_pin_directives([project / "build.gradle.kts"])
    elapsed = time.monotonic() - start
    assert elapsed < 0.1, (
        f"Gradle pin detection took {elapsed * 1000:.1f}ms "
        f"(budget 100ms)"
    )
