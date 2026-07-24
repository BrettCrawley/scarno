"""PR-6 red test — REQ-21b / FR-224: exclude(group, module). TA-314."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-224")
def test_walker_emits_exclude_directive(tmp_path):
    """TA-314 — ``implementation(...) { exclude(group=..., module=...) }``
    yields a GradleExclusion record naming the excluded group +
    artifact."""
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        """
plugins { id("java") }
dependencies {
    implementation("com.lib:y:2.0") {
        exclude(group = "com.example", module = "vulnerable-x")
    }
}
"""
    )
    exclusions = _dsl.parse_exclusions([project / "build.gradle.kts"])
    matching = [
        e for e in exclusions
        if e.excluded_group == "com.example"
        and e.excluded_artifact == "vulnerable-x"
    ]
    assert matching, "exclude(group, module) not emitted"
