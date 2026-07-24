"""PR-6 red test — REQ-21b / FR-223: resolutionStrategy.eachDependency
useVersion. TA-313."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-223")
def test_walker_emits_each_dependency_directive(tmp_path):
    """TA-313 — ``eachDependency { useVersion("1.5") }`` with a
    literal version-string argument yields a GradleForceDirective
    with ``dynamic=False`` (the literal path)."""
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        """
plugins { id("java") }
configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "com.example" && requested.name == "x") {
            useVersion("1.5")
        }
    }
}
"""
    )
    directives = _dsl.parse_pin_directives([project / "build.gradle.kts"])
    matching = [
        d for d in directives
        if d.group == "com.example" and d.artifact == "x"
    ]
    assert matching, "eachDependency useVersion directive not emitted"
    assert matching[0].version == "1.5"
    assert matching[0].dynamic is False
    assert "eachdependency" in matching[0].source.lower() or "usever" in matching[0].source.lower()
