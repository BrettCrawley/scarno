"""PR-6 red test — REQ-21b / FR-220: tree-sitter walker emits
GradleForceDirective for force() in resolutionStrategy. TA-310."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-220")
def test_walker_emits_force_directive(tmp_path):
    """TA-310 — build.gradle.kts with
    ``force("com.example:patched-x:1.5")`` inside resolutionStrategy
    yields a GradleForceDirective with source containing 'force'."""
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        """
plugins { id("java") }
configurations.all {
    resolutionStrategy {
        force("com.example:patched-x:1.5")
    }
}
"""
    )
    directives = _dsl.parse_pin_directives([project / "build.gradle.kts"])
    matching = [
        d for d in directives
        if d.group == "com.example" and d.artifact == "patched-x"
    ]
    assert matching, "force() directive not emitted"
    assert matching[0].version == "1.5"
    assert "force" in matching[0].source.lower()
    assert matching[0].dynamic is False
