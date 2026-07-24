"""PR-6 red test — REQ-21b / FR-221: strictly() in version constraint.
TA-311."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-221")
def test_walker_emits_strictly_directive(tmp_path):
    """TA-311 — ``version { strictly("1.5") }`` inside a dep block
    yields a GradleForceDirective with source containing 'strictly'.
    """
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        """
plugins { id("java") }
dependencies {
    implementation("com.example:patched-x") {
        version { strictly("1.5") }
    }
}
"""
    )
    directives = _dsl.parse_pin_directives([project / "build.gradle.kts"])
    matching = [
        d for d in directives
        if d.group == "com.example" and d.artifact == "patched-x"
    ]
    assert matching, "strictly() directive not emitted"
    assert matching[0].version == "1.5"
    assert "strict" in matching[0].source.lower()
