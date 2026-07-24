"""PR-6 red test — REQ-21b / FR-222: constraints {} block. TA-312."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-222")
def test_walker_emits_constraints_block(tmp_path):
    """TA-312 — ``constraints { implementation("com.lib:z:1.4") }``
    yields a GradleForceDirective with source containing 'constraints'.
    """
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        """
plugins { id("java") }
dependencies {
    constraints {
        implementation("com.lib:z:1.4") {
            because("CVE-2024-XXXX patched in 1.4")
        }
    }
}
"""
    )
    directives = _dsl.parse_pin_directives([project / "build.gradle.kts"])
    matching = [
        d for d in directives
        if d.group == "com.lib" and d.artifact == "z"
    ]
    assert matching, "constraints {} directive not emitted"
    assert matching[0].version == "1.4"
    assert "constraint" in matching[0].source.lower()
