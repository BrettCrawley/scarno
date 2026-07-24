"""PR-2 red test — FR-204 resolved-version detection (Gradle). TA-225a..b."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-204")
def test_gradle_resolved_version_via_dependencies_output():
    """TA-225a — A `gradle dependencies` line ``a:b:1.0 -> 1.5`` records
    the resolved version 1.5 for coordinate a:b."""
    from scarno.analysers.java import gradle as _gradle

    output = (
        "+--- com.example:a:1.0 -> 1.5\n"
        "+--- com.example:b:2.0\n"
    )
    resolved = _gradle._resolve_versions_from_dependencies_output(output)
    assert resolved.get("com.example:a") == "1.5"
    # Coords WITHOUT the arrow report their declared version as resolved.
    assert resolved.get("com.example:b") == "2.0"


@pytest.mark.requirement("FR-204")
def test_gradle_lockfile_overrides_dependencies_output(tmp_path):
    """TA-225b — When both gradle.lockfile and gradle dependencies output
    are present, the lockfile's per-coord versions win."""
    from scarno.analysers.java import gradle as _gradle

    output = "+--- com.example:a:1.0 -> 1.5\n"
    lockfile_lines = [
        "# This is a Gradle generated file for dependency locking.",
        "# Manual edits can break the build and are not advised.",
        "# This file is expected to be part of source control.",
        "com.example:a:1.7=runtimeClasspath",
        "empty=",
    ]
    lockfile_text = "\n".join(lockfile_lines) + "\n"
    resolved = _gradle._resolve_versions_with_lockfile_priority(
        gradle_output=output,
        lockfile_text=lockfile_text,
    )
    assert resolved.get("com.example:a") == "1.7", (
        "lockfile must override the gradle dependencies output value"
    )
