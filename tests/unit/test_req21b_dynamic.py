"""PR-6 red tests — REQ-21b / FR-225 + SUC-48: dynamic-pin fallback to
UNCERTAIN (TA-315 + TA-316 + R-Phase9-02)."""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-225")
def test_dynamic_useVersion_emits_dynamic_directive(tmp_path):
    """TA-315 — ``useVersion(loadVersion("com.lib"))`` (non-literal
    argument) yields a GradleForceDirective with ``dynamic=True`` and
    ``version=None``. The walker MUST NOT silently drop the directive
    — the dep needs to be flagged UNCERTAIN, not SAFE."""
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    (project / "build.gradle").write_text(
        """
plugins { id 'java' }
configurations.all {
    resolutionStrategy.eachDependency { details ->
        if (details.requested.group == "com.lib") {
            details.useVersion(loadVersion("com.lib"))
        }
    }
}
"""
    )
    directives = _dsl.parse_pin_directives([project / "build.gradle"])
    # We accept any directive that flagged dynamic=True; the precise
    # group/artifact matching is hard to extract from a Groovy if-block
    # statically so the walker may emit a wildcard record.
    dynamic_ones = [d for d in directives if d.dynamic]
    assert dynamic_ones, (
        "dynamic useVersion call did not produce dynamic=True directive"
    )


@pytest.mark.requirement("FR-225")
def test_dynamic_pin_classifies_dep_uncertain():
    """TA-316 — Dependency matched by a dynamic directive gets
    pin_override_kind=GRADLE_DYNAMIC_PIN, classifier downgrades to
    UNCERTAIN with 'manual review required' reason (PR-2 safety
    function handles this via the dynamic branch)."""
    from scarno.core import classifier as _cls
    from scarno.models import (
        Dependency,
        DependencyStatus,
        VersionedNode,
    )

    dep = Dependency(
        name="com.lib:dynamic-x",
        version="1.0",
        status=DependencyStatus.IN_USE,
        reason="",
        pin_override=True,
        pin_override_kind="GRADLE_DYNAMIC_PIN",
        pin_override_target=(
            "Gradle dynamic pin in build.gradle:42 — manual review required"
        ),
        ecosystem="gradle",
    )
    node = VersionedNode(
        canonical="com.lib:dynamic-x",
        declared_version="1.0",
        status=DependencyStatus.SAFE,
        removable=True,
    )
    _cls.apply_pin_override_safety(dep, node)
    assert node.status is DependencyStatus.UNCERTAIN
    assert "manual" in node.reason.lower() or "review" in node.reason.lower()
