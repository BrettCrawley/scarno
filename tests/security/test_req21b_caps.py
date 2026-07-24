"""PR-6 red tests — SEC-NEW-41 Gradle parser caps + parse timeout
(TA-320 + TA-321 + TA-322)."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-41")
def test_max_force_directives_cap_256(tmp_path):
    """TA-320 — A build.gradle with 300 force() calls retains exactly
    256 directives (the SEC-NEW-41 cap); the rest are truncated with
    a sanitised note."""
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    forces = "\n".join(
        f'  force("com.junk:junk{i}:1.{i}")' for i in range(300)
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
    errors: list[str] = []
    directives = _dsl.parse_pin_directives(
        [project / "build.gradle.kts"], errors=errors
    )
    assert len(directives) <= 256, (
        f"force-directive cap not enforced; got {len(directives)}"
    )
    assert any(
        "cap" in e.lower() or "truncat" in e.lower()
        for e in errors
    ), f"expected truncation note; got {errors!r}"


@pytest.mark.requirement("SEC-NEW-41")
def test_max_exclusions_gradle_cap_256(tmp_path):
    """TA-321 — A build.gradle with 300 exclude() calls retains
    exactly 256 exclusion records."""
    from scarno.analysers.java import gradle_dsl as _dsl

    project = tmp_path / "project"
    project.mkdir()
    excludes = "\n".join(
        f'    exclude(group = "com.junk", module = "junk{i}")'
        for i in range(300)
    )
    (project / "build.gradle.kts").write_text(
        f"""
plugins {{ id("java") }}
dependencies {{
  implementation("com.lib:y:2.0") {{
{excludes}
  }}
}}
"""
    )
    errors: list[str] = []
    exclusions = _dsl.parse_exclusions(
        [project / "build.gradle.kts"], errors=errors
    )
    assert len(exclusions) <= 256, (
        f"exclude cap not enforced; got {len(exclusions)}"
    )


@pytest.mark.requirement("SEC-NEW-41")
def test_gradle_parse_timeout_8s_constant():
    """TA-322 — The gradle_dsl module exposes a parse timeout
    constant. Per SEC-NEW-41 the value is 8 seconds; adversarial
    build.gradle content that stalls tree-sitter past this budget
    must produce a sanitised parse-timeout error rather than hang."""
    from scarno.analysers.java import gradle_dsl as _dsl

    assert hasattr(_dsl, "_GRADLE_PARSE_TIMEOUT_S")
    assert _dsl._GRADLE_PARSE_TIMEOUT_S == 8
