"""PR-2 red tests — SEC-NEW-52: PATH-fallback verbose warning for mvn.
Extends SEC-NEW-28 (the MAVEN_HOME pin).

TA-231a..c covered the Gradle binary resolver. They were removed with
it: scarno never runs Gradle (SEC-011, GitHub issue #1), and
``tests/security/test_no_gradle_spawn.py`` enforces that. TA-231d stays.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


# ── TA-231d ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-52")
def test_resolve_mvn_binary_path_fallback_warns(monkeypatch, capsys):
    """TA-231d — Same as TA-231c, for mvn. Extends the existing
    SEC-NEW-28 (env-var pin) with a PATH-fallback warning the operator
    can grep for in CI logs.
    """
    from scarno.analysers.java import maven as _maven

    monkeypatch.delenv("MAVEN_HOME", raising=False)
    monkeypatch.delenv("M2_HOME", raising=False)
    monkeypatch.setattr(_maven.shutil, "which", lambda _name: "/usr/bin/mvn")

    if hasattr(_maven, "_warn_path_fallback_once"):
        if hasattr(_maven._warn_path_fallback_once, "_seen"):
            _maven._warn_path_fallback_once._seen.clear()  # type: ignore[attr-defined]
    _maven._resolve_mvn_binary()
    captured = capsys.readouterr()
    assert "mvn" in (captured.err + captured.out).lower(), (
        "expected stderr/stdout warning that mvn was resolved via PATH"
    )
