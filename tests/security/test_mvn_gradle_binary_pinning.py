"""PR-2 red tests — SEC-NEW-52: GRADLE_HOME mandatory verification +
PATH-fallback verbose warning. Mirrors SEC-NEW-12 (which exists for
javap) and SEC-NEW-28 (which exists for mvn) — extends the same
discipline to Gradle and adds a PATH-fallback warning to both.

TA-231a..d.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.security


# ── TA-231a ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-52")
def test_resolve_gradle_binary_pins_under_GRADLE_HOME(tmp_path, monkeypatch):
    """TA-231a — When GRADLE_HOME is set and contains bin/gradle, the
    resolver returns that path and confirms it sits under the env-var
    tree.
    """
    from scarno.analysers.java import gradle as _gradle

    fake_home = tmp_path / "gradle_home"
    bin_dir = fake_home / "bin"
    bin_dir.mkdir(parents=True)
    fake_gradle = bin_dir / "gradle"
    fake_gradle.write_text("#!/bin/sh\necho stub")
    fake_gradle.chmod(0o755)

    monkeypatch.setenv("GRADLE_HOME", str(fake_home))
    monkeypatch.delenv("PATH", raising=False)

    resolved = _gradle._resolve_gradle_binary()
    assert resolved is not None
    assert Path(resolved).resolve() == fake_gradle.resolve()


# ── TA-231b ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-52")
def test_resolve_gradle_binary_rejects_path_when_env_set_but_missing(
    tmp_path, monkeypatch
):
    """TA-231b — GRADLE_HOME set but no bin/gradle inside. Returns None;
    PATH fallback NOT used (would defeat the env pinning).
    """
    from scarno.analysers.java import gradle as _gradle

    empty = tmp_path / "no_gradle_here"
    empty.mkdir()
    monkeypatch.setenv("GRADLE_HOME", str(empty))
    # PATH still set, but the env-var pin must override.
    resolved = _gradle._resolve_gradle_binary()
    assert resolved is None


# ── TA-231c ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-52")
def test_resolve_gradle_binary_path_fallback_warns(monkeypatch, capsys):
    """TA-231c — Neither GRADLE_HOME nor any equivalent set; resolver
    falls back to PATH. A verbose-mode stderr warning fires once per
    process (idempotent) so the operator knows the binary is unverified.
    """
    from scarno.analysers.java import gradle as _gradle

    monkeypatch.delenv("GRADLE_HOME", raising=False)
    # Ensure shutil.which finds something.
    monkeypatch.setattr(_gradle.shutil, "which", lambda _name: "/usr/bin/gradle")
    # The implementation must surface the warning either via stderr or
    # via a recorded module-level flag. We accept either path.

    if hasattr(_gradle, "_warn_path_fallback_once"):
        # Reset the once-flag so the warning fires for this test.
        if hasattr(_gradle._warn_path_fallback_once, "_seen"):
            _gradle._warn_path_fallback_once._seen.clear()  # type: ignore[attr-defined]
    _gradle._resolve_gradle_binary()
    captured = capsys.readouterr()
    assert "gradle" in (captured.err + captured.out).lower(), (
        "expected stderr/stdout warning that gradle was resolved via PATH"
    )


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
