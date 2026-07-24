"""PR-2 red tests — REQ-19a NEW-ARCH-013 / FR-255: safe_subprocess_run API.

Generic primitive in security.py enforcing shell=False, mandatory
timeout, optional binary-root confinement. Per-binary helpers
(_invoke_mvn_safe / _invoke_gradle_safe / legacy _invoke_javap_safe)
compose this with binary-specific resolution and argv allowlists.
"""
from __future__ import annotations

from pathlib import Path

import pytest


# ── TA-227a ────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-255")
def test_safe_subprocess_run_enforces_shell_false():
    """TA-227a — A trivial echo invocation succeeds and runs with shell=False
    (verified by passing a metacharacter that the shell would expand —
    if shell=True it would error, with shell=False it's literal argv).
    """
    from scarno.security import safe_subprocess_run

    # /bin/echo always exists on macOS / Linux dev machines.
    completed = safe_subprocess_run(
        ["/bin/echo", "hello;world"], timeout_s=5
    )
    assert completed.returncode == 0
    # With shell=False, the semicolon is literal — not a shell separator.
    assert "hello;world" in completed.stdout


# ── TA-227b ────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-255")
def test_safe_subprocess_run_timeout_required():
    """TA-227b — ``timeout_s`` is keyword-only AND required. A call
    without it raises TypeError before any subprocess spawns.
    """
    from scarno.security import safe_subprocess_run

    with pytest.raises(TypeError):
        safe_subprocess_run(["/bin/echo", "hi"])  # type: ignore[call-arg]


# ── TA-227c ────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-255")
@pytest.mark.requirement("SEC-NEW-52")
def test_safe_subprocess_run_binary_root_confined(tmp_path):
    """TA-227c — When ``binary_root`` is supplied and argv[0] resolves
    OUTSIDE that tree, BinaryNotConfinedError is raised BEFORE spawn.
    """
    from scarno.security import (
        BinaryNotConfinedError,
        safe_subprocess_run,
    )

    # /bin/echo lives at /bin, NOT under tmp_path.
    fake_root = tmp_path / "fake_home"
    fake_root.mkdir()
    with pytest.raises(BinaryNotConfinedError):
        safe_subprocess_run(
            ["/bin/echo", "hi"],
            timeout_s=5,
            binary_root=fake_root,
        )


# ── TA-227d ────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-255")
def test_safe_subprocess_run_no_binary_root_unconfined():
    """TA-227d — When ``binary_root=None``, no confinement check fires.

    Mirrors the legacy ``_invoke_javap_safe`` semantics where
    confinement is governed by JAVA_HOME being set, not by the
    primitive itself.
    """
    from scarno.security import safe_subprocess_run

    completed = safe_subprocess_run(
        ["/bin/echo", "hi"], timeout_s=5, binary_root=None
    )
    assert completed.returncode == 0
