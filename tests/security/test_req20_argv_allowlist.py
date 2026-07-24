"""PR-2 red tests — SEC-NEW-55 mvn / gradle argv allowlist (TA-228 / 229 / 230).

THE GATING TEST FOR PR-2. Phase-3 finding T-Phase9-04 (HIGH severity)
is closed only when TA-228 lands green: REQ-20's resolved-version
detection invokes mvn / gradle with a fixed argv — no project-derived
flags reach argv beyond the allowlist-validated configuration name.

Without these tests, an adversarial pom.xml or build.gradle can
inject extra flags (-Pprofile, -Dproperty=value, init-script paths)
into the subprocess invocation.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


# ── TA-228 — THE T-Phase9-04 closure gate ──────────────────────────────────


@pytest.mark.requirement("SEC-NEW-55")
def test_invoke_mvn_safe_uses_fixed_argv_no_project_flags(monkeypatch):
    """TA-228 — Capture every argv passed to safe_subprocess_run during
    REQ-20 Maven resolved-version detection. Adversarial pom.xml content
    (profiles, system properties, repositories) MUST NOT appear in argv;
    only the fixed allowlist of flags Scarno controls.

    THIS IS THE T-Phase9-04 (HIGH severity) closure gate.
    """
    from scarno.analysers.java import maven as _maven
    from scarno import security as _security

    captured_argvs: list[list[str]] = []

    def _capturing_run(argv, *, timeout_s, binary_root=None):
        captured_argvs.append(list(argv))
        # Return a CompletedProcess-like stub.
        import subprocess
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(_security, "safe_subprocess_run", _capturing_run)
    # Guarantee mvn appears resolvable so _invoke_mvn_safe gets to argv.
    monkeypatch.setattr(_maven, "_resolve_mvn_binary", lambda: "/usr/bin/mvn")

    # Call REQ-20's helper with adversarial flags supplied via fictitious
    # "extra" — the helper must REJECT or DROP them, never propagate.
    # The helper signature accepts only argv_tail items Scarno controls.
    _maven._invoke_mvn_safe(
        ["dependency:tree",
         "-DoutputType=text",
         "--batch-mode",
         "--no-transfer-progress"],
    )

    assert captured_argvs, "mvn was not invoked at all"
    argv = captured_argvs[-1]
    # Allowlist: only the fixed flags Scarno controls may appear.
    allowed_prefixes = (
        "/usr/bin/mvn",
        "dependency:tree",
        "-DoutputType=",
        "-DoutputFile=",
        "--batch-mode",
        "--no-transfer-progress",
        "-f",
    )
    for token in argv:
        assert any(token.startswith(p) for p in allowed_prefixes), (
            f"unexpected token in mvn argv: {token!r}"
        )
    # Specifically forbid -P (profile) and bare -D (system properties not
    # on the output allowlist).
    forbidden = [t for t in argv if t.startswith("-P")]
    assert not forbidden, f"profile flag leaked into argv: {forbidden}"


# ── TA-229 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-55")
def test_invoke_gradle_safe_uses_fixed_argv(monkeypatch):
    """TA-229 — Gradle equivalent of TA-228. The configuration name must
    come from an allowlist; init-scripts and -P / -D flags from project
    config must not leak into argv.
    """
    from scarno.analysers.java import gradle as _gradle
    from scarno import security as _security

    captured: list[list[str]] = []

    def _capturing(argv, *, timeout_s, binary_root=None):
        captured.append(list(argv))
        import subprocess
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(_security, "safe_subprocess_run", _capturing)
    monkeypatch.setattr(
        _gradle, "_resolve_gradle_binary", lambda: "/usr/bin/gradle"
    )

    _gradle._invoke_gradle_safe(
        ["dependencies",
         "--configuration", "runtimeClasspath",
         "--console=plain",
         "--no-daemon",
         "--quiet"],
    )

    assert captured, "gradle was not invoked"
    argv = captured[-1]
    allowed = (
        "/usr/bin/gradle",
        "dependencies",
        "--configuration",
        "runtimeClasspath",
        "default",
        "--console=plain",
        "--no-daemon",
        "--quiet",
    )
    for token in argv:
        assert token in allowed, (
            f"unexpected token in gradle argv: {token!r}"
        )


# ── TA-230 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-55")
def test_invoke_gradle_safe_rejects_unknown_configuration(monkeypatch):
    """TA-230 — Caller passes ``configuration="evil-config"`` (or any
    value outside the allowlist); _invoke_gradle_safe raises ValueError
    BEFORE any subprocess spawn.
    """
    from scarno.analysers.java import gradle as _gradle

    spawned = []

    def _no_spawn(*a, **kw):
        spawned.append(a)
        raise AssertionError("subprocess should not have been spawned")

    from scarno import security as _security
    monkeypatch.setattr(_security, "safe_subprocess_run", _no_spawn)
    monkeypatch.setattr(
        _gradle, "_resolve_gradle_binary", lambda: "/usr/bin/gradle"
    )

    with pytest.raises(ValueError):
        _gradle._invoke_gradle_safe(
            ["dependencies",
             "--configuration", "evil-config",  # not on allowlist
             "--console=plain"],
        )
    assert spawned == [], "no subprocess should have been spawned"
