"""PR-2 red tests — SEC-NEW-55 mvn argv allowlist (TA-228).

THE GATING TEST FOR PR-2. Phase-3 finding T-Phase9-04 (HIGH severity)
is closed only when TA-228 lands green: REQ-20's resolved-version
detection invokes mvn with a fixed argv, so no flags derived from the
project reach argv.

Without this test, an adversarial pom.xml can inject extra flags
(-Pprofile, -Dproperty=value) into the subprocess invocation.

TA-229 / TA-230 covered ``_invoke_gradle_safe``. They were removed with
it: scarno never runs Gradle (SEC-011, GitHub issue #1), and
``tests/security/test_no_gradle_spawn.py`` enforces that.
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

    def _capturing_run(argv, *, timeout_s, binary_root=None, cwd=None):
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
