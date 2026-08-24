"""REQ-22 / FR-273 — ``signature_diff`` output is invariant under
``PYTHONHASHSEED`` (TA-363 + TA-364).

``docs/SCARNO-BUG-signature-diff.md`` measured ``changed`` swinging
between 50 and 58 across seeds on one real jar pair, because the diff
picked an arbitrary representative overload per identity out of a
``set``. A same-process round-trip test cannot see that — the
representative is stable within one interpreter — so TA-364 re-runs
the diff in child interpreters, which is the reporter's own
reproduction.

The NEW-ARCH-011 / SEC-NEW-58 "no subprocess" invariants are AST scans
over ``src/scarno/`` only (see ``tests/security/test_arch_subprocess_
call_sites.py``); test code is free to spawn interpreters.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src"

# Overload-heavy fixture shared by both tests: one identity with three
# declared descriptors of which one is deleted and one is added, a
# second identity deleted outright, a third whose sole descriptor is
# retyped, and a stable field.
_FIXTURE = """
from scarno.models import JavaSignature


def sig(name, descriptor, kind="method", mods=("public",)):
    return JavaSignature(
        fqcn="org.example.Widget",
        member_kind=kind,
        member_name=name,
        descriptor=descriptor,
        modifiers=frozenset(mods),
    )


DECLARED = {
    sig("render", "(java.lang.String)"),
    sig("render", "(int)"),
    sig("render", "(java.lang.StringBuilder, java.lang.String)"),
    sig("legacyOnly", "()"),
    sig("retyped", "(int)"),
    sig("VERSION", "java.lang.String", kind="field"),
}
RESOLVED = {
    sig("render", "(java.lang.String)"),
    sig("render", "(int)"),
    sig("render", "(java.lang.CharSequence)"),
    sig("retyped", "(long)"),
    sig("VERSION", "java.lang.String", kind="field"),
}
"""

_CHILD = _FIXTURE + """
import json
from scarno.analysers.java.abi_diff import signature_diff


def canonical(bucket):
    return sorted(
        [s.fqcn, s.member_kind, s.member_name, s.descriptor,
         sorted(s.modifiers)]
        for s in bucket
    )


diff = signature_diff(declared=DECLARED, resolved=RESOLVED)
print(json.dumps({
    "added": canonical(diff.added),
    "removed": canonical(diff.removed),
    "changed": canonical(diff.changed),
}, sort_keys=True))
"""


def _names(bucket) -> set[tuple[str, str]]:
    return {(s.member_name, s.descriptor) for s in bucket}


@pytest.mark.requirement("FR-273")
def test_overload_heavy_diff_exact_sets():
    """TA-363 — assert the three buckets exactly on an overload-heavy
    fixture. A correct implementation is a pure function of its inputs
    with no representative selection anywhere, so this pins the
    behaviour in-process."""
    namespace: dict[str, object] = {}
    exec(compile(_FIXTURE, "<fixture>", "exec"), namespace)  # noqa: S102
    from scarno.analysers.java.abi_diff import signature_diff

    diff = signature_diff(
        declared=namespace["DECLARED"], resolved=namespace["RESOLVED"],
    )
    # `render` is overloaded on both sides — it keeps two descriptors,
    # loses (StringBuilder, String) and gains (CharSequence). Pairing
    # those two as a "change" would be a guess, so the deletion is a
    # removal and the addition is an addition.
    # `legacyOnly` is an identity absent from the resolved side.
    assert _names(diff.removed) == {
        ("render", "(java.lang.StringBuilder, java.lang.String)"),
        ("legacyOnly", "()"),
    }
    assert _names(diff.added) == {
        ("render", "(java.lang.CharSequence)"),
    }
    # `retyped` has one descriptor on each side and they differ — the
    # FR-233 signature-change case.
    assert _names(diff.changed) == {("retyped", "(long)")}


@pytest.mark.requirement("FR-273")
@pytest.mark.parametrize("seed", ["0", "1", "2", "3", "42"])
def test_signature_diff_invariant_under_hash_seed(seed: str):
    """TA-364 — the bug report's reproduction. Same inputs, same code,
    only ``PYTHONHASHSEED`` varying: the diff must serialise
    identically."""
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = seed
    env["PYTHONPATH"] = (
        f"{_SRC}{os.pathsep}{env['PYTHONPATH']}"
        if env.get("PYTHONPATH")
        else str(_SRC)
    )
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    observed = json.loads(proc.stdout)

    expected = {
        "added": [
            [
                "org.example.Widget", "method", "render",
                "(java.lang.CharSequence)", ["public"],
            ],
        ],
        "removed": sorted([
            [
                "org.example.Widget", "method", "legacyOnly",
                "()", ["public"],
            ],
            [
                "org.example.Widget", "method", "render",
                "(java.lang.StringBuilder, java.lang.String)", ["public"],
            ],
        ]),
        "changed": [
            [
                "org.example.Widget", "method", "retyped",
                "(long)", ["public"],
            ],
        ],
    }
    assert observed == expected, (
        f"signature_diff varies with PYTHONHASHSEED={seed}"
    )