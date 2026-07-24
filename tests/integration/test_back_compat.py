"""PR-1 red tests — NEW-ARCH-009 back-compat fixtures + strict-inclusion
semantics (TA-221 / TA-222 / TA-223).

The pre-Phase-9 fixture set was captured from the current code base on
2026-05-11. Strict-inclusion semantics: every key / rule-id present in
the fixture MUST be present in the current output. New keys / rules are
allowed (the change is additive). Removed keys / rules fail the test —
removal requires explicit PR-description justification per
``docs/scarno-security-architecture.md`` §11.15.10 NEW-ARCH-009.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

# The fixture is rooted at tests/fixtures/back_compat/ in this repo.
_FIXTURE_DIR = (
    Path(__file__).resolve().parent.parent / "fixtures" / "back_compat"
)
# The fixture project that produced the captured outputs.
_FIXTURE_PROJECT = (
    Path(__file__).resolve().parent.parent / "fixtures" / "simple_python"
)


def _walk_keys(obj, prefix=""):
    """Recursively yield every dotted key path inside a JSON-shaped object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{prefix}.{k}" if prefix else k
            yield here
            yield from _walk_keys(v, here)
    elif isinstance(obj, list) and obj:
        # We probe the first element only for shape; lists are treated as
        # homogeneous wrt key shape.
        yield from _walk_keys(obj[0], prefix + "[]")


# ── TA-221 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-253")
def test_back_compat_fixture_present():
    """TA-221 — pre-Phase-9 fixture files exist and are non-empty.

    Captured 2026-05-11 from current codebase before any Phase-9
    implementation lands. Required by NEW-ARCH-009.
    """
    for name in ("pre_phase9.json", "pre_phase9.sarif",
                 "pre_phase9.md", "pre_phase9.txt"):
        path = _FIXTURE_DIR / name
        assert path.exists(), f"missing back-compat fixture: {path}"
        assert path.stat().st_size > 0, f"empty back-compat fixture: {path}"


def _current_json_for_fixture_project() -> dict:
    """Run the current code's JsonReporter against the fixture project,
    return the parsed JSON object for shape comparison."""
    # The orchestrator + reporter wiring lives in cli.py; we import lazily.
    from scarno.cli import _run_options_default, run_analysis  # type: ignore[attr-defined]

    opts = _run_options_default()  # type: ignore[call-arg]
    rendered = run_analysis(  # type: ignore[call-arg]
        path=str(_FIXTURE_PROJECT), opts=opts, output_format="json"
    )
    return json.loads(rendered) if isinstance(rendered, str) else rendered


# ── TA-222 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-49")
def test_back_compat_strict_inclusion_json():
    """TA-222 — Every JSON key path present in the fixture is still present
    in the current JSON output. New keys are allowed; removed keys fail.
    """
    fixture = json.loads((_FIXTURE_DIR / "pre_phase9.json").read_text())
    current_obj = _current_json_for_fixture_project()
    fixture_keys = set(_walk_keys(fixture))
    current_keys = set(_walk_keys(current_obj))
    missing = sorted(fixture_keys - current_keys)
    assert not missing, (
        "Back-compat regression: keys removed since pre-Phase-9 snapshot:\n"
        + "\n".join(f"  - {k}" for k in missing)
        + "\n\nRemoval requires explicit justification in the PR description "
        + "per NEW-ARCH-009 / SEC-NEW-49."
    )


# ── TA-223 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-49")
def test_back_compat_strict_inclusion_sarif():
    """TA-223 — Every SARIF rule-id present in the fixture is still present
    in the current SARIF output. Removed rule IDs fail the test.
    """
    fixture = json.loads((_FIXTURE_DIR / "pre_phase9.sarif").read_text())
    fixture_rule_ids = {
        r["id"] for r in fixture["runs"][0]["tool"]["driver"]["rules"]
    }

    # Run current code through the SARIF reporter against the fixture project.
    from scarno.cli import _run_options_default, run_analysis  # type: ignore[attr-defined]

    current_sarif = run_analysis(  # type: ignore[call-arg]
        path=str(_FIXTURE_PROJECT),
        opts=_run_options_default(),  # type: ignore[call-arg]
        output_format="sarif",
    )
    if isinstance(current_sarif, str):
        current_sarif = json.loads(current_sarif)
    current_rule_ids = {
        r["id"] for r in current_sarif["runs"][0]["tool"]["driver"]["rules"]
    }
    missing = sorted(fixture_rule_ids - current_rule_ids)
    assert not missing, (
        "Back-compat regression: SARIF rule IDs removed since pre-Phase-9 "
        "snapshot:\n"
        + "\n".join(f"  - {r}" for r in missing)
        + "\n\nRemoval requires explicit justification in the PR description."
    )
