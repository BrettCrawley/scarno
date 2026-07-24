"""SEC-NEW-71 — TS-INTEGRITY-MISMATCH rule is registered.

Slice E v1 ships the rule definition; the cross-check pipeline that
emits it is deferred to a follow-up (SEC-NEW-74 retry-once + cross-
check orchestration). Until then, the rule must at least exist in
the catalogue so SARIF + reporters know about it and so a follow-up
PR can wire it without touching the rule shape.

Also tags T-40 and T-41 — the rule is the named control mitigating
both threats (compromised index / coordinate typosquat respectively
in their adversarial-integrity dimension).
"""
from __future__ import annotations

import pytest

from scarno.findings.rules import RULES
from scarno.models import FindingKind, FindingSeverity


@pytest.mark.requirement("SEC-NEW-71")
@pytest.mark.requirement("T-40")
@pytest.mark.requirement("T-41")
def test_ts_integrity_mismatch_rule_registered():
    rule = RULES.get("TS-INTEGRITY-MISMATCH")
    assert rule is not None, (
        "SEC-NEW-71 rule TS-INTEGRITY-MISMATCH missing from catalogue"
    )
    assert rule.severity is FindingSeverity.HIGH
    assert rule.kind is FindingKind.ABI_INTEGRITY_MISMATCH
    # Message + remediation must be non-empty (sanity).
    assert rule.message
    assert rule.remediation
