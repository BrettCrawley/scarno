"""PR-4 red test — REQ-22 / FR-233: signature_diff yields
ADDED / REMOVED / CHANGED sets. TA-269."""
from __future__ import annotations

import pytest


def _sig(member_name: str, descriptor: str = "()V", fqcn: str = "Helper"):
    from scarno.models import JavaSignature
    return JavaSignature(
        fqcn=fqcn,
        member_kind="method",
        member_name=member_name,
        descriptor=descriptor,
        modifiers=frozenset({"public"}),
    )


@pytest.mark.requirement("FR-233")
def test_signature_diff_added_removed_changed():
    """TA-269 — Diff produces ADDED / REMOVED / CHANGED frozensets."""
    from scarno.analysers.java.abi_diff import signature_diff

    declared = {_sig("kept"), _sig("removed"), _sig("changed", "(I)V")}
    resolved = {_sig("kept"), _sig("added"), _sig("changed", "(II)V")}
    diff = signature_diff(declared=declared, resolved=resolved)
    removed_names = {s.member_name for s in diff.removed}
    added_names = {s.member_name for s in diff.added}
    changed_names = {s.member_name for s in diff.changed}
    assert "removed" in removed_names
    assert "added" in added_names
    assert "changed" in changed_names
