"""PR-4 red test — REQ-22 / FR-233: signature_diff yields
ADDED / REMOVED / CHANGED sets. TA-269.

Extended for FR-272 (TA-357..TA-362) — descriptor-granular matching,
so a deleted overload of a member that survives under another
descriptor is still reported. See ``docs/SCARNO-BUG-signature-diff.md``:
the original implementation collapsed each identity to one arbitrary
overload, hiding 20 of 20 real deletions on the reporter's jetty-util
sample.
"""
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


# ── FR-272 — descriptor-granular matching ───────────────────────────────────


@pytest.mark.requirement("FR-272")
def test_deleted_overload_of_surviving_member_is_removed():
    """TA-357 — ``foo(String)`` + ``foo(int)`` → ``foo(int)``.

    The identity ``(Helper, method, foo)`` survives, so the pre-fix
    implementation reported nothing at all. The deleted descriptor is
    a NoSuchMethodError at any call site compiled against it.
    """
    from scarno.analysers.java.abi_diff import signature_diff

    gone = _sig("foo", "(java.lang.String)")
    kept = _sig("foo", "(int)")
    diff = signature_diff(declared={gone, kept}, resolved={kept})
    assert gone in diff.removed
    assert kept not in diff.removed
    assert kept not in diff.added
    assert kept not in diff.changed


@pytest.mark.requirement("FR-272")
def test_added_overload_is_added_not_removed():
    """TA-358 — the mirror case, guarding against over-reporting:
    widening a member with a new overload removes nothing."""
    from scarno.analysers.java.abi_diff import signature_diff

    kept = _sig("foo", "(int)")
    extra = _sig("foo", "(java.lang.String)")
    diff = signature_diff(declared={kept}, resolved={kept, extra})
    assert diff.added == frozenset({extra})
    assert diff.removed == frozenset()
    assert diff.changed == frozenset()


@pytest.mark.requirement("FR-272")
@pytest.mark.requirement("FR-233")
def test_sole_overload_retype_is_changed():
    """TA-359 — a member that is not overloaded on either side, whose
    one descriptor differs, is the FR-233 "retyped parameter" case:
    CHANGED, not REMOVED + ADDED."""
    from scarno.analysers.java.abi_diff import signature_diff

    before = _sig("foo", "(int)")
    after = _sig("foo", "(int, int)")
    diff = signature_diff(declared={before}, resolved={after})
    assert diff.changed == frozenset({after}), "report the resolved side"
    assert diff.removed == frozenset()
    assert diff.added == frozenset()


@pytest.mark.requirement("FR-272")
def test_modifier_only_shift_is_changed():
    """TA-360 — same descriptor, shifted modifiers (e.g. a method that
    became static) is CHANGED, reported on the resolved side."""
    from scarno.analysers.java.abi_diff import signature_diff
    from scarno.models import JavaSignature

    before = _sig("foo", "(int)")
    after = JavaSignature(
        fqcn="Helper",
        member_kind="method",
        member_name="foo",
        descriptor="(int)",
        modifiers=frozenset({"public", "static"}),
    )
    diff = signature_diff(declared={before}, resolved={after})
    assert diff.changed == frozenset({after})
    assert diff.removed == frozenset()
    assert diff.added == frozenset()


@pytest.mark.requirement("FR-272")
def test_field_and_constructor_identities_round_trip():
    """TA-361 — fields cannot overload but constructors can; both
    kinds go through the same descriptor-granular path."""
    from scarno.analysers.java.abi_diff import signature_diff
    from scarno.models import JavaSignature

    def _member(kind: str, name: str, descriptor: str) -> JavaSignature:
        return JavaSignature(
            fqcn="Helper",
            member_kind=kind,
            member_name=name,
            descriptor=descriptor,
            modifiers=frozenset({"public"}),
        )

    field = _member("field", "VERSION", "java.lang.String")
    ctor_gone = _member("constructor", "Helper", "(java.lang.String)")
    ctor_kept = _member("constructor", "Helper", "()")
    diff = signature_diff(
        declared={field, ctor_gone, ctor_kept}, resolved={ctor_kept},
    )
    assert field in diff.removed, "removed field"
    assert ctor_gone in diff.removed, "deleted constructor overload"
    assert ctor_kept not in diff.removed


@pytest.mark.requirement("FR-272")
def test_uriutil_encodepath_regression():
    """TA-362 — the bug report's named witness.

    ``URIUtil.encodePath(StringBuilder, String)`` is deleted between
    jetty-util 9.4.51 and 12.0.22 while ``encodePath(String)``
    survives. A path-encoding API silently vanishing from the diff was
    the motivating false negative.
    """
    from scarno.analysers.java.abi_diff import signature_diff

    fqcn = "org.eclipse.jetty.util.URIUtil"
    gone = _sig(
        "encodePath",
        "(java.lang.StringBuilder, java.lang.String)",
        fqcn=fqcn,
    )
    kept = _sig("encodePath", "(java.lang.String)", fqcn=fqcn)
    other = _sig("decodePath", "(java.lang.String)", fqcn=fqcn)
    diff = signature_diff(
        declared={gone, kept, other}, resolved={kept, other},
    )
    assert gone in diff.removed
