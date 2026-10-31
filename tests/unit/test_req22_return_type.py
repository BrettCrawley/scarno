"""REQ-22 / FR-277: a method's return type takes part in the ABI diff
(TA-367..TA-375).

A caller's compiled ``invokevirtual`` names ``owner.name:(args)ret``, so
changing only the return type is a ``NoSuchMethodError`` at every call
site compiled against the old one. Before FR-277, ``JavaSignature`` did
not record the return type at all, so such a change matched as identical
and was never reported.

The return type is deliberately a separate field, not part of
``descriptor``. javap emits a covariant override's compiler-generated
bridge beside the real method, e.g. ``StringBuilder append(int)`` and
``AbstractStringBuilder append(int)``. Folding the return type into the
descriptor would split those into separate members that churn as
added/removed. As a separate field it takes part in the CHANGED
comparison without changing identity or descriptor grouping.
"""
from __future__ import annotations

import pytest

from scarno.analysers.java.abi_diff import (
    AbiDiffResult,
    CrossVersionAbiDiffer,
    _signature_sort_key,
    javap_public_signatures,
    signature_diff,
)
from scarno.models import JavaSignature

_FQCN = "com.thirdparty.Widget"


def _m(
    name: str,
    descriptor: str,
    return_type: str | None,
    mods: tuple[str, ...] = ("public",),
) -> JavaSignature:
    return JavaSignature(
        fqcn=_FQCN,
        member_kind="method",
        member_name=name,
        descriptor=descriptor,
        modifiers=frozenset(mods),
        return_type=return_type,
    )


_JAVAP = """\
Compiled from "Widget.java"
public class com.thirdparty.Widget extends com.thirdparty.Base {
  public com.thirdparty.Widget(int);
  public static java.lang.String join(java.lang.String...);
  public int[] counts();
  protected final void flush() throws java.io.IOException;
  public java.util.List<java.lang.String> names();
  public static final int MAX;
}
"""


# ── Parsing ─────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-277")
def test_parser_records_method_return_types() -> None:
    """TA-367: methods carry their return type, including static
    methods, arrays, generics and methods with a throws clause."""
    by_name = {
        s.member_name: s for s in javap_public_signatures(_JAVAP)
        if s.member_kind == "method"
    }
    assert by_name["join"].return_type == "java.lang.String"
    assert by_name["counts"].return_type == "int[]"
    assert by_name["flush"].return_type == "void"
    assert by_name["names"].return_type == "java.util.List<java.lang.String>"


@pytest.mark.requirement("FR-277")
def test_constructors_and_fields_have_no_return_type() -> None:
    """TA-368: a constructor has no return type, and a field's type is
    already its descriptor, so both leave ``return_type`` unset."""
    others = [
        s for s in javap_public_signatures(_JAVAP)
        if s.member_kind in {"constructor", "field"}
    ]
    assert {s.member_kind for s in others} == {"constructor", "field"}
    assert all(s.return_type is None for s in others)


# ── Diff ────────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-277")
@pytest.mark.requirement("FR-233")
def test_return_type_only_change_is_changed() -> None:
    """TA-369: ``int size(String)`` → ``long size(String)`` is CHANGED,
    reported on the resolved side, and neither REMOVED nor ADDED."""
    before = _m("size", "(java.lang.String)", "int")
    after = _m("size", "(java.lang.String)", "long")
    diff = signature_diff(declared={before}, resolved={after})
    assert diff.changed == frozenset({after})
    assert diff.removed == frozenset()
    assert diff.added == frozenset()


@pytest.mark.requirement("FR-277")
def test_unchanged_return_type_is_not_reported() -> None:
    """TA-370: the guard against over-reporting. An identical method on
    both sides produces no diff."""
    sig = _m("size", "(java.lang.String)", "int")
    diff = signature_diff(declared={sig}, resolved={sig})
    assert diff == AbiDiffResult(
        added=frozenset(), removed=frozenset(), changed=frozenset()
    )


@pytest.mark.requirement("FR-277")
def test_bridge_pair_on_both_sides_is_not_changed() -> None:
    """TA-371: a covariant override and its bridge, present unchanged in
    both versions, share a descriptor. Comparing the set of return types
    per descriptor makes them match, so nothing is reported."""
    pair = {
        _m("append", "(int)", "java.lang.StringBuilder"),
        _m("append", "(int)", "java.lang.AbstractStringBuilder"),
    }
    diff = signature_diff(declared=set(pair), resolved=set(pair))
    assert diff.changed == frozenset()
    assert diff.removed == frozenset()
    assert diff.added == frozenset()


@pytest.mark.requirement("FR-277")
def test_losing_the_bridge_is_changed() -> None:
    """TA-372: if the covariant override goes away, so does its bridge.
    Code compiled against the bridge's return type (``append:(I)Lcom/
    thirdparty/Base;``) then fails to link, so the change must be
    reported. It is reported as CHANGED on the descriptor that
    survives."""
    real = _m("append", "(int)", "com.thirdparty.Widget")
    bridge = _m("append", "(int)", "com.thirdparty.Base")
    survivor = _m("append", "(int)", "com.thirdparty.Base")
    diff = signature_diff(declared={real, bridge}, resolved={survivor})
    assert diff.changed == frozenset({survivor})
    assert diff.removed == frozenset()
    assert diff.added == frozenset()


@pytest.mark.requirement("FR-277")
def test_return_type_does_not_split_overload_identity() -> None:
    """TA-373: a return type change on one overload leaves its sibling
    overload alone, and descriptor grouping is unchanged: no spurious
    REMOVED + ADDED."""
    kept = _m("read", "(byte[])", "int")
    before = _m("read", "()", "int")
    after = _m("read", "()", "long")
    diff = signature_diff(declared={kept, before}, resolved={kept, after})
    assert diff.changed == frozenset({after})
    assert diff.removed == frozenset()
    assert diff.added == frozenset()


# ── Findings ────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-277")
@pytest.mark.requirement("FR-274")
def test_finding_message_names_the_new_return_type(tmp_path) -> None:
    """TA-374: without the return type, the message for a return-type-only
    change would name text identical to the declared side and read as if
    nothing had changed."""
    after = _m("size", "(java.lang.String)", "long")
    differ = CrossVersionAbiDiffer(
        m2_root=tmp_path, invoke_javap=lambda jar, cls: None,
    )
    findings = differ._emit_findings(
        coord="com.thirdparty:widget",
        declared_version="1.0",
        resolved_version="2.0",
        diff=AbiDiffResult(
            added=frozenset(), removed=frozenset(),
            changed=frozenset({after}),
        ),
        source_symbols={f"{_FQCN}.size"},
    )
    assert len(findings) == 1
    assert f"long {_FQCN}.size(java.lang.String)" in findings[0].message


@pytest.mark.requirement("FR-277")
@pytest.mark.requirement("FR-273")
def test_sort_key_separates_signatures_differing_only_in_return_type() -> None:
    """TA-375: a bridge pair differs only in return type. Without it in
    ``_signature_sort_key`` the two sort equal and their order falls back
    to set iteration, which depends on the hash seed."""
    a = _m("append", "(int)", "java.lang.StringBuilder")
    b = _m("append", "(int)", "java.lang.AbstractStringBuilder")
    assert _signature_sort_key(a) != _signature_sort_key(b)
    assert sorted([a, b], key=_signature_sort_key) == sorted(
        [b, a], key=_signature_sort_key
    )
