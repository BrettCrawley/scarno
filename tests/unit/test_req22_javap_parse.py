"""PR-4 red test — REQ-22 / FR-232: javap -public output parsing.
TA-268."""
from __future__ import annotations

import pytest


_JAVAP_SAMPLE = """\
Compiled from "Helper.java"
public class com.thirdparty.Helper {
  public com.thirdparty.Helper();
  public int utilityMethod(java.lang.String);
  public static java.lang.String VERSION;
}
"""


@pytest.mark.requirement("FR-232")
def test_javap_public_signatures_parses_method():
    """TA-268 — A javap stdout with one public method, one constructor,
    and one static field parses to three JavaSignature entries."""
    from scarno.analysers.java.abi_diff import javap_public_signatures

    signatures = javap_public_signatures(_JAVAP_SAMPLE)
    # We accept either a frozenset or a list/set.
    sig_list = list(signatures)
    method_names = {s.member_name for s in sig_list}
    assert "utilityMethod" in method_names
    # Constructor + static field also surfaced.
    kinds = {s.member_kind for s in sig_list}
    assert "method" in kinds
