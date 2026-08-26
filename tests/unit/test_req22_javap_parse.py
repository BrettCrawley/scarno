"""REQ-22 / FR-232, FR-275, FR-276 — javap output parsing.

TA-268 plus the coverage added for
``docs/issues/SCARNO-BUG-protected-members.md``.

Two independent defects made whole slices of the ABI surface invisible to
``TS-ABI-RUNTIME-RISK``:

* extraction ran at ``javap -public``, so protected and package-private
  members were never emitted — yet a protected member removed between two
  versions raises ``NoSuchMethodError`` for a subclass exactly as a public
  one does, and subclassing library base classes is the idiomatic way to
  use Jackson, Netty, Jetty and SnakeYAML;
* the parser's modifier alternations required at least one modifier and
  omitted ``private``, its name group disallowed dots, and it had no room
  for a ``throws`` clause — so package-private members, every
  constructor, and every method declaring a checked exception were
  dropped even when javap did emit them.
"""
from __future__ import annotations

import pytest

from scarno.analysers.java.abi_diff import javap_public_signatures

_JAVAP_SAMPLE = """\
Compiled from "Helper.java"
public class com.thirdparty.Helper {
  public com.thirdparty.Helper();
  public int utilityMethod(java.lang.String);
  public static java.lang.String VERSION;
}
"""

# A class exercising every access level, both member kinds, a constructor
# and a throws clause — the shapes `javap -package` really emits.
_MIXED_ACCESS = """\
Compiled from "Composer.java"
public class org.yaml.snakeyaml.composer.Composer {
  protected final org.yaml.snakeyaml.parser.Parser parser;
  org.yaml.snakeyaml.LoaderOptions loadingConfig;
  public org.yaml.snakeyaml.composer.Composer(org.yaml.snakeyaml.parser.Parser);
  public boolean checkNode();
  protected org.yaml.snakeyaml.nodes.Node composeNode(org.yaml.snakeyaml.nodes.Node);
  void increaseNestingDepth();
  public void flush() throws java.io.IOException;
  static final boolean $assertionsDisabled;
}
"""


def _declaration_lines(stdout: str) -> list[str]:
    """Every line javap terminates with ';' is a member declaration."""
    return [
        line for line in stdout.splitlines()
        if line.strip().endswith(";") and not line.strip().startswith("Compiled")
    ]


@pytest.mark.requirement("FR-232")
def test_javap_public_signatures_parses_method():
    """TA-268 — one method, one constructor and one static field parse to
    three entries. The constructor half of this went unasserted for a
    long time, and was in fact being dropped."""
    signatures = list(javap_public_signatures(_JAVAP_SAMPLE))

    assert len(signatures) == 3, signatures
    by_kind = {s.member_kind for s in signatures}
    assert by_kind == {"method", "constructor", "field"}, by_kind
    assert "utilityMethod" in {s.member_name for s in signatures}


@pytest.mark.requirement("FR-276")
def test_no_declaration_is_silently_dropped():
    """The invariant that makes a parser regression fail the build: every
    ';'-terminated line javap emits must become a signature."""
    parsed = javap_public_signatures(_MIXED_ACCESS)
    emitted = _declaration_lines(_MIXED_ACCESS)

    assert len(parsed) == len(emitted), (
        f"parsed {len(parsed)} of {len(emitted)} declarations — "
        f"a member shape is being dropped"
    )


@pytest.mark.requirement("FR-276")
@pytest.mark.parametrize("line,kind,name", [
    # Access levels. Package-private carries no modifier at all, which is
    # what defeated the old '+' quantifier.
    ("  public void a();", "method", "a"),
    ("  protected void b();", "method", "b"),
    ("  void c();", "method", "c"),
    ("  private void d();", "method", "d"),
    ("  public int e;", "field", "e"),
    ("  protected int f;", "field", "f"),
    ("  int g;", "field", "g"),
    # Constructors: javap prints them fully qualified and with no return
    # type, so a name group without dots dropped every one.
    ("  public com.example.Widget();", "constructor", "Widget"),
    ("  com.example.Widget(java.lang.String);", "constructor", "Widget"),
    # A throws clause sits between ')' and ';'.
    ("  public void h() throws java.io.IOException;", "method", "h"),
    ("  void i() throws java.io.IOException, java.sql.SQLException;",
     "method", "i"),
    # Shapes that already worked and must keep working.
    ("  public java.util.List<java.lang.String> j();", "method", "j"),
    ("  public byte[] k();", "method", "k"),
    ("  public void l(java.lang.String...);", "method", "l"),
    ("  public static final int M;", "field", "M"),
    ("  static final boolean $assertionsDisabled;", "field",
     "$assertionsDisabled"),
])
def test_member_shapes_parse(line, kind, name):
    stdout = f"public class com.example.Widget {{\n{line}\n}}\n"
    parsed = list(javap_public_signatures(stdout))

    assert len(parsed) == 1, f"{line!r} produced {parsed}"
    assert parsed[0].member_kind == kind
    assert parsed[0].member_name == name


@pytest.mark.requirement("FR-276")
def test_static_initialiser_is_not_a_member():
    """``static {};`` is not a declaration and must not become one."""
    stdout = "public class com.example.Widget {\n  static {};\n}\n"
    assert javap_public_signatures(stdout) == set()


@pytest.mark.requirement("FR-276")
def test_constructor_identity_uses_the_simple_name():
    """The FQCN is already the first element of a signature's identity, so
    a constructor is recorded under the simple name rather than repeating
    the package."""
    stdout = (
        "public class com.example.Widget {\n"
        "  public com.example.Widget(int);\n"
        "  public com.example.Widget(java.lang.String);\n"
        "}\n"
    )
    parsed = list(javap_public_signatures(stdout))

    assert {s.member_name for s in parsed} == {"Widget"}
    # Two overloads, distinguished by descriptor rather than collapsed.
    assert {s.descriptor for s in parsed} == {"(int)", "(java.lang.String)"}


@pytest.mark.requirement("FR-275")
def test_extraction_runs_at_package_access_level():
    """``-public`` omits protected and package-private members entirely,
    so no parser change can recover them — the flag is half the fix."""
    import inspect

    from scarno.analysers.java.source_analyser import JvmSourceAnalyser

    source = inspect.getsource(JvmSourceAnalyser._invoke_javap_safe)
    assert '"-package"' in source, (
        "javap must be invoked at -package so the protected surface is "
        "visible to the ABI diff"
    )
    assert '"-public"' not in source
    # -p / -private would add members no external caller can reference.
    assert '"-p"' not in source and '"-private"' not in source


class TestProtectedRemovalIsDetectedEndToEnd:
    """The report's regression test 1: a protected member removed between
    two versions must be reported. It passed trivially before only
    because the member was invisible on both sides.
    """

    @staticmethod
    def _sigs(stdout: str):
        return javap_public_signatures(stdout)

    @pytest.mark.requirement("FR-275")
    def test_removed_protected_method_reaches_the_diff(self):
        from scarno.analysers.java.abi_diff import signature_diff

        declared = self._sigs(
            "public class com.example.Base {\n"
            "  public void keep();\n"
            "  protected void onEvent(com.example.Event);\n"
            "}\n"
        )
        resolved = self._sigs(
            "public class com.example.Base {\n"
            "  public void keep();\n"
            "}\n"
        )
        diff = signature_diff(declared=declared, resolved=resolved)

        removed = {(s.member_name, s.descriptor) for s in diff.removed}
        assert ("onEvent", "(com.example.Event)") in removed, (
            "a removed protected method is invisible to the ABI diff"
        )

    @pytest.mark.requirement("FR-275")
    def test_removed_package_private_method_reaches_the_diff(self):
        from scarno.analysers.java.abi_diff import signature_diff

        declared = self._sigs(
            "public class com.example.Base {\n"
            "  public void keep();\n"
            "  void internalHook();\n"
            "}\n"
        )
        resolved = self._sigs(
            "public class com.example.Base {\n  public void keep();\n}\n"
        )
        diff = signature_diff(declared=declared, resolved=resolved)

        assert "internalHook" in {s.member_name for s in diff.removed}

    @pytest.mark.requirement("FR-276")
    def test_removed_constructor_overload_reaches_the_diff(self):
        """Constructor removal is a NoSuchMethodError source too, and no
        constructor parsed at all before."""
        from scarno.analysers.java.abi_diff import signature_diff

        declared = self._sigs(
            "public class com.example.Widget {\n"
            "  public com.example.Widget();\n"
            "  public com.example.Widget(java.lang.String);\n"
            "}\n"
        )
        resolved = self._sigs(
            "public class com.example.Widget {\n"
            "  public com.example.Widget();\n"
            "}\n"
        )
        diff = signature_diff(declared=declared, resolved=resolved)

        removed = {(s.member_kind, s.descriptor) for s in diff.removed}
        assert ("constructor", "(java.lang.String)") in removed, removed

    @pytest.mark.requirement("FR-276")
    def test_removed_throwing_method_reaches_the_diff(self):
        """A method declaring a checked exception never parsed, so its
        removal was invisible at every access level — including public."""
        from scarno.analysers.java.abi_diff import signature_diff

        declared = self._sigs(
            "public class com.example.Io {\n"
            "  public void read() throws java.io.IOException;\n"
            "}\n"
        )
        resolved = self._sigs("public class com.example.Io {\n}\n")
        diff = signature_diff(declared=declared, resolved=resolved)

        assert "read" in {s.member_name for s in diff.removed}
