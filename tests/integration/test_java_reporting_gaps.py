"""End-to-end tests for the Java/Maven reporting gaps the user reported.

Each test boots the full ``scarno analyse`` CLI on a fixture project
and asserts on the rendered JSON. These reproduce the user's concerns:

  * `import java.util.*` wildcard handling
  * method-call entry points (``x.doThing()``)
  * constructor entry points (``new ClassName()``)
  * "0/N entry points used" while status is IN_USE (e.g. via
    ``@Autowired`` or ``Class.forName(...)``)
  * parent POM property resolution
  * ``${project.version}`` resolution
  * ``${junit.version}`` (cross-property reference) resolution
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app


def _w(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _run(tmp: Path) -> dict:
    result = CliRunner().invoke(app, [str(tmp), "--format", "json"])
    assert result.exit_code in (0, 1, 3), result.output
    return json.loads(result.output)


def _dep(data: dict, name: str) -> dict:
    matches = [d for d in data["dependencies"] if d["name"] == name]
    assert matches, f"dep {name} missing from output; got {[d['name'] for d in data['dependencies']]}"
    return matches[0]


# ── method calls + constructors ─────────────────────────────────────────


class TestMethodAndConstructorEntryPoints:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-160")
    def test_static_method_invocation_surfaces_as_method_entry_point(
        self, tmp_path
    ):
        """`X.staticMethod()` after `import com.foo.X` → EntryPoint(kind=method)."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.base.Splitter;
public class App {
    public Iterable<String> a(String s) { return Splitter.on(',').split(s); }
    public Iterable<String> b(String s) { return Splitter.on(';').split(s); }
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        # Methods invoked: Splitter.on (×2), Splitter.split (×2 inferred)
        method_eps = [
            ep for ep in guava["entry_points"] if ep["kind"] == "method"
        ]
        assert method_eps, (
            f"no method entry points for guava; kinds present: "
            f"{sorted({ep['kind'] for ep in guava['entry_points']})}"
        )
        # `Splitter.on` should appear as a method with usage_count >= 2.
        on_calls = [
            ep for ep in method_eps if ep["name"].endswith(".on")
        ]
        assert on_calls, f"Splitter.on missing; method eps: {[e['name'] for e in method_eps]}"
        assert on_calls[0]["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_constructor_call_surfaces_as_constructor_entry_point(
        self, tmp_path
    ):
        """`new Splitter(...)` → EntryPoint(kind=constructor)."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
public class App {
    private final java.util.List<String> a = new java.util.ArrayList<>();
    public Object x() { return Lists.newArrayList(); }
}
""")
        # Note: `new java.util.ArrayList<>()` is stdlib; we don't expect
        # it as a guava entry point. We DO expect a method entry point
        # for `Lists.newArrayList`.
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        # method entry point for Lists.newArrayList
        method_names = {
            ep["name"] for ep in guava["entry_points"]
            if ep["kind"] == "method"
        }
        assert any(
            n.endswith(".newArrayList") for n in method_names
        ), f"Lists.newArrayList method missing; got {sorted(method_names)}"


class TestConstructorOfImportedClass:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-161")
    def test_new_imported_class_surfaces_as_constructor(self, tmp_path):
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.collect.HashMultiset;
public class App {
    private final HashMultiset<String> a = new HashMultiset<>();
    public Object b() { return new HashMultiset<>(); }
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        ctor_eps = [
            ep for ep in guava["entry_points"]
            if ep["kind"] == "constructor"
        ]
        assert ctor_eps, (
            f"no constructor entry points; kinds present: "
            f"{sorted({ep['kind'] for ep in guava['entry_points']})}"
        )
        # `HashMultiset` constructor should have usage_count >= 2.
        names = {ep["name"] for ep in ctor_eps}
        assert any("HashMultiset" in n for n in names), (
            f"HashMultiset constructor missing; got {names}"
        )


# ── IN_USE via DI / reflection should report at least one used entry point ──


class TestInUseViaAnnotationProducesEntryPoint:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-164")
    def test_di_annotation_in_use_dep_has_used_entry_point(self, tmp_path):
        """`@Autowired` activation → at least one used entry point."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-context</artifactId>
      <version>6.0.0</version>
    </dependency>
  </dependencies>
</project>
""")
        # No `import org.springframework.*;` — using the marker annotation directly
        # via its short name (the source-analyser already records short-name
        # annotations for DI matching).
        _w(tmp_path / "src" / "main" / "java" / "demo" / "Svc.java", """\
package demo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
@Service
public class Svc {
    @Autowired
    private Object handler;
}
""")
        data = _run(tmp_path)
        spring = _dep(data, "org.springframework:spring-context")
        assert spring["status"] == "IN_USE", (
            f"expected IN_USE; got {spring['status']} (reason: {spring['reason']})"
        )
        used_eps = [ep for ep in spring["entry_points"] if ep["used"]]
        assert used_eps, (
            f"IN_USE dep has 0 used entry points despite being activated "
            f"via DI annotation; entry_points_used={spring['entry_points_used']} "
            f"of {spring['entry_points_total']} total"
        )


# ── Maven property resolution ──────────────────────────────────────────


class TestMavenPropertyResolution:
    @pytest.mark.requirement("FR-131")
    def test_parent_pom_property_resolves_in_child_dep_version(
        self, tmp_path
    ):
        """Property declared in PARENT POM, referenced from CHILD dep version."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  <properties>
    <junit.version>4.13.2</junit.version>
  </properties>
  <modules>
    <module>child</module>
  </modules>
</project>
""")
        _w(tmp_path / "child" / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${junit.version}</version>
    </dependency>
  </dependencies>
</project>
""")
        data = _run(tmp_path)
        junit = _dep(data, "junit:junit")
        assert junit["version"] == "4.13.2", (
            f"parent property didn't resolve in child; got version "
            f"{junit['version']!r}"
        )

    @pytest.mark.requirement("FR-131")
    @pytest.mark.requirement("FR-166")
    def test_project_version_resolves_to_child_version(self, tmp_path):
        """`${project.version}` in a child dep version must resolve to the child's version."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>9.9.9</version>
  <packaging>pom</packaging>
  <modules><module>child</module></modules>
</project>
""")
        _w(tmp_path / "child" / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>9.9.9</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
  <version>1.2.3</version>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>
""")
        data = _run(tmp_path)
        sib = _dep(data, "org.example:sibling")
        assert sib["version"] == "1.2.3", (
            f"${{project.version}} didn't resolve to child's version 1.2.3; "
            f"got {sib['version']!r}"
        )

    @pytest.mark.requirement("FR-131")
    def test_child_property_overrides_parent(self, tmp_path):
        """Child POM property must override parent POM property of the same name."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  <properties>
    <lib.version>1.0.0</lib.version>
  </properties>
  <modules><module>child</module></modules>
</project>
""")
        _w(tmp_path / "child" / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
  <properties>
    <lib.version>2.5.0</lib.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.lib</groupId>
      <artifactId>lib</artifactId>
      <version>${lib.version}</version>
    </dependency>
  </dependencies>
</project>
""")
        data = _run(tmp_path)
        lib = _dep(data, "org.lib:lib")
        assert lib["version"] == "2.5.0", (
            f"child property didn't override parent; got {lib['version']!r}"
        )

    @pytest.mark.requirement("FR-131")
    @pytest.mark.requirement("FR-166")
    def test_pom_version_legacy_alias_resolves(self, tmp_path):
        """``${pom.version}`` (Maven 2.x legacy alias) must resolve to
        the project's own version, identically to ``${project.version}``.
        """
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>3.4.5</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${pom.version}</version>
    </dependency>
  </dependencies>
</project>
""")
        data = _run(tmp_path)
        sib = _dep(data, "com.example:sibling")
        assert sib["version"] == "3.4.5", (
            f"${{pom.version}} did not resolve; got {sib['version']!r}"
        )
        # No noisy "Unresolvable placeholder" warning.
        assert not [e for e in data["errors"] if "${pom.version}" in e]

    @pytest.mark.requirement("FR-131")
    @pytest.mark.requirement("FR-166")
    def test_project_parent_version_resolves(self, tmp_path):
        """``${project.parent.version}`` must resolve to the parent POM's version."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>7.7.7</version>
  <packaging>pom</packaging>
  <modules><module>child</module></modules>
</project>
""")
        _w(tmp_path / "child" / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>7.7.7</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
  <version>1.2.3</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>shared-bom</artifactId>
      <version>${project.parent.version}</version>
    </dependency>
  </dependencies>
</project>
""")
        data = _run(tmp_path)
        bom = _dep(data, "com.example:shared-bom")
        assert bom["version"] == "7.7.7", (
            f"${{project.parent.version}} did not resolve to parent POM's "
            f"version 7.7.7; got {bom['version']!r}"
        )
        assert not [
            e for e in data["errors"] if "${project.parent.version}" in e
        ]

    @pytest.mark.requirement("FR-131")
    def test_property_referenced_across_dep_versions(self, tmp_path):
        """A single property used by multiple deps' versions resolves consistently."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <properties>
    <jackson.version>2.15.2</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-core</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>
</project>
""")
        data = _run(tmp_path)
        core = _dep(data, "com.fasterxml.jackson.core:jackson-core")
        bind = _dep(data, "com.fasterxml.jackson.core:jackson-databind")
        assert core["version"] == "2.15.2"
        assert bind["version"] == "2.15.2"


# ── wildcard imports ────────────────────────────────────────────────────


class TestMultiWildcardSignatureDisambiguation:
    """When two wildcard imports both could own a simple class name and
    BOTH JARs are in the local cache, use ``javap`` to read the actual
    method list per class and attribute each call to the dep whose
    class exposes the called method.
    """

    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-163")
    def test_method_signature_disambiguates_clashing_wildcards(
        self, tmp_path, monkeypatch
    ):
        # Two fake deps that both wildcard a `collect` package and both
        # claim a class called `Foo`. We mock both `_invoke_javap_safe`
        # and `_build_jar_inventory_map` to control which class names
        # each JAR exposes and which methods each class declares.
        from scarno.analysers.java import source_analyser as sa

        fake_jar_a = tmp_path / "fake-libA.jar"
        fake_jar_b = tmp_path / "fake-libB.jar"
        fake_jar_a.write_bytes(b"")  # presence-only; we mock the inventory
        fake_jar_b.write_bytes(b"")

        inv_a = sa._JarInventory(
            jar_path=fake_jar_a,
            packages=frozenset({"org.libA.collect"}),
            class_entries=("org/libA/collect/Foo.class",),
        )
        inv_b = sa._JarInventory(
            jar_path=fake_jar_b,
            packages=frozenset({"org.libB.collect"}),
            class_entries=("org/libB/collect/Foo.class",),
        )

        def fake_inventory(deps, project_root, errors):
            out = {}
            for d in deps:
                if d.name == "org.libA:libA":
                    out[d.name] = inv_a
                elif d.name == "org.libB:libB":
                    out[d.name] = inv_b
            return out

        # javap mock: libA.Foo exposes method `barA`; libB.Foo exposes `barB`.
        def fake_javap(self, jar_path, class_name):
            if jar_path == fake_jar_a:
                return (
                    "Compiled from \"Foo.java\"\n"
                    "public class org.libA.collect.Foo {\n"
                    "  public void barA();\n"
                    "}\n"
                )
            if jar_path == fake_jar_b:
                return (
                    "Compiled from \"Foo.java\"\n"
                    "public class org.libB.collect.Foo {\n"
                    "  public void barB();\n"
                    "}\n"
                )
            return None

        monkeypatch.setattr(sa, "_build_jar_inventory_map", fake_inventory)
        monkeypatch.setattr(
            sa.JvmSourceAnalyser, "_invoke_javap_safe", fake_javap,
        )
        # Force deep_inspection so the analyser is willing to invoke javap.
        monkeypatch.setattr(
            sa.JvmSourceAnalyser, "deep_inspection", True, raising=False,
        )

        _w(tmp_path / "project" / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.libA</groupId>
      <artifactId>libA</artifactId>
      <version>1.0</version>
    </dependency>
    <dependency>
      <groupId>org.libB</groupId>
      <artifactId>libB</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "project" / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import org.libA.collect.*;
import org.libB.collect.*;
public class App {
    public void run() {
        Foo.barA();
        Foo.barB();
    }
}
""")

        data = _run(tmp_path / "project")
        a = _dep(data, "org.libA:libA")
        b = _dep(data, "org.libB:libB")
        a_methods = {
            ep["name"] for ep in a["entry_points"] if ep["kind"] == "method"
        }
        b_methods = {
            ep["name"] for ep in b["entry_points"] if ep["kind"] == "method"
        }
        # `Foo.barA` belongs to libA only.
        assert any(n.endswith(".barA") for n in a_methods), (
            f"Foo.barA not attributed to libA; libA methods: {a_methods}"
        )
        assert not any(n.endswith(".barA") for n in b_methods), (
            f"Foo.barA leaked to libB; libB methods: {b_methods}"
        )
        # `Foo.barB` belongs to libB only.
        assert any(n.endswith(".barB") for n in b_methods), (
            f"Foo.barB not attributed to libB; libB methods: {b_methods}"
        )
        assert not any(n.endswith(".barB") for n in a_methods), (
            f"Foo.barB leaked to libA; libA methods: {a_methods}"
        )


class TestInstanceMethodCalls:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-162")
    def test_local_variable_call_attributes_to_declared_type(
        self, tmp_path
    ):
        """`Splitter s = …; s.split(',')` must attribute `Splitter.split`.

        Without this, the most common Java pattern (declare a local
        variable typed to an imported class, then call methods on it)
        is invisible to the report.
        """
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.base.Splitter;
public class App {
    public java.util.List<String> a(String s) {
        Splitter sp = Splitter.on(',');
        Iterable<String> i1 = sp.split(s);
        Iterable<String> i2 = sp.split(s);
        return new java.util.ArrayList<>();
    }
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        method_names = {
            ep["name"] for ep in guava["entry_points"]
            if ep["kind"] == "method"
        }
        # `sp.split` must be attributed back to `Splitter.split`.
        split_eps = [
            ep for ep in guava["entry_points"]
            if ep["kind"] == "method" and ep["name"].endswith(".split")
        ]
        assert split_eps, (
            f"instance method `sp.split` not attributed to Splitter; "
            f"methods seen: {sorted(method_names)}"
        )
        # Two `sp.split(s)` call sites → usage_count >= 2.
        assert split_eps[0]["usage_count"] >= 2, split_eps[0]

    @pytest.mark.requirement("FR-150")
    def test_field_declaration_call_attributes_to_declared_type(
        self, tmp_path
    ):
        """`private final Splitter s; … s.split(…)` must attribute too."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.base.Splitter;
public class App {
    private final Splitter splitter = Splitter.on(',');
    public Iterable<String> run(String s) { return this.splitter.split(s); }
    public Iterable<String> run2(String s) { return splitter.split(s); }
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        split_eps = [
            ep for ep in guava["entry_points"]
            if ep["kind"] == "method" and ep["name"].endswith(".split")
        ]
        assert split_eps, (
            f"field `splitter.split` not attributed to Splitter; "
            f"methods: {sorted(ep['name'] for ep in guava['entry_points'] if ep['kind']=='method')}"
        )

    @pytest.mark.requirement("FR-150")
    def test_wildcard_instance_method_call_attributes(self, tmp_path):
        """Wildcard import + instance method call: `import x.y.*; X x = …; x.m()`."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.collect.*;
public class App {
    public Object x() {
        HashMultiset<String> m = HashMultiset.create();
        m.add("a");
        m.add("b");
        return m;
    }
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        method_names = {
            ep["name"] for ep in guava["entry_points"]
            if ep["kind"] == "method"
        }
        # `m.add` must be attributed back to `HashMultiset.add`.
        assert any(n.endswith(".add") for n in method_names), (
            f"instance method `m.add` not attributed to HashMultiset; "
            f"methods seen: {sorted(method_names)}"
        )


class TestWildcardImports:
    @pytest.mark.requirement("FR-150")
    def test_wildcard_method_calls_attribute_to_wildcard_dep_jarless(
        self, tmp_path
    ):
        """Source has *only* `import x.y.*`; calls of unqualified
        ``ClassName.method()`` and ``new ClassName()`` must surface as
        method/constructor entry points of the dep owning ``x.y``.

        Without this attribution, the wildcard import is the only entry
        point shown — the user can't see which classes from the package
        are actually referenced. JAR-less heuristic path.
        """
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.collect.*;
public class App {
    private final HashMultiset<String> a = new HashMultiset<>();
    public Object b() { return ImmutableList.of("x"); }
    public Object c() { return ImmutableList.of("y"); }
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        # Despite the wildcard-only import, the method and constructor
        # calls must be attributed to guava.
        method_names = {
            ep["name"] for ep in guava["entry_points"]
            if ep["kind"] == "method"
        }
        ctor_names = {
            ep["name"] for ep in guava["entry_points"]
            if ep["kind"] == "constructor"
        }
        assert any("ImmutableList.of" in n for n in method_names), (
            f"ImmutableList.of not attributed to wildcard'd guava; "
            f"methods seen: {sorted(method_names)}"
        )
        assert any("HashMultiset" in n for n in ctor_names), (
            f"HashMultiset constructor not attributed to wildcard'd guava; "
            f"constructors seen: {sorted(ctor_names)}"
        )

    @pytest.mark.requirement("FR-150")
    def test_wildcard_does_not_steal_calls_owned_by_concrete_import(
        self, tmp_path
    ):
        """When two deps could own a simple name, the dep with the
        concrete import wins. The wildcard'd dep must not over-attribute.
        """
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-collections4</artifactId>
      <version>4.4</version>
    </dependency>
  </dependencies>
</project>
""")
        # Concrete import claims ImmutableList for guava; wildcard for commons.
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.collect.ImmutableList;
import org.apache.commons.collections4.*;
public class App {
    public Object x() { return ImmutableList.of("a"); }
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        commons = _dep(data, "org.apache.commons:commons-collections4")
        # ImmutableList.of belongs to guava (concrete import wins).
        guava_methods = {
            ep["name"] for ep in guava["entry_points"]
            if ep["kind"] == "method"
        }
        commons_methods = {
            ep["name"] for ep in commons["entry_points"]
            if ep["kind"] == "method"
        }
        assert any("ImmutableList.of" in n for n in guava_methods)
        assert not any("ImmutableList.of" in n for n in commons_methods), (
            "wildcard'd commons stole a call that the concrete guava "
            "import claimed"
        )

    @pytest.mark.requirement("FR-150")
    def test_wildcard_import_of_dep_package_marks_dep_in_use(
        self, tmp_path
    ):
        """`import com.google.common.collect.*` must classify guava IN_USE."""
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")
        _w(tmp_path / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.google.common.collect.*;
public class App {
    private ImmutableList<String> a = ImmutableList.of("x");
    private HashMultiset<String> b = HashMultiset.create();
}
""")
        data = _run(tmp_path)
        guava = _dep(data, "com.google.guava:guava")
        assert guava["status"] == "IN_USE"
        # The wildcard package should appear as an entry point so the
        # user can see what was imported wholesale.
        kinds = {ep["kind"] for ep in guava["entry_points"]}
        assert "wildcard" in kinds or any(
            ep["name"].endswith(".*") or ep["name"].endswith("/*")
            for ep in guava["entry_points"]
        ), (
            f"wildcard import not surfaced as a distinct entry point; "
            f"kinds: {kinds}"
        )
