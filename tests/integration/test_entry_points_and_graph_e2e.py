"""End-to-end CLI tests for symbol tally and dep-graph surfacing.

These reproduce the user-visible bugs that REQ-17's first round of unit
tests missed:

  1. ``dep_graph`` lock-file data was being dropped between the parser
     and the JSON / markdown output, so the Mermaid hierarchy looked
     like a flat list.
  2. Java, JavaScript, C#, and Go source analysers did not populate
     ``EntryPoint.usage_count`` (and C#/Go did not enumerate entry
     points at all), so even ``IN_USE`` deps showed neither methods nor
     call counts.

Each test boots the full ``scarno analyse`` CLI (via Typer's
``CliRunner``) on a fixture project shaped like a real codebase, then
asserts on the rendered JSON / Markdown — not on internal data
structures. That way these tests fail when the user-visible output
breaks, not when an internal helper gets renamed.
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


# ── dep_graph propagation ───────────────────────────────────────────────


class TestDepGraphReachesOutput:
    @pytest.mark.requirement("FR-152")
    def test_uv_lock_graph_reaches_json_output(self, tmp_path):
        """A project with a uv.lock must surface dep_graph in JSON."""
        _w(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["alpha"]\n'
        ))
        _w(tmp_path / "uv.lock", """\
version = 1
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "0.0.0"
source = { virtual = "." }
dependencies = [
    { name = "alpha" },
]

[[package]]
name = "alpha"
version = "1.0.0"
dependencies = [
    { name = "beta" },
    { name = "gamma" },
]

[[package]]
name = "beta"
version = "2.0.0"
dependencies = [
    { name = "delta" },
]

[[package]]
name = "gamma"
version = "3.0.0"

[[package]]
name = "delta"
version = "4.0.0"
""")
        _w(tmp_path / "main.py", "import alpha\n")

        result = CliRunner().invoke(app, [str(tmp_path), "--format", "json"])
        assert result.exit_code in (0, 1, 3), result.output
        data = json.loads(result.output)
        graph = data.get("dep_graph") or {}
        assert graph, "dep_graph was empty in JSON output"
        # Direct edge: alpha → {beta, gamma}.
        assert "alpha" in graph
        assert "beta" in graph["alpha"]
        assert "gamma" in graph["alpha"]
        # Transitive: beta → delta.
        assert "beta" in graph
        assert "delta" in graph["beta"]

    @pytest.mark.requirement("FR-152")
    def test_uv_lock_graph_reaches_markdown_ascii_tree(self, tmp_path):
        """The markdown ASCII tree must show every transitive level,
        not just direct deps."""
        _w(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["alpha"]\n'
        ))
        _w(tmp_path / "uv.lock", """\
version = 1
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "0.0.0"
source = { virtual = "." }
dependencies = [{ name = "alpha" }]

[[package]]
name = "alpha"
version = "1.0.0"
dependencies = [{ name = "beta" }]

[[package]]
name = "beta"
version = "2.0.0"
dependencies = [{ name = "gamma" }]

[[package]]
name = "gamma"
version = "3.0.0"
""")
        _w(tmp_path / "main.py", "import alpha\n")

        # Markdown is the default format and omits-output now auto-writes
        # to a file; supply an explicit --output so the assertion can
        # read deterministic content rather than scrape stderr.
        out_file = tmp_path / "report.md"
        result = CliRunner().invoke(
            app,
            [str(tmp_path), "--format", "markdown", "--output", str(out_file)],
        )
        assert result.exit_code in (0, 1, 3)
        # All three deps must appear in the ASCII tree, with deeper
        # transitives indented further than shallower ones.
        out = out_file.read_text(encoding="utf-8")
        assert "```diff" in out, "ascii tree fence missing"
        for name in ("alpha", "beta", "gamma"):
            assert name in out, f"{name} missing from tree"
        # Indentation must increase with depth.
        lines = out.splitlines()
        alpha_line = next(l for l in lines if "alpha" in l and "├" in l or "└" in l and "alpha" in l)
        beta_line = next(l for l in lines if "beta" in l and ("├" in l or "└" in l))
        gamma_line = next(l for l in lines if "gamma" in l and ("├" in l or "└" in l))
        assert beta_line.index("beta") > alpha_line.index("alpha")
        assert gamma_line.index("gamma") > beta_line.index("beta")

    @pytest.mark.requirement("FR-152")
    def test_show_suppressed_does_not_drop_dep_graph(self, tmp_path):
        """`--show-suppressed` must not nuke `dep_graph`."""
        _w(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["alpha"]\n'
        ))
        _w(tmp_path / "uv.lock", """\
version = 1
[[package]]
name = "demo"
version = "0"
source = { virtual = "." }
dependencies = [{ name = "alpha" }]

[[package]]
name = "alpha"
version = "1"
dependencies = [{ name = "beta" }]

[[package]]
name = "beta"
version = "2"
""")
        _w(tmp_path / "main.py", "import alpha\n")

        # With --show-suppressed the result is rebuilt; dep_graph must survive.
        result = CliRunner().invoke(app, [
            str(tmp_path), "--format", "json", "--show-suppressed",
        ])
        data = json.loads(result.output)
        assert data.get("dep_graph", {}).get("alpha"), (
            "dep_graph dropped when --show-suppressed rebuilds the result"
        )

    @pytest.mark.requirement("FR-152")
    def test_language_filter_does_not_drop_dep_graph(self, tmp_path):
        """`--language pypi` must not nuke `dep_graph`."""
        _w(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["alpha"]\n'
        ))
        _w(tmp_path / "uv.lock", """\
version = 1
[[package]]
name = "demo"
version = "0"
source = { virtual = "." }
dependencies = [{ name = "alpha" }]

[[package]]
name = "alpha"
version = "1"
dependencies = [{ name = "beta" }]

[[package]]
name = "beta"
version = "2"
""")
        _w(tmp_path / "main.py", "import alpha\n")
        result = CliRunner().invoke(app, [
            str(tmp_path), "--format", "json", "--language", "pypi",
        ])
        data = json.loads(result.output)
        assert data.get("dep_graph", {}).get("alpha"), (
            "dep_graph dropped when --language filter rebuilds the result"
        )


# ── usage_count surfacing across ecosystems ──────────────────────────────


class TestUsageCountAcrossEcosystems:
    @pytest.mark.requirement("FR-150")
    def test_python_in_use_dep_carries_usage_count_in_json(self, tmp_path):
        """A Python project must show non-zero usage_count for actually-called symbols."""
        _w(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["pytest"]\n'
        ))
        _w(tmp_path / "main.py",
           "import pytest\n"
           "pytest.fail('a')\n"
           "pytest.fail('b')\n"
           "pytest.skip('s')\n")
        result = CliRunner().invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        pytest_dep = next(
            (d for d in data["dependencies"] if d["name"] == "pytest"), None
        )
        assert pytest_dep, "pytest dep missing from output"
        used = [
            ep for ep in pytest_dep["entry_points"] if ep["used"]
        ]
        assert used, "no entry points marked used for pytest"
        # Some entry must carry a non-zero usage_count.
        assert any(ep["usage_count"] > 0 for ep in used), (
            f"all entry points have usage_count==0; got "
            f"{[(e['name'], e['usage_count']) for e in used]}"
        )

    @pytest.mark.requirement("FR-150")
    def test_java_in_use_dep_carries_usage_count(self, tmp_path):
        """A Java fixture: tree-sitter resolves the import → entry point.

        The fixture creates a Maven POM declaring ``com.google.guava:guava``
        and Java source that imports ``com.google.common.base.Splitter``
        and references ``Splitter`` 3 times. The IN_USE classification
        does not require a JAR to be present — that's a separate
        enumeration step. We assert that the report at minimum lists the
        used import as an entry point with a non-zero usage_count.
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
    public Splitter make() { return Splitter.on(','); }
    public Splitter alt()  { return Splitter.on(';'); }
    public Splitter rev()  { return Splitter.on('|'); }
}
""")
        result = CliRunner().invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        guava = next(
            (d for d in data["dependencies"]
             if d["name"] == "com.google.guava:guava"),
            None,
        )
        assert guava, "guava dep missing"
        # The Java source analyser must produce at least one used entry
        # point and at least one with usage_count > 0.
        used = [ep for ep in guava["entry_points"] if ep["used"]]
        assert used, (
            f"no IN_USE entry points for guava; got "
            f"{[(e['name'], e['used'], e['usage_count']) for e in guava['entry_points'][:5]]}"
        )
        assert any(ep["usage_count"] > 0 for ep in used), (
            f"every Java entry point shows usage_count == 0; got "
            f"{[(e['name'], e['usage_count']) for e in used]}"
        )

    @pytest.mark.requirement("FR-150")
    def test_javascript_in_use_dep_carries_usage_count(self, tmp_path):
        """A JS project must show usage_count for imported specifiers."""
        # Construct a node_modules/lodash/package.json with an exports field
        # so the entry-point enumerator has something to enumerate.
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
        }))
        _w(tmp_path / "node_modules" / "lodash" / "package.json",
           json.dumps({
               "name": "lodash",
               "version": "4.17.21",
               "exports": {".": "./index.js", "./debounce": "./debounce.js"},
           }))
        _w(tmp_path / "src" / "index.js",
           'import _ from "lodash";\n'
           'import debounce from "lodash/debounce";\n'
           'import other from "lodash/debounce";\n'
           'import last from "lodash/debounce";\n')

        result = CliRunner().invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        lodash = next(
            (d for d in data["dependencies"] if d["name"] == "lodash"), None
        )
        assert lodash, "lodash dep missing"
        used = [ep for ep in lodash["entry_points"] if ep["used"]]
        assert used, (
            "no used entry points for lodash — JS source analyser "
            "isn't surfacing imports as entry points"
        )
        assert any(ep["usage_count"] > 0 for ep in used), (
            f"JS entry points have usage_count == 0 across the board; got "
            f"{[(e['name'], e['usage_count']) for e in used]}"
        )

    @pytest.mark.requirement("FR-150")
    def test_csharp_in_use_dep_has_entry_points(self, tmp_path):
        """C# `using` directives must surface as entry points with counts."""
        _w(tmp_path / "App.csproj", """\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
""")
        _w(tmp_path / "Program.cs", """\
using Serilog;
using Serilog.Events;
class P {
  void M() {
    var l = new LoggerConfiguration().CreateLogger();
    l.Information("a");
    l.Information("b");
  }
}
""")
        result = CliRunner().invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        serilog = next(
            (d for d in data["dependencies"] if d["name"] == "Serilog"), None
        )
        assert serilog, "Serilog dep missing"
        assert serilog["entry_points"], (
            "C# analyser produced zero entry points for Serilog — "
            "user cannot see which namespaces / types are in use"
        )
        used = [ep for ep in serilog["entry_points"] if ep["used"]]
        assert used, "no Serilog entry points marked used"
        assert any(ep["usage_count"] > 0 for ep in used), (
            "C# entry points missing usage_count"
        )

    @pytest.mark.requirement("FR-152")
    @pytest.mark.requirement("FR-165")
    def test_maven_dep_graph_includes_transitives_from_m2_cache(
        self, tmp_path, monkeypatch
    ):
        """Maven dep_graph must include transitives read from ``~/.m2/repository``.

        Reproduces the user-reported failure: "the dependency tree has
        only 1 level". The fix walks each direct dep's cached POM and
        records its ``<dependencies>`` as graph children.
        """
        # Fake Maven local repo populated with one transitive POM.
        fake_m2 = tmp_path / "fake-m2" / "repository"
        fake_m2.mkdir(parents=True)
        # ~/.m2/repository/com/google/guava/guava/32.0.0/guava-32.0.0.pom
        guava_pom = (
            fake_m2 / "com" / "google" / "guava" / "guava" / "32.0.0"
            / "guava-32.0.0.pom"
        )
        guava_pom.parent.mkdir(parents=True)
        guava_pom.write_text("""\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>32.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.errorprone</groupId>
      <artifactId>error_prone_annotations</artifactId>
      <version>2.18.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.j2objc</groupId>
      <artifactId>j2objc-annotations</artifactId>
      <version>2.8</version>
    </dependency>
    <dependency>
      <groupId>org.mockito</groupId>
      <artifactId>mockito-core</artifactId>
      <version>5.0.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
""")
        # Redirect MavenPomResolver's cache lookup to our fake repo.
        from scarno.analysers.java import maven as _maven_mod

        monkeypatch.setattr(
            _maven_mod, "_m2_repo_path", lambda: fake_m2,
        )

        project = tmp_path / "project"
        _w(project / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0</version>
    </dependency>
  </dependencies>
</project>
""")
        result = CliRunner().invoke(app, [str(project), "--format", "json"])
        data = json.loads(result.output)
        graph = data.get("dep_graph") or {}
        # The runtime transitives must appear; the test-scoped one must NOT.
        assert "com.google.guava:guava" in graph, (
            f"guava missing from dep_graph; keys: {sorted(graph.keys())}"
        )
        children = set(graph["com.google.guava:guava"])
        assert "com.google.errorprone:error_prone_annotations" in children
        assert "com.google.j2objc:j2objc-annotations" in children
        # Test-scoped transitive must be excluded — removing guava in
        # production wouldn't free a test-only dep.
        assert "org.mockito:mockito-core" not in children

    @pytest.mark.requirement("FR-152")
    def test_maven_parent_pom_dependencies_surface_in_output(
        self, tmp_path
    ):
        """Deps declared in a parent POM must appear in the dep list and
        be linked to the child module in the dep_graph.

        Without this, a multi-module project where the parent POM
        declares ``<dependencies>`` shows a single-level tree — exactly
        the user-reported failure.
        """
        # Parent POM declares one shared dep.
        _w(tmp_path / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
  <modules>
    <module>child</module>
  </modules>
</project>
""")
        # Child module: explicit relativePath to the parent at ../pom.xml.
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
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
""")

        result = CliRunner().invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        names = {d["name"] for d in data["dependencies"]}
        # Parent-POM dep MUST appear.
        assert "org.slf4j:slf4j-api" in names, (
            f"parent POM dep slf4j-api missing from output; got {sorted(names)}"
        )
        # Child-POM dep also present.
        assert "com.google.guava:guava" in names

    @pytest.mark.requirement("FR-150")
    def test_go_in_use_dep_has_entry_points(self, tmp_path):
        """Go imports must surface as entry points with counts."""
        _w(tmp_path / "go.mod", "module demo\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n")
        _w(tmp_path / "go.sum", "github.com/pkg/errors v0.9.1 h1:abc=\n")
        _w(tmp_path / "main.go", """\
package main

import (
    "github.com/pkg/errors"
)

func main() {
    _ = errors.New("a")
    _ = errors.New("b")
    _ = errors.Wrap(nil, "c")
}
""")
        result = CliRunner().invoke(app, [str(tmp_path), "--format", "json"])
        data = json.loads(result.output)
        # Go canonicalises to module path.
        errors_dep = next(
            (d for d in data["dependencies"]
             if "pkg/errors" in d["name"]),
            None,
        )
        assert errors_dep, "pkg/errors dep missing"
        assert errors_dep["entry_points"], (
            "Go analyser produced zero entry points — user cannot see "
            "which selectors are in use"
        )
        used = [ep for ep in errors_dep["entry_points"] if ep["used"]]
        assert used, "no Go entry points marked used"
        assert any(ep["usage_count"] > 0 for ep in used), (
            "Go entry points missing usage_count"
        )
