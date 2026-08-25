"""One-pass simple-name reference counting (REQ-17 / FR-150).

The analysers used to run one full-file ``re.findall`` per import, which
is quadratic in file size (CWE-1333). The single-pass tally that replaced
it must produce *identical* counts — these tests pin that equivalence
against the original per-name regex, which is spelled out here as the
reference implementation.
"""
from __future__ import annotations

import random
import re

import pytest

from scarno.analysers.name_counts import (
    MAX_FULL_SCANS,
    count_boundary_refs,
    count_selector_refs,
)


# ── reference implementations — the pre-fix per-name scans ─────────────────


def _ref_boundary(source: str, name: str) -> int:
    return len(re.findall(rf"\b{re.escape(name)}\b", source))


def _ref_selector(source: str, name: str) -> int:
    return len(re.findall(rf"\b{re.escape(name)}\.", source))


REAL_WORLD_JAVA = """
package com.example.app;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.StringUtils;

/** Splitter is mentioned in this Javadoc, and "Splitter" in a literal. */
public class Service {
    private final Splitter splitter = Splitter.on(',');

    public ImmutableList<String> parse(String raw) {
        if (StringUtils.isBlank(raw)) {
            return ImmutableList.of();
        }
        return ImmutableList.copyOf(splitter.split(raw));
    }
}
"""

REAL_WORLD_GO = """
package main

import (
    "fmt"
    "github.com/pkg/errors"
    "golang.org/x/sync/errgroup"
)

func main() {
    var g errgroup.Group
    g.Go(func() error { return errors.New("boom") })
    fmt.Println(g.Wait(), errors.Is(nil, nil))
}
"""

TRICKY_SOURCES = [
    "",
    "Foo",
    "Foo Foo Foo",
    "FooBar Foo_Bar Foo.Bar Foo$Bar Foo9",
    "xFoo Foox _Foo Foo_ (Foo) [Foo] {Foo};Foo,Foo\nFoo\tFoo",
    "Foo.Foo.Foo..Foo.",
    "$Foo$ $$Foo$$ a$Foo$b",
    "@Foo @@Foo x@Foo x@Foo.",
    "Fooé éFoo Fooé Fooﬀ",          # unicode word chars neighbour the name
    "漢Foo Foo漢 Foo 漢",
    "Foo" * 50,
    "Foo " * 50,
    REAL_WORLD_JAVA,
    REAL_WORLD_GO,
]

TRICKY_NAMES = [
    "Foo", "foo", "Foo_Bar", "FooBar", "_Foo", "Foo9", "a", "é", "漢",
    "Foo$Bar", "$Foo", "Foo$", "$", "@Foo", "errors", "errgroup", "fmt",
    "Splitter", "ImmutableList", "StringUtils",
]

# Alphabets that mix word characters, the non-word characters the
# analysers' identifier grammars allow ($ / @), separators, and
# non-ASCII word characters (Python's \b is Unicode-aware).
FUZZ_ALPHABETS = [
    "abAB_09",
    "abAB_09$@.;\n \t",
    "Foo Bar Baz_1 $ . ; @ \n",
    "aA_ éüΩ漢",
    "aA_.$@#()[]{}<>*+?|\\^- ",
]


class TestCountEquivalence:
    """The tally must agree with the per-name regex, character for
    character — the counts drive every reported usage number."""

    @pytest.mark.requirement("FR-150")
    @pytest.mark.parametrize("source", TRICKY_SOURCES)
    def test_boundary_counts_match_per_name_findall(self, source):
        counts, uncounted = count_boundary_refs(source, TRICKY_NAMES)
        assert not uncounted
        for name in TRICKY_NAMES:
            assert counts[name] == _ref_boundary(source, name), name

    @pytest.mark.requirement("FR-150")
    @pytest.mark.parametrize("source", TRICKY_SOURCES)
    def test_selector_counts_match_per_name_findall(self, source):
        counts, uncounted = count_selector_refs(source, TRICKY_NAMES)
        assert not uncounted
        for name in TRICKY_NAMES:
            assert counts[name] == _ref_selector(source, name), name

    @pytest.mark.requirement("FR-150")
    def test_randomised_sources_match_per_name_findall(self):
        """Differential fuzz — 3,000 random source/name combinations."""
        rng = random.Random(20260807)
        for _ in range(3000):
            alphabet = rng.choice(FUZZ_ALPHABETS)
            source = "".join(
                rng.choice(alphabet) for _ in range(rng.randint(0, 300))
            )
            names = rng.sample(TRICKY_NAMES, rng.randint(1, 8))
            counts, _ = count_boundary_refs(source, names)
            for name, got in counts.items():
                assert got == _ref_boundary(source, name), (name, source)
            counts, _ = count_selector_refs(source, names)
            for name, got in counts.items():
                assert got == _ref_selector(source, name), (name, source)

    @pytest.mark.requirement("FR-150")
    def test_duplicate_names_counted_once_each(self):
        counts, _ = count_boundary_refs("Foo Foo Bar", ["Foo", "Foo", "Bar"])
        assert counts == {"Foo": 2, "Bar": 1}


class TestFullScanCap:
    """Names holding a non-word character keep the per-name scan, so
    that fallback is capped — and the cap is reported, never silent."""

    @pytest.mark.requirement("FR-150")
    def test_names_within_cap_are_counted_exactly(self):
        names = [f"A{i}$B" for i in range(MAX_FULL_SCANS)]
        source = " ".join(names) + " " + names[0]
        counts, uncounted = count_boundary_refs(source, names)
        assert uncounted == []
        for name in names:
            assert counts[name] == _ref_boundary(source, name)

    @pytest.mark.requirement("FR-150")
    def test_names_beyond_cap_are_returned_not_dropped(self):
        names = [f"A{i:04d}$B" for i in range(MAX_FULL_SCANS + 5)]
        source = " ".join(names)
        counts, uncounted = count_boundary_refs(source, names)
        assert len(uncounted) == 5
        assert set(uncounted).isdisjoint(counts)
        # Deterministic across runs even though callers iterate sets.
        assert uncounted == sorted(names)[MAX_FULL_SCANS:]

    @pytest.mark.requirement("FR-150")
    def test_word_only_names_are_never_capped(self):
        names = [f"N{i}" for i in range(MAX_FULL_SCANS * 4)]
        source = " ".join(names)
        counts, uncounted = count_boundary_refs(source, names)
        assert uncounted == []
        assert all(counts[n] == 1 for n in names)


# ── call-site equivalence — the analysers' own pre-fix loops ───────────────


def _old_java_counts(source: str, imports: set[str]) -> dict[str, int]:
    """The pre-fix loop from ``_populate_import_counts``, verbatim."""
    out: dict[str, int] = {}
    for fqcn in imports:
        simple = fqcn.rsplit(".", 1)[-1]
        if not re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", simple):
            out[fqcn] = out.get(fqcn, 0) + 1
            continue
        n = len(re.findall(rf"\b{re.escape(simple)}\b", source))
        out[fqcn] = out.get(fqcn, 0) + max(n, 1)
    return out


def _old_go_counts(text: str, imports: set[str]) -> dict[str, int]:
    """The pre-fix loop from the Go analyser's ``_scan_file``, verbatim."""
    out: dict[str, int] = {}
    for imp in imports:
        last = imp.rsplit("/", 1)[-1]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", last):
            n = len(re.findall(rf"\b{re.escape(last)}\.", text))
        else:
            n = 0
        out[imp] = out.get(imp, 0) + max(n, 1)
    return out


def _old_csharp_counts(text: str, namespaces: set[str]) -> dict[str, int]:
    """The pre-fix loop from the C# analyser's ``_scan_cs_file``, verbatim."""
    out: dict[str, int] = {}
    for ns in namespaces:
        simple = ns.rsplit(".", 1)[-1]
        if re.match(r"^[A-Za-z_@][A-Za-z0-9_]*$", simple):
            n = len(re.findall(rf"\b{re.escape(simple)}\b", text))
            out[ns] = out.get(ns, 0) + max(n, 1)
        else:
            out[ns] = out.get(ns, 0) + 1
    return out


REAL_WORLD_KOTLIN = """
package com.example

import com.squareup.moshi.Moshi
import okhttp3.OkHttpClient
import org.slf4j.LoggerFactory

class Client(private val http: OkHttpClient = OkHttpClient()) {
    private val log = LoggerFactory.getLogger(Client::class.java)
    private val moshi = Moshi.Builder().build()
    fun go() = log.info("{}", moshi.adapter(String::class.java))
}
"""

REAL_WORLD_CSHARP = """
using System;
using System.Collections.Generic;
using Serilog;
using Newtonsoft.Json;

namespace App {
    public class Program {
        public static void Main() {
            Log.Information("start");
            var list = new List<string>();
            Console.WriteLine(JsonConvert.SerializeObject(list));
        }
    }
}
"""


class TestCallSiteEquivalence:
    """Each analyser call site must report exactly what its pre-fix loop
    reported — the counts decide which dependencies look used."""

    @pytest.mark.requirement("FR-150")
    @pytest.mark.parametrize("source", [REAL_WORLD_JAVA, "class A {}"])
    def test_java_extractor_matches_old_loop(self, source):
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_java

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter grammars unavailable")
        facts = extract_java(source)
        assert facts.import_counts == _old_java_counts(source, facts.imports)

    @pytest.mark.requirement("FR-150")
    def test_kotlin_extractor_matches_old_loop(self):
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_kotlin

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter grammars unavailable")
        facts = extract_kotlin(REAL_WORLD_KOTLIN)
        assert facts.imports
        assert facts.import_counts == _old_java_counts(
            REAL_WORLD_KOTLIN, facts.imports
        )

    @pytest.mark.requirement("FR-150")
    def test_java_regex_fallback_matches_old_loop(self):
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        analyser = JvmSourceAnalyser()
        errors: list[str] = []
        # Force the non-AST branch by asking for an unknown language.
        facts = analyser._extract_facts(REAL_WORLD_JAVA, "unknown", errors)
        assert facts.imports
        assert facts.import_counts == _old_java_counts(
            REAL_WORLD_JAVA, facts.imports
        )
        assert errors == []

    @pytest.mark.requirement("FR-150")
    def test_go_scan_matches_old_loop(self):
        from scarno.analysers.go import source_analyser as go_sa

        if not go_sa.GO_AST_AVAILABLE:
            pytest.skip("tree-sitter-go unavailable")
        facts = go_sa._Facts()
        errors: list[str] = []
        go_sa._scan_file(
            REAL_WORLD_GO.encode("utf-8"), facts, errors, "main.go", ("main.go",)
        )
        assert facts.imports
        assert facts.import_counts == _old_go_counts(REAL_WORLD_GO, facts.imports)
        assert errors == []

    @pytest.mark.requirement("FR-150")
    def test_csharp_scan_matches_old_loop(self, tmp_path):
        from scarno.analysers.csharp import source_analyser as cs_sa

        if not cs_sa.CSHARP_AST_AVAILABLE:
            pytest.skip("tree-sitter-c-sharp unavailable")
        path = tmp_path / "Program.cs"
        path.write_text(REAL_WORLD_CSHARP)
        facts = cs_sa._Facts()
        errors: list[str] = []
        cs_sa._scan_cs_file(path, tmp_path, facts, errors)
        assert facts.namespaces
        assert facts.namespace_counts == _old_csharp_counts(
            REAL_WORLD_CSHARP, facts.namespaces
        )
        assert errors == []

    @pytest.mark.requirement("FR-150")
    def test_scan_cap_is_reported_not_silent(self):
        """Past the cap the count falls back to the bare import, and the
        shortfall reaches the caller's error channel."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_java

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter grammars unavailable")
        n = MAX_FULL_SCANS + 10
        source = (
            "".join(f"import p{i}.C{i}$D;\n" for i in range(n))
            + "public class Big { }\n"
        )
        errors: list[str] = []
        facts = extract_java(source, "Big.java", errors)
        assert len(facts.imports) == n
        # Every import still counts as used at least once.
        assert all(v >= 1 for v in facts.import_counts.values())
        assert len(errors) == 1
        assert "capped" in errors[0]
        assert "Big.java" in errors[0]
        assert str(n - MAX_FULL_SCANS) in errors[0]

    @pytest.mark.requirement("FR-150")
    def test_csharp_scan_cap_is_reported_not_silent(self, tmp_path):
        """C# verbatim identifiers (``@a0``) are the non-word case there."""
        from scarno.analysers.csharp import source_analyser as cs_sa

        if not cs_sa.CSHARP_AST_AVAILABLE:
            pytest.skip("tree-sitter-c-sharp unavailable")
        n = MAX_FULL_SCANS + 6
        source = (
            "".join(f"using N{i}.@a{i};\n" for i in range(n))
            + "class P { static void Main() {} }\n"
        )
        path = tmp_path / "P.cs"
        path.write_text(source)
        facts = cs_sa._Facts()
        errors: list[str] = []
        cs_sa._scan_cs_file(path, tmp_path, facts, errors)
        assert len(facts.namespaces) == n
        assert all(v >= 1 for v in facts.namespace_counts.values())
        assert len(errors) == 1
        assert "capped" in errors[0]
        assert "P.cs" in errors[0]
        assert str(n - MAX_FULL_SCANS) in errors[0]


# ── Cap-reached reporting on the analyser call sites ───────────────────────


class TestCapShortfallIsReported:
    """``count_boundary_refs`` returns over-cap names instead of dropping
    them so the caller can record the shortfall. The C# call site is
    exercised elsewhere; these pin the JVM ones, and the Go invariant
    that makes its own shortfall branch unreachable.
    """

    @staticmethod
    def _dollar_heavy_java() -> str:
        """A source file whose imports all end in ``$``-bearing simple
        names. ``$`` is not a word character, so every one of them needs
        its own scan and the per-file cap is passed."""
        imports = "\n".join(
            f"import com.example.Outer{i:04d}$Inner;"
            for i in range(MAX_FULL_SCANS + 5)
        )
        return f"package demo;\n{imports}\n\npublic class Demo {{}}\n"

    @pytest.mark.requirement("FR-150")
    def test_java_regex_fallback_reports_cap_shortfall(self):
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        analyser = JvmSourceAnalyser()
        errors: list[str] = []
        # "unknown" forces the regex-fallback branch.
        facts = analyser._extract_facts(
            self._dollar_heavy_java(), "unknown", errors,
        )

        assert len(facts.imports) == MAX_FULL_SCANS + 5
        assert any("reference counting capped at" in e for e in errors), errors
        # Nothing is silently dropped: every import still has a count.
        assert len(facts.import_counts) == MAX_FULL_SCANS + 5
        assert all(n >= 1 for n in facts.import_counts.values())

    @pytest.mark.requirement("FR-150")
    def test_java_ast_path_reports_cap_shortfall(self):
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter grammars unavailable")
        errors: list[str] = []
        facts = extract_java(self._dollar_heavy_java(), errors=errors)

        assert facts.imports
        assert any("reference counting capped at" in e for e in errors), errors
        assert all(n >= 1 for n in facts.import_counts.values())

    @pytest.mark.requirement("FR-150")
    def test_go_names_can_never_reach_the_cap(self):
        """The Go call site filters names through ``_GO_PKG_NAME_RE``
        (``^[A-Za-z_][A-Za-z0-9_]*$``), and every character that admits
        is a word character — so a Go package name can never take the
        per-name fallback and the shortfall branch there is unreachable
        by construction. Pinned as an invariant: widening that regex to
        admit a non-word character would make the branch live, and this
        test is what says so.
        """
        from scarno.analysers.go.source_analyser import _GO_PKG_NAME_RE

        candidates = [
            "errors", "fmt", "x_1", "_a", "A0",
            "pkg$x", "pkg-x", "pkg.x", "@pkg", "üni",
        ]
        admitted = [n for n in candidates if _GO_PKG_NAME_RE.match(n)]
        assert admitted, "regex must still admit ordinary package names"
        assert all(re.fullmatch(r"\w+", n) for n in admitted), admitted

        _, uncounted = count_selector_refs(
            "errors.New()", [f"pkg{i}" for i in range(MAX_FULL_SCANS * 4)],
        )
        assert uncounted == []
