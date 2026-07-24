"""End-to-end tests for the JavaScript reporting gaps that mirror the
Java/Python work: per-symbol attribution, constructors, static and
instance method calls.

Each test sets up a tiny project with `package.json` declaring a dep,
plus `node_modules/<pkg>/package.json` with an `exports` field so the
existing FR-110 entry-point resolver has data. Tests assert on the
rendered JSON.
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
    assert matches, (
        f"dep {name} missing from output; got "
        f"{[d['name'] for d in data['dependencies']]}"
    )
    return matches[0]


def _project(tmp: Path) -> None:
    _w(tmp / "package.json", json.dumps({
        "name": "demo",
        "version": "1.0.0",
        "dependencies": {"lodash": "^4", "redis": "^4"},
    }))


# ── Named-import per-symbol tracking ────────────────────────────────────


class TestNamedImports:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-169")
    def test_named_import_function_call_surfaces_with_count(self, tmp_path):
        """`import { debounce } from "lodash"; debounce(fn); debounce(fn);`
        must produce a per-symbol entry point with usage_count >= 2.
        """
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import { debounce, throttle } from "lodash";
const a = debounce(() => {});
const b = debounce(() => {});
const c = throttle(() => {});
""")
        data = _run(tmp_path)
        lodash = _dep(data, "lodash")
        names = {ep["name"]: ep for ep in lodash["entry_points"]}
        # Per-symbol entries must exist.
        debounce = next(
            (ep for ep in lodash["entry_points"]
             if ep["name"].endswith(".debounce")
             or ep["name"] == "debounce"),
            None,
        )
        assert debounce is not None, (
            f"debounce not surfaced as a per-symbol entry point; "
            f"names: {sorted(names.keys())}"
        )
        assert debounce["used"] is True
        assert debounce["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_default_import_call_count(self, tmp_path):
        """`import lodash from "lodash"; lodash.foo(); lodash.foo();`
        attributes the calls back to lodash.
        """
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import lodash from "lodash";
lodash.chunk([1,2,3], 2);
lodash.chunk([4,5,6], 2);
""")
        data = _run(tmp_path)
        lodash = _dep(data, "lodash")
        # Either via a `chunk` symbol-level entry (preferred) or via the
        # default-import entry point with usage > 1.
        entry_chunk = next(
            (ep for ep in lodash["entry_points"]
             if ep["name"].endswith(".chunk")),
            None,
        )
        assert entry_chunk is not None, (
            f"static method `lodash.chunk` not surfaced; got "
            f"{[ep['name'] for ep in lodash['entry_points']]}"
        )
        assert entry_chunk["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_namespace_import_call_count(self, tmp_path):
        """`import * as _ from "lodash"; _.debounce(...);` must attribute."""
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import * as _ from "lodash";
_.debounce(() => {});
_.debounce(() => {});
_.throttle(() => {});
""")
        data = _run(tmp_path)
        lodash = _dep(data, "lodash")
        debounce = next(
            (ep for ep in lodash["entry_points"]
             if ep["name"].endswith(".debounce")),
            None,
        )
        assert debounce is not None, (
            f"namespace import call `_.debounce` not attributed to lodash; "
            f"entries: {[ep['name'] for ep in lodash['entry_points']]}"
        )
        assert debounce["usage_count"] >= 2


# ── Constructor calls ──────────────────────────────────────────────────


class TestConstructorCalls:
    @pytest.mark.requirement("FR-150")
    def test_new_expression_surfaces_as_constructor(self, tmp_path):
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import { Redis } from "redis";
const a = new Redis({ host: "x" });
const b = new Redis({ host: "y" });
""")
        data = _run(tmp_path)
        redis = _dep(data, "redis")
        ctors = [
            ep for ep in redis["entry_points"]
            if ep["kind"] == "constructor"
        ]
        assert ctors, (
            f"no constructor entries for redis; kinds present: "
            f"{sorted({ep['kind'] for ep in redis['entry_points']})}"
        )
        assert any("Redis" in ep["name"] for ep in ctors)
        assert ctors[0]["usage_count"] >= 1


# ── Instance method calls via type binding ─────────────────────────────


class TestInstanceMethodAttribution:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-170")
    def test_const_assignment_to_new_binds_type(self, tmp_path):
        """`const c = new Redis(); c.set("k", "v")` must attribute
        `c.set` to `Redis.set`.
        """
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import { Redis } from "redis";
const c = new Redis({ host: "x" });
c.set("k1", "v1");
c.set("k2", "v2");
c.get("k1");
""")
        data = _run(tmp_path)
        redis = _dep(data, "redis")
        method_eps = [
            ep for ep in redis["entry_points"]
            if ep["kind"] == "method"
        ]
        assert method_eps, (
            f"no method entries for redis; got "
            f"{[(ep['kind'], ep['name']) for ep in redis['entry_points']]}"
        )
        method_names = {ep["name"] for ep in method_eps}
        assert any(n.endswith(".set") for n in method_names), (
            f"c.set not attributed to Redis; got methods: {sorted(method_names)}"
        )
        set_ep = next(ep for ep in method_eps if ep["name"].endswith(".set"))
        assert set_ep["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_typescript_type_annotation_binds(self, tmp_path):
        """TS `const c: Redis = …; c.set(…)` — annotation alone is the binding."""
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import { Redis } from "redis";
function make(): Redis { return null as any; }
const c: Redis = make();
c.set("k", "v");
c.set("a", "b");
""")
        data = _run(tmp_path)
        redis = _dep(data, "redis")
        method_eps = [
            ep for ep in redis["entry_points"]
            if ep["kind"] == "method" and ep["name"].endswith(".set")
        ]
        assert method_eps, (
            "TS type annotation not used to bind c -> Redis"
        )

    @pytest.mark.requirement("FR-150")
    def test_function_param_type_binds(self, tmp_path):
        """`function f(c: Redis) { c.get("k"); }` — param type binds."""
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import { Redis } from "redis";
function f(c: Redis): void {
  c.get("a");
  c.get("b");
}
""")
        data = _run(tmp_path)
        redis = _dep(data, "redis")
        method_eps = [
            ep for ep in redis["entry_points"]
            if ep["kind"] == "method" and ep["name"].endswith(".get")
        ]
        assert method_eps, (
            "TS function-parameter annotation not used to bind type"
        )
        assert method_eps[0]["usage_count"] >= 2


class TestNoFalseAttribution:
    @pytest.mark.requirement("FR-150")
    def test_unrelated_local_variable_not_attributed(self, tmp_path):
        """`const r = openFile(); r.read();` — `r` isn't bound to any
        imported type. `r.read` must not surface as a method on any dep.
        """
        _project(tmp_path)
        _w(tmp_path / "src" / "index.ts", """\
import { Redis } from "redis";
function f() {
  const r = (Math.random() > 0.5) ? "a" : "b";
  return r.length;
}
""")
        data = _run(tmp_path)
        redis = _dep(data, "redis")
        method_names = {
            ep["name"] for ep in redis["entry_points"]
            if ep["kind"] == "method"
        }
        # r.length must NOT be attributed to redis.
        assert not any(
            n.endswith(".length") for n in method_names
        ), f"r.length got attributed to redis; methods: {method_names}"
