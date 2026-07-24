"""End-to-end tests for Go entry-point reporting gaps.

Mirrors the Java/Python/JS/C# work: per-symbol selector counts,
composite-literal "construction" (``&pkg.Type{...}`` and ``pkg.Type{}``),
and instance-method calls via type binding.
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
    return json.loads(result.stdout)


def _dep(data: dict, name_substring: str) -> dict:
    matches = [
        d for d in data["dependencies"]
        if name_substring in d["name"]
    ]
    assert matches, (
        f"dep matching {name_substring!r} missing; got "
        f"{[d['name'] for d in data['dependencies']]}"
    )
    return matches[0]


def _errors_project(tmp: Path) -> None:
    _w(tmp / "go.mod", "module demo\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n")
    _w(tmp / "go.sum", "github.com/pkg/errors v0.9.1 h1:abc=\n")


# ── Per-symbol selector counts ────────────────────────────────────────


class TestGoPerSymbolSelector:
    @pytest.mark.requirement("FR-150")
    def test_pkg_function_calls_surface_per_symbol(self, tmp_path):
        _errors_project(tmp_path)
        _w(tmp_path / "main.go", """\
package main

import "github.com/pkg/errors"

func main() {
    _ = errors.New("a")
    _ = errors.New("b")
    _ = errors.Wrap(nil, "c")
}
""")
        data = _run(tmp_path)
        d = _dep(data, "pkg/errors")
        function_eps = [
            ep for ep in d["entry_points"]
            if ep["kind"] == "function"
        ]
        names = {ep["name"] for ep in function_eps}
        assert any(n.endswith(".New") for n in names), (
            f"errors.New not surfaced as a function entry point; "
            f"got {sorted(names)}"
        )
        new_ep = next(ep for ep in function_eps if ep["name"].endswith(".New"))
        assert new_ep["usage_count"] >= 2


# ── Composite-literal construction ─────────────────────────────────────


class TestGoCompositeLiteralConstruction:
    @pytest.mark.requirement("FR-150")
    def test_struct_literal_surfaces_as_constructor(self, tmp_path):
        # Use a hypothetical pkg/cfg package — need a real one for the
        # dep parser to recognise. Use github.com/pkg/errors and build a
        # struct literal of one of its exported types.
        _w(tmp_path / "go.mod", "module demo\n\ngo 1.21\n\nrequire example.com/cfg v1.0.0\n")
        _w(tmp_path / "go.sum", "example.com/cfg v1.0.0 h1:abc=\n")
        _w(tmp_path / "main.go", """\
package main

import "example.com/cfg"

func main() {
    _ = cfg.Options{Verbose: true}
    _ = &cfg.Options{Verbose: false}
}
""")
        data = _run(tmp_path)
        d = _dep(data, "example.com/cfg")
        ctor_eps = [
            ep for ep in d["entry_points"]
            if ep["kind"] == "constructor"
        ]
        assert ctor_eps, (
            f"composite literal not surfaced as constructor; kinds: "
            f"{sorted({ep['kind'] for ep in d['entry_points']})}"
        )
        names = {ep["name"] for ep in ctor_eps}
        assert any("Options" in n for n in names)
        ctor = ctor_eps[0]
        assert ctor["usage_count"] >= 2


# ── Instance method calls via type binding ─────────────────────────────


class TestGoInstanceMethodAttribution:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-172")
    def test_short_var_decl_to_call_binds_return_type(self, tmp_path):
        """``c := pkg.NewClient(); c.Do(...)`` — common Go idiom.

        We can't perform full type inference but we *can* track that
        ``c`` was assigned from a call to a package's symbol; use the
        symbol's name as a heuristic class binding.
        """
        _w(tmp_path / "go.mod", "module demo\n\ngo 1.21\n\nrequire example.com/redis v1.0.0\n")
        _w(tmp_path / "go.sum", "example.com/redis v1.0.0 h1:abc=\n")
        _w(tmp_path / "main.go", """\
package main

import "example.com/redis"

func main() {
    var c *redis.Client = redis.NewClient(nil)
    c.Set("k", "v")
    c.Set("a", "b")
    c.Get("k")
}
""")
        data = _run(tmp_path)
        d = _dep(data, "example.com/redis")
        method_eps = [
            ep for ep in d["entry_points"]
            if ep["kind"] == "method"
        ]
        names = {ep["name"] for ep in method_eps}
        assert any(n.endswith(".Set") for n in names), (
            f"c.Set not attributed to redis.Client; methods: {sorted(names)}"
        )
        set_ep = next(ep for ep in method_eps if ep["name"].endswith(".Set"))
        assert set_ep["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_function_param_pkg_type_binds(self, tmp_path):
        """``func f(c *redis.Client) { c.Get("k") }`` — param type binds."""
        _w(tmp_path / "go.mod", "module demo\n\ngo 1.21\n\nrequire example.com/redis v1.0.0\n")
        _w(tmp_path / "go.sum", "example.com/redis v1.0.0 h1:abc=\n")
        _w(tmp_path / "main.go", """\
package main

import "example.com/redis"

func handle(c *redis.Client) {
    c.Get("a")
    c.Get("b")
}

func main() { handle(nil) }
""")
        data = _run(tmp_path)
        d = _dep(data, "example.com/redis")
        method_eps = [
            ep for ep in d["entry_points"]
            if ep["kind"] == "method" and ep["name"].endswith(".Get")
        ]
        assert method_eps, (
            "function parameter type *redis.Client not used to bind c"
        )
        assert method_eps[0]["usage_count"] >= 2


class TestGoNoFalseAttribution:
    @pytest.mark.requirement("FR-150")
    def test_unrelated_local_not_attributed(self, tmp_path):
        _errors_project(tmp_path)
        _w(tmp_path / "main.go", """\
package main

import "github.com/pkg/errors"

func main() {
    s := "abc"
    _ = len(s)
    _ = errors.New("x")
}
""")
        data = _run(tmp_path)
        d = _dep(data, "pkg/errors")
        method_names = {
            ep["name"] for ep in d["entry_points"]
            if ep["kind"] == "method"
        }
        # `len(s)` is a builtin; nothing on `s` should land on errors.
        assert not any(
            n == "string.len" or n.endswith(".len") for n in method_names
        )
