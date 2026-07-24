"""End-to-end tests for C# entry-point reporting gaps.

Mirrors the Java/Python/JS work: constructor calls, static + instance
method calls, variable-type binding via ``var`` / explicit declaration
/ method parameters.
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
        f"dep {name} missing; got {[d['name'] for d in data['dependencies']]}"
    )
    return matches[0]


def _serilog_project(tmp: Path) -> None:
    _w(tmp / "App.csproj", """\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
""")


# ── Constructors ───────────────────────────────────────────────────────


class TestCsharpConstructors:
    @pytest.mark.requirement("FR-150")
    def test_object_creation_surfaces_as_constructor(self, tmp_path):
        _serilog_project(tmp_path)
        _w(tmp_path / "Program.cs", """\
using Serilog;
class P {
  void Run() {
    var cfg = new LoggerConfiguration();
    var cfg2 = new LoggerConfiguration();
  }
}
""")
        data = _run(tmp_path)
        s = _dep(data, "Serilog")
        ctor_eps = [
            ep for ep in s["entry_points"] if ep["kind"] == "constructor"
        ]
        assert ctor_eps, (
            f"no constructor entry points; kinds present: "
            f"{sorted({ep['kind'] for ep in s['entry_points']})}"
        )
        assert any(
            "LoggerConfiguration" in ep["name"] for ep in ctor_eps
        )
        assert ctor_eps[0]["usage_count"] >= 2


# ── Static method calls ────────────────────────────────────────────────


class TestCsharpStaticMethodCalls:
    @pytest.mark.requirement("FR-150")
    def test_static_method_call_surfaces_as_method(self, tmp_path):
        _serilog_project(tmp_path)
        # Log.Information is a static helper on Serilog.Log.
        _w(tmp_path / "Program.cs", """\
using Serilog;
class P {
  void Run() {
    Log.Information("hello");
    Log.Information("there");
    Log.Warning("careful");
  }
}
""")
        data = _run(tmp_path)
        s = _dep(data, "Serilog")
        method_eps = [
            ep for ep in s["entry_points"] if ep["kind"] == "method"
        ]
        names = {ep["name"] for ep in method_eps}
        assert any("Log.Information" in n for n in names), (
            f"Log.Information not surfaced; methods: {sorted(names)}"
        )
        info = next(ep for ep in method_eps if ep["name"].endswith(".Information"))
        assert info["usage_count"] >= 2


# ── Instance method calls via type binding ─────────────────────────────


class TestCsharpInstanceMethodAttribution:
    @pytest.mark.requirement("FR-150")
    def test_explicit_typed_local_binds(self, tmp_path):
        _serilog_project(tmp_path)
        _w(tmp_path / "Program.cs", """\
using Serilog;
class P {
  void Run() {
    LoggerConfiguration cfg = new LoggerConfiguration();
    var l = cfg.CreateLogger();
    cfg.WriteTo.Console();
  }
}
""")
        data = _run(tmp_path)
        s = _dep(data, "Serilog")
        method_eps = [
            ep for ep in s["entry_points"] if ep["kind"] == "method"
        ]
        names = {ep["name"] for ep in method_eps}
        assert any(n.endswith(".CreateLogger") for n in names), (
            f"cfg.CreateLogger not attributed to LoggerConfiguration; "
            f"methods: {sorted(names)}"
        )

    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-171")
    def test_var_assignment_to_new_binds(self, tmp_path):
        """`var cfg = new LoggerConfiguration(); cfg.CreateLogger();`."""
        _serilog_project(tmp_path)
        _w(tmp_path / "Program.cs", """\
using Serilog;
class P {
  void Run() {
    var cfg = new LoggerConfiguration();
    var l1 = cfg.CreateLogger();
    var l2 = cfg.CreateLogger();
  }
}
""")
        data = _run(tmp_path)
        s = _dep(data, "Serilog")
        method_eps = [
            ep for ep in s["entry_points"] if ep["kind"] == "method"
        ]
        cl = next(
            (ep for ep in method_eps if ep["name"].endswith(".CreateLogger")),
            None,
        )
        assert cl is not None, (
            f"var-binding lost; methods: {[ep['name'] for ep in method_eps]}"
        )
        assert cl["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_method_parameter_type_binds(self, tmp_path):
        """`void Use(LoggerConfiguration cfg) { cfg.CreateLogger(); }`."""
        _serilog_project(tmp_path)
        _w(tmp_path / "Program.cs", """\
using Serilog;
class P {
  void Use(LoggerConfiguration cfg) {
    cfg.CreateLogger();
    cfg.CreateLogger();
  }
}
""")
        data = _run(tmp_path)
        s = _dep(data, "Serilog")
        method_eps = [
            ep for ep in s["entry_points"] if ep["kind"] == "method"
            and ep["name"].endswith(".CreateLogger")
        ]
        assert method_eps, (
            "method parameter type not used to bind cfg → LoggerConfiguration"
        )
        assert method_eps[0]["usage_count"] >= 2


class TestCsharpNoFalseAttribution:
    @pytest.mark.requirement("FR-150")
    def test_local_var_with_unrelated_type_not_attributed(self, tmp_path):
        _serilog_project(tmp_path)
        _w(tmp_path / "Program.cs", """\
using Serilog;
class P {
  void Run() {
    string s = "hi";
    int n = s.Length;
  }
}
""")
        data = _run(tmp_path)
        s_dep = _dep(data, "Serilog")
        method_names = {
            ep["name"] for ep in s_dep["entry_points"]
            if ep["kind"] == "method"
        }
        # `s.Length` must NOT be attributed to Serilog.
        assert not any(
            n.endswith(".Length") for n in method_names
        ), f"s.Length got falsely attributed to Serilog; methods: {method_names}"
