"""End-to-end tests for the Python reporting gaps that mirror the
Java work: wildcards, instance-method calls via type binding, and
annotated-assignment type binding.

Each test sets up a tiny project with a real PyPI package the test
environment is guaranteed to have installed (``pytest`` itself, since
Scarno is uv-managed) so entry-point enumeration via
``importlib`` can succeed. Tests assert on the rendered JSON.
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


def _dep(data: dict, name: str) -> dict:
    matches = [d for d in data["dependencies"] if d["name"] == name]
    assert matches, (
        f"dep {name} missing from output; got "
        f"{[d['name'] for d in data['dependencies']]}"
    )
    return matches[0]


def _ep_named(dep: dict, suffix: str) -> dict | None:
    for ep in dep["entry_points"]:
        if ep["name"] == suffix or ep["name"].endswith("." + suffix):
            return ep
    return None


def _project_with_pytest(tmp: Path) -> None:
    _w(tmp / "pyproject.toml", (
        "[project]\n"
        'name = "demo"\n'
        'version = "0.0.0"\n'
        'dependencies = ["pytest"]\n'
    ))


# ── Wildcards ──────────────────────────────────────────────────────────


class TestPythonWildcardImports:
    @pytest.mark.requirement("FR-150")
    def test_wildcard_import_surfaces_as_distinct_entry_point_kind(
        self, tmp_path
    ):
        """`from pytest import *` produces kind=wildcard entry point."""
        _project_with_pytest(tmp_path)
        _w(tmp_path / "main.py", "from pytest import *\nfail('x')\n")
        data = _run(tmp_path)
        py = _dep(data, "pytest")
        kinds = {ep["kind"] for ep in py["entry_points"] if ep["used"]}
        assert "wildcard" in kinds, (
            f"wildcard import not labeled distinctly; used kinds: {kinds}"
        )

    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-167")
    def test_wildcard_import_attributes_unqualified_calls(self, tmp_path):
        """`from pytest import *; fail(...)` attributes `fail` back to pytest."""
        _project_with_pytest(tmp_path)
        _w(tmp_path / "main.py", (
            "from pytest import *\n"
            "fail('a')\n"
            "fail('b')\n"
            "skip('s')\n"
        ))
        data = _run(tmp_path)
        py = _dep(data, "pytest")
        ep_by_name = {ep["name"]: ep for ep in py["entry_points"]}
        assert "pytest.fail" in ep_by_name, (
            "pytest.fail not surfaced even though source uses it via wildcard"
        )
        # Either `used` directly OR usage_count > 0 — implementation choice.
        assert ep_by_name["pytest.fail"]["used"] is True
        assert ep_by_name["pytest.fail"]["usage_count"] >= 2


# ── Instance method calls via type binding ─────────────────────────────


class TestPythonInstanceMethodAttribution:
    @pytest.mark.requirement("FR-150")
    @pytest.mark.requirement("FR-168")
    def test_assignment_to_constructor_binds_type(self, tmp_path):
        """`s = Session(); s.get(url); s.get(url)` — `s.get` ↔ `Session.get`.

        Python doesn't have explicit type declarations on locals, so we
        bind via the value's call expression. This is the common
        idiom: assign the constructor result to a variable, then call
        methods on it.
        """
        # Use pytest.Config because it's in pytest's __all__ and is a class
        # we know is installed in the test env. ``Config(...)`` won't
        # actually run (we never execute the source), so the args are
        # arbitrary.
        _project_with_pytest(tmp_path)
        _w(tmp_path / "main.py", (
            "from pytest import Config\n"
            "def f(args):\n"
            "    cfg = Config(args)\n"
            "    cfg.getoption('x')\n"
            "    cfg.getoption('y')\n"
            "    return cfg\n"
        ))
        data = _run(tmp_path)
        py = _dep(data, "pytest")
        # Either a Config.getoption row OR pytest.Config usage_count > the
        # bare-import count (because each `cfg.getoption` should attribute
        # back to the binding type at minimum).
        method_eps = [
            ep for ep in py["entry_points"]
            if ep["kind"] == "method" and ".getoption" in ep["name"]
        ]
        assert method_eps, (
            f"cfg.getoption not attributed to Config; "
            f"methods seen: {[ep['name'] for ep in py['entry_points'] if ep['kind']=='method']}"
        )
        assert method_eps[0]["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_annotated_assignment_binds_type(self, tmp_path):
        """`cfg: Config = …; cfg.getoption(…)` — annotation is the binding."""
        _project_with_pytest(tmp_path)
        _w(tmp_path / "main.py", (
            "from pytest import Config\n"
            "def f(args):\n"
            "    cfg: Config = Config(args)\n"
            "    cfg.getoption('x')\n"
            "    return cfg\n"
        ))
        data = _run(tmp_path)
        py = _dep(data, "pytest")
        method_eps = [
            ep for ep in py["entry_points"]
            if ep["kind"] == "method" and ".getoption" in ep["name"]
        ]
        assert method_eps, (
            "annotated-assign type binding lost; cfg.getoption not "
            "attributed to Config"
        )

    @pytest.mark.requirement("FR-150")
    def test_function_parameter_annotation_binds_type(self, tmp_path):
        """`def f(cfg: Config): cfg.getoption(...)` — param annotation binds."""
        _project_with_pytest(tmp_path)
        _w(tmp_path / "main.py", (
            "from pytest import Config\n"
            "def f(cfg: Config) -> None:\n"
            "    cfg.getoption('x')\n"
            "    cfg.getoption('y')\n"
        ))
        data = _run(tmp_path)
        py = _dep(data, "pytest")
        method_eps = [
            ep for ep in py["entry_points"]
            if ep["kind"] == "method" and ".getoption" in ep["name"]
        ]
        assert method_eps, (
            "function-parameter annotation not used to bind type for "
            "instance-call attribution"
        )
        assert method_eps[0]["usage_count"] >= 2

    @pytest.mark.requirement("FR-150")
    def test_local_variable_does_not_steal_unrelated_attribute(
        self, tmp_path
    ):
        """A local var `r` not bound to any imported type must NOT attribute
        `r.read()` to anything — no false-positive method entries."""
        _project_with_pytest(tmp_path)
        _w(tmp_path / "main.py", (
            "import pytest\n"
            "def f():\n"
            "    r = open('/tmp/x')\n"
            "    return r.read()\n"
        ))
        data = _run(tmp_path)
        py = _dep(data, "pytest")
        # No method entry pointing at .read should be on pytest.
        method_names = {
            ep["name"] for ep in py["entry_points"] if ep["kind"] == "method"
        }
        assert not any(
            n.endswith(".read") for n in method_names
        ), (
            f"unrelated `r.read()` got attributed to pytest; "
            f"methods: {method_names}"
        )
