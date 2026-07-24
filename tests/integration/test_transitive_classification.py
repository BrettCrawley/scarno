"""Regression tests for transitive-dep classification.

If a direct dep is IN_USE and a transitive sits beneath it in the
declared dep_graph, the transitive is IN_USE *indirectly* — it must
not show as UNCERTAIN or SAFE merely because no source file imports
it directly.

Status propagation (post-fix):
  * Any parent IN_USE         → transitive IN_USE
  * Only UNCERTAIN parents     → transitive UNCERTAIN
  * All parents SAFE OR none   → transitive SAFE (orphaned)
  * imported_directly=True     → IN_USE regardless of parents (REQ-17)
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
        f"dep {name} missing; got "
        f"{[d['name'] for d in data['dependencies']]}"
    )
    return matches[0]


class TestTransitiveOfInUseParent:
    @pytest.mark.requirement("FR-150")
    def test_transitive_of_in_use_direct_classifies_in_use(self, tmp_path):
        """alpha is directly imported and is IN_USE. beta is alpha's
        transitive in uv.lock and not imported in source. beta must
        classify as IN_USE (required by alpha), NOT UNCERTAIN/SAFE."""
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
dependencies = [{ name = "beta" }, { name = "gamma" }]

[[package]]
name = "beta"
version = "2"

[[package]]
name = "gamma"
version = "3"
""")
        _w(tmp_path / "main.py", "import alpha\n")
        data = _run(tmp_path)
        alpha = _dep(data, "alpha")
        beta = _dep(data, "beta")
        gamma = _dep(data, "gamma")
        assert alpha["status"] == "IN_USE"
        assert beta["status"] == "IN_USE", (
            f"beta should be IN_USE because alpha (its parent) is "
            f"IN_USE; got {beta['status']} (reason: {beta['reason']!r})"
        )
        assert gamma["status"] == "IN_USE"
        # The reason must name the direct dep that pulled it in.
        assert "alpha" in beta["reason"]
        assert "alpha" in gamma["reason"]

    @pytest.mark.requirement("FR-150")
    def test_chained_transitive_of_in_use_direct_classifies_in_use(
        self, tmp_path,
    ):
        """alpha → beta → gamma. alpha is IN_USE; both beta and gamma
        must be IN_USE (the chain is alive)."""
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
dependencies = [{ name = "gamma" }]

[[package]]
name = "gamma"
version = "3"
""")
        _w(tmp_path / "main.py", "import alpha\n")
        data = _run(tmp_path)
        for name in ("alpha", "beta", "gamma"):
            dep = _dep(data, name)
            assert dep["status"] == "IN_USE", (
                f"{name} should be IN_USE; got {dep['status']} "
                f"(reason: {dep['reason']!r})"
            )

    @pytest.mark.requirement("FR-150")
    def test_transitive_of_safe_direct_remains_safe(self, tmp_path):
        """No regression: a transitive whose only parent is SAFE
        (orphaned) must still classify as SAFE."""
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
        # Source has no imports → alpha SAFE → beta also SAFE.
        _w(tmp_path / "main.py", "")
        data = _run(tmp_path)
        alpha = _dep(data, "alpha")
        beta = _dep(data, "beta")
        assert alpha["status"] == "SAFE"
        assert beta["status"] == "SAFE", (
            "transitive of a SAFE-only parent must stay SAFE — orphaned"
        )

    @pytest.mark.requirement("FR-150")
    def test_transitive_with_mixed_parents_takes_strongest(self, tmp_path):
        """A transitive shared by an IN_USE parent AND a SAFE parent
        is IN_USE (the IN_USE parent dominates)."""
        _w(tmp_path / "pyproject.toml", (
            "[project]\n"
            'name = "demo"\n'
            'version = "0.0.0"\n'
            'dependencies = ["used", "unused"]\n'
        ))
        _w(tmp_path / "uv.lock", """\
version = 1
[[package]]
name = "demo"
version = "0"
source = { virtual = "." }
dependencies = [{ name = "used" }, { name = "unused" }]

[[package]]
name = "used"
version = "1"
dependencies = [{ name = "shared" }]

[[package]]
name = "unused"
version = "1"
dependencies = [{ name = "shared" }]

[[package]]
name = "shared"
version = "1"
""")
        _w(tmp_path / "main.py", "import used\n")
        data = _run(tmp_path)
        shared = _dep(data, "shared")
        assert shared["status"] == "IN_USE", (
            f"shared has one IN_USE parent — must be IN_USE; got "
            f"{shared['status']}"
        )

    @pytest.mark.requirement("FR-150")
    def test_transitive_of_uncertain_parent_only_is_uncertain(
        self, tmp_path,
    ):
        """When the only parent is UNCERTAIN (dynamic import,
        non-literal), the transitive stays UNCERTAIN — we can't claim
        it's in use, but we can't claim it's orphaned either."""
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
        # Dynamic import with non-literal — alpha classifies as UNCERTAIN.
        _w(tmp_path / "main.py",
           "import importlib\nname = 'alpha'\nimportlib.import_module(name)\n")
        data = _run(tmp_path)
        alpha = _dep(data, "alpha")
        beta = _dep(data, "beta")
        assert alpha["status"] == "UNCERTAIN"
        assert beta["status"] == "UNCERTAIN", (
            f"transitive of UNCERTAIN-only parent must stay UNCERTAIN; "
            f"got {beta['status']}"
        )
