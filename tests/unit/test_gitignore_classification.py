"""FR-278: how dependency classification treats gitignored files.

The default (``uncertain``) exists because the commonest gitignored code
that really uses a dependency is generated: protobuf ``_pb2.py`` stubs,
OpenAPI clients. Ignoring it tells the user to remove the dependency, and
the build breaks. Counting it fully lets a dirty local tree mask a real
removal. So a dependency whose only usage is in gitignored files is
UNCERTAIN, with a reason that says why.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.analysers.python.source_analyser import GITIGNORED_ONLY_REASON


def _project(root: Path, *, tracked_uses_genlib: bool = False) -> Path:
    (root / "requirements.txt").write_text("requests\ngenlib\n", encoding="utf-8")
    app = "import requests\n" + ("import genlib\n" if tracked_uses_genlib else "")
    (root / "app.py").write_text(app, encoding="utf-8")
    gen = root / "gen"
    gen.mkdir()
    (gen / "service_pb2.py").write_text("import genlib\n", encoding="utf-8")
    (root / ".gitignore").write_text("gen/\n", encoding="utf-8")
    return root


def _deps(runner, root: Path, *argv: str) -> dict[str, dict]:
    from scarno.cli import app

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code in (0, 1), result.output
    return {d["name"]: d for d in json.loads(result.output)["dependencies"]}


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("argv", "status"),
    [
        ([], "UNCERTAIN"),
        (["--gitignore", "uncertain"], "UNCERTAIN"),
        (["--gitignore", "include"], "IN_USE"),
        (["--no-gitignore"], "IN_USE"),
        (["--gitignore", "exclude"], "SAFE"),
    ],
)
def test_dep_used_only_in_gitignored_code_follows_the_mode(
    runner, tmp_path: Path, argv: list[str], status: str
) -> None:
    deps = _deps(runner, _project(tmp_path), *argv)
    assert deps["genlib"]["status"] == status
    assert deps["requests"]["status"] == "IN_USE"


@pytest.mark.requirement("FR-278")
@pytest.mark.requirement("PRV-008")
def test_uncertain_reason_is_fixed_and_names_no_file(
    runner, tmp_path: Path
) -> None:
    deps = _deps(runner, _project(tmp_path))
    assert deps["genlib"]["reason"] == GITIGNORED_ONLY_REASON
    assert "service_pb2" not in GITIGNORED_ONLY_REASON
    assert "gen/" not in GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", ["uncertain", "include", "exclude"])
def test_tracked_usage_wins_in_every_mode(
    runner, tmp_path: Path, mode: str
) -> None:
    root = _project(tmp_path, tracked_uses_genlib=True)
    deps = _deps(runner, root, "--gitignore", mode)
    assert deps["genlib"]["status"] == "IN_USE"


@pytest.mark.requirement("FR-278")
def test_unused_dep_stays_safe_by_default(runner, tmp_path: Path) -> None:
    """The downgrade needs evidence. A dep used nowhere, gitignored files
    included, is still SAFE."""
    root = _project(tmp_path)
    (root / "requirements.txt").write_text(
        "requests\ngenlib\nunusedlib\n", encoding="utf-8"
    )
    deps = _deps(runner, root)
    assert deps["unusedlib"]["status"] == "SAFE"


@pytest.mark.requirement("FR-278")
def test_gitignored_notebook_usage_is_uncertain_by_default(
    runner, tmp_path: Path
) -> None:
    """Notebooks used to ignore .gitignore entirely, so their imports always
    counted. They now follow the same mode as .py files."""
    (tmp_path / "requirements.txt").write_text("requests\nnblib\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    nb = {
        "cells": [{"cell_type": "code", "source": ["import nblib\n"],
                   "metadata": {}, "outputs": [], "execution_count": None}],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    }
    (tmp_path / "explore.ipynb").write_text(json.dumps(nb), encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.ipynb\n", encoding="utf-8")

    assert _deps(runner, tmp_path)["nblib"]["status"] == "UNCERTAIN"
    assert _deps(runner, tmp_path, "--gitignore", "include")["nblib"]["status"] == "IN_USE"


@pytest.mark.requirement("FR-278")
def test_by_name_excluded_code_never_counts_for_classification(
    runner, tmp_path: Path
) -> None:
    """``build/`` holds copies of the project's own code. The rules read it,
    but its imports must not keep a dependency alive in any mode."""
    (tmp_path / "requirements.txt").write_text("requests\nbuiltlib\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    (tmp_path / "build" / "lib").mkdir(parents=True)
    (tmp_path / "build" / "lib" / "copy.py").write_text(
        "import builtlib\n", encoding="utf-8"
    )
    for mode in ("uncertain", "include", "exclude"):
        deps = _deps(runner, tmp_path, "--gitignore", mode)
        assert deps["builtlib"]["status"] == "SAFE", mode
