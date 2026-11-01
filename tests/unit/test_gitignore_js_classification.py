"""FR-278 for the JS/TS source analyser (step 6 of
docs/plans/gitignore-consistent-discovery.md).

Before step 6 the analyser ignored ``.gitignore``, so an import in a
gitignored generated client counted like any other, and it read ``.js``
files shipped inside Python virtualenvs (step 1: 237 on one sample).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.analysers.javascript.source_analyser import (
    JS_AST_AVAILABLE,
    analyse_npm_sources,
)
from scarno.core.discovery import (
    GITIGNORED_ONLY_REASON,
    GitignoreMode,
    unignored_environments_line,
)
from scarno.models import Dependency, DependencyStatus

pytestmark = pytest.mark.skipif(
    not JS_AST_AVAILABLE, reason="tree-sitter JS grammars not installed"
)

_S, _U, _I = DependencyStatus.SAFE, DependencyStatus.UNCERTAIN, DependencyStatus.IN_USE
_USES_AXIOS = 'import axios from "axios";\nexport const c = axios.create();\n'


def _dep(name: str, *, stub: bool = False) -> Dependency:
    return Dependency(
        name=name,
        version="1.0.0",
        status=DependencyStatus.UNCERTAIN,
        reason="pending source analysis",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        source="package.json",
        is_type_stub=stub,
        ecosystem="npm",
    )


def _project(root: Path, gitignore: str) -> Path:
    (root / "src").mkdir()
    (root / "src" / "index.ts").write_text("export const x = 1;\n", encoding="utf-8")
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    return root


def _write(root: Path, rel: str, text: str = _USES_AXIOS) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _classify(
    root: Path,
    deps: list[Dependency] | None = None,
    mode: GitignoreMode = GitignoreMode.UNCERTAIN,
    operator_excludes: tuple[str, ...] = (),
) -> tuple[dict[str, Dependency], list[str]]:
    out, errors = analyse_npm_sources(
        str(root),
        deps if deps is not None else [_dep("axios")],
        gitignore=mode,
        operator_excludes=operator_excludes,
    )
    return {d.name: d for d in out}, errors


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "status"),
    [(GitignoreMode.UNCERTAIN, _U), (GitignoreMode.INCLUDE, _I), (GitignoreMode.EXCLUDE, _S)],
)
def test_gitignored_generated_client_as_only_importer_follows_the_mode(
    tmp_path: Path, mode: GitignoreMode, status: DependencyStatus
) -> None:
    root = _project(tmp_path, "src/generated/\n")
    _write(root, "src/generated/api/client.ts")
    deps, _ = _classify(root, mode=mode)
    assert deps["axios"].status is status
    if status is _U:
        assert deps["axios"].reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
def test_tracked_usage_wins_in_every_mode(tmp_path: Path, mode: GitignoreMode) -> None:
    root = _project(tmp_path, "src/generated/\n")
    _write(root, "src/generated/api/client.ts")
    _write(root, "src/app.ts")
    deps, _ = _classify(root, mode=mode)
    assert deps["axios"].status is _I
    assert deps["axios"].reason != GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "undeclared"),
    [(GitignoreMode.UNCERTAIN, False), (GitignoreMode.INCLUDE, True), (GitignoreMode.EXCLUDE, False)],
)
def test_gitignored_imports_add_undeclared_only_under_include(
    tmp_path: Path, mode: GitignoreMode, undeclared: bool
) -> None:
    """Ignored-only evidence can only lift SAFE to UNCERTAIN. It is not
    enough to claim the project depends on an undeclared package."""
    root = _project(tmp_path, "gen/\n")
    # UNDECLARED entries come from static imports only.
    _write(root, "gen/x.js", 'import leftPad from "left-pad";\n')
    deps, _ = _classify(root, [], mode=mode)
    assert ("left-pad" in deps) is undeclared


@pytest.mark.requirement("FR-278")
def test_non_literal_dynamic_import_in_gitignored_file_is_not_evidence(
    tmp_path: Path,
) -> None:
    """In a tracked file a ``require(name)`` makes every dep UNCERTAIN. A
    gitignored bundle is full of them, so there it names nothing."""
    root = _project(tmp_path, "public/\n")
    _write(root, "public/bundle.js", "const m = require(process.argv[2]);\n")
    deps, _ = _classify(root)
    assert deps["axios"].status is _S


@pytest.mark.requirement("FR-278")
def test_type_stub_follows_its_gitignored_runtime_package(tmp_path: Path) -> None:
    root = _project(tmp_path, "src/generated/\n")
    _write(root, "src/generated/client.ts", 'import express from "express";\n')
    deps, _ = _classify(root, [_dep("express"), _dep("@types/express", stub=True)])
    assert deps["express"].status is _U
    assert deps["@types/express"].status is _U
    assert deps["@types/express"].reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
@pytest.mark.parametrize("dirname", ["dist", "build", ".next", "coverage"])
def test_build_output_never_counts(
    tmp_path: Path, mode: GitignoreMode, dirname: str
) -> None:
    """Unchanged: by-name directories hold build output of the tracked
    sources, gitignored or not, so they add no evidence in any mode."""
    root = _project(tmp_path, f"{dirname}/\n")
    _write(root, f"{dirname}/server.js", 'const a = require("axios");\n')
    deps, _ = _classify(root, mode=mode)
    assert deps["axios"].status is _S


@pytest.mark.requirement("SEC-NEW-76")
def test_operator_exclude_removes_the_evidence(tmp_path: Path) -> None:
    root = _project(tmp_path, "")
    _write(root, "legacy/old.js", 'const a = require("axios");\n')
    before, _ = _classify(root)
    after, _ = _classify(root, operator_excludes=("legacy",))
    assert before["axios"].status is _I
    assert after["axios"].status is _S


@pytest.mark.requirement("PRV-008")
def test_javascript_inside_a_virtualenv_is_not_read(tmp_path: Path) -> None:
    root = _project(tmp_path, "")
    _write(root, "env/pyvenv.cfg", "home = /usr/bin\n")
    _write(
        root,
        "env/lib/python3.12/site-packages/notebook/static/main.js",
        'const a = require("axios");\n',
    )
    deps, errors = _classify(root, mode=GitignoreMode.INCLUDE)
    assert deps["axios"].status is _S
    assert errors.count(unignored_environments_line(1)) == 1


# ── end to end: the CLI and JavascriptAnalyser forward the mode ───────────


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("argv", "status"),
    [
        ([], "UNCERTAIN"),
        (["--gitignore", "include"], "IN_USE"),
        (["--no-gitignore"], "IN_USE"),
        (["--gitignore", "exclude"], "SAFE"),
    ],
)
def test_cli_forwards_the_mode(runner, tmp_path: Path, argv: list[str], status: str) -> None:
    from scarno.cli import app

    root = _project(tmp_path, "src/generated/\n")
    (root / "package.json").write_text(
        json.dumps({"name": "demo", "version": "1.0.0", "dependencies": {"axios": "^1.6.0"}}),
        encoding="utf-8",
    )
    _write(root, "src/generated/api/client.ts")

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code in (0, 1, 3), result.output
    deps = {d["name"]: d for d in json.loads(result.output)["dependencies"]}
    assert deps["axios"]["status"] == status
