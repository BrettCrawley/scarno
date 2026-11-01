"""FR-278 for the Go source analyser (step 7 of
docs/plans/gitignore-consistent-discovery.md).

Before step 7 the analyser ignored ``.gitignore``, so an import in
gitignored generated code (``*.pb.go``, mocks) counted like any other.
``vendor/`` and ``testdata/`` stay out of classification as before.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.analysers.go.source_analyser import GO_AST_AVAILABLE, analyse_go_sources
from scarno.core.discovery import (
    GITIGNORED_ONLY_REASON,
    GitignoreMode,
    unignored_environments_line,
)
from scarno.models import Dependency, DependencyStatus

pytestmark = pytest.mark.skipif(
    not GO_AST_AVAILABLE, reason="tree-sitter-go not installed"
)

_S, _U, _I = DependencyStatus.SAFE, DependencyStatus.UNCERTAIN, DependencyStatus.IN_USE
PROTO = "google.golang.org/protobuf"
_USES_PROTO = (
    "package gen\n\n"
    'import "google.golang.org/protobuf/proto"\n\n'
    "var _ = proto.Marshal\n"
)
_UNUSED = 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println() }\n'


def _dep(name: str = PROTO) -> Dependency:
    return Dependency(
        name=name,
        version="v1.33.0",
        status=DependencyStatus.UNCERTAIN,
        reason="pending source analysis",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        source="go.mod",
        ecosystem="go",
    )


def _project(root: Path, gitignore: str) -> Path:
    (root / "main.go").write_text(_UNUSED, encoding="utf-8")
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    return root


def _write(root: Path, rel: str, text: str = _USES_PROTO) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _classify(
    root: Path,
    deps: list[Dependency] | None = None,
    mode: GitignoreMode = GitignoreMode.UNCERTAIN,
    operator_excludes: tuple[str, ...] = (),
) -> tuple[dict[str, Dependency], list[str]]:
    out, errors = analyse_go_sources(
        str(root),
        deps if deps is not None else [_dep()],
        gitignore=mode,
        operator_excludes=operator_excludes,
    )
    return {d.name: d for d in out}, errors


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "status"),
    [(GitignoreMode.UNCERTAIN, _U), (GitignoreMode.INCLUDE, _I), (GitignoreMode.EXCLUDE, _S)],
)
def test_gitignored_generated_code_as_only_importer_follows_the_mode(
    tmp_path: Path, mode: GitignoreMode, status: DependencyStatus
) -> None:
    root = _project(tmp_path, "*.pb.go\n")
    _write(root, "api/v1/service.pb.go")
    deps, _ = _classify(root, mode=mode)
    assert deps[PROTO].status is status
    if status is _U:
        assert deps[PROTO].reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
def test_blank_import_in_gitignored_file_counts(tmp_path: Path) -> None:
    root = _project(tmp_path, "gen/\n")
    _write(root, "gen/register.go", 'package gen\n\nimport _ "google.golang.org/protobuf/types/known/anypb"\n')
    deps, _ = _classify(root)
    assert deps[PROTO].status is _U


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
def test_tracked_usage_wins_in_every_mode(tmp_path: Path, mode: GitignoreMode) -> None:
    root = _project(tmp_path, "*.pb.go\n")
    _write(root, "api/v1/service.pb.go")
    _write(root, "internal/codec/codec.go")
    deps, _ = _classify(root, mode=mode)
    assert deps[PROTO].status is _I
    assert deps[PROTO].reason != GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "undeclared"),
    [(GitignoreMode.UNCERTAIN, False), (GitignoreMode.INCLUDE, True), (GitignoreMode.EXCLUDE, False)],
)
def test_gitignored_imports_add_undeclared_only_under_include(
    tmp_path: Path, mode: GitignoreMode, undeclared: bool
) -> None:
    root = _project(tmp_path, "gen/\n")
    _write(root, "gen/x.go", 'package gen\n\nimport "github.com/acme/widget"\n\nvar _ = widget.New\n')
    deps, _ = _classify(root, [], mode=mode)
    assert ("github.com/acme/widget" in deps) is undeclared


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
@pytest.mark.parametrize("dirname", ["vendor", "testdata"])
@pytest.mark.parametrize("ignored", [True, False])
def test_vendor_and_testdata_never_count(
    tmp_path: Path, mode: GitignoreMode, dirname: str, ignored: bool
) -> None:
    """Unchanged: ``vendor/`` holds copies of the dependencies themselves
    and ``testdata/`` is ignored by the Go tool, gitignored or not."""
    root = _project(tmp_path, f"{dirname}/\n" if ignored else "")
    _write(root, f"{dirname}/example.com/x/x.go")
    deps, _ = _classify(root, mode=mode)
    assert deps[PROTO].status is _S


@pytest.mark.requirement("SEC-NEW-79")
def test_operator_exclude_removes_the_evidence(tmp_path: Path) -> None:
    root = _project(tmp_path, "")
    _write(root, "legacy/old.go")
    before, _ = _classify(root)
    after, _ = _classify(root, operator_excludes=("legacy",))
    assert before[PROTO].status is _I
    assert after[PROTO].status is _S


@pytest.mark.requirement("PRV-008")
def test_go_inside_a_virtualenv_is_not_read(tmp_path: Path) -> None:
    root = _project(tmp_path, "")
    _write(root, "env/pyvenv.cfg", "home = /usr/bin\n")
    _write(root, "env/lib/python3.12/site-packages/pkg/x.go")
    deps, errors = _classify(root, mode=GitignoreMode.INCLUDE)
    assert deps[PROTO].status is _S
    assert errors.count(unignored_environments_line(1)) == 1


# ── end to end: the CLI and GoAnalyser forward the mode ───────────────────


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

    root = _project(tmp_path, "*.pb.go\n")
    (root / "go.mod").write_text(
        f"module example.com/demo\n\ngo 1.22\n\nrequire {PROTO} v1.33.0\n",
        encoding="utf-8",
    )
    _write(root, "api/v1/service.pb.go")

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code in (0, 1, 3), result.output
    deps = {d["name"]: d for d in json.loads(result.output)["dependencies"]}
    assert deps[PROTO]["status"] == status
