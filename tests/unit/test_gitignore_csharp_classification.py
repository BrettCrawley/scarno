"""FR-278 for the C# source analyser (step 8 of
docs/plans/gitignore-consistent-discovery.md).

Before step 8 the analyser ignored ``.gitignore`` and skipped ``bin/`` and
``obj/`` by name. ``obj/`` is where the SDK writes source-generator output
and ``GlobalUsings.g.cs`` (from the project's ``<Using Include>`` items),
so a package only that code uses was SAFE.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.analysers.csharp.source_analyser import (
    CSHARP_AST_AVAILABLE,
    analyse_csharp_sources,
)
from scarno.core.discovery import (
    GITIGNORED_ONLY_REASON,
    GitignoreMode,
    unignored_environments_line,
)
from scarno.models import Dependency, DependencyStatus

pytestmark = pytest.mark.skipif(
    not CSHARP_AST_AVAILABLE, reason="tree-sitter-c-sharp not installed"
)

_S, _U, _I = DependencyStatus.SAFE, DependencyStatus.UNCERTAIN, DependencyStatus.IN_USE
PKG = "Serilog"
_USES = "using Serilog;\n\nnamespace Demo { class Log { } }\n"
_UNUSED = "using System;\n\nnamespace Demo { class Program { static void Main() { } } }\n"


def _dep(name: str = PKG) -> Dependency:
    return Dependency(
        name=name,
        version="3.1.1",
        status=DependencyStatus.UNCERTAIN,
        reason="pending source analysis",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        source="Demo.csproj",
        ecosystem="nuget",
    )


def _project(root: Path, gitignore: str) -> Path:
    (root / "Program.cs").write_text(_UNUSED, encoding="utf-8")
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    return root


def _write(root: Path, rel: str, text: str = _USES) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _classify(
    root: Path,
    deps: list[Dependency] | None = None,
    mode: GitignoreMode = GitignoreMode.UNCERTAIN,
    operator_excludes: tuple[str, ...] = (),
) -> tuple[dict[str, Dependency], list[str]]:
    out, errors = analyse_csharp_sources(
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
def test_gitignored_source_as_only_user_follows_the_mode(
    tmp_path: Path, mode: GitignoreMode, status: DependencyStatus
) -> None:
    root = _project(tmp_path, "Generated/\n")
    _write(root, "Generated/Logging.g.cs")
    deps, _ = _classify(root, mode=mode)
    assert deps[PKG].status is status
    if status is _U:
        assert deps[PKG].reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "status"),
    [(GitignoreMode.UNCERTAIN, _U), (GitignoreMode.INCLUDE, _U), (GitignoreMode.EXCLUDE, _S)],
)
@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("obj/Debug/net8.0/Demo.GlobalUsings.g.cs", "global using global::Serilog;\n"),
        (
            "obj/Debug/net8.0/generated/Gen/Gen.Logging/Log.g.cs",
            _USES,
        ),
    ],
)
def test_generated_source_in_obj_follows_the_mode(
    tmp_path: Path, mode: GitignoreMode, status: DependencyStatus, rel: str, text: str
) -> None:
    """The plan's case. ``obj/`` stays out of full-weight classification by
    name in every mode, so even ``include`` gives UNCERTAIN there; only
    ``exclude`` restores the old SAFE."""
    root = _project(tmp_path, "bin/\nobj/\n")
    _write(root, rel, text)
    deps, _ = _classify(root, mode=mode)
    assert deps[PKG].status is status
    if status is _U:
        assert deps[PKG].reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
def test_committed_obj_still_does_not_count(tmp_path: Path, mode: GitignoreMode) -> None:
    root = _project(tmp_path, "")
    _write(root, "obj/Debug/net8.0/Demo.GlobalUsings.g.cs", "global using global::Serilog;\n")
    deps, _ = _classify(root, mode=mode)
    assert deps[PKG].status is _S


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
def test_tracked_usage_wins_in_every_mode(tmp_path: Path, mode: GitignoreMode) -> None:
    root = _project(tmp_path, "Generated/\nobj/\n")
    _write(root, "Generated/Logging.g.cs")
    _write(root, "obj/Demo.GlobalUsings.g.cs", "global using global::Serilog;\n")
    _write(root, "Services/Worker.cs")
    deps, _ = _classify(root, mode=mode)
    assert deps[PKG].status is _I
    assert deps[PKG].reason != GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
def test_razor_using_in_gitignored_view_counts(tmp_path: Path) -> None:
    root = _project(tmp_path, "Views/Generated/\n")
    _write(root, "Views/Generated/Index.cshtml", "@using Serilog\n<p>hi</p>\n")
    deps, _ = _classify(root)
    assert deps[PKG].status is _U


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "undeclared"),
    [(GitignoreMode.UNCERTAIN, False), (GitignoreMode.INCLUDE, True), (GitignoreMode.EXCLUDE, False)],
)
def test_gitignored_usings_add_undeclared_only_under_include(
    tmp_path: Path, mode: GitignoreMode, undeclared: bool
) -> None:
    root = _project(tmp_path, "Generated/\n")
    _write(root, "Generated/X.cs", "using Acme.Widgets;\n\nnamespace Demo { class X { } }\n")
    deps, _ = _classify(root, [], mode=mode)
    assert any(name.startswith("Acme") for name in deps) is undeclared


@pytest.mark.requirement("SEC-NEW-79")
def test_operator_exclude_removes_the_evidence(tmp_path: Path) -> None:
    root = _project(tmp_path, "")
    _write(root, "Legacy/Old.cs")
    before, _ = _classify(root)
    after, _ = _classify(root, operator_excludes=("Legacy",))
    assert before[PKG].status is _I
    assert after[PKG].status is _S


@pytest.mark.requirement("PRV-008")
def test_csharp_inside_a_virtualenv_is_not_read(tmp_path: Path) -> None:
    root = _project(tmp_path, "")
    _write(root, "env/pyvenv.cfg", "home = /usr/bin\n")
    _write(root, "env/lib/python3.12/site-packages/pythonnet/x.cs")
    deps, errors = _classify(root, mode=GitignoreMode.INCLUDE)
    assert deps[PKG].status is _S
    assert errors.count(unignored_environments_line(1)) == 1


# ── end to end: the CLI and CsharpAnalyser forward the mode ───────────────

_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
"""


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

    root = _project(tmp_path, "Generated/\n")
    (root / "Demo.csproj").write_text(_CSPROJ, encoding="utf-8")
    _write(root, "Generated/Logging.g.cs")

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code in (0, 1, 3), result.output
    deps = {d["name"]: d for d in json.loads(result.output)["dependencies"]}
    assert deps[PKG]["status"] == status


# ── global:: qualified usings (found while writing the obj/ case) ─────────


@pytest.mark.requirement("FR-128")
@pytest.mark.parametrize(
    ("directive", "namespace"),
    [
        ("global using global::Serilog;", "Serilog"),
        ("using global::Serilog.Core;", "Serilog.Core"),
        ("using static global::Serilog.Log;", "Serilog.Log"),
        ("using L = global::Serilog.Log;", "Serilog.Log"),
        ("global using Serilog;", "Serilog"),
    ],
)
def test_alias_qualified_usings_name_the_namespace(directive: str, namespace: str) -> None:
    """``global::`` was dropped (``global using global::Serilog;`` gave
    nothing) or garbled (``using global::Serilog.Core;`` gave ``Core``), so
    a package used only that way was SAFE, tracked file or not."""
    from scarno.analysers.csharp import source_analyser as cs_sa

    facts = cs_sa._Facts()
    tree = cs_sa._CS_PARSER.parse(directive.encode("utf-8"))
    cs_sa._walk_usings(tree.root_node, facts)
    assert facts.namespaces == {namespace}
