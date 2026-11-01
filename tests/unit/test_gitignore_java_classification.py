"""FR-278 for the Java/Kotlin source analyser (step 5 of
docs/plans/gitignore-consistent-discovery.md).

Before step 5 the analyser ignored ``.gitignore`` entirely, so usage in a
gitignored file counted like any other, and it skipped ``target/`` and
``build/`` by name, so a dep only generated sources used was SAFE. Both
now follow ``--gitignore``: usage only gitignored files show makes a dep
UNCERTAIN by default.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.analysers.java.source_analyser import JvmSourceAnalyser
from scarno.core.discovery import (
    GITIGNORED_ONLY_REASON,
    GitignoreMode,
    unignored_environments_line,
)
from scarno.models import Dependency, DependencyStatus

GUAVA = "com.google.guava:guava"
_USES_GUAVA = (
    "import com.google.common.collect.ImmutableList;\n"
    "public class Client { ImmutableList<String> x; }\n"
)
_UNUSED = "public class Main {}\n"


def _dep() -> Dependency:
    return Dependency(
        name=GUAVA,
        version="33.0.0-jre",
        status=DependencyStatus.UNCERTAIN,
        reason="pending source analysis",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


def _project(root: Path, gitignore: str) -> Path:
    (root / "src" / "main" / "java").mkdir(parents=True)
    (root / "src" / "main" / "java" / "Main.java").write_text(_UNUSED, encoding="utf-8")
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    return root


def _write(root: Path, rel: str, text: str = _USES_GUAVA) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _classify(
    root: Path,
    mode: GitignoreMode = GitignoreMode.UNCERTAIN,
    operator_excludes: tuple[str, ...] = (),
) -> tuple[Dependency, list[str]]:
    analyser = JvmSourceAnalyser()
    analyser.gitignore = mode
    analyser.operator_excludes = operator_excludes
    result = analyser.analyse(str(root), [_dep()])
    (dep,) = result.dependencies
    return dep, result.errors


_S, _U, _I = DependencyStatus.SAFE, DependencyStatus.UNCERTAIN, DependencyStatus.IN_USE


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "status"),
    [(GitignoreMode.UNCERTAIN, _U), (GitignoreMode.INCLUDE, _I), (GitignoreMode.EXCLUDE, _S)],
)
def test_gitignored_source_as_only_user_follows_the_mode(
    tmp_path: Path, mode: GitignoreMode, status: DependencyStatus
) -> None:
    root = _project(tmp_path, "gen/\n")
    _write(root, "gen/com/example/Client.java")
    dep, _ = _classify(root, mode)
    assert dep.status is status
    if status is _U:
        assert dep.reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("mode", "status"),
    [(GitignoreMode.UNCERTAIN, _U), (GitignoreMode.INCLUDE, _U), (GitignoreMode.EXCLUDE, _S)],
)
@pytest.mark.parametrize(
    "rel",
    [
        "target/generated-sources/annotations/com/example/Client.java",
        "build/generated/source/kapt/main/com/example/Client.kt",
    ],
)
def test_generated_sources_under_build_output_follow_the_mode(
    tmp_path: Path, mode: GitignoreMode, status: DependencyStatus, rel: str
) -> None:
    """The plan's case. ``target/`` and ``build/`` stay out of full-weight
    classification by name in every mode, so even ``include`` gives
    UNCERTAIN, not IN_USE: stale build output must not keep a dep alive.
    Only ``exclude`` restores the old SAFE."""
    root = _project(tmp_path, "target/\nbuild/\n")
    text = _USES_GUAVA
    if rel.endswith(".kt"):
        text = "import com.google.common.collect.ImmutableList\nclass Client\n"
    _write(root, rel, text)
    dep, _ = _classify(root, mode)
    assert dep.status is status
    if status is _U:
        assert dep.reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
def test_committed_build_output_still_does_not_count(
    tmp_path: Path, mode: GitignoreMode
) -> None:
    """Unchanged: a ``target/`` the tree does not gitignore is build output
    by name, and its reason text could not truthfully name .gitignore."""
    root = _project(tmp_path, "")
    _write(root, "target/generated-sources/com/example/Client.java")
    dep, _ = _classify(root, mode)
    assert dep.status is _S


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", list(GitignoreMode))
def test_tracked_usage_wins_in_every_mode(tmp_path: Path, mode: GitignoreMode) -> None:
    root = _project(tmp_path, "gen/\n")
    _write(root, "gen/com/example/Client.java")
    _write(root, "src/main/java/com/example/Real.java")
    dep, _ = _classify(root, mode)
    assert dep.status is _I
    assert dep.reason != GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
def test_reflective_use_in_gitignored_source_is_uncertain(tmp_path: Path) -> None:
    root = _project(tmp_path, "gen/\n")
    _write(
        root,
        "gen/Loader.java",
        'public class Loader { Object o = Class.forName("com.google.common.collect.ImmutableList"); }\n',
    )
    dep, _ = _classify(root)
    assert dep.status is _U
    assert dep.reason == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
def test_only_gitignored_sources_is_not_called_safe(tmp_path: Path) -> None:
    """With every source file gitignored the analyser has no full-weight
    evidence, so it says so rather than calling anything SAFE."""
    (tmp_path / ".gitignore").write_text("gen/\n", encoding="utf-8")
    _write(tmp_path, "gen/Client.java", _UNUSED)
    dep, _ = _classify(tmp_path)
    assert dep.status is _U


@pytest.mark.requirement("SEC-NEW-76")
def test_operator_exclude_removes_the_evidence(tmp_path: Path) -> None:
    root = _project(tmp_path, "gen/\n")
    _write(root, "gen/com/example/Client.java")
    dep, _ = _classify(root, operator_excludes=("gen",))
    assert dep.status is _S


@pytest.mark.requirement("PRV-008")
def test_installed_environment_sources_are_not_read(tmp_path: Path) -> None:
    root = _project(tmp_path, "")
    _write(root, "env/pyvenv.cfg", "home = /usr/bin\n")
    _write(root, "env/lib/python3.12/site-packages/jpype/Client.java")
    dep, errors = _classify(root, GitignoreMode.INCLUDE)
    assert dep.status is _S
    assert errors.count(unignored_environments_line(1)) == 1


# ── end to end: the CLI and JavaAnalyser forward the mode ─────────────────

_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
"""


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(
    ("argv", "status"),
    [
        ([], "UNCERTAIN"),
        (["--gitignore", "include"], "UNCERTAIN"),
        (["--gitignore", "exclude"], "SAFE"),
    ],
)
def test_cli_forwards_the_mode_to_the_java_source_analyser(
    runner, tmp_path: Path, argv: list[str], status: str
) -> None:
    """``JavaAnalyser`` used to forward only ``use_gitignore``, a bool, so
    ``exclude`` would have arrived as the default."""
    from scarno.cli import app

    root = _project(tmp_path, "target/\n")
    (root / "pom.xml").write_text(_POM, encoding="utf-8")
    _write(root, "target/generated-sources/com/example/Client.java")

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code in (0, 1, 3), result.output
    deps = {d["name"]: d for d in json.loads(result.output)["dependencies"]}
    assert deps[GUAVA]["status"] == status
