"""Shared source discovery (FR-279), the gitignore classification mode
(FR-278) and operator ``--exclude`` (SEC-NEW-76).

``docs/plans/gitignore-consistent-discovery.md``, step 2. No analyser uses
the helper yet. These tests pin its contract before steps 3–8 port each
analyser onto it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from scarno.core import discovery as _discovery
from scarno.core.discovery import (
    DiscoveredFiles,
    GitignoreMode,
    discover,
    sanitise_exclude_globs,
)
from scarno.core.test_scope import TestScopeMatcher as _ScopeMatcher


def _write(root: Path, rel: str, text: str = "x = 1\n") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _rels(root: Path, paths: list[Path]) -> list[str]:
    base = root.resolve()
    return [p.relative_to(base).as_posix() for p in paths]


def _discover(root: Path, **kw) -> tuple[DiscoveredFiles, list[str]]:
    errors: list[str] = []
    kw.setdefault("label", "test")
    return discover(root, (".py",), errors, **kw), errors


# ── The three sets ──────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-279")
def test_files_split_into_tracked_ignored_and_rule_only(tmp_path: Path) -> None:
    """Nested ``.gitignore`` files are honoured for marking. By-name
    classification exclusions go to ``rule_only`` even when also ignored,
    so classification never reads them and the rules always do."""
    _write(tmp_path, ".gitignore", "generated/\n")
    _write(tmp_path, "pkg/.gitignore", "local_*.py\n")
    _write(tmp_path, "app.py")
    _write(tmp_path, "generated/api_pb2.py")
    _write(tmp_path, "pkg/mod.py")
    _write(tmp_path, "pkg/local_scratch.py")
    _write(tmp_path, "build/lib/copy.py")
    _write(tmp_path, "build/.gitignore", "*\n")

    found, errors = _discover(
        tmp_path, classification_excluded_dirs=frozenset({"build"}),
    )

    assert errors == []
    assert _rels(tmp_path, found.tracked) == ["app.py", "pkg/mod.py"]
    assert _rels(tmp_path, found.ignored) == [
        "generated/api_pb2.py", "pkg/local_scratch.py",
    ]
    assert _rels(tmp_path, found.rule_only) == ["build/lib/copy.py"]


@pytest.mark.requirement("FR-279")
def test_name_excluded_suffix_matches_egg_info(tmp_path: Path) -> None:
    """Python's ``*.egg-info`` exclusion is a suffix, not a name."""
    _write(tmp_path, "pkg.egg-info/setup_hook.py")
    found, _ = _discover(
        tmp_path, classification_excluded_dir_suffixes=(".egg-info",),
    )
    assert found.tracked == []
    assert _rels(tmp_path, found.rule_only) == ["pkg.egg-info/setup_hook.py"]


@pytest.mark.requirement("FR-279")
def test_suffix_match_is_case_insensitive_and_exact(tmp_path: Path) -> None:
    _write(tmp_path, "A.PY")
    _write(tmp_path, "notes.pyc")
    _write(tmp_path, "readme.txt")
    found, _ = _discover(tmp_path)
    assert _rels(tmp_path, found.tracked) == ["A.PY"]


@pytest.mark.requirement("FR-279")
def test_output_is_sorted_and_deterministic(tmp_path: Path) -> None:
    for name in ("zeta.py", "alpha.py", "mid/b.py", "mid/a.py"):
        _write(tmp_path, name)
    first, _ = _discover(tmp_path)
    second, _ = _discover(tmp_path)
    assert first.tracked == sorted(first.tracked) == second.tracked


# ── Installed environments (structural) ─────────────────────────────────────


@pytest.mark.requirement("FR-279")
@pytest.mark.parametrize(
    "layout",
    [
        "env/pyvenv.cfg",                      # unlisted venv name (F23 case)
        ".direnv/python-3.12/pyvenv.cfg",      # direnv layout, step 1 sample
        "anything/lib/python3.12/site-packages/x",
        "deb/dist-packages/x",
        "__pypackages__/3.12/lib/x",
        "web/node_modules/x",
    ],
)
def test_installed_environments_are_pruned_by_structure(
    tmp_path: Path, layout: str
) -> None:
    """Third-party code in an installed environment trips CRITICAL rules
    (step 1 measured 11 such findings across two samples). Neither set
    returns it, whatever the directory is called, and gitignored or not."""
    marker = _write(tmp_path, layout, "")
    env_root = marker.parent
    _write(env_root, "evil_looking.py", "exec(requests.get(u).text)\n")
    _write(env_root, "deeper/also.py")
    _write(tmp_path, "app.py")

    found, errors = _discover(tmp_path)

    assert errors == []
    assert _rels(tmp_path, found.for_rules()) == ["app.py"]
    assert found.environment_dirs_skipped == 1


@pytest.mark.requirement("FR-279")
def test_root_with_pyvenv_cfg_is_still_scanned(tmp_path: Path) -> None:
    """Pointing scarno at a virtualenv is the operator's explicit choice.
    The root itself is never treated as an environment to skip."""
    _write(tmp_path, "pyvenv.cfg", "")
    _write(tmp_path, "tool.py")
    found, _ = _discover(tmp_path)
    assert _rels(tmp_path, found.tracked) == ["tool.py"]
    assert found.environment_dirs_skipped == 0


@pytest.mark.requirement("FR-279")
def test_planted_marker_hides_its_directory_documented_residual(
    tmp_path: Path,
) -> None:
    """Documented residual risk (THREAT-MODEL): a committed ``pyvenv.cfg``
    hides its directory from every consumer. The marker is a file in the
    pull request's diff, so it is reviewable. That is the trade-off against
    flooding every run with third-party findings. This test records the
    behaviour so a change to it is deliberate."""
    _write(tmp_path, "src/innocent/pyvenv.cfg", "")
    _write(tmp_path, "src/innocent/payload.py", "exec(x)\n")
    found, _ = _discover(tmp_path)
    assert found.for_rules() == []
    assert found.environment_dirs_skipped == 1


@pytest.mark.requirement("FR-279")
def test_dot_git_is_never_entered(tmp_path: Path) -> None:
    _write(tmp_path, ".git/hooks/pre-commit.py")
    _write(tmp_path, "app.py")
    found, _ = _discover(tmp_path)
    assert _rels(tmp_path, found.for_rules()) == ["app.py"]


# ── Confinement and size (SEC-002) ──────────────────────────────────────────


@pytest.mark.requirement("FR-279")
@pytest.mark.requirement("SEC-002")
def test_symlinked_file_escaping_root_is_blocked(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = _write(tmp_path, "outside/secret.py")
    _write(root, "real.py")
    (root / "link.py").symlink_to(outside)
    (root / "inside.py").symlink_to(root / "real.py")

    found, errors = _discover(root)

    # inside.py resolves to real.py, so it is returned once per name, as
    # Python discovery always did. Only the escaping link is blocked.
    assert set(_rels(root, found.tracked)) == {"real.py"}
    assert errors == ["test: symlink escape blocked: link.py"]


@pytest.mark.requirement("FR-279")
@pytest.mark.requirement("SEC-002")
def test_symlinked_directories_are_not_entered(tmp_path: Path) -> None:
    """Matches ``Path.rglob`` on every supported Python: a symlinked
    directory is not descended, whether it points in or out."""
    root = tmp_path / "root"
    _write(tmp_path, "outside/secret.py")
    _write(root, "real/a.py")
    (root / "out").symlink_to(tmp_path / "outside", target_is_directory=True)
    (root / "again").symlink_to(root / "real", target_is_directory=True)
    found, errors = _discover(root)
    assert _rels(root, found.tracked) == ["real/a.py"]
    assert errors == []


@pytest.mark.requirement("FR-279")
def test_oversized_files_are_skipped_with_a_path_relative_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_discovery, "MAX_FILE_BYTES", 10)
    _write(tmp_path, "big.py", "x" * 11)
    _write(tmp_path, "ok.py", "x")
    found, errors = _discover(tmp_path)
    assert _rels(tmp_path, found.tracked) == ["ok.py"]
    assert errors == ["test: skipped big.py — file too large (11 bytes > 10)"]


# ── Operator --exclude (SEC-NEW-76) ─────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-76")
def test_operator_exclude_applies_to_every_set(tmp_path: Path) -> None:
    """A file glob and a directory glob both apply to tracked, ignored and
    rule-only files. A directory match prunes the subtree."""
    _write(tmp_path, ".gitignore", "gen/\n")
    _write(tmp_path, "app.py")
    _write(tmp_path, "scratch_1.py")
    _write(tmp_path, "gen/client.py")
    _write(tmp_path, "build/copy.py")
    _write(tmp_path, "noisy/deep/tree/x.py")

    found, _ = _discover(
        tmp_path,
        classification_excluded_dirs=frozenset({"build"}),
        operator_excludes=("scratch_*.py", "gen", "build/*.py", "noisy"),
    )

    assert _rels(tmp_path, found.for_rules()) == ["app.py"]
    assert found.operator_excluded == 4


@pytest.mark.requirement("SEC-NEW-76")
@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (("../etc",), "no '..' segments"),
        (("a/../../b",), "no '..' segments"),
        (("a\\b",), "POSIX `/` separators"),
        (("x" * 257,), "pattern too long"),
        (tuple(f"p{i}" for i in range(65)), "too many"),
    ],
)
def test_exclude_globs_validated_like_test_paths(
    raw: tuple[str, ...], message: str
) -> None:
    with pytest.raises(ValueError, match="--exclude") as exc:
        sanitise_exclude_globs(raw)
    assert message in str(exc.value)


@pytest.mark.requirement("SEC-NEW-76")
def test_exclude_globs_strip_leading_slash() -> None:
    assert sanitise_exclude_globs(("/gen/**", "build")) == ("gen/**", "build")


# ── Test-scope interaction ──────────────────────────────────────────────────


@pytest.mark.requirement("FR-279")
def test_test_files_are_skipped_and_counted_like_python_today(
    tmp_path: Path,
) -> None:
    """Test files are removed from every set under ``--exclude-tests``. The
    count includes only files classification would otherwise have read,
    matching the old Python summary, which checked .gitignore first."""
    _write(tmp_path, ".gitignore", "ignored_tests/\n")
    _write(tmp_path, "app.py")
    _write(tmp_path, "tests/test_app.py")
    _write(tmp_path, "ignored_tests/test_x.py")
    matcher = _ScopeMatcher(
        "python", exclude_tests=True,
        user_patterns=("ignored_tests/**",),
    )
    found, _ = _discover(tmp_path, test_matcher=matcher)
    assert _rels(tmp_path, found.for_rules()) == ["app.py"]
    assert found.test_skipped == 1


# ── Gitignore availability and switches ────────────────────────────────────


@pytest.mark.requirement("FR-279")
def test_missing_gitignorefile_fails_safe_for_the_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the matcher nothing can be marked ignored, so everything is
    tracked. The rules still see every file."""
    monkeypatch.setitem(sys.modules, "gitignorefile", None)
    _write(tmp_path, ".gitignore", "gen/\n")
    _write(tmp_path, "gen/client.py")
    found, errors = _discover(tmp_path)
    assert _rels(tmp_path, found.tracked) == ["gen/client.py"]
    assert errors == [(
        "test: gitignorefile not installed — skipping .gitignore filtering "
        "(install with `pip install gitignorefile`)"
    )]


@pytest.mark.requirement("FR-279")
def test_use_gitignore_false_marks_nothing_ignored(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "gen/\n")
    _write(tmp_path, "gen/client.py")
    found, _ = _discover(tmp_path, use_gitignore=False)
    assert _rels(tmp_path, found.tracked) == ["gen/client.py"]
    assert found.ignored == []


@pytest.mark.requirement("FR-279")
def test_missing_root_reports_and_returns_empty(tmp_path: Path) -> None:
    found, errors = _discover(tmp_path / "nope")
    assert found.for_rules() == []
    assert len(errors) == 1 and errors[0].startswith(
        "test: could not resolve project path"
    )


# ── Mode semantics (FR-278) ─────────────────────────────────────────────────


@pytest.mark.requirement("FR-278")
def test_for_classification_follows_the_mode(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "gen/\n")
    _write(tmp_path, "app.py")
    _write(tmp_path, "gen/client.py")
    _write(tmp_path, "build/copy.py")
    found, _ = _discover(
        tmp_path, classification_excluded_dirs=frozenset({"build"}),
    )
    tracked = ["app.py"]
    assert _rels(tmp_path, found.for_classification(GitignoreMode.EXCLUDE)) == tracked
    assert _rels(tmp_path, found.for_classification(GitignoreMode.UNCERTAIN)) == tracked
    assert _rels(tmp_path, found.for_classification(GitignoreMode.INCLUDE)) == [
        "app.py", "gen/client.py",
    ]
    # Rules see everything that is not an environment or operator-excluded.
    assert _rels(tmp_path, found.for_rules()) == [
        "app.py", "build/copy.py", "gen/client.py",
    ]


@pytest.mark.requirement("FR-278")
def test_base_analyser_use_gitignore_is_a_view_of_the_mode() -> None:
    from scarno.core.base_analyser import BaseAnalyser
    from scarno.models import AnalysisResult

    class _A(BaseAnalyser):
        def supports(self, project_path: str) -> bool:
            return True

        def analyse(self, project_path: str) -> AnalysisResult:
            return AnalysisResult(project_type="x", project_path=project_path)

    a = _A()
    assert a.gitignore is GitignoreMode.UNCERTAIN and a.use_gitignore
    a.use_gitignore = False
    assert a.gitignore is GitignoreMode.INCLUDE
    a.use_gitignore = True
    assert a.gitignore is GitignoreMode.UNCERTAIN
    a.gitignore = GitignoreMode.EXCLUDE
    a.use_gitignore = True
    assert a.gitignore is GitignoreMode.EXCLUDE, "True must not reset a chosen mode"


# ── CLI parsing and propagation ─────────────────────────────────────────────


_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "simple_python"


def _captured_analyser(monkeypatch: pytest.MonkeyPatch) -> list:
    """Replace the analysers the CLI builds with one recorder, and return
    the list it records into."""
    from scarno import cli
    from scarno.core.base_analyser import BaseAnalyser
    from scarno.models import AnalysisResult

    seen: list = []

    class _Recorder(BaseAnalyser):
        def supports(self, project_path: str) -> bool:
            return True

        def analyse(self, project_path: str) -> AnalysisResult:
            seen.append((self.gitignore, self.operator_excludes))
            return AnalysisResult(project_type="python", project_path=project_path)

    monkeypatch.setattr(cli.registry, "analysers_for", lambda _t: [_Recorder()])
    return seen


@pytest.mark.requirement("FR-278")
@pytest.mark.requirement("SEC-NEW-76")
@pytest.mark.parametrize(
    ("argv", "mode", "excludes"),
    [
        ([], GitignoreMode.UNCERTAIN, ()),
        (["--gitignore", "EXCLUDE"], GitignoreMode.EXCLUDE, ()),
        (["--gitignore", "include"], GitignoreMode.INCLUDE, ()),
        (["--no-gitignore"], GitignoreMode.INCLUDE, ()),
        (["--no-gitignore", "--gitignore", "include"], GitignoreMode.INCLUDE, ()),
        (["--exclude", "/gen/**", "--exclude", "build"],
         GitignoreMode.UNCERTAIN, ("gen/**", "build")),
    ],
)
def test_cli_sets_mode_and_excludes_on_every_analyser(
    runner, monkeypatch: pytest.MonkeyPatch, argv, mode, excludes
) -> None:
    from scarno.cli import app

    seen = _captured_analyser(monkeypatch)
    result = runner.invoke(app, [str(_FIXTURE), "--format", "json", *argv])
    assert result.exit_code in (0, 1), result.output
    assert seen == [(mode, excludes)]


@pytest.mark.requirement("FR-278")
@pytest.mark.requirement("SEC-NEW-76")
@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--gitignore", "sometimes"], "--gitignore must be one of"),
        (["--no-gitignore", "--gitignore", "exclude"], "conflicts with"),
        (["--exclude", "../outside"], "no '..' segments"),
        (["--exclude", "a\\b"], "POSIX"),
    ],
)
def test_cli_rejects_bad_mode_and_globs_with_exit_2(
    runner, monkeypatch: pytest.MonkeyPatch, argv, message
) -> None:
    from scarno.cli import app

    seen = _captured_analyser(monkeypatch)
    result = runner.invoke(app, [str(_FIXTURE), *argv])
    assert result.exit_code == 2
    assert message in result.output
    assert seen == [], "no analyser may run on a usage error"


@pytest.mark.requirement("SEC-NEW-76")
def test_new_options_stay_hidden_until_analysers_honour_them(runner) -> None:
    """Step 2 adds the options but no analyser reads them yet. Step 3 makes
    them visible together with the first analyser that honours them."""
    from scarno.cli import app

    out = runner.invoke(app, ["--help"], env={"COLUMNS": "200"}).output
    assert "--gitignore " not in out.replace("--gitignore include", "")
    assert "--exclude " not in out.replace("--exclude-", "")
