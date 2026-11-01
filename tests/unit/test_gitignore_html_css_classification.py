"""FR-278 for the HTML template scanner and the CSS analyser (step 4 of
docs/plans/gitignore-consistent-discovery.md).

Both detect npm packages a project loads without declaring: a CDN
``<script src>`` in a template, an ``@import "~pkg"`` in a stylesheet.
Before step 4 a detection in a gitignored file was IN_USE like any
other. It now follows ``--gitignore``, as Python does: UNCERTAIN by
default, IN_USE under ``include``, not reported under ``exclude``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.core.discovery import (
    GITIGNORED_ONLY_REASON,
    consolidate_audit_lines,
    gitignored_findings_line,
    unignored_environments_line,
)

_CDN = '<script src="https://cdn.jsdelivr.net/npm/alpinejs@3.13.0/dist/cdn.min.js"></script>\n'
_CSS_IMPORT = '@import "~normalize.css";\n'


def _project(root: Path) -> Path:
    (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (root / "app.py").write_text("import requests\n", encoding="utf-8")
    (root / "site.css").write_text("body { margin: 0 }\n", encoding="utf-8")
    (root / ".gitignore").write_text("gen/\n", encoding="utf-8")
    (root / "gen").mkdir()
    return root


def _deps(runner, root: Path, *argv: str) -> dict[str, dict]:
    from scarno.cli import app

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code in (0, 1, 3), result.output
    return {d["name"]: d for d in json.loads(result.output)["dependencies"]}


_MODES = [
    ([], "UNCERTAIN"),
    (["--gitignore", "include"], "IN_USE"),
    (["--no-gitignore"], "IN_USE"),
    (["--gitignore", "exclude"], None),
]


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(("argv", "status"), _MODES)
def test_cdn_dep_in_gitignored_template_follows_the_mode(
    runner, tmp_path: Path, argv: list[str], status: str | None
) -> None:
    root = _project(tmp_path)
    (root / "gen" / "index.html").write_text(_CDN, encoding="utf-8")
    dep = _deps(runner, root, *argv).get("alpinejs")
    assert (dep and dep["status"]) == status
    if status == "UNCERTAIN":
        assert dep["reason"] == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize(("argv", "status"), _MODES)
def test_css_import_in_gitignored_stylesheet_follows_the_mode(
    runner, tmp_path: Path, argv: list[str], status: str | None
) -> None:
    root = _project(tmp_path)
    (root / "gen" / "theme.scss").write_text(_CSS_IMPORT, encoding="utf-8")
    dep = _deps(runner, root, *argv).get("normalize.css")
    assert (dep and dep["status"]) == status
    if status == "UNCERTAIN":
        assert dep["reason"] == GITIGNORED_ONLY_REASON


@pytest.mark.requirement("FR-278")
@pytest.mark.parametrize("mode", ["uncertain", "include", "exclude"])
def test_tracked_usage_wins_in_every_mode(runner, tmp_path: Path, mode: str) -> None:
    """A tracked template or stylesheet anywhere in the tree makes the dep
    IN_USE, whichever file the walk reaches first."""
    root = _project(tmp_path)
    # "gen/" sorts before "templates/" and "zz.css", so the ignored file is
    # always seen first.
    (root / "gen" / "index.html").write_text(_CDN, encoding="utf-8")
    (root / "gen" / "theme.scss").write_text(_CSS_IMPORT, encoding="utf-8")
    (root / "templates").mkdir()
    (root / "templates" / "base.html").write_text(_CDN, encoding="utf-8")
    (root / "zz.css").write_text(_CSS_IMPORT, encoding="utf-8")

    deps = _deps(runner, root, "--gitignore", mode)

    assert deps["alpinejs"]["status"] == "IN_USE"
    assert deps["normalize.css"]["status"] == "IN_USE"
    if mode != "include":
        # Under include a gitignored file counts like any other, so it can
        # be the one named. Otherwise the evidence named is tracked.
        assert "gen/" not in deps["alpinejs"]["reason"]
        assert deps["normalize.css"]["source"] == "zz.css:@import"


@pytest.mark.requirement("FR-278")
def test_by_name_excluded_directories_never_count(runner, tmp_path: Path) -> None:
    """``dist/`` is rule-scanned now, but its contents are build output, not
    usage, so they still add no dependency in any mode."""
    root = _project(tmp_path)
    (root / "dist").mkdir()
    (root / "dist" / "index.html").write_text(_CDN, encoding="utf-8")
    (root / "dist" / "bundle.css").write_text(_CSS_IMPORT, encoding="utf-8")
    for mode in ("uncertain", "include", "exclude"):
        deps = _deps(runner, root, "--gitignore", mode)
        assert "alpinejs" not in deps, mode
        assert "normalize.css" not in deps, mode


# ── consolidate_audit_lines ────────────────────────────────────────────────


@pytest.mark.requirement("PRV-008")
def test_consolidation_sums_findings_and_takes_the_largest_environment_count() -> None:
    errors = [
        "python: something",
        gitignored_findings_line(2),
        unignored_environments_line(1),
        "css: other",
        gitignored_findings_line(3),
        unignored_environments_line(2),
        unignored_environments_line(1),
    ]
    assert consolidate_audit_lines(errors) == [
        "python: something",
        "css: other",
        gitignored_findings_line(5),
        unignored_environments_line(2),
    ]


@pytest.mark.requirement("PRV-008")
def test_consolidation_leaves_other_lines_alone() -> None:
    errors = ["a", "3 finding(s) came from somewhere else", "b"]
    assert consolidate_audit_lines(errors) == errors
    assert consolidate_audit_lines([]) == []
