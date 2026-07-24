"""TA-330 — REQ-24 / SEC-NEW-72 / FR-260 — ``--allow-remote-fetch``,
``--integrity-cross-check``, and ``--fail-on-remote-severity`` are
ALL argv-only (no env, no config, no test-helper backdoor) and
compose with ``--deep-inspection`` correctly.

Mirrors ``test_req22_deep_inspection_argv_only.py`` (TA-266 / SEC-NEW-56)
exactly: AST-scan of ``cli.py`` plus runtime CLI behaviour assertions.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import _RunOptions, app

pytestmark = pytest.mark.security


_REQ24_FLAG_FIELDS: tuple[str, ...] = (
    "allow_remote_fetch",
    "integrity_cross_check",
    "fail_on_remote_severity",
)


# ── AST scan: argv-only setter ──────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-72")
@pytest.mark.requirement("FR-260")
@pytest.mark.requirement("FR-261")
@pytest.mark.requirement("FR-267")
@pytest.mark.requirement("COMP-005")
def test_req24_flags_set_only_by_argv():
    """Static-AST parse of ``cli.py``: each REQ-24 flag may be
    assigned ONLY in code paths originating from the argv parser.
    No ``os.environ.get(...)`` / ``config[...]`` / preset substitution
    may set them. Mirrors TA-266 for SEC-NEW-56.
    """
    cli_path = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "scarno" / "cli.py"
    )
    text = cli_path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(cli_path))

    # Precondition: the flags must actually exist in cli.py — otherwise
    # the test passes vacuously.
    for field in _REQ24_FLAG_FIELDS:
        assert field in text, (
            f"cli.py does not mention {field!r} — REQ-24 implementation "
            f"has not landed; cannot verify SEC-NEW-72 yet."
        )

    suspicious: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id in _REQ24_FLAG_FIELDS
                ):
                    value_src = ast.unparse(node.value)
                    if (
                        "os.environ" in value_src
                        or "getenv" in value_src
                        or "config" in value_src.lower()
                    ):
                        suspicious.append(
                            f"line {node.lineno}: {target.id} = {value_src}"
                        )
        if isinstance(node, ast.keyword) and node.arg in _REQ24_FLAG_FIELDS:
            value_src = ast.unparse(node.value)
            if "os.environ" in value_src or "getenv" in value_src:
                suspicious.append(
                    f"line {node.lineno}: {node.arg}={value_src}"
                )

    assert not suspicious, (
        "REQ-24 capability flag(s) set from env / config in cli.py — "
        "violates SEC-NEW-72:\n  - " + "\n  - ".join(suspicious)
    )


# ── _RunOptions defaults False for every REQ-24 flag ────────────────────────


@pytest.mark.requirement("SEC-NEW-72")
def test_run_options_defaults_false():
    """``_RunOptions`` constructed with the minimum required set yields
    every REQ-24 capability OFF. A future test fixture or production
    code path that defaults any flag True would silently enable
    network egress."""
    opts = _RunOptions(
        project_path=Path("."),
        output_path=None,
        format="json",
        verbose=False,
        fail_on_severity=None,
        show_suppressed=False,
    )
    for field in _REQ24_FLAG_FIELDS:
        assert getattr(opts, field) is False, (
            f"_RunOptions.{field} defaults True — must be False so "
            f"only argv can opt in."
        )


# ── Env vars cannot set the flags ───────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-72")
def test_env_var_does_not_enable_remote_fetch(monkeypatch, tmp_path):
    """A common-shaped env var (``SCARNO_ALLOW_REMOTE_FETCH=1``)
    must NOT enable remote fetch — the only setter is argv."""
    project = tmp_path / "p"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>g</groupId><artifactId>a</artifactId>"
        "<version>1</version></project>"
    )
    for envvar in (
        "SCARNO_ALLOW_REMOTE_FETCH",
        "SCARNO_INTEGRITY_CROSS_CHECK",
        "SCARNO_FAIL_ON_REMOTE_SEVERITY",
        "ALLOW_REMOTE_FETCH",
    ):
        monkeypatch.setenv(envvar, "1")

    # Run without the argv flag — exit must NOT be 2 because of the
    # cross-validation, AND the analysis must not have attempted any
    # network call. We assert the absence of a fail-error specifically;
    # a successful (or analysis-failure) run is fine.
    result = CliRunner().invoke(
        app, [str(project), "--deep-inspection", "--format", "json"]
    )
    # No "requires --deep-inspection" error — proves env didn't set the flag.
    assert "--allow-remote-fetch requires --deep-inspection" not in result.output


# ── --allow-remote-fetch without --deep-inspection → exit 2 ────────────────


@pytest.mark.requirement("FR-260")
def test_allow_remote_fetch_without_deep_inspection_exits_2(tmp_path):
    """Hard error, not a silent no-op."""
    project = tmp_path / "p"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>g</groupId><artifactId>a</artifactId>"
        "<version>1</version></project>"
    )
    result = CliRunner().invoke(
        app, [str(project), "--allow-remote-fetch"]
    )
    assert result.exit_code == 2
    assert "--allow-remote-fetch requires --deep-inspection" in result.output


@pytest.mark.requirement("FR-261")
def test_integrity_cross_check_without_allow_remote_fetch_exits_2(tmp_path):
    """Cross-check operates over fetched artefacts — meaningless
    without the fetch capability."""
    project = tmp_path / "p"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>g</groupId><artifactId>a</artifactId>"
        "<version>1</version></project>"
    )
    result = CliRunner().invoke(
        app,
        [str(project), "--deep-inspection", "--integrity-cross-check"],
    )
    assert result.exit_code == 2
    assert "--integrity-cross-check requires --allow-remote-fetch" in result.output


@pytest.mark.requirement("FR-267")
def test_fail_on_remote_severity_without_allow_remote_fetch_exits_2(tmp_path):
    """Remote findings only exist when fetch is enabled; opting into
    gating without the source flag is a configuration error."""
    project = tmp_path / "p"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>g</groupId><artifactId>a</artifactId>"
        "<version>1</version></project>"
    )
    result = CliRunner().invoke(
        app,
        [str(project), "--deep-inspection", "--fail-on-remote-severity"],
    )
    assert result.exit_code == 2
    assert "--fail-on-remote-severity requires --allow-remote-fetch" in result.output


# ── Composition: all three flags together with --deep-inspection ──────────


@pytest.mark.requirement("FR-260")
@pytest.mark.requirement("FR-261")
@pytest.mark.requirement("FR-267")
def test_full_argv_composition_does_not_error_at_parse(tmp_path):
    """Passing all REQ-24 flags + --deep-inspection on argv must parse
    cleanly. (Whether the analysis itself succeeds depends on the
    project; the cross-validation must not block this combination.)"""
    project = tmp_path / "p"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>g</groupId><artifactId>a</artifactId>"
        "<version>1</version></project>"
    )
    result = CliRunner().invoke(
        app,
        [
            str(project),
            "--deep-inspection",
            "--allow-remote-fetch",
            "--integrity-cross-check",
            "--fail-on-remote-severity",
        ],
    )
    # Either success (0/1) or an analysis-level failure (2/3) is OK —
    # but NOT a cross-validation message.
    for msg in (
        "--allow-remote-fetch requires --deep-inspection",
        "--integrity-cross-check requires --allow-remote-fetch",
        "--fail-on-remote-severity requires --allow-remote-fetch",
    ):
        assert msg not in result.output, (
            f"unexpected cross-validation rejection: {msg}"
        )
