"""SRTM coverage pytest plugin.

Collects every ``@pytest.mark.requirement("<ID>")`` marker across the
test session and reports:

  * which SRTM rows are covered (≥ 1 test),
  * which SRTM rows have no test (gaps),
  * any requirement ID used in a test marker that is NOT in the authoritative
    SRTM list in ``tests/srtm.py`` (typo / unregistered requirement).

Behaviour:
  * A terminal summary section ``SRTM coverage`` is always printed.
  * A machine-readable ``srtm-coverage.json`` is written to the invocation
    directory when ``--srtm-report`` is passed.
  * When ``--srtm-fail-on-gap`` is passed, the session fails if any
    ``TEST_REQUIRED_REQUIREMENTS`` row is uncovered or any marker references
    an unknown ID. Intended for CI.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from tests.srtm import (
    STATIC_ANALYSIS_COVERED,
    TEST_REQUIRED_REQUIREMENTS,
)

_COVERAGE: dict[str, set[str]] = defaultdict(set)
_UNKNOWN_IDS: set[str] = set()


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("srtm")
    group.addoption(
        "--srtm-report",
        action="store",
        default=None,
        help="Write SRTM coverage JSON report to the given path.",
    )
    group.addoption(
        "--srtm-fail-on-gap",
        action="store_true",
        default=False,
        help="Fail the test run if any in-scope SRTM requirement has zero tests.",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Harvest requirement markers from every collected test."""
    for item in items:
        for marker in item.iter_markers(name="requirement"):
            if not marker.args:
                continue
            req_id = str(marker.args[0])
            _COVERAGE[req_id].add(item.nodeid)
            if req_id not in TEST_REQUIRED_REQUIREMENTS and req_id not in STATIC_ANALYSIS_COVERED:
                _UNKNOWN_IDS.add(req_id)


def _build_report() -> dict[str, Any]:
    covered = {req_id: sorted(nodes) for req_id, nodes in _COVERAGE.items()}
    uncovered = sorted(TEST_REQUIRED_REQUIREMENTS - _COVERAGE.keys())
    return {
        "required_total": len(TEST_REQUIRED_REQUIREMENTS),
        "covered_count": sum(
            1 for req in TEST_REQUIRED_REQUIREMENTS if req in _COVERAGE
        ),
        "uncovered": uncovered,
        "unknown_ids": sorted(_UNKNOWN_IDS),
        "static_analysis_covered": sorted(STATIC_ANALYSIS_COVERED),
        "coverage": covered,
    }


def pytest_terminal_summary(
    terminalreporter: Any, exitstatus: int, config: pytest.Config
) -> None:
    report = _build_report()
    tr = terminalreporter
    tr.section("SRTM coverage", sep="=")
    tr.write_line(
        f"requirements covered: {report['covered_count']} / {report['required_total']}"
    )
    if report["uncovered"]:
        tr.write_line("")
        tr.write_line("UNCOVERED requirements (no @pytest.mark.requirement found):")
        for req in report["uncovered"]:
            tr.write_line(f"  - {req}")
    if report["unknown_ids"]:
        tr.write_line("")
        tr.write_line(
            "UNKNOWN requirement IDs in markers (add to tests/srtm.py or fix typo):"
        )
        for req in report["unknown_ids"]:
            tr.write_line(f"  - {req}")
    if report["static_analysis_covered"]:
        tr.write_line("")
        tr.write_line(
            "Static-analysis / policy-covered (no unit test required): "
            + ", ".join(report["static_analysis_covered"])
        )

    report_path: str | None = config.getoption("--srtm-report")
    if report_path:
        Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True))
        tr.write_line("")
        tr.write_line(f"SRTM coverage JSON written to: {report_path}")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not session.config.getoption("--srtm-fail-on-gap"):
        return
    uncovered = TEST_REQUIRED_REQUIREMENTS - _COVERAGE.keys()
    problems: list[str] = []
    if uncovered:
        problems.append(
            "Uncovered SRTM requirements: " + ", ".join(sorted(uncovered))
        )
    if _UNKNOWN_IDS:
        problems.append(
            "Unknown requirement IDs in markers: " + ", ".join(sorted(_UNKNOWN_IDS))
        )
    if problems:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        # Attach to the terminal so CI logs surface the reason.
        tr = session.config.pluginmanager.get_plugin("terminalreporter")
        if tr is not None:
            tr.section("SRTM coverage failure", sep="!", red=True, bold=True)
            for p in problems:
                tr.write_line(p)
