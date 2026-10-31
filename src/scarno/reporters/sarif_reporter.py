# Copyright 2026 Brett Crawley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""SARIF 2.1.0 report — for GitHub Code Scanning, SonarQube, Azure DevOps.

Emits a single-run SARIF log. The ``tool.driver.rules`` array is
derived from the REQ-3c rule catalogue plus four synthesised dep-status
rules so that ``SAFE`` / ``UNDECLARED`` / ``UNCERTAIN`` classifications
appear alongside security findings in any SARIF-aware viewer.

Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

Safety:
  * All user-derived strings pass through :func:`sanitise` (SEC-003,
    SEC-NEW-03) before reaching the JSON buffer.
  * JSON is serialised via ``json.dumps`` (SEC-004) — no f-string
    interpolation into the output.
  * URIs use forward slashes and are POSIX-relative; backslashes in
    paths (e.g. on Windows) are normalised, and characters that are not
    legal in a URI reference (spaces, non-ASCII) are percent-encoded.

GitHub Code Scanning compatibility:
  * GitHub validates uploads against the SARIF 2.1.0 schema, so a
    ``logicalLocations`` key directly on a result rejects the whole
    file. Logical locations live inside ``result.locations[]``.
  * GitHub also rejects any result without a ``physicalLocation``
    ("expected at least one location"), which the schema itself allows.
    Every result therefore carries one. Dependency results point at the
    file that declares the dependency, or, for an undeclared import, at
    the manifest it should be declared in. A result with no file to
    point at is left out of ``results`` and counted in
    ``run.properties.resultsWithoutLocation``.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import quote

from scarno import __version__ as _SCARNO_VERSION
from scarno.findings.rules import RULES
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
    FindingSeverity,
)
from scarno.reporters._remote_banner import compute_state
from scarno.security import sanitise

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_INFORMATION_URI = "https://github.com/BrettCrawley/scarno"
# RFC 3986 characters left unencoded in a path: unreserved, sub-delims,
# ":" and "@" (pchar), plus "/" as the segment separator.
_URI_PATH_SAFE = "/:@!$&'()*+,;=-._~"


# SARIF level mapping. SARIF defines four: "error", "warning", "note", "none".
_SEVERITY_TO_LEVEL: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
}

# Synthesised rules for dep statuses. These live alongside the REQ-3c
# rules so SARIF consumers can show them as a single unified feed.
_DEP_RULES: dict[str, dict[str, str]] = {
    "TS-DEP-SAFE": {
        "name": "SafeToRemoveDependency",
        "short": "Dependency declared but not used",
        "full": (
            "No import or usage of this dependency was found in the project's "
            "source. Consider removing it to reduce CVE surface and build time."
        ),
        "level": "note",
    },
    "TS-DEP-UNCERTAIN": {
        "name": "UncertainDependency",
        "short": "Dynamic or reflective usage — manual review required",
        "full": (
            "Scarno detected a dynamic import (importlib / __import__ / "
            "reflection) that may reference this dependency. Manual review "
            "required before removal."
        ),
        "level": "note",
    },
    "TS-DEP-UNDECLARED": {
        "name": "UndeclaredImport",
        "short": "Import not present in any dependency file",
        "full": (
            "An import resolves to a package that is not declared in "
            "requirements.txt, pyproject.toml, or any other recognised "
            "dependency file. This is a latent breakage risk."
        ),
        "level": "warning",
    },
    # REQ-17 — IN_USE dep with entry-point usage_count carried in properties.
    "TS-DEP-INUSE": {
        "name": "DependencyInUse",
        "short": "Dependency is used by project source",
        "full": (
            "Project source imports this dependency. Per-symbol usage counts "
            "are surfaced in result.properties.entry_points so SARIF "
            "consumers can sort/group by call frequency."
        ),
        "level": "note",
    },
    # REQ-20 / FR-207 — coordinate present at >1 declared version.
    "TS-DEP-MULTI-VERSION": {
        "name": "MultipleVersionsDetected",
        "short": "Coordinate present at multiple declared versions",
        "full": (
            "The dependency graph contains multiple declared versions of "
            "this coordinate. SBOM consumers should match vulnerabilities "
            "against the resolved version only; other declared versions "
            "may be removable depending on which parents reach them."
        ),
        "level": "note",
    },
    # REQ-21 / FR-215 — Maven pin-override (exclusion or DM).
    "TS-DEP-PIN-OVERRIDE-MAVEN": {
        "name": "MavenPinOverride",
        "short": "Direct Maven dependency is a load-bearing pin",
        "full": (
            "This direct <dependency> is kept on the classpath as a "
            "substitute for an excluded or dependencyManagement-pinned "
            "transitive. Removing it would silently re-introduce the "
            "substituted version."
        ),
        "level": "note",
    },
    # REQ-23 / FR-246 — npm pin-override (overrides / resolutions / pnpm).
    "TS-DEP-PIN-OVERRIDE-NPM": {
        "name": "NpmPinOverride",
        "short": "Direct npm dependency is a load-bearing pin",
        "full": (
            "This direct npm dependency is the target of an "
            "``overrides`` / ``resolutions`` / ``pnpm.overrides`` "
            "directive. Removing it would silently re-allow the "
            "previous version to resolve."
        ),
        "level": "note",
    },
    # REQ-21b / FR-225 — Gradle pin-override. Dual severity: 'note'
    # for static kinds (force / strictly / constraints / exclude);
    # 'warning' for GRADLE_DYNAMIC_PIN per R-Phase9-02 so operator CI
    # dashboards highlight the dynamic case.
    "TS-DEP-PIN-OVERRIDE-GRADLE": {
        "name": "GradlePinOverride",
        "short": "Direct Gradle dependency is a load-bearing pin",
        "full": (
            "This direct dependency is kept on the classpath by a "
            "Gradle resolution-strategy directive (force / strictly / "
            "constraints / eachDependency / exclude). When the target "
            "version is computed dynamically the SARIF level is "
            "'warning' rather than 'note' to surface the higher "
            "review-required signal."
        ),
        "level": "note",
    },
}


def _clean(value: str) -> str:
    return sanitise(value)


def _uri(path: str) -> str:
    """Normalise a file path to a POSIX-relative SARIF URI reference."""
    return quote(_clean(path.replace("\\", "/")), safe=_URI_PATH_SAFE)


def _directory_uri(path: str) -> str:
    """An absolute directory path as a ``file:`` URI with a trailing slash.

    SARIF 3.4.3 wants ``workingDirectory`` to be an absolute URI. A bare
    path is not one. Relative paths keep the plain relative form.
    """
    cleaned = _clean(path)
    if PureWindowsPath(cleaned).drive:
        posix = "/" + cleaned.replace("\\", "/")
    elif PurePosixPath(cleaned).is_absolute():
        posix = cleaned
    else:
        return _uri(cleaned.rstrip("/\\") + "/")
    return "file://" + quote(posix.rstrip("/") + "/", safe=_URI_PATH_SAFE)


def _dep_file(dep: Dependency) -> str | None:
    """The file that declares *dep*, or None for a detected-only dep."""
    if not dep.source or dep.source == "unknown" or dep.source.startswith("detected:"):
        return None
    return dep.source.split(":", 1)[0] or None


def _manifest_by_ecosystem(deps: list[Dependency]) -> tuple[dict[str, str], str | None]:
    """The most-used declaring file per ecosystem, plus the overall one.

    An undeclared import has no declaring file. Its natural location is
    the manifest it should be added to. Ties break alphabetically so the
    output is deterministic.
    """
    per_eco: dict[str, Counter[str]] = {}
    overall: Counter[str] = Counter()
    for dep in deps:
        file_ = _dep_file(dep)
        if file_ is None:
            continue
        per_eco.setdefault((dep.ecosystem or "").lower(), Counter())[file_] += 1
        overall[file_] += 1

    def _top(c: Counter[str]) -> str:
        return min(c, key=lambda k: (-c[k], k))

    return {eco: _top(c) for eco, c in per_eco.items()}, (
        _top(overall) if overall else None
    )


def _file_location(file_: str) -> dict[str, Any]:
    return {"physicalLocation": {"artifactLocation": {"uri": _uri(file_)}}}


def _remote_provenance_summary(result: AnalysisResult) -> dict[str, Any]:
    """REQ-24 / FR-266 — structured banner data on the SARIF run."""
    state = compute_state(result)
    return {
        "active": state.is_active,
        "fetchCount": state.fetch_count,
        "remoteFindingCount": state.remote_finding_count,
    }


def _build_rule_descriptor(rule_id: str) -> dict[str, Any]:
    rule = RULES[rule_id]
    return {
        "id": rule.rule_id,
        "name": _clean(rule.kind.value),
        "shortDescription": {"text": _clean(rule.message)},
        "fullDescription": {"text": _clean(rule.message)},
        "help": {"text": _clean(rule.remediation)},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL[rule.severity],
        },
        "properties": {
            "severity": rule.severity.value,
            "kind": rule.kind.value,
        },
    }


def _build_dep_rule_descriptor(rule_id: str) -> dict[str, Any]:
    data = _DEP_RULES[rule_id]
    return {
        "id": rule_id,
        "name": data["name"],
        "shortDescription": {"text": data["short"]},
        "fullDescription": {"text": data["full"]},
        "defaultConfiguration": {"level": data["level"]},
        "properties": {"kind": "dependency_status"},
    }


def _finding_to_result(
    finding: Finding, fallback_file: str | None = None
) -> dict[str, Any]:
    """A finding as a SARIF result.

    A finding with no file (the REQ-22 ABI findings are about a resolved
    artefact, not a source line) is placed on *fallback_file*, the
    manifest that declares the package, with no region. With neither, the
    result has no location and the caller drops it.
    """
    locations: list[dict[str, Any]]
    if finding.file_path:
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(finding.file_path)},
                    "region": {
                        "startLine": max(1, finding.line),
                        "snippet": {"text": _clean(finding.snippet)},
                    },
                }
            }
        ]
    elif fallback_file is not None:
        locations = [_file_location(fallback_file)]
    else:
        locations = []
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": _clean(finding.message)},
        "locations": locations,
        "properties": {
            "severity": finding.severity.value,
            "kind": finding.kind.value,
            "remediation": _clean(finding.remediation),
        },
    }
    if finding.package_hint:
        result["properties"]["packageHint"] = _clean(finding.package_hint)
    if finding.suppressed:
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": "Suppressed via Scarno inline or config suppression.",
            }
        ]
    return result


def _dep_to_result(
    dep: Dependency, fallback_file: str | None = None
) -> dict[str, Any] | None:
    """Convert an IN_USE/SAFE/UNCERTAIN/UNDECLARED dep to a SARIF result.

    IN_USE deps don't become results (nothing to flag); SAFE deps become
    ``note``-level results; UNDECLARED become ``warning``; UNCERTAIN
    become ``note``. The ``locations`` field is a single location
    pointing at the dep-file source (e.g. ``requirements.txt``), or at
    *fallback_file* for a detected-only dep. GitHub Code Scanning
    rejects a result without one.
    """
    rule_id_map = {
        DependencyStatus.SAFE: "TS-DEP-SAFE",
        DependencyStatus.UNCERTAIN: "TS-DEP-UNCERTAIN",
        DependencyStatus.UNDECLARED: "TS-DEP-UNDECLARED",
        DependencyStatus.IN_USE: "TS-DEP-INUSE",
    }
    rule_id = rule_id_map.get(dep.status)
    if rule_id is None:
        return None
    # REQ-17 — IN_USE deps only emit a SARIF result when they have at least
    # one used entry point worth tallying.
    if dep.status is DependencyStatus.IN_USE and not any(
        ep.used for ep in dep.entry_points
    ):
        return None
    label = dep.name + (f"=={dep.version}" if dep.version else "")
    message = _clean(f"{label}: {dep.reason}") if dep.reason else _clean(label)
    level = _DEP_RULES[rule_id]["level"]

    properties: dict[str, Any] = {
        "package": _clean(dep.name),
        "version": _clean(dep.version) if dep.version else None,
        "status": dep.status.value,
        "source": _clean(dep.source),
    }
    # REQ-17 — symbol-usage tally for IN_USE results.
    if dep.entry_points:
        properties["entry_points"] = [
            {
                "name": _clean(ep.name),
                "kind": _clean(ep.kind),
                "used": ep.used,
                "usage_count": ep.usage_count,
            }
            for ep in dep.entry_points
        ]
    if dep.imported_directly:
        properties["imported_directly"] = True

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "properties": properties,
    }
    # The location is the declaring file (``requirements.txt``,
    # ``pyproject.toml:project`` → ``pyproject.toml``, ...). The caller
    # supplies a fallback for detected-only deps; with neither, the
    # result has no location and the caller drops it.
    file_ = _dep_file(dep) or fallback_file
    if file_ is not None:
        result["locations"] = [_file_location(file_)]
    return result


class SarifReporter:
    """Render an :class:`AnalysisResult` as a SARIF 2.1.0 JSON string."""

    def render(self, result: AnalysisResult) -> str:
        # Rule descriptors — every REQ-3c rule plus the four dep rules,
        # regardless of whether this run produced a matching result.
        # SARIF consumers use the rules array for display metadata.
        rules: list[dict[str, Any]] = [
            _build_rule_descriptor(rule_id) for rule_id in sorted(RULES.keys())
        ]
        rules.extend(
            _build_dep_rule_descriptor(rule_id) for rule_id in sorted(_DEP_RULES.keys())
        )

        manifest_for_eco, any_manifest = _manifest_by_ecosystem(result.dependencies)

        def _fallback(dep: Dependency) -> str | None:
            return manifest_for_eco.get((dep.ecosystem or "").lower(), any_manifest)

        def _package_location(name: str, file_: str | None) -> list[dict[str, Any]]:
            if file_ is None:
                return []
            loc = _file_location(file_)
            loc["logicalLocations"] = [{"name": _clean(name), "kind": "package"}]
            return [loc]

        deps_by_name: dict[str, Dependency] = {}
        for dep in result.dependencies:
            deps_by_name.setdefault(dep.name, dep)

        results: list[dict[str, Any]] = []
        for finding in result.findings:
            hinted = deps_by_name.get(finding.package_hint or "")
            finding_fallback = (
                (_dep_file(hinted) or _fallback(hinted)) if hinted else any_manifest
            )
            results.append(_finding_to_result(finding, finding_fallback))
        for dep in result.dependencies:
            converted = _dep_to_result(dep, _fallback(dep))
            if converted is not None:
                results.append(converted)
        # REQ-21 / 21b / 23 — pin-override SARIF results, one per
        # pin_override dep, with the rule-id selected per ecosystem.
        # PR-6: gradle ecosystem now has its own rule; dual severity
        # depending on pin_override_kind. A Maven-style pin that
        # happens to have ecosystem="java" but GRADLE_* kind also
        # routes to the Gradle rule.
        _PIN_OVERRIDE_RULE_BY_ECO = {
            "maven": "TS-DEP-PIN-OVERRIDE-MAVEN",
            "java": "TS-DEP-PIN-OVERRIDE-MAVEN",
            "gradle": "TS-DEP-PIN-OVERRIDE-GRADLE",
            "npm": "TS-DEP-PIN-OVERRIDE-NPM",
            "javascript": "TS-DEP-PIN-OVERRIDE-NPM",
        }
        for dep in result.dependencies:
            if not dep.pin_override:
                continue
            eco = (dep.ecosystem or "").lower()
            rule_id = _PIN_OVERRIDE_RULE_BY_ECO.get(eco)
            # Gradle kind on a "java" ecosystem dep → still use the
            # Gradle rule (the kind is the authoritative discriminator).
            if (dep.pin_override_kind or "").startswith("GRADLE_"):
                rule_id = "TS-DEP-PIN-OVERRIDE-GRADLE"
            if rule_id is None:
                continue
            # R-Phase9-02 — dynamic Gradle pins are 'warning', not 'note'.
            level = (
                "warning"
                if dep.pin_override_kind == "GRADLE_DYNAMIC_PIN"
                else "note"
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": _clean(
                            f"{dep.name}: {dep.pin_override_kind} — "
                            f"{dep.pin_override_target or ''}"
                        ),
                    },
                    "locations": _package_location(
                        dep.name, _dep_file(dep) or _fallback(dep)
                    ),
                    "properties": {
                        "kind": "pin_override",
                        "pinOverrideKind": _clean(
                            dep.pin_override_kind or ""
                        ),
                        "pinOverrideTarget": _clean(
                            dep.pin_override_target or ""
                        ),
                        "ecosystem": _clean(dep.ecosystem or ""),
                    },
                }
            )
        # REQ-20 / FR-207 — one TS-DEP-MULTI-VERSION result per
        # coordinate present at >1 declared version.
        for coord in (result.multi_version_coords or []):
            owner = deps_by_name.get(coord)
            coord_file = (
                (_dep_file(owner) or _fallback(owner)) if owner else any_manifest
            )
            results.append(
                {
                    "ruleId": "TS-DEP-MULTI-VERSION",
                    "level": "note",
                    "message": {
                        "text": _clean(
                            f"Coordinate {coord} is declared at multiple "
                            f"versions; see report 'Multiple versions "
                            f"detected' for the full table."
                        ),
                    },
                    "locations": _package_location(coord, coord_file),
                    "properties": {
                        "kind": "multi_version",
                        "coordinate": _clean(coord),
                    },
                }
            )

        # GitHub Code Scanning rejects the whole upload if any result lacks
        # a physical location. A result with no file to point at (no
        # finding file, no manifest anywhere in the run) is dropped and
        # counted instead.
        located = [r for r in results if r.get("locations")]
        without_location = len(results) - len(located)
        results = located

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "scarno",
                    "version": _SCARNO_VERSION,
                    "informationUri": _INFORMATION_URI,
                    "rules": rules,
                }
            },
            "invocations": [
                {
                    "executionSuccessful": True,
                    "workingDirectory": {
                        "uri": _directory_uri(result.project_path)
                    },
                }
            ],
            "results": results,
            "properties": {
                "projectType": _clean(result.project_type),
                "projectPath": _clean(result.project_path),
                "errorCount": len(result.errors),
                "resultsWithoutLocation": without_location,
                # REQ-9 — every ecosystem scanned in this run.
                "languages": [_clean(lang) for lang in result.languages],
                # REQ-24 / FR-266 — structured banner data on the run
                # so SARIF consumers (Code Scanning, third-party
                # dashboards) can flag network-augmented analysis.
                "remoteProvenance": _remote_provenance_summary(result),
            },
        }
        notifications: list[dict[str, Any]] = [
            {"message": {"text": _clean(e)}} for e in result.errors
        ]
        if without_location:
            notifications.append({
                "level": "warning",
                "message": {"text": (
                    f"{without_location} result(s) left out: no file to attach "
                    "them to, and GitHub Code Scanning rejects a result "
                    "without one. The JSON report lists them."
                )},
            })
        if notifications:
            run["invocations"][0]["toolExecutionNotifications"] = notifications

        payload: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [run],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)
