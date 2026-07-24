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

"""JSON report formatter.

Structured output for CI pipelines. Everything goes through
``json.dumps`` with ``ensure_ascii=False`` — never f-string
interpolation — so adversarial dep names cannot break the JSON shape
(SEC-004). All user-derived strings pass through ``sanitise`` first so
ANSI escapes and control bytes never reach the output buffer
(SEC-003 / SEC-NEW-03).
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from scarno import __version__ as _SCARNO_VERSION
from scarno.models import AnalysisResult, Dependency, EntryPoint, Finding
from scarno.reporters._remote_banner import compute_state
from scarno.security import sanitise


def _clean(value: Any) -> Any:
    """Recursively sanitise strings in nested dict/list/primitive values."""
    if isinstance(value, str):
        return sanitise(value)
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items()}
    return value


def _dep_to_dict(dep: Dependency) -> dict[str, Any]:
    # ``status`` is a StrEnum — asdict renders its value. Same for EntryPoint.
    cleaned: dict[str, Any] = _clean(asdict(dep))
    return cleaned


def _ep_to_dict(ep: EntryPoint) -> dict[str, Any]:
    cleaned: dict[str, Any] = _clean(asdict(ep))
    return cleaned


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    cleaned: dict[str, Any] = _clean(asdict(f))
    return cleaned


class JsonReporter:
    """Render an :class:`AnalysisResult` as a JSON string."""

    def render(self, result: AnalysisResult) -> str:
        # REQ-17 — flatten dep_graph (dict[str, set[str]]) to plain JSON
        # types: sets become sorted lists so the output is deterministic.
        # Every key and value passes through sanitise().
        dep_graph_json: dict[str, list[str]] = {
            sanitise(parent): sorted(sanitise(c) for c in children)
            for parent, children in result.dep_graph.items()
        }
        payload: dict[str, Any] = {
            "scarno_version": _SCARNO_VERSION,
            "analysis_timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "project_type": sanitise(result.project_type),
            "project_path": sanitise(result.project_path),
            # REQ-9 — every ecosystem scanned, in detection order.
            "languages": [sanitise(lang) for lang in result.languages],
            "dependencies": [_dep_to_dict(d) for d in result.dependencies],
            "errors": [sanitise(e) for e in result.errors],
            "findings": [_finding_to_dict(f) for f in result.findings],
            # REQ-17 — adjacency map for downstream visualisations.
            "dep_graph": dep_graph_json,
            # REQ-20 — per-version classifier output. ``versioned_nodes``
            # is one record per (coordinate, declared_version);
            # ``multi_version_coords`` lists the coordinates present at
            # more than one version. Both empty when the analysed
            # ecosystem does not emit version-keyed edges.
            "versioned_nodes": [
                _clean(asdict(n)) for n in result.versioned_nodes
            ],
            "multi_version_coords": [
                sanitise(c) for c in result.multi_version_coords
            ],
            # REQ-24 / FR-266 — structured banner data so downstream
            # tooling can detect a network-augmented analysis without
            # parsing prose. ``active`` is True when any artefact was
            # fetched OR any finding has provenance="remote".
            "remote_provenance": {
                "active": compute_state(result).is_active,
                "fetch_count": compute_state(result).fetch_count,
                "remote_finding_count":
                    compute_state(result).remote_finding_count,
            },
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)
