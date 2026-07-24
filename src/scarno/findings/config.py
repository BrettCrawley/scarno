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

"""Suppression config reader for REQ-3c.

Reads ``[tool.scarno.findings]`` from ``pyproject.toml`` and returns
the set of globally-suppressed rule IDs plus per-path overrides. Warns
on any rule ID that isn't in the authoritative catalogue (SF-010).
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from scarno.findings.rules import RULES


@dataclass
class SuppressionConfig:
    suppress: set[str] = field(default_factory=set)
    per_path: dict[str, set[str]] = field(default_factory=dict)


def load_suppression_config(
    project_root: Path,
) -> tuple[SuppressionConfig, list[str]]:
    """Return the suppression config + any parse / validation warnings."""
    errors: list[str] = []
    config = SuppressionConfig()

    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return config, errors
    try:
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        # Silently tolerate here — dep_file_parser already reports TOML
        # parse errors for pyproject.toml.
        return config, errors

    section = (
        (data.get("tool") or {}).get("scarno") or {}
    ).get("findings") or {}
    if not isinstance(section, dict):
        return config, errors

    raw_suppress = section.get("suppress")
    if isinstance(raw_suppress, list):
        for entry in raw_suppress:
            if not isinstance(entry, str):
                errors.append(
                    "pyproject.toml: [tool.scarno.findings].suppress "
                    "entries must be strings"
                )
                continue
            if entry not in RULES:
                errors.append(
                    f"pyproject.toml: [tool.scarno.findings].suppress "
                    f"references unknown rule id '{entry}'"
                )
                continue
            config.suppress.add(entry)

    raw_paths = section.get("paths")
    if isinstance(raw_paths, dict):
        for path_key, rule_list in raw_paths.items():
            if not isinstance(rule_list, list):
                continue
            acc: set[str] = set()
            for entry in rule_list:
                if isinstance(entry, str) and entry in RULES:
                    acc.add(entry)
                elif isinstance(entry, str):
                    errors.append(
                        f"pyproject.toml: [tool.scarno.findings].paths."
                        f"'{path_key}' references unknown rule id '{entry}'"
                    )
            if acc:
                config.per_path[str(path_key)] = acc
    return config, errors
