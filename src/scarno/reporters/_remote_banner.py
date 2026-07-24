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

"""REQ-24 / FR-266 — top-of-report banner helper.

Centralised so the four reporters (text, markdown, json, sarif)
can render the same provenance summary from a single source of truth.

The banner surfaces:
  * how many artefacts were fetched from a non-cache index, and
  * how many findings have ``provenance="remote"``,

so an operator scanning the report knows immediately that the
verdict was network-augmented (consistency with TS-SI-008 /
TS-SI-015 for *other projects'* custom registries — scarno
should not let its own remote fetches be invisible).
"""
from __future__ import annotations

from dataclasses import dataclass

from scarno.models import AnalysisResult


# Prefix for per-attempt success audit lines emitted by
# ``RemoteArtifactFetcher._try_endpoint``. We count distinct fetches
# from this prefix rather than from the disclosure line so retried /
# secondary fetches are accounted for accurately.
_FETCH_SUCCESS_PREFIX: str = "req24-fetch: fetched "


@dataclass(frozen=True)
class RemoteBannerState:
    """Pre-computed counts a reporter renders into its banner."""

    fetch_count: int
    remote_finding_count: int

    @property
    def is_active(self) -> bool:
        return self.fetch_count > 0 or self.remote_finding_count > 0


def compute_state(result: AnalysisResult) -> RemoteBannerState:
    """Return the banner state derived from ``result``."""
    fetch_count = sum(
        1 for line in result.errors
        if line.startswith(_FETCH_SUCCESS_PREFIX)
    )
    remote_finding_count = sum(
        1 for f in result.findings
        if not f.suppressed and f.provenance == "remote"
    )
    return RemoteBannerState(
        fetch_count=fetch_count,
        remote_finding_count=remote_finding_count,
    )


def text_banner(state: RemoteBannerState) -> str | None:
    """Return the banner string for the text + markdown reporters,
    or ``None`` when no remote activity took place."""
    if not state.is_active:
        return None
    return (
        f"This analysis fetched {state.fetch_count} artefact(s) from "
        f"non-cache indexes; {state.remote_finding_count} finding(s) "
        f"have provenance=remote (verdict depended on network trust — "
        f"see --fail-on-remote-severity to gate CI on these)."
    )
