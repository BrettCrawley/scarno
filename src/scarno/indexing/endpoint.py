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

"""REQ-24 — :class:`IndexEndpoint` and :class:`IndexConfigSource`.

Trivial data carriers, kept in a separate module so the
``IndexConfigResolver`` and the future ``RemoteArtifactFetcher`` can
both import them without circular dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IndexConfigSource(str, Enum):
    """Provenance of an :class:`IndexEndpoint` — recorded for the
    per-attempt audit log (FR-264) so an operator can tell which trust
    surface contributed each URL."""

    CLI = "cli"
    USER_CONFIG = "user_config"
    ENV = "env"


@dataclass(frozen=True)
class IndexEndpoint:
    """A single configured package index for one ecosystem.

    Attributes
    ----------
    ecosystem:
        Canonical ecosystem identifier (``"maven"``, ``"npm"``, …).
    url:
        ``https://`` URL of the index. HTTPS is enforced at parse time
        (:func:`scarno.indexing.resolver._validate_url`) AND at
        request time by :class:`SafeHttpsClient` (defence in depth).
    priority:
        Per-ecosystem rank. ``0`` = primary; ``1`` = first secondary;
        etc. Determined by declaration order within the source.
    source:
        Which trusted source contributed this entry.
    credential_ref:
        **Reserved for v2.** A name pointing at an external credential
        store — never the secret itself. v1 keeps this ``None`` and
        unsettable from CLI / env / config (auth is anonymous-only).
        The field exists on the model now so the future auth layer
        slots in without breaking changes (parallel to
        ``coordinate_prefix``).
    coordinate_prefix:
        **Reserved for v2.** Limits this endpoint to coordinates whose
        canonical form starts with the prefix (``"com.corp."``). v2
        surfaces it via TOML config; v1 leaves it ``None``.
    """

    ecosystem: str
    url: str
    priority: int
    source: IndexConfigSource
    credential_ref: str | None = None
    coordinate_prefix: str | None = None
