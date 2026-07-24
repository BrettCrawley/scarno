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

"""REQ-24 — package-index configuration, coordinate validation, and
remote-artefact fetching for the cross-version ABI diff.

Public surface (what other scarno components import):

* :class:`IndexEndpoint`, :class:`IndexConfigSource` — dataclass +
  enum describing one configured package index.
* :class:`ValidatedCoordinate`, :class:`CoordinateValidator`,
  :exc:`UnknownEcosystemError` — opaque-coordinate validation
  primitives. Construction of ``ValidatedCoordinate`` is structurally
  non-bypassable (REQ-24 / SEC-NEW-59).
* :func:`resolve_indexes` — merge CLI > user-config > env into an
  ordered ``list[IndexEndpoint]`` plus audit-line warnings. The sole
  index-config entry point for the CLI / orchestrator.

Slice C/D/E components (``SafeHttpsClient``, ``RemoteArtifactFetcher``)
land in subsequent commits and will export from this package too.
"""
from __future__ import annotations

from scarno.indexing.endpoint import IndexConfigSource, IndexEndpoint
from scarno.indexing.fetcher import (
    RemoteArtifactFetcher,
    default_cache_root,
)
from scarno.indexing.http_client import (
    HttpResponse,
    SafeHttpsClient,
    SafeHttpsError,
)
from scarno.indexing.resolver import resolve_indexes
from scarno.indexing.validator import (
    CoordinateValidator,
    UnknownEcosystemError,
    ValidatedCoordinate,
)

__all__ = [
    "CoordinateValidator",
    "HttpResponse",
    "IndexConfigSource",
    "IndexEndpoint",
    "RemoteArtifactFetcher",
    "SafeHttpsClient",
    "SafeHttpsError",
    "UnknownEcosystemError",
    "ValidatedCoordinate",
    "default_cache_root",
    "resolve_indexes",
]
