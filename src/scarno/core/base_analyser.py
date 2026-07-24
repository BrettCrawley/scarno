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

"""Abstract base class for language analysers. Phase 0a stub."""
from __future__ import annotations

from abc import ABC, abstractmethod

from scarno.models import AnalysisResult


class BaseAnalyser(ABC):
    """Every language analyser must subclass this."""

    # Set to False via ``--no-gitignore`` CLI flag to skip .gitignore filtering.
    use_gitignore: bool = True
    # REQ-17 — set by orchestrator from --exclude-tests flag.
    exclude_tests: bool = False
    # REQ-17 — operator-supplied glob list (already validated by
    # ``scarno.core.test_scope.sanitise_test_paths``).
    test_paths: tuple[str, ...] = ()
    # REQ-17 — npm-only opt-in to drop devDependencies (off by default).
    exclude_dev: bool = False
    # REQ-22 — set by the orchestrator from the --deep-inspection flag.
    # JVM-only effect today (cross-version ABI diff); inert for the other
    # analysers, which simply ignore the attribute.
    deep_inspection: bool = False
    # REQ-24 — set by the orchestrator from the REQ-24 argv flags.
    # JVM-only effect today (the fetcher serves the cross-version ABI
    # diff); inert for the other analysers.
    allow_remote_fetch: bool = False
    integrity_cross_check: bool = False
    # Repeatable ``--index ECOSYSTEM=URL`` strings; parsed by
    # ``IndexConfigResolver`` inside the analyser when fetch is enabled.
    cli_indexes: tuple[str, ...] = ()
    # Repeatable ``--allow-private-index-host HOST`` argv values. Argv-only
    # (same SEC-NEW-72 pattern as the other REQ-24 capability gates).
    # Hostnames listed here are permitted to resolve to RFC 1918 / ULA
    # addresses through ``SafeHttpsClient``; every other SSRF guard
    # (loopback / link-local / CGNAT / multicast / reserved) still
    # applies, and DNS-rebinding defence (pin-resolved-IP + getpeername
    # re-check) applies identically. Hostnames not also named by an
    # ``--index`` entry are warned about but otherwise inert.
    private_index_hosts: tuple[str, ...] = ()
    # ``--native-tls``: use the OS-native trust store via the
    # ``truststore`` package (same approach as uv / pip / hatch /
    # pdm) so corporate CAs deployed to the macOS Keychain / Windows
    # cert store / Linux NSS are automatically trusted. Cert
    # verification + hostname check remain mandatory; only the trust
    # roots change. Argv-only; off by default.
    native_tls: bool = False

    @abstractmethod
    def supports(self, project_path: str) -> bool:
        """Return True if this analyser can handle the given directory."""

    @abstractmethod
    def analyse(self, project_path: str) -> AnalysisResult:
        """Run the analysis and return a result."""