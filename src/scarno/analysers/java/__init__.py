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

"""Java / Kotlin project analyser.

Orchestrates the build-system resolver (Maven — REQ-4; Gradle — REQ-5)
and the JVM source / bytecode analyser (REQ-6) to produce a classified
:class:`AnalysisResult`.

Dispatch:
  * ``pom.xml`` present → Maven resolver runs
  * ``build.gradle`` / ``build.gradle.kts`` / ``settings.gradle(.kts)``
    present → Gradle resolver runs
  * Both present (rare but legal — a polyglot monorepo can build half
    its modules via Maven, half via Gradle) → both run; deps merged
  * Source analysis (JvmSourceAnalyser) runs over whatever deps the
    build-system resolvers produced
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from scarno.analysers.java._maven_version import declared_covers_resolved
from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
from scarno.analysers.java.gradle import GradleBuildResolver
from scarno.analysers.java.maven import (
    MavenPomResolver,
    _m2_repo_path,
    _nearest_wins_from_edges,
)
from scarno.analysers.java.source_analyser import JvmSourceAnalyser
from scarno.core import registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.core.classifier import _normalise, classify_versioned
from scarno.indexing import (
    CoordinateValidator,
    RemoteArtifactFetcher,
    SafeHttpsClient,
    UnknownEcosystemError,
    resolve_indexes,
)
from scarno.models import (
    AnalysisResult,
    Dependency,
    DepEdge,
    VersionedNode,
)


class JavaAnalyser(BaseAnalyser):
    """JVM-project analyser. Dispatches Maven + Gradle → source-analysis."""

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        return (
            (root / "pom.xml").exists()
            or (root / "build.gradle").exists()
            or (root / "build.gradle.kts").exists()
            or (root / "settings.gradle").exists()
            or (root / "settings.gradle.kts").exists()
        )

    def analyse(self, project_path: str) -> AnalysisResult:
        root = Path(project_path).resolve(strict=False)
        errors: list[str] = []
        # REQ-24 / Option 2 — the cross-check finding sink and the
        # ABI-diff finding sink share this list; pre-allocate so the
        # fetcher can be constructed BEFORE MavenPomResolver runs (so
        # POMs missing from m2 can be fetched during the transitive
        # walk, not just JARs during the ABI diff).
        findings: list[Any] = []  # list[Finding]
        dependencies: list[Dependency] = []

        has_maven = (root / "pom.xml").exists()
        has_gradle = (
            (root / "build.gradle").exists()
            or (root / "build.gradle.kts").exists()
            or (root / "settings.gradle").exists()
            or (root / "settings.gradle.kts").exists()
        )

        # REQ-24 / Option 2 — construct the fetcher early so it can
        # serve POM lookups during the Maven walk (not just JAR
        # lookups during the ABI diff). When --allow-remote-fetch is
        # off, ``fetcher`` stays None and the resolver behaves
        # identically to pre-Option-2 (m2-only).
        fetcher, endpoints = self._maybe_build_fetcher(
            root, errors, findings,
        )

        # REQ-17 / FR-152 — accumulate dep_graph from each resolver so
        # the ASCII dependency tree shows the full transitive closure.
        # (The Mermaid renderer is retained as a defensive helper but
        # is not the live render path.)
        merged_graph: dict[str, set[str]] = {}
        # REQ-19 — accumulate the version-keyed edges too. Maven's
        # resolver populates these from each direct dep's POM; the
        # per-version classifier (REQ-20) and the cross-version ABI
        # diff (REQ-22) both need them.
        dep_edges: list[DepEdge] = []

        if has_maven:
            mvn = MavenPomResolver()
            # REQ-17 — forward flags to the underlying resolver instance.
            mvn.exclude_tests = self.exclude_tests
            mvn.test_paths = self.test_paths
            mvn.exclude_dev = self.exclude_dev
            mvn.use_gitignore = self.use_gitignore
            # REQ-24 / Option 2 — pass the REQ-24 fetcher (if any) so
            # POMs missing from ~/.m2 can be fetched mid-walk via the
            # configured indexes (cache-first, audit-logged).
            mvn.fetcher = fetcher
            mvn.endpoints = endpoints
            # The resolver's legacy ``mvn dependency:get`` tier is an
            # outbound fetch too, so it needs the same operator opt-in
            # as the fetcher above. Forward the capability rather than
            # leaving the resolver on its BaseAnalyser default (False).
            mvn.allow_remote_fetch = self.allow_remote_fetch
            mvn_result = mvn.analyse(str(root))
            dependencies.extend(mvn_result.dependencies)
            errors.extend(mvn_result.errors)
            for parent, children in mvn_result.dep_graph.items():
                merged_graph.setdefault(parent, set()).update(children)
            dep_edges.extend(mvn_result.dep_edges)

        if has_gradle:
            gradle = GradleBuildResolver()
            gradle.exclude_tests = self.exclude_tests
            gradle.test_paths = self.test_paths
            gradle.exclude_dev = self.exclude_dev
            gradle.use_gitignore = self.use_gitignore
            gradle_result = gradle.analyse(str(root))
            dependencies.extend(gradle_result.dependencies)
            errors.extend(gradle_result.errors)
            for parent, children in gradle_result.dep_graph.items():
                merged_graph.setdefault(parent, set()).update(children)
            # Gradle does not yet emit version-keyed edges; this is a
            # no-op today but keeps the merge correct once it does.
            dep_edges.extend(gradle_result.dep_edges)

        if not has_maven and not has_gradle:
            errors.append(
                "java analyser: no pom.xml / build.gradle / build.gradle.kts found"
            )

        # Merge deps with identical group:artifact coordinates (Maven + Gradle
        # may both reference the same artifact). Precedence: Maven wins when
        # both populate the version; Gradle version fills a Maven None.
        dependencies = _dedup_by_coords(dependencies)

        # REQ-22 — forward --deep-inspection so the source analyser
        # spawns javap for public-API entry points; the cross-version
        # ABI diff below is gated on the same flag.
        src = JvmSourceAnalyser(deep_inspection=self.deep_inspection)
        src.exclude_tests = self.exclude_tests
        src.test_paths = self.test_paths
        src.use_gitignore = self.use_gitignore
        source_result = src.analyse(str(root), dependencies)
        errors.extend(source_result.errors)

        # REQ-20 — per-version classification. ``classify_versioned``
        # also returns a rolled-up dependency list, but we deliberately
        # keep the source analyser's classification authoritative here
        # and consume only the version-keyed output: versioned_nodes
        # drive the "Multiple versions detected" report section and the
        # ABI diff's resolved-version baseline.
        versioned_nodes: list[VersionedNode] = []
        multi_version_coords: list[str] = []
        if dep_edges:
            # ``_nearest_wins_from_edges`` keys by the raw edge child
            # name; the classifier matches on the normalised canonical
            # form, so normalise the keys before handing them over.
            resolved_versions = {
                _normalise(coord): version
                for coord, version in _nearest_wins_from_edges(
                    dep_edges
                ).items()
            }
            _, versioned_nodes, multi_version_coords = classify_versioned(
                source_result.dependencies,
                dep_edges,
                resolved_versions=resolved_versions,
                # G4 — Maven version expressions support range syntax
                # (``[1.0,2.0)``, ``(,1.5]``, ``[1.0,1.5),[1.6,2.0)``).
                # Without this comparator a range would never match the
                # concrete resolved version and every range-pinned dep
                # surfaced as a spurious multi-version conflict.
                version_match=declared_covers_resolved,
            )

        result = AnalysisResult(
            project_type="java",
            project_path=str(root),
            dependencies=source_result.dependencies,
            errors=errors,
            findings=findings,
            languages=["java"],
            dep_graph=merged_graph,
            dep_edges=dep_edges,
            versioned_nodes=versioned_nodes,
            multi_version_coords=multi_version_coords,
        )

        # REQ-22 — cross-version ABI diff. Gated on --deep-inspection
        # AND the presence of version-keyed edges. Spawns javap via the
        # source analyser's hardened, JAVA_HOME-pinned helper
        # (NEW-ARCH-011). Best-effort: a failure here degrades to a
        # warning, never an analysis failure. ``diff_all`` appends its
        # own skip reasons to ``result.errors`` (the same list object).
        if self.deep_inspection and dep_edges:
            # REQ-24 / Option 2 — lazy ``find_jar``. When fetcher is
            # wired, every (coord, version) the differ asks for is
            # eligible (no minimisation gate). The fetcher's own
            # cache-first / SSRF / checksum / fallthrough invariants
            # apply on every call. Findings derived from a fetched
            # JAR are tagged provenance="remote" by the differ.
            find_jar = self._build_lazy_find_jar(fetcher, endpoints)
            try:
                differ = CrossVersionAbiDiffer(
                    m2_root=_m2_repo_path(),
                    invoke_javap=src._invoke_javap_safe,
                    find_jar=find_jar,
                )
                # ``source_symbols`` cross-references the project's call
                # sites to escalate ABI_DRIFT → ABI_RUNTIME_RISK. The
                # JVM source analyser does not yet surface that map, so
                # findings land as ABI_DRIFT (MEDIUM) until it does.
                result.findings.extend(
                    differ.diff_all(result, source_symbols={})
                )
            except Exception as exc:  # noqa: BLE001 — never fail analysis
                result.errors.append(
                    f"abi-diff: deep inspection failed — {exc!s}"
                )

        return result

    # ── REQ-24 / Option 2 — fetcher construction + lazy find_jar ───────────

    def _maybe_build_fetcher(
        self,
        project_root: Path,
        errors: list[str],
        findings: list[Any],
    ) -> tuple[object | None, list[Any]]:
        """Build the REQ-24 fetcher if ``--allow-remote-fetch`` is on
        and at least one index resolved. Returns ``(fetcher, endpoints)``
        — both may be ``(None, [])`` when fetch is disabled or no
        indexes are configured.

        Construction happens BEFORE ``MavenPomResolver`` runs (Option 2
        change — H3) so the same fetcher serves POM lookups during the
        transitive walk AND JAR lookups during the ABI diff. The
        ``warnings`` and ``findings`` lists passed to the fetcher are
        the very lists that will become ``AnalysisResult.errors`` and
        ``AnalysisResult.findings`` — append-throughs land in the
        rendered report directly.
        """
        if not self.allow_remote_fetch:
            return None, []
        endpoints, resolver_warnings = resolve_indexes(
            cli_indexes=list(self.cli_indexes),
            fetch_enabled=True,
            project_root=project_root,
        )
        errors.extend(resolver_warnings)
        if not endpoints:
            errors.append(
                "req24-fetch: --allow-remote-fetch set but no "
                "indexes configured; cache-miss artefacts cannot be "
                "fetched (pass --index, populate "
                "~/.config/scarno/config.toml, or set "
                "SCARNO_INDEX_<ECO>)."
            )
            return None, []
        client = SafeHttpsClient(
            private_index_hosts=tuple(self.private_index_hosts),
            native_tls=bool(self.native_tls),
        )
        fetcher = RemoteArtifactFetcher(
            client=client,
            warnings=errors,
            cross_check=self.integrity_cross_check,
            findings=findings,
        )
        # REQ-24 — N-3 / N-8 startup warnings about cross-check usage.
        self._emit_cross_check_advice_to(errors, endpoints)
        # REQ-24 — surface any allow-list entries that don't match a
        # configured index host (most common: typo, or a host the
        # operator forgot to also list under --index). Inert — the
        # allowance only takes effect when the host actually receives
        # a fetch attempt — but worth flagging.
        self._emit_private_host_advice_to(errors, endpoints)
        return fetcher, endpoints

    def _build_lazy_find_jar(
        self,
        fetcher: object | None,
        endpoints: list[Any],
    ) -> Callable[[str, str], Path | None] | None:
        """Return a lazy ``find_jar`` callable for
        :class:`CrossVersionAbiDiffer`. The callable validates the
        coordinate and delegates to ``fetcher.fetch`` — which itself
        does cache-first lookup (quarantined cache → network). The
        ABI differ's own m2-first ordering (H4 in abi_diff.py) means
        ``find_jar`` is only invoked on m2-misses, so the network is
        never hit for artefacts already in ``~/.m2``.

        Returns ``None`` when fetch is disabled — ``CrossVersionAbiDiffer``
        then falls back to its m2-only behaviour.
        """
        if fetcher is None or not endpoints:
            return None

        def _find(coord_str: str, version: str) -> Path | None:
            try:
                vc = CoordinateValidator.validate("maven", coord_str)
            except (ValueError, UnknownEcosystemError):
                # Coordinate failed validation — log nothing here (the
                # fetcher's own audit channel only fires on actual
                # network attempts; coord-validation rejection is a
                # silent miss, identical to "not in cache").
                return None
            result: Path | None = fetcher.fetch(  # type: ignore[attr-defined]
                vc, version, endpoints,
            )
            return result

        return _find

    # ── REQ-24 — private-host allow-list startup advice ────────────────────

    def _emit_private_host_advice_to(
        self,
        errors: list[str],
        endpoints: list[Any],
    ) -> None:
        """Warn when ``--allow-private-index-host`` names a host that
        isn't backing any configured ``--index`` entry. The allowance
        is still inert (it only fires when that host receives a fetch
        attempt), but a mismatch is almost always a typo or a forgotten
        ``--index`` and worth surfacing in the audit channel."""
        if not self.private_index_hosts:
            return
        from urllib.parse import urlparse
        index_hosts: set[str] = set()
        for ep in endpoints:
            try:
                host = urlparse(ep.url).hostname or ""
            except (ValueError, AttributeError):
                host = ""
            if host:
                index_hosts.add(host.lower())
        allow_listed = {
            h.strip().lower() for h in self.private_index_hosts
            if h and h.strip()
        }
        orphaned = sorted(allow_listed - index_hosts)
        for host in orphaned:
            errors.append(
                f"req24-fetch: --allow-private-index-host "
                f"{host!r} does not match any configured --index "
                "host; the allowance is inert until you also register "
                "an index for this host."
            )

    # ── REQ-24 — N-3 / N-8 startup warnings ────────────────────────────────

    def _emit_cross_check_advice_to(
        self,
        errors: list[str],
        endpoints: list[Any],
    ) -> None:
        """REQ-24 N-3 + N-8 — surface cross-check (mis)configurations
        the operator may want to act on.

        N-3: ``--allow-remote-fetch`` is set + ≥2 endpoints for some
        ecosystem + ``--integrity-cross-check`` is OFF → suggest
        enabling cross-check.
        N-8: ``--integrity-cross-check`` is set + <2 endpoints for some
        ecosystem → cross-check is a no-op for that ecosystem; warn so
        the operator doesn't believe they have a control they don't.

        Renamed from ``_emit_cross_check_advice`` (took an
        ``AnalysisResult``) — Option 2 calls this BEFORE the result is
        constructed, so the advice goes into the pre-allocated
        ``errors`` list directly.
        """
        endpoints_by_eco: dict[str, int] = {}
        for ep in endpoints:
            endpoints_by_eco[ep.ecosystem] = (
                endpoints_by_eco.get(ep.ecosystem, 0) + 1
            )
        if not self.integrity_cross_check:
            ecosystems_with_two = [
                eco for eco, n in endpoints_by_eco.items() if n >= 2
            ]
            for eco in sorted(ecosystems_with_two):
                errors.append(
                    f"req24-fetch: indexes for {eco!r} could be "
                    "cross-checked; pass --integrity-cross-check to "
                    "verify byte-identical artefacts across indexes "
                    "(SEC-NEW-71 / N-3)."
                )
        else:
            ecosystems_without_two = [
                eco for eco, n in endpoints_by_eco.items() if n < 2
            ]
            for eco in sorted(ecosystems_without_two):
                errors.append(
                    f"req24-fetch: --integrity-cross-check set but only "
                    f"{endpoints_by_eco[eco]} index for {eco!r}; "
                    "cross-check is a no-op for this ecosystem (N-8)."
                )


def _dedup_by_coords(deps: list[Dependency]) -> list[Dependency]:
    """Collapse duplicate ``group:artifact`` entries across Maven + Gradle."""
    by_key: dict[str, Dependency] = {}
    for dep in deps:
        key = dep.name  # "group:artifact"
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = dep
            continue
        # Prefer the dep carrying a version; prefer maven ecosystem when
        # both carry versions (the pom's declaration is usually more
        # authoritative than a gradle ext-var reference).
        if existing.version is None and dep.version is not None:
            by_key[key] = dep
        elif (
            existing.version is not None
            and dep.version is not None
            and existing.ecosystem == "gradle"
            and dep.ecosystem == "maven"
        ):
            by_key[key] = dep
    return list(by_key.values())


# REQ-9 — self-register with the core registry on import.
registry.register("java", JavaAnalyser)

# REQ-19a / NEW-ARCH-012 — Maven has <exclusions> + <dependencyManagement>;
# Gradle has force / strictly / constraints / resolutionStrategy /
# exclude. Both ecosystems registered as pin-detector placeholders;
# REQ-21 (PR-3) ships the real Maven detector, REQ-21b (PR-6) ships
# the Gradle detector. Until then Dependency.pin_override stays
# False on every dep so SUC-42 enforcement is inert.
from scarno.core import classifier as _classifier  # noqa: E402
_classifier.register_pin_detector("java")
_classifier.register_pin_detector("maven")
_classifier.register_pin_detector("gradle")
