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

"""Maven POM hierarchy resolver — REQ-4.

Parses ``pom.xml`` and traverses parent / child relationships, expands
``<dependencyManagement>`` sections (including BOM imports), and
produces a flat list of :class:`Dependency` objects for every declared
dep across a single-module or multi-module project.

Safety:
  * Uses ``xml.etree.ElementTree`` (stdlib) for POM parsing.
  * Rejects any ``<!DOCTYPE`` declaration outright so XXE and
    entity-expansion (billion-laughs) attacks are blocked before parse
    time (SEC-NEW-01, T-02, D-02).
  * Parent POM ``<relativePath>`` is confined to the project root's
    parent directory — sibling / grandparent POMs are allowed
    (a common monorepo layout) but traversal beyond that is blocked
    (T-07, SEC-002).
  * Module and parent traversal both cycle-detect by resolved path
    (SEC-NEW-08, D-06) and cap depth (``_MAX_MODULE_DEPTH``,
    ``_MAX_PARENT_DEPTH``) to bound runtime.

Parent / BOM POM resolution tiers (FR-131, FR-132, FR-133):
  1. Filesystem ``<relativePath>`` (confined to project root's parent).
  2. Local Maven cache ``~/.m2/repository`` lookup by GAV coordinates
     (SEC-NEW-27 — GAV validated, path confined to repo root).
  3. ``mvn dependency:get`` CLI fallback — downloads the POM into the
     local cache, then re-reads via tier 2 (SEC-NEW-28 — binary
     resolution confined to ``$MAVEN_HOME``). This tier makes an
     outbound network request for coordinates read out of the
     analysed project's own ``pom.xml``, so it is gated on the
     ``--allow-remote-fetch`` capability exactly like the REQ-24
     fetcher tier — see
     :meth:`MavenPomResolver._locate_or_fetch_pom`. Without the flag
     the resolver performs zero network calls.

Each tier degrades gracefully: missing cache → skip; missing ``mvn``
binary → skip; invalid GAV → skip with error.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 — wrapped with strict argv validation
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from scarno.core.base_analyser import BaseAnalyser
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    DepEdge,
)
from scarno.security import (
    MAX_FILE_BYTES,
    PathEscapeError,
    resolve_and_confine,
    sanitise_declared_version,
)

_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"
_MAX_MODULE_DEPTH = 20
# FR-152 — transitive Maven dep_graph traversal cap. Bounds worst-case
# work when a project pulls in a large dep tree from ``~/.m2/repository``.
# Bumped 1000 → 2000 to absorb wider real-world Spring / Jakarta dep
# graphs without elision; T-21 mitigation (path confinement +
# _validate_gav strict pre-check + DOCTYPE rejection) is unaffected
# by the cap value.
_MAX_TRANSITIVE_NODES = 2000
_MAX_PARENT_DEPTH = 30
_MAX_PROPERTY_EXPANSION_PASSES = 10
_MVN_TIMEOUT_SEC = 60
_DOCTYPE_RE = re.compile(r"<!DOCTYPE\b", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\$\{([^}]+)\}")
# Maven GAV segment: starts with alnum, may contain alnum/dot/hyphen/underscore.
_GAV_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


# ── GAV validation & cache helpers ─────────────────────────────────────────


def _is_valid_gav_component(value: str) -> bool:
    """Return ``True`` if *value* is a safe Maven coordinate segment."""
    if not value or len(value) > 256:
        return False
    if "\x00" in value or "/" in value or "\\" in value:
        return False
    if ".." in value:
        return False
    return _GAV_COMPONENT_RE.match(value) is not None


def _validate_gav(coords: tuple[str, str, str]) -> bool:
    """Return ``True`` if all three GAV components are valid."""
    return all(_is_valid_gav_component(c) for c in coords)


def _m2_repo_path() -> Path:
    """Return the default Maven local-repository root."""
    return Path.home() / ".m2" / "repository"


def _gav_to_pom_path(
    repo_root: Path, group_id: str, artifact_id: str, version: str
) -> Path:
    """Convert GAV coordinates to the Maven local-repository POM path."""
    group_path = group_id.replace(".", os.sep)
    return repo_root / group_path / artifact_id / version / f"{artifact_id}-{version}.pom"


def _gav_to_jar_path(
    repo_root: Path, group_id: str, artifact_id: str, version: str
) -> Path:
    """Convert GAV coordinates to the Maven local-repository JAR path."""
    group_path = group_id.replace(".", os.sep)
    return repo_root / group_path / artifact_id / version / f"{artifact_id}-{version}.jar"


def _locate_pom_in_local_cache(
    coords: tuple[str, str, str], errors: list[str]
) -> Path | None:
    """Tier 1: look up a POM in ``~/.m2/repository`` by GAV (FR-131)."""
    if not _validate_gav(coords):
        # SEC-NEW-38 — never echo the raw version into an error message;
        # adversarial pom.xml content could smuggle Mermaid / control-char
        # payloads via the rendered Warnings section.
        safe_coords = (
            coords[0],
            coords[1],
            sanitise_declared_version(coords[2]) or "<unparseable>",
        )
        errors.append(
            f"Invalid GAV coordinates {':'.join(safe_coords)}; "
            f"skipping local cache lookup"
        )
        return None
    repo_root = _m2_repo_path()
    if not repo_root.is_dir():
        return None
    candidate = _gav_to_pom_path(repo_root, *coords)
    # Confine resolved path to the repository root (SEC-NEW-27).
    try:
        confined = resolve_and_confine(candidate, repo_root)
    except PathEscapeError:
        errors.append(
            f"Local cache path for {':'.join(coords)} escapes "
            f"repository root {repo_root}; blocked"
        )
        return None
    if not confined.exists():
        return None
    try:
        if confined.stat().st_size > MAX_FILE_BYTES:
            errors.append(
                f"Cached POM for {':'.join(coords)} exceeds size limit; skipped"
            )
            return None
    except OSError:
        return None
    return confined


def _resolve_mvn_binary() -> str | None:
    """Locate the ``mvn`` binary, preferring ``$MAVEN_HOME`` (SEC-NEW-28).

    Follows the same confinement pattern as ``_resolve_javap_binary``
    in :mod:`source_analyser`.
    """
    for env_var in ("MAVEN_HOME", "M2_HOME"):
        maven_home = os.environ.get(env_var)
        if maven_home:
            candidate = Path(maven_home) / "bin" / "mvn"
            if candidate.exists():
                try:
                    resolved = candidate.resolve()
                    resolved.relative_to(Path(maven_home).resolve())
                except (OSError, ValueError):
                    return None
                return str(resolved)
            # Env var set but binary missing — don't fall through to PATH.
            return None
    # PATH fallback — emit verbose-mode warning per SEC-NEW-52 (idempotent).
    found = shutil.which("mvn")
    if found is not None:
        _warn_path_fallback_once("mvn")
    return found


def _fetch_pom_via_maven(
    coords: tuple[str, str, str], errors: list[str]
) -> Path | None:
    """Tier 2: download a POM via ``mvn dependency:get`` (FR-132).

    On success the POM lands in ``~/.m2/repository`` and is re-read
    through :func:`_locate_pom_in_local_cache`.

    NETWORK CAPABILITY: this spawns Maven, which resolves the given
    coordinates against a remote repository. Callers MUST NOT reach
    it unless the operator passed ``--allow-remote-fetch``; the gate
    lives in :meth:`MavenPomResolver._locate_or_fetch_pom`, the only
    production call site.
    """
    if not _validate_gav(coords):
        return None
    mvn = _resolve_mvn_binary()
    if mvn is None:
        return None
    artifact = f"{coords[0]}:{coords[1]}:{coords[2]}:pom"
    # REQ-19a / NEW-ARCH-013 — migrated to _invoke_mvn_safe so the
    # SEC-NEW-58 AST scan + SEC-NEW-55 argv allowlist apply uniformly.
    completed = _invoke_mvn_safe(
        ["dependency:get", f"-Dartifact={artifact}", "-Dtransitive=false"],
        timeout_s=_MVN_TIMEOUT_SEC,
    )
    if completed is None:
        errors.append(
            f"mvn dependency:get for {artifact} failed (timeout or OS error)"
        )
        return None
    if completed.returncode != 0:
        errors.append(
            f"mvn dependency:get for {artifact} exited with code "
            f"{completed.returncode}"
        )
        return None
    # The POM should now be in the local cache.
    return _locate_pom_in_local_cache(coords, errors)


# Sentinel: <relativePath/> or <relativePath></relativePath> was present
# but empty — Maven semantics: skip filesystem, go straight to repository.
_EMPTY_RELATIVE_PATH = ""


@dataclass
class _PomData:
    """Raw data extracted from a single ``pom.xml`` before merging."""

    path: Path
    group_id: str | None = None
    artifact_id: str | None = None
    version: str | None = None
    parent_coords: tuple[str, str, str] | None = None
    # None = no <relativePath> element (default to ../pom.xml);
    # _EMPTY_RELATIVE_PATH = explicitly empty (skip filesystem);
    # str = explicit path.
    parent_relative_path: str | None = None
    properties: dict[str, str] = field(default_factory=dict)
    dependencies: list[dict[str, str | None]] = field(default_factory=list)
    managed: list[dict[str, str | None]] = field(default_factory=list)
    bom_imports: list[dict[str, str | None]] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)


# ── XML helpers ──────────────────────────────────────────────────────────────


def _find(elem: ET.Element, tag: str) -> ET.Element | None:
    """Find a direct child ``tag`` — matches with or without Maven namespace."""
    child = elem.find(f"{_MAVEN_NS}{tag}")
    if child is not None:
        return child
    return elem.find(tag)


def _findall(elem: ET.Element, tag: str) -> list[ET.Element]:
    return elem.findall(f"{_MAVEN_NS}{tag}") + elem.findall(tag)


def _text(elem: ET.Element | None) -> str | None:
    if elem is None or elem.text is None:
        return None
    stripped = elem.text.strip()
    return stripped or None


def _local_tag(tag: str) -> str:
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def _parse_dependency_node(dep_elem: ET.Element) -> dict[str, str | None]:
    return {
        "groupId": _text(_find(dep_elem, "groupId")),
        "artifactId": _text(_find(dep_elem, "artifactId")),
        "version": _text(_find(dep_elem, "version")),
        "scope": _text(_find(dep_elem, "scope")),
        "type": _text(_find(dep_elem, "type")),
    }


# ── POM file parser ─────────────────────────────────────────────────────────


def _parse_pom_file(path: Path, errors: list[str]) -> _PomData | None:
    """Parse a single ``pom.xml`` into :class:`_PomData` or return ``None``."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        errors.append(f"{path.name}: stat failed — {exc}")
        return None
    if size > MAX_FILE_BYTES:
        errors.append(f"{path.name}: exceeds size limit; skipped")
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"{path.name}: read failed — {exc}")
        return None

    # XXE / billion-laughs defense — refuse any POM with a DOCTYPE.
    # The Maven POM schema does not use DOCTYPE, so its presence is
    # either a bug or an attack. Rejecting pre-parse means the entity
    # table is never constructed.
    if _DOCTYPE_RE.search(text):
        errors.append(
            f"{path.name}: DOCTYPE declaration rejected — POM files must "
            f"not declare DOCTYPE (XXE / entity-expansion defense)"
        )
        return None

    try:
        # B314 — DOCTYPE has already been rejected above (SEC-NEW-01); with
        # no DTD present the remaining xml.etree attack surface (external
        # entities, billion-laughs) is not reachable. Using defusedxml
        # would add a transitive dep without strengthening the guarantee.
        root_elem = ET.fromstring(text)  # nosec B314
    except ET.ParseError as exc:
        errors.append(f"{path.name}: XML parse error — {exc}")
        return None

    data = _PomData(path=path)
    data.group_id = _text(_find(root_elem, "groupId"))
    data.artifact_id = _text(_find(root_elem, "artifactId"))
    data.version = _text(_find(root_elem, "version"))

    parent = _find(root_elem, "parent")
    if parent is not None:
        data.parent_coords = (
            _text(_find(parent, "groupId")) or "",
            _text(_find(parent, "artifactId")) or "",
            _text(_find(parent, "version")) or "",
        )
        rel_elem = _find(parent, "relativePath")
        if rel_elem is None:
            data.parent_relative_path = None  # absent → default ../pom.xml
        else:
            data.parent_relative_path = _text(rel_elem) or _EMPTY_RELATIVE_PATH
        # Maven POM: groupId + version inherit from parent if absent.
        if data.group_id is None:
            data.group_id = data.parent_coords[0] or None
        if data.version is None:
            data.version = data.parent_coords[2] or None

    properties_elem = _find(root_elem, "properties")
    if properties_elem is not None:
        for child in list(properties_elem):
            key = _local_tag(child.tag)
            value = _text(child)
            if value is not None:
                data.properties[key] = value

    dep_mgmt = _find(root_elem, "dependencyManagement")
    if dep_mgmt is not None:
        deps_parent = _find(dep_mgmt, "dependencies")
        if deps_parent is not None:
            for dep_elem in _findall(deps_parent, "dependency"):
                parsed = _parse_dependency_node(dep_elem)
                if parsed.get("scope") == "import" and parsed.get("type") == "pom":
                    data.bom_imports.append(parsed)
                else:
                    data.managed.append(parsed)

    deps_parent = _find(root_elem, "dependencies")
    if deps_parent is not None:
        for dep_elem in _findall(deps_parent, "dependency"):
            data.dependencies.append(_parse_dependency_node(dep_elem))

    modules_elem = _find(root_elem, "modules")
    if modules_elem is not None:
        for m in _findall(modules_elem, "module"):
            if m.text and m.text.strip():
                data.modules.append(m.text.strip())

    return data


# ── Placeholder resolution ──────────────────────────────────────────────────


def _seed_project_properties(
    properties: dict[str, str], target: "_PomData",
) -> None:
    """Populate the Maven-reserved ``project.*`` / ``pom.*`` /
    ``project.parent.*`` placeholder values from ``target``.

    Maven exposes the *current* POM's coordinates as
    ``${project.version}`` / ``${project.groupId}`` /
    ``${project.artifactId}``. Maven 2.x used ``${pom.X}`` as a synonym
    — still seen in legacy build files. ``${project.parent.X}`` exposes
    the parent POM's coordinates and is the conventional way to
    reference a corporate parent's release line.

    All three families are reserved: user-defined ``<properties>``
    cannot shadow them. This helper is called both *before* and *after*
    the user-property merge so the final map always wins.
    """
    if target.version:
        properties["project.version"] = target.version
        properties["pom.version"] = target.version
    if target.group_id:
        properties["project.groupId"] = target.group_id
        properties["pom.groupId"] = target.group_id
    if target.artifact_id:
        properties["project.artifactId"] = target.artifact_id
        properties["pom.artifactId"] = target.artifact_id
    if target.parent_coords is not None:
        p_g, p_a, p_v = target.parent_coords
        if p_g:
            properties["project.parent.groupId"] = p_g
            properties["pom.parent.groupId"] = p_g
        if p_a:
            properties["project.parent.artifactId"] = p_a
            properties["pom.parent.artifactId"] = p_a
        if p_v:
            properties["project.parent.version"] = p_v
            properties["pom.parent.version"] = p_v


def _resolve_placeholders(
    value: str | None, properties: dict[str, str]
) -> tuple[str | None, bool]:
    """Expand ``${property}`` references. Returns (resolved, fully_resolved)."""
    if value is None or "${" not in value:
        return value, True
    current = value
    for _ in range(_MAX_PROPERTY_EXPANSION_PASSES):
        unresolved: list[str] = []

        def _sub(match: re.Match[str]) -> str:
            key = match.group(1).strip()
            if key in properties:
                return properties[key]
            unresolved.append(key)
            return match.group(0)

        next_val = _PLACEHOLDER_RE.sub(_sub, current)
        if next_val == current:
            return current, not unresolved
        current = next_val
    return current, "${" not in current


# ── Main resolver ───────────────────────────────────────────────────────────


class MavenPomResolver(BaseAnalyser):
    """Filesystem-only Maven POM resolver.

    REQ-24 / Option 2 — when ``self.fetcher`` is set (wired by
    :class:`JavaAnalyser` once ``--allow-remote-fetch`` is on), POMs
    that are not in ``~/.m2/repository`` will be fetched from the
    configured ``self.endpoints`` via the hardened
    :class:`RemoteArtifactFetcher` and read from the quarantined cache.
    Without those attributes set the resolver behaves identically to
    pre-Option-2 (m2-only).
    """

    # REQ-24 — set by orchestrator when --allow-remote-fetch is on.
    # Default ``None`` preserves the pre-Option-2 m2-only behaviour.
    fetcher: object = None  # RemoteArtifactFetcher; typed loosely to
    # avoid an import cycle into the indexing package at module load.
    endpoints: list[Any] = []  # list[IndexEndpoint]
    # Set once per resolver instance the first time the Maven CLI tier
    # is suppressed, so the "why didn't this POM resolve?" note appears
    # exactly once instead of per unresolved coordinate.
    _cli_tier_note_emitted: bool = False

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        return (root / "pom.xml").exists()

    # ── REQ-24 / Option 2 — POM resolution with optional remote tier ──────

    def _locate_or_fetch_pom(
        self,
        coords: tuple[str, str, str],
        errors: list[str],
    ) -> Path | None:
        """Three-tier POM lookup:

        1. ``~/.m2/repository`` (existing :func:`_locate_pom_in_local_cache`).
        2. REQ-24 :class:`RemoteArtifactFetcher` over the configured
           indexes (Option 2 — when ``self.fetcher`` is wired).
        3. ``mvn dependency:get`` CLI fallback
           (:func:`_fetch_pom_via_maven`) — legacy tier, requires mvn
           on PATH AND ``--allow-remote-fetch``; used only when (1)
           and (2) miss.

        Order matters: (2) is preferred over (3) because it goes through
        ``SafeHttpsClient`` (HTTPS-only, SSRF-guarded, audit-logged) and
        never spawns a subprocess. (3) stays available so installations
        without REQ-24 indexes configured still resolve POMs the way
        they always did — but only under the same network capability.

        Both (2) and (3) are network tiers driven by coordinates read
        out of the analysed project's untrusted ``pom.xml``. Neither
        may run unless the operator opted in with
        ``--allow-remote-fetch``: with the flag off, analysis makes
        zero outbound calls, which is the documented contract.
        """
        # Tier 1.
        cached = _locate_pom_in_local_cache(coords, errors)
        if cached is not None:
            return cached

        # Tier 2 — REQ-24 fetcher.
        if self.fetcher is not None and self.endpoints:
            try:
                # Local import to avoid a module-load cycle: maven.py
                # is read by indexing/* only via abi_diff which is
                # itself loaded from java/__init__.py after maven.
                from scarno.indexing.validator import (
                    CoordinateValidator,
                    UnknownEcosystemError,
                )
                vc = CoordinateValidator.validate(
                    "maven", f"{coords[0]}:{coords[1]}"
                )
                fetched: Path | None = self.fetcher.fetch_pom(  # type: ignore[attr-defined]
                    vc, coords[2], self.endpoints,
                )
                if fetched is not None:
                    return fetched
            except (ValueError, UnknownEcosystemError) as exc:
                errors.append(
                    f"req24-fetch: pom validation rejected "
                    f"{coords[0]}:{coords[1]}: {exc!s}"
                )

        # Tier 3 — Maven CLI fallback, behind the network capability.
        # ``mvn dependency:get`` is an outbound artefact download for
        # coordinates that came from the analysed project's pom.xml,
        # so it needs the same operator opt-in as the REQ-24 tier
        # above. Without --allow-remote-fetch this returns None and
        # the caller degrades exactly as it does on a cache miss.
        if not self.allow_remote_fetch:
            self._note_cli_tier_disabled(errors)
            return None
        return _fetch_pom_via_maven(coords, errors)

    def _note_cli_tier_disabled(self, errors: list[str]) -> None:
        """Record — once per resolver — that the Maven CLI tier was
        suppressed, so an operator who expected a POM to resolve can
        tell the difference between "not found" and "not allowed".
        """
        if self._cli_tier_note_emitted:
            return
        self._cli_tier_note_emitted = True
        errors.append(
            "maven-cli-fetch: one or more POMs are missing from "
            "~/.m2/repository and the 'mvn dependency:get' fallback is "
            "disabled — it would make outbound network calls for "
            "coordinates read out of the analysed project. Re-run with "
            "--deep-inspection --allow-remote-fetch to enable it."
        )

    def analyse(self, project_path: str) -> AnalysisResult:
        root = Path(project_path).resolve(strict=False)
        errors: list[str] = []
        deps_by_key: dict[tuple[str, str], Dependency] = {}

        pom_path = root / "pom.xml"
        if pom_path.exists():
            self._resolve_module(
                pom_path,
                project_root=root,
                deps_by_key=deps_by_key,
                errors=errors,
                visited_modules=set(),
                module_depth=0,
            )

        # FR-152 — populate dep_graph from each direct dep's POM in
        # ``~/.m2/repository`` so the ASCII dependency tree shows the
        # transitive closure, not just a flat list. (Mermaid renderer is
        # retained in the markdown reporter as a defensive helper but
        # is not the live render path.) Best-effort: missing cache
        # entries contribute nothing rather than failing the analysis.
        # REQ-19 (FR-191) — also collect the per-edge declared versions.
        # G3 — and the set of transitive coords discovered along the
        # walk so we can synthesise Dependency entries (otherwise the
        # ASCII tree silently drops them and the multi-version table
        # references coords not visible elsewhere in the report).
        dep_graph, dep_edges, transitives = self._build_transitive_graph(
            deps_by_key, errors
        )

        # G3 — surface every discovered transitive as a real
        # Dependency. Without this, anything REACHED only via the m2
        # walk (no direct manifest declaration) is invisible to the
        # ASCII tree (which gates by ``c in by_name``) and to the
        # classifier's ``dep_by_name`` lookup (so apply_pin_override_safety
        # doesn't run on them — addressed by G2 too as defence-in-depth).
        for coord, version in transitives.items():
            parts = coord.split(":", 1)
            if len(parts) != 2:
                continue
            g, a = parts
            if (g, a) in deps_by_key:
                continue
            deps_by_key[(g, a)] = Dependency(
                name=coord,
                version=version,
                # Status is conservative IN_USE — the per-version
                # classifier (REQ-20) is the source of truth for
                # what's actually safe to remove. Using IN_USE as
                # the seed avoids spurious "SAFE direct" downgrade
                # via _effective_direct_status (which would force
                # UNCERTAIN for ecosystems without a pin detector,
                # and Maven HAS one — but a synthesised transitive
                # is conceptually a "downstream" dep, not a direct).
                status=DependencyStatus.IN_USE,
                reason="transitive (discovered via ~/.m2 walk)",
                ecosystem="maven",
                is_transitive=True,
                resolved=True,
            )

        # REQ-21 — pin-override detection (PR-3). Two patterns:
        # exclusion-override and dependencyManagement pin. Mutates
        # entries in deps_by_key in place. SUC-42 enforcement happens
        # later in the classifier; here we just flag.
        try:
            exclusions = _collect_exclusions_from_walked_poms(
                root, errors=errors
            )
            dm_index = _collect_dependency_management(
                root, errors=errors
            )
            _detect_pin_overrides(
                deps_by_key=deps_by_key,
                exclusions=exclusions,
                dm_index=dm_index,
                edges=dep_edges,
                errors=errors,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(
                f"Maven pin-override detection failed: {exc!s}"
            )

        return AnalysisResult(
            project_type="java",
            project_path=str(root),
            dependencies=list(deps_by_key.values()),
            errors=errors,
            findings=[],
            dep_graph=dep_graph,
            dep_edges=dep_edges,
        )

    def _build_transitive_graph(
        self,
        deps_by_key: dict[tuple[str, str], Dependency],
        errors: list[str],
    ) -> tuple[dict[str, set[str]], list[DepEdge], dict[str, str | None]]:
        """Read each direct dep's POM from ``~/.m2/repository`` and
        add edges to a graph keyed by ``groupId:artifactId``.

        Cycles are bounded by ``visited`` set + a per-node depth cap.
        Missing-cache entries are silently skipped — the graph is
        best-effort and the rest of the report stays usable.

        REQ-19 (FR-191): also returns per-edge declared versions as a
        list of :class:`DepEdge`. Direct deps emit edges from the
        synthetic root (``parent=""``); each cached POM contributes
        edges for every ``<dependency>`` it declares. Versions pass
        through ``sanitise_declared_version`` so adversarial pom.xml
        content cannot smuggle Mermaid / control-char payloads into
        the report (SEC-NEW-38).

        REQ-19 acceptance: a transitive whose ``<version>`` placeholder
        cannot be resolved is emitted with ``declared_version=None``
        rather than dropped, so an attacker cannot suppress an edge by
        breaking a property reference (FR-191 / TA-205).
        """
        graph: dict[str, set[str]] = {}
        edges: list[DepEdge] = []
        visited: set[str] = set()
        # G3 — collect every transitive coord we discover via the m2
        # walk so the caller can synthesise Dependency entries for
        # them. Without this, transitives surface in dep_edges /
        # dep_graph but NOT in result.dependencies, and the ASCII
        # tree's ``c in by_name`` filter silently drops them
        # (user-reported "libraries listed in multiversion table that
        # are not in the dependency tree"). First-seen version per
        # coord is good enough for the Dependency record — the
        # multi-version table will still display every variant from
        # the edge list.
        discovered_transitives: dict[str, str | None] = {}
        # Worklist starts with every direct dep we already emitted.
        # REQ-19 — emit a root-edge per direct dep so the renderer can
        # nest the version label under the project node.
        worklist: list[tuple[str, str | None, str | None]] = []
        for (g, a), dep in deps_by_key.items():
            worklist.append((dep.name, dep.version, None))
            edges.append(
                DepEdge(
                    parent="",
                    child=dep.name,
                    declared_version=sanitise_declared_version(dep.version),
                )
            )

        while worklist:
            label, version, _src = worklist.pop()
            if label in visited:
                continue
            visited.add(label)
            if len(visited) > _MAX_TRANSITIVE_NODES:
                errors.append(
                    "Maven dep_graph: transitive node cap reached; "
                    "further edges elided"
                )
                break
            parts = label.split(":")
            if len(parts) != 2 or version is None:
                continue
            group_id, artifact_id = parts
            cached = self._locate_or_fetch_pom(
                (group_id, artifact_id, version), errors
            )
            if cached is None:
                continue
            pom = _parse_pom_file(cached, errors)
            if pom is None:
                continue

            # FR-165 — resolve placeholders against THIS cached POM's
            # ``<properties>`` plus its reserved ``project.*`` /
            # ``pom.*`` / ``project.parent.*`` keys before passing
            # child coords to the cache lookup.
            local_props: dict[str, str] = {}
            _seed_project_properties(local_props, pom)
            local_props.update(pom.properties)
            _seed_project_properties(local_props, pom)

            children: set[str] = set()
            for dep_map in pom.dependencies:
                # Skip test- and provided-scoped transitives — runtime
                # closure is what determines "footprint freed if removed".
                scope = (dep_map.get("scope") or "").lower()
                if scope in {"test", "provided", "system"}:
                    continue
                raw_g = dep_map.get("groupId")
                raw_a = dep_map.get("artifactId")
                raw_v = dep_map.get("version")
                if not raw_g or not raw_a:
                    continue
                child_g, g_ok = _resolve_placeholders(raw_g, local_props)
                child_a, a_ok = _resolve_placeholders(raw_a, local_props)
                child_v: str | None
                v_ok: bool
                if raw_v is None:
                    child_v, v_ok = None, True
                else:
                    child_v, v_ok = _resolve_placeholders(raw_v, local_props)
                # We still skip the transitive walk when the GROUP or
                # ARTIFACT placeholder can't resolve — without those, we
                # can't even name the child. But REQ-19 §FR-191 requires
                # we DO emit an edge with ``declared_version=None`` when
                # only the VERSION placeholder is unresolvable, so an
                # adversarial POM can't suppress edges by breaking a
                # property reference (TA-205).
                if not g_ok or not a_ok:
                    continue
                if not child_g or not child_a:
                    continue
                child_label = f"{child_g}:{child_a}"
                emitted_version: str | None
                if v_ok and child_v:
                    emitted_version = sanitise_declared_version(child_v)
                else:
                    emitted_version = None
                children.add(child_label)
                edges.append(
                    DepEdge(
                        parent=label,
                        child=child_label,
                        declared_version=emitted_version,
                        scope=scope or "runtime",
                    )
                )
                # G3 — record the first-seen version per discovered
                # transitive. ``setdefault`` preserves first-wins so a
                # later None-version edge doesn't overwrite a concrete
                # one (mirrors the G1 fix in _nearest_wins_from_edges).
                if child_label not in discovered_transitives:
                    discovered_transitives[child_label] = emitted_version
                elif (
                    discovered_transitives[child_label] is None
                    and emitted_version
                ):
                    discovered_transitives[child_label] = emitted_version
                if v_ok and child_label not in visited:
                    worklist.append((child_label, child_v, label))
            if children:
                graph[label] = children
        return graph, edges, discovered_transitives

    # ── internals ────────────────────────────────────────────────────────

    def _resolve_module(
        self,
        pom_path: Path,
        *,
        project_root: Path,
        deps_by_key: dict[tuple[str, str], Dependency],
        errors: list[str],
        visited_modules: set[Path],
        module_depth: int,
    ) -> None:
        try:
            resolved_pom = resolve_and_confine(pom_path, project_root)
        except PathEscapeError:
            errors.append(
                f"module POM path escape blocked: {pom_path} is outside "
                f"project root {project_root}"
            )
            return
        if resolved_pom in visited_modules:
            errors.append(
                f"Module cycle detected: {resolved_pom} already visited "
                f"(circular <module> reference)"
            )
            return
        if module_depth > _MAX_MODULE_DEPTH:
            errors.append(
                f"Module traversal depth exceeded {_MAX_MODULE_DEPTH}; stopping"
            )
            return

        visited_modules = visited_modules | {resolved_pom}

        chain = self._walk_parent_chain(resolved_pom, project_root, errors)
        if not chain:
            return
        target = chain[-1]

        merged_properties: dict[str, str] = {}
        merged_managed: dict[tuple[str, str], str | None] = {}
        _seed_project_properties(merged_properties, target)
        # Ancestor-first, so child properties override parent ones
        for pom in chain:
            merged_properties.update(pom.properties)
            for managed in pom.managed:
                group_id = managed.get("groupId")
                artifact_id = managed.get("artifactId")
                if group_id and artifact_id:
                    merged_managed[(group_id, artifact_id)] = managed.get("version")
        # Re-assert reserved keys so user-defined properties cannot
        # silently shadow Maven's ``project.*`` / ``pom.*`` /
        # ``project.parent.*``.
        _seed_project_properties(merged_properties, target)

        # Resolve BOM imports (FR-133) — must happen before dependency
        # resolution so BOM-managed versions are available.
        for pom in chain:
            for bom in pom.bom_imports:
                bom_data = self._resolve_bom_pom(bom, merged_properties, errors)
                if bom_data is not None:
                    for managed in bom_data.managed:
                        mg = managed.get("groupId")
                        ma = managed.get("artifactId")
                        if mg and ma:
                            merged_managed.setdefault((mg, ma), managed.get("version"))

        for dep in target.dependencies:
            # REQ-17 — drop test-scoped declared deps.
            if self.exclude_tests and dep.get("scope") == "test":
                continue
            group_id, g_ok = _resolve_placeholders(
                dep.get("groupId"), merged_properties
            )
            artifact_id, a_ok = _resolve_placeholders(
                dep.get("artifactId"), merged_properties
            )
            version: str | None
            version, v_ok = _resolve_placeholders(
                dep.get("version"), merged_properties
            )
            # Fall back to merged dependencyManagement when version absent.
            if version is None and group_id and artifact_id:
                managed_version = merged_managed.get((group_id, artifact_id))
                if managed_version is not None:
                    version, v_ok = _resolve_placeholders(
                        managed_version, merged_properties
                    )

            if not g_ok or not a_ok or (version is not None and not v_ok):
                errors.append(
                    f"Unresolvable placeholder in dependency "
                    f"{group_id}:{artifact_id}:{version}"
                )

            if not group_id or not artifact_id:
                continue
            key = (group_id, artifact_id)
            try:
                source_rel = str(resolved_pom.relative_to(project_root))
            except ValueError:
                source_rel = resolved_pom.name
            reason = (
                f"declared in {resolved_pom.name} — source analysis pending"
            )
            if key not in deps_by_key:
                deps_by_key[key] = Dependency(
                    name=f"{group_id}:{artifact_id}",
                    version=version,
                    status=DependencyStatus.UNCERTAIN,
                    reason=reason,
                    entry_points=[],
                    entry_points_used=0,
                    entry_points_total=0,
                    source=source_rel,
                    ecosystem="maven",
                )

        for module in target.modules:
            submodule_dir = (resolved_pom.parent / module).resolve()
            submodule_pom = submodule_dir / "pom.xml"
            if submodule_pom == resolved_pom:
                errors.append(
                    f"Module cycle detected: <module>{module}</module> points "
                    f"to the parent POM itself"
                )
                continue
            if not submodule_pom.exists():
                errors.append(
                    f"Module '{module}' has no pom.xml at {submodule_pom}"
                )
                continue
            self._resolve_module(
                submodule_pom,
                project_root=project_root,
                deps_by_key=deps_by_key,
                errors=errors,
                visited_modules=visited_modules,
                module_depth=module_depth + 1,
            )

    def _resolve_bom_pom(
        self,
        bom: dict[str, str | None],
        merged_properties: dict[str, str],
        errors: list[str],
    ) -> _PomData | None:
        """Resolve a BOM import POM via Tier 1 (cache) → Tier 2 (mvn).

        Returns the parsed :class:`_PomData` or ``None``.
        """
        raw_g = bom.get("groupId")
        raw_a = bom.get("artifactId")
        raw_v = bom.get("version")
        if not raw_g or not raw_a:
            return None
        g, _ = _resolve_placeholders(raw_g, merged_properties)
        a, _ = _resolve_placeholders(raw_a, merged_properties)
        v, _ = _resolve_placeholders(raw_v, merged_properties)
        if not g or not a or not v:
            errors.append(
                f"BOM import {raw_g}:{raw_a}:{raw_v} has unresolvable "
                f"coordinates; skipped"
            )
            return None
        coords = (g, a, v)
        if not _validate_gav(coords):
            errors.append(
                f"BOM import {g}:{a}:{v} has invalid GAV coordinates; skipped"
            )
            return None
        pom_path = self._locate_or_fetch_pom(coords, errors)
        if pom_path is None:
            errors.append(
                f"BOM import {g}:{a}:{v} not resolved "
                f"(not found in local cache, REQ-24 indexes, or Maven CLI)"
            )
            return None
        return _parse_pom_file(pom_path, errors)

    def _walk_parent_chain(
        self,
        pom_path: Path,
        project_root: Path,
        errors: list[str],
    ) -> list[_PomData]:
        """Walk the parent chain top-down. Returns ``[oldest_ancestor, …, target]``."""
        chain: list[_PomData] = []
        current: Path | None = pom_path
        depth = 0
        visited_paths: set[Path] = set()
        visited_gavs: set[tuple[str, str, str]] = set()
        # Parent POMs may legitimately live in a sibling directory
        # (shared-parent monorepo) so we confine to the project root's
        # parent — wide enough for siblings, narrow enough to reject
        # ``../../../etc/passwd``.
        try:
            parent_sandbox = project_root.parent.resolve()
        except (OSError, RuntimeError):
            parent_sandbox = project_root

        current_from_cache = False
        while current is not None and depth < _MAX_PARENT_DEPTH:
            resolved = current.resolve()
            if resolved in visited_paths:
                errors.append(
                    f"Parent POM cycle detected at {resolved}; stopping"
                )
                break
            visited_paths.add(resolved)

            data = _parse_pom_file(current, errors)
            if data is None:
                break
            chain.append(data)

            if data.parent_coords is None:
                break

            # GAV-level cycle detection — catches cycles through the
            # Maven cache / CLI path where the same coordinates resolve
            # to different filesystem paths.
            if data.parent_coords in visited_gavs:
                errors.append(
                    f"Parent POM GAV cycle detected: "
                    f"{':'.join(data.parent_coords)}; stopping"
                )
                break
            visited_gavs.add(data.parent_coords)

            next_pom = self._locate_parent_pom(
                data,
                current_dir=current.parent,
                project_root=project_root,
                parent_sandbox=parent_sandbox,
                errors=errors,
                from_cache=current_from_cache,
            )
            if next_pom is None:
                break
            # Track whether the resolved POM came from the .m2 cache
            # (or mvn fetch) so the next iteration skips meaningless
            # filesystem resolution using its <relativePath>.
            m2 = _m2_repo_path()
            try:
                next_pom.resolve().relative_to(m2.resolve())
                current_from_cache = True
            except (ValueError, OSError):
                current_from_cache = False
            current = next_pom
            depth += 1

        return list(reversed(chain))

    def _locate_parent_pom(
        self,
        data: _PomData,
        *,
        current_dir: Path,
        project_root: Path,
        parent_sandbox: Path,
        errors: list[str],
        from_cache: bool = False,
    ) -> Path | None:
        """Resolve the parent POM file path, returning None if not found."""
        coords = data.parent_coords or ("", "", "")
        label = ":".join(coords)

        # Skip filesystem resolution when:
        # - <relativePath/> is explicitly empty (Maven: go to repository), OR
        # - the current POM was itself resolved from the .m2 cache / mvn
        #   (its <relativePath> is relative to the original source tree, not
        #   the cache layout — filesystem resolution would be meaningless
        #   and could accidentally match unrelated POMs or trigger slow
        #   mvn calls through the sandbox/Tier fallthrough path).
        skip_filesystem = (
            from_cache
            or data.parent_relative_path == _EMPTY_RELATIVE_PATH
        )

        if not skip_filesystem:
            relative = data.parent_relative_path or "../pom.xml"

            candidate = (current_dir / relative).resolve()
            if candidate.is_dir():
                candidate = candidate / "pom.xml"

            # Defence: candidate must be a ``pom.xml`` file that's confined
            # to the ``parent_sandbox``. Anything else is an escape attempt.
            try:
                candidate.relative_to(parent_sandbox)
            except ValueError:
                errors.append(
                    f"Parent POM for {data.artifact_id}: {label} — "
                    f"relativePath '{relative}' escapes project sandbox "
                    f"({parent_sandbox}); blocked"
                )
                return None
            if candidate.name != "pom.xml":
                errors.append(
                    f"Parent POM not found for {data.artifact_id}: {label} — "
                    f"relativePath '{relative}' does not point to a pom.xml"
                )
                return None
            if candidate.exists():
                return candidate

        # Filesystem missed (or skipped) — fall through to local cache
        # (Tier 1), REQ-24 fetcher (Tier 2), and Maven CLI (Tier 3) via
        # the parent's GAV coordinates. ``_locate_or_fetch_pom`` walks
        # all three in order.
        if data.parent_coords and _validate_gav(data.parent_coords):
            cached = self._locate_or_fetch_pom(data.parent_coords, errors)
            if cached is not None:
                return cached

        errors.append(
            f"Parent POM not found for {data.artifact_id}: {label}"
        )
        return None


# ── REQ-19a / NEW-ARCH-013 — per-binary subprocess hardening ────────────────
#
# Composes ``security.safe_subprocess_run`` with Maven-specific binary
# resolution + argv allowlist. Replaces inline ``subprocess.run`` in
# ``_fetch_pom_via_maven`` (migrated below) and is the only sanctioned
# entry point for any future ``mvn`` invocation Scarno code adds
# (REQ-20 resolved-version detection lives here too).

_MVN_ARGV_ALLOWED_PREFIXES: tuple[str, ...] = (
    "dependency:get",
    "dependency:tree",
    "-DoutputType=",
    "-DoutputFile=",
    "-Dartifact=",
    "-Dtransitive=",
    "--batch-mode",
    "--no-transfer-progress",
    "-f",
)


def _warn_path_fallback_once(binary_name: str) -> None:
    """Emit a verbose-mode stderr warning the first time a binary is
    resolved via PATH (i.e. neither ``MAVEN_HOME`` / ``M2_HOME`` /
    ``GRADLE_HOME`` is set). Idempotent per process — once per binary.
    """
    seen = getattr(_warn_path_fallback_once, "_seen", None)
    if seen is None:
        seen = set()
        _warn_path_fallback_once._seen = seen  # type: ignore[attr-defined]
    if binary_name in seen:
        return
    seen.add(binary_name)
    print(
        f"[scarno] warning: {binary_name} resolved via PATH (no "
        f"{binary_name.upper()}_HOME / equivalent env var set); the binary "
        f"is unverified — set the home env var to confine resolution.",
        file=sys.stderr,
    )


def _invoke_mvn_safe(
    argv_tail: list[str], *, timeout_s: float = _MVN_TIMEOUT_SEC
) -> "subprocess.CompletedProcess[str] | None":
    """REQ-19a / SEC-NEW-55 — argv-allowlist-checked mvn invocation.

    ``argv_tail`` MUST be supplied by Scarno code. Each token is
    checked against the fixed allowlist; project-derived flags (``-P``
    profile names, arbitrary ``-D`` system properties) are rejected
    before spawn. Returns the :class:`subprocess.CompletedProcess` or
    ``None`` on binary-missing / timeout / OS error.
    """
    for tok in argv_tail:
        if not any(
            tok.startswith(p) or tok == p
            for p in _MVN_ARGV_ALLOWED_PREFIXES
        ):
            raise ValueError(
                f"_invoke_mvn_safe: token {tok!r} is not on the SEC-NEW-55 "
                f"argv allowlist; only fixed REQ-20 / REQ-4 flags are "
                f"permitted."
            )
    mvn = _resolve_mvn_binary()
    if mvn is None:
        return None
    binary_root = None
    for env_var in ("MAVEN_HOME", "M2_HOME"):
        v = os.environ.get(env_var)
        if v:
            binary_root = Path(v)
            break
    try:
        from scarno.security import (
            BinaryNotConfinedError,
            safe_subprocess_run,
        )
        return safe_subprocess_run(
            [mvn, *argv_tail],
            timeout_s=timeout_s,
            binary_root=binary_root,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    except BinaryNotConfinedError:
        return None


# ── REQ-20 / FR-203 — resolved-version detection (Maven) ────────────────────


_MVN_DEP_TREE_LINE_RE = re.compile(
    r"""
    ^[\s\\|+\-]*       # tree-glyph prefix
    (?P<group>[\w.\-]+):
    (?P<artifact>[\w.\-]+):
    (?:[\w.\-]+:)?     # optional packaging (e.g. jar)
    (?P<version>[\w.\-+]+)
    (?::[\w.\-]+)?     # optional scope
    \s*$
    """,
    re.VERBOSE,
)


def _resolve_versions_from_dependency_tree(output: str) -> dict[str, str]:
    """Parse ``mvn dependency:tree`` text output into
    ``{group:artifact: version}``. Last-write-wins: if mvn lists
    multiple versions for one coordinate, the last one in the output
    is kept (matches Maven's "nearest wins" output ordering).
    """
    out: dict[str, str] = {}
    for line in output.splitlines():
        m = _MVN_DEP_TREE_LINE_RE.match(line)
        if not m:
            continue
        coord = f"{m.group('group')}:{m.group('artifact')}"
        out[coord] = m.group("version")
    return out


def _nearest_wins_from_edges(edges: list[DepEdge]) -> dict[str, str]:
    """Fallback resolved-version detector when ``mvn dependency:tree``
    is unavailable. Walks ``dep_edges`` BFS from synthetic root and
    picks the FIRST (shortest-path) **concrete** declared version per
    coordinate.

    Approximates Maven's nearest-wins semantics; not a perfect
    substitute (it ignores ``<dependencyManagement>`` overrides for
    *resolution*, but G3 ensures depmgmt-resolved versions are visible
    to the caller via ``Dependency.version``).

    Bug-fix history (G1): an earlier version added the child to the
    ``visited`` set unconditionally — including when the edge had
    ``declared_version=None`` (a depmgmt-deferred edge). Subsequent
    edges with concrete versions for the same coord were then skipped
    entirely, leaving the coord unresolved. The current shape uses
    two independent guards: ``resolved`` is updated whenever a
    concrete version is seen for an unresolved coord; ``visited``
    only gates re-recursion into a child's subtree. Edge ordering no
    longer affects the resolved-version outcome.
    """
    children_by_parent: dict[str, list[DepEdge]] = {}
    for e in edges:
        children_by_parent.setdefault(e.parent, []).append(e)
    resolved: dict[str, str] = {}
    visited: set[str] = set()
    # BFS from synthetic root.
    from collections import deque
    queue: deque[DepEdge] = deque(children_by_parent.get("", []))
    while queue:
        edge = queue.popleft()
        # Try to resolve regardless of visited state — a concrete
        # version on ANY edge to this child wins, not just the first
        # edge by traversal order. This fixes the case where a
        # depmgmt-deferred (None-version) edge is processed before
        # the concrete-version edge for the same child.
        if edge.child not in resolved and edge.declared_version:
            resolved[edge.child] = edge.declared_version
        # Re-recursion guard. We still only walk a child's subtree
        # once per BFS so a diamond doesn't re-enqueue exponentially.
        if edge.child in visited:
            continue
        visited.add(edge.child)
        for child_edge in children_by_parent.get(edge.child, []):
            queue.append(child_edge)
    return resolved


# ── REQ-21 — pin-override detection (Maven) ─────────────────────────────────
#
# Two patterns flagged:
#  (a) Some POM declares <exclusion>X</exclusion>; the project also
#      declares a direct <dependency>X</dependency> at the same GA. The
#      direct dep is a substitute for the excluded transitive — flag it
#      as PIN_OVERRIDE_EXCLUSION so the user is not advised to remove it.
#  (b) Root POM <dependencyManagement> pins X; X is reached transitively
#      via some other dep; source code never imports X. Flag as
#      PIN_OVERRIDE_DEPENDENCY_MANAGEMENT.
#
# SEC-NEW-40 caps prevent pathological POMs from blowing up the
# detector or the report.

_MAX_EXCLUSIONS_PER_DEP: int = 128
_MAX_DM_ENTRIES: int = 2048


def _collect_exclusions_from_walked_poms(
    project_root: Path, *, errors: list[str]
) -> list[tuple[str, str, str]]:
    """Walk the project's pom.xml + (where reachable on disk) module POMs
    collecting every ``<exclusion>`` block. Returns a list of
    ``(excluded_group, excluded_artifact, parent_coord)`` tuples so the
    pin-override reason text can name which transitive's exclusion the
    direct dep substitutes for.

    SEC-NEW-40 — caps the per-dependency exclusion count at 128 to bound
    work on adversarial pom.xml content.
    """
    out: list[tuple[str, str, str]] = []
    pom_path = project_root / "pom.xml"
    if not pom_path.exists():
        return out
    pom = _parse_pom_file(pom_path, errors)
    if pom is None:
        return out
    for dep in pom.dependencies:
        excl_list = dep.get("exclusions") if isinstance(dep, dict) else None
        if not isinstance(excl_list, list):
            continue
        if len(excl_list) > _MAX_EXCLUSIONS_PER_DEP:
            errors.append(
                f"Maven exclusions: dep "
                f"{dep.get('groupId')}:{dep.get('artifactId')} declares "
                f"{len(excl_list)} <exclusion> entries (cap "
                f"{_MAX_EXCLUSIONS_PER_DEP}); truncating."
            )
            excl_list = excl_list[:_MAX_EXCLUSIONS_PER_DEP]
        parent_coord = (
            f"{dep.get('groupId') or '?'}:{dep.get('artifactId') or '?'}"
        )
        for excl in excl_list:
            if not isinstance(excl, dict):
                continue
            g = excl.get("groupId")
            a = excl.get("artifactId")
            if not g or not a:
                continue
            out.append((g, a, parent_coord))
    return out


# Patch the existing _parse_pom_file to also collect <exclusions> per dep.
# We do this by post-processing: re-read the pom_path's XML, walk
# <dependency><exclusions>, and attach the result to the matching
# pom.dependencies entry. This avoids invasive changes to the existing
# parser while making exclusions available to _collect_exclusions_*.


def _augment_pom_with_exclusions(pom_path: Path, pom: "_PomData") -> None:
    """Read ``<exclusions>`` blocks from each ``<dependency>`` in ``pom_path``
    and attach them to the matching entries in ``pom.dependencies``.

    Called lazily by ``_collect_exclusions_from_walked_poms`` so the
    main parser path doesn't pay the cost when pin-override detection
    isn't enabled (it always is, but the augmentation is cheap).
    """
    try:
        raw = pom_path.read_bytes()
    except OSError:
        return
    # XXE / billion-laughs defence (SEC-NEW-01) — mirror the main parser and
    # refuse any POM declaring a DOCTYPE before it reaches the stdlib parser.
    # Without this guard, augmentation re-parses the file with no protection.
    # (bytes pattern: raw is undecoded so ET.fromstring can honour any XML
    # encoding declaration, which a str would reject.)
    if re.search(rb"<!DOCTYPE\b", raw[:4096], re.IGNORECASE):
        return
    try:
        # B314 — DOCTYPE rejected above; with no DTD reachable the residual
        # xml.etree attack surface (external entities, entity-expansion) is
        # not exploitable. defusedxml would add a dep without adding safety.
        root = ET.fromstring(raw)  # nosec B314
    except ET.ParseError:
        return
    deps_elem = _find(root, "dependencies")
    if deps_elem is None:
        return
    for i, dep_elem in enumerate(_findall(deps_elem, "dependency")):
        excls_elem = _find(dep_elem, "exclusions")
        if excls_elem is None:
            continue
        excls: list[dict[str, str | None]] = []
        for excl_elem in _findall(excls_elem, "exclusion"):
            excls.append(
                {
                    "groupId": _text(_find(excl_elem, "groupId")),
                    "artifactId": _text(_find(excl_elem, "artifactId")),
                }
            )
        if i < len(pom.dependencies):
            # The dependency dicts are declared ``dict[str, str | None]`` for
            # their coordinate fields, but this augmentation attaches a list of
            # exclusion maps under a reserved key. Cast to a permissive mapping
            # so the heterogeneous write is type-valid without widening the
            # value type everywhere else the coordinate fields are read.
            cast(dict[str, object], pom.dependencies[i])["exclusions"] = excls


# Re-entry point used by _collect_exclusions_from_walked_poms.
_orig_parse_pom_file = _parse_pom_file


def _parse_pom_file_with_exclusions(  # noqa: F811 — re-export with augmentation
    path: Path, errors: list[str]
) -> "_PomData | None":
    pom = _orig_parse_pom_file(path, errors)
    if pom is not None:
        _augment_pom_with_exclusions(path, pom)
    return pom


# Replace the symbol so _collect_exclusions_from_walked_poms uses the
# augmented variant.
_parse_pom_file = _parse_pom_file_with_exclusions


def _collect_dependency_management(
    project_root: Path, *, errors: list[str]
) -> dict[tuple[str, str], str]:
    """Parse the root POM's <dependencyManagement> after property
    resolution. Returns ``{(group, artifact): version}``.

    SEC-NEW-40 — caps total entries at 2048.
    """
    out: dict[tuple[str, str], str] = {}
    pom_path = project_root / "pom.xml"
    if not pom_path.exists():
        return out
    pom = _orig_parse_pom_file(pom_path, errors)
    if pom is None:
        return out
    # Resolve placeholders against the POM's own <properties>.
    local_props: dict[str, str] = {}
    _seed_project_properties(local_props, pom)
    local_props.update(pom.properties)
    _seed_project_properties(local_props, pom)
    for dm in pom.managed:
        g = dm.get("groupId")
        a = dm.get("artifactId")
        v = dm.get("version")
        if not g or not a or not v:
            continue
        g_resolved, g_ok = _resolve_placeholders(g, local_props)
        a_resolved, a_ok = _resolve_placeholders(a, local_props)
        v_resolved, v_ok = _resolve_placeholders(v, local_props)
        if not (g_ok and a_ok and v_ok):
            continue
        if not g_resolved or not a_resolved or not v_resolved:
            continue
        out[(g_resolved, a_resolved)] = v_resolved
        if len(out) >= _MAX_DM_ENTRIES:
            errors.append(
                f"Maven <dependencyManagement>: entry cap "
                f"({_MAX_DM_ENTRIES}) reached; remaining entries truncated."
            )
            break
    return out


def _detect_pin_overrides(
    *,
    deps_by_key: dict[tuple[str, str], Dependency],
    exclusions: list[tuple[str, str, str]],
    dm_index: dict[tuple[str, str], str],
    edges: list[DepEdge],
    errors: list[str],
) -> None:
    """Mutate ``deps_by_key`` in place: flag each direct dep that
    matches pattern (a) (exclusion-override) or pattern (b)
    (dependencyManagement pin) with ``pin_override=True``.

    The two flags ``pin_override`` and ``manifest_redundant`` are
    mutually exclusive — defer to whichever detector fired first
    when both COULD apply. (The contested-dep test in
    tests/integration/test_req21_invariants.py exercises this case.)

    REQ-21 acceptance: pattern (a) reason text MUST include
    "manual review recommended — coincidental GA match is possible"
    per Phase-3 T-Phase9-02.
    """
    # Pattern (a) index: (group, artifact) → list of parent coords
    # whose <exclusion> mentions that GA.
    excl_by_ga: dict[tuple[str, str], list[str]] = {}
    for g, a, parent in exclusions:
        excl_by_ga.setdefault((g, a), []).append(parent)

    # Build a forward-reachability set from any direct dep so pattern
    # (b) can verify "X is reached transitively". We treat any edge
    # in dep_edges as a reachability hop.
    children_of: dict[str, list[str]] = {}
    for e in edges:
        children_of.setdefault(e.parent or "", []).append(e.child)
    reachable_from_root: set[str] = set()
    stack = list(children_of.get("", []))
    while stack:
        cur = stack.pop()
        if cur in reachable_from_root:
            continue
        reachable_from_root.add(cur)
        stack.extend(children_of.get(cur, []))

    for (group, artifact), dep in deps_by_key.items():
        if dep.manifest_redundant:
            # FR-150 fired first; respect the mutex (NEW-ARCH-007).
            continue
        # Pattern (a): a direct dep at the same GA as some exclusion target.
        excl_parents = excl_by_ga.get((group, artifact))
        if excl_parents:
            # Skip self-exclusion (a dep excluding itself; rare but legal).
            other_parents = [
                p for p in excl_parents if p != f"{group}:{artifact}"
            ]
            if other_parents:
                target_text = (
                    f"substitutes for excluded transitive of "
                    f"{', '.join(sorted(set(other_parents)))}; "
                    f"manual review recommended — coincidental GA match "
                    f"is possible"
                )
                _set_pin_override(dep, "EXCLUSION", target_text)
                continue
        # Pattern (b): DM-pinned + reached transitively + no source use.
        dm_version = dm_index.get((group, artifact))
        if dm_version is None:
            continue
        canonical = f"{group}:{artifact}"
        if canonical not in reachable_from_root:
            continue
        if dep.status is DependencyStatus.IN_USE:
            # Source already uses it — DM is normal version-pin scaffolding,
            # not a substitution. Don't flag.
            continue
        target_text = (
            f"pinned via <dependencyManagement> to {dm_version}"
        )
        _set_pin_override(dep, "DEPENDENCY_MANAGEMENT", target_text)


def _set_pin_override(
    dep: Dependency, kind: str, target: str
) -> None:
    """Flip ``pin_override`` flags on ``dep`` in place. We can't use
    ``dataclasses.replace`` because the caller's deps_by_key map holds
    references to the same Dependency instances we mutate — and the
    result.dependencies list is also the same list of references.

    Defends NEW-ARCH-007: never set pin_override when manifest_redundant
    is already True.
    """
    if dep.manifest_redundant:
        return
    object.__setattr__(dep, "pin_override", True)
    object.__setattr__(dep, "pin_override_kind", kind)
    object.__setattr__(dep, "pin_override_target", target)
