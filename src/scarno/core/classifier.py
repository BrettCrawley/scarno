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

"""REQ-19a / REQ-20 — shared per-version classifier.

Single source of truth for transitive-status propagation across every
ecosystem. Replaces the Python-analyser-private
``_resolve_transitive_statuses`` extracted from
``analysers/python/source_analyser.py`` (NEW-ARCH-006).

Two public classifier entry points:

* :func:`classify_canonical` — legacy canonical-only propagation
  (``dep_graph`` shape from REQ-17). Identical semantics to the
  pre-Phase-9 Python helper; used when an analyser has not yet
  migrated to REQ-19 (empty ``dep_edges``).

* :func:`classify_versioned` — per-version propagation over
  ``dep_edges`` (REQ-19). Each ``(canonical, declared_version)`` pair
  classifies independently. Applies SUC-42 pin-override safety, the
  per-coordinate version cap (SEC-NEW-39), and the ADR-012
  fail-closed default for ecosystems registered in neither registry.

Pin-detector registry (ADR-012 / NEW-ARCH-012): every ecosystem
analyser package calls exactly one of :func:`register_pin_detector`
(it has a real detector for `<exclusions>` / `overrides` /
``resolutionStrategy`` directives) OR
:func:`register_no_pin_mechanism` (its packaging system has no
analogue of those constructs — pypi / go / nuget / css). Ecosystems
absent from both registries trigger the fail-closed UNCERTAIN
downgrade for direct deps that look removable.
"""
from __future__ import annotations

import os
import re
from dataclasses import replace
from typing import Callable

from scarno.models import (
    Dependency,
    DependencyStatus,
    DepEdge,
    VersionedNode,
)


# ── NEW-ARCH-012 — Pin-detector registry ────────────────────────────────────


_PIN_DETECTOR_REGISTRY: set[str] = set()
_NO_PIN_MECHANISM_REGISTRY: set[str] = set()


def register_pin_detector(ecosystem: str) -> None:
    """Mark an ecosystem as having a pin-detector implementation.

    Called at module-import time by analyser packages whose ecosystem
    supports pinning constructs (Maven ``<exclusions>``,
    npm ``overrides``, Gradle ``force``/``strictly``).
    """
    _PIN_DETECTOR_REGISTRY.add(ecosystem)


def register_no_pin_mechanism(ecosystem: str) -> None:
    """Mark an ecosystem as having no pin mechanism to detect.

    Called at module-import time by analyser packages whose packaging
    system has no analogue of ``<exclusions>`` / ``overrides`` /
    ``resolutionStrategy`` (Python wheels, Go modules, NuGet packages,
    CSS imports). The classifier treats these as SAFE-eligible
    without requiring a pin-detector to register first.
    """
    _NO_PIN_MECHANISM_REGISTRY.add(ecosystem)


def has_pin_detector(ecosystem: str) -> bool:
    """Return True when ``ecosystem`` registered a pin-detector."""
    return ecosystem in _PIN_DETECTOR_REGISTRY


def has_no_pin_mechanism(ecosystem: str) -> bool:
    """Return True when ``ecosystem`` registered as having no pin mechanism."""
    return ecosystem in _NO_PIN_MECHANISM_REGISTRY


# ── REQ-19a — _safe_cpu_count helper (D-Phase9-01) ──────────────────────────


def _safe_cpu_count(default: int = 1) -> int:
    """Return ``os.cpu_count()`` or ``default`` on None / error.

    Defensive wrapper used by REQ-22 (PR-4) for ``ThreadPoolExecutor``
    sizing. Lives here as the natural shared utility location; the
    one-liner is trivial enough that the import-time cost is nil.
    """
    try:
        n = os.cpu_count()
    except Exception:
        return default
    return n or default


# ── REQ-20 — SUC-42 pin-override safety ─────────────────────────────────────


_PIN_TRIGGER_KINDS_DYNAMIC: frozenset[str] = frozenset(
    {"GRADLE_DYNAMIC_PIN"}
)


def apply_pin_override_safety(
    dep: Dependency | None, versioned_node: VersionedNode
) -> None:
    """Enforce SUC-42 on a per-version node.

    Single canonical enforcement point for the pin-deferral safety
    rule that prevents silent vulnerability reintroduction. Every
    classification path MUST call this before promoting a node to
    SAFE.

    Behaviour:

    * ``pin_override=True`` AND ``pin_override_kind`` in
      :data:`_PIN_TRIGGER_KINDS_DYNAMIC` → status forced
      ``UNCERTAIN`` with "manual review" reason (Gradle dynamic-pin
      semantics per REQ-21b SUC-48).
    * Any of ``pin_override=True`` / ``manifest_redundant=True`` /
      ``versioned_node.is_resolved=True`` → status forced ``IN_USE``,
      ``removable=False``, reason names the trigger.
    * No flag set → no-op.

    Also asserts the NEW-ARCH-007 mutex (pin_override XOR
    manifest_redundant) on entry as defence-in-depth — construction-time
    enforcement happens in ``Dependency.__post_init__`` but a future
    code path could mutate both flags after construction.

    Bug-fix history (G2): the dep-specific branches (pin_override,
    manifest_redundant) are now gated on ``dep is not None``, but
    the ``is_resolved`` rule fires unconditionally. Earlier, the whole
    function was skipped when the caller had no ``Dependency`` for a
    purely-transitive coordinate (one that lives in ``dep_edges`` but
    not in ``result.dependencies``); a node with ``is_resolved=True``
    could then keep ``removable=True``, producing the user-reported
    "resolved versions flagged for removal" symptom.
    """
    if dep is not None:
        assert not (dep.pin_override and dep.manifest_redundant), (
            f"{dep.name}: pin_override and manifest_redundant are mutually "
            f"exclusive (SEC-NEW-47)"
        )
        if (
            dep.pin_override
            and dep.pin_override_kind in _PIN_TRIGGER_KINDS_DYNAMIC
        ):
            versioned_node.status = DependencyStatus.UNCERTAIN
            versioned_node.removable = False
            versioned_node.reason = (
                f"manual review required — Gradle dynamic-pin "
                f"({dep.pin_override_kind}) keeps this version on the "
                f"classpath but the target version is computed at "
                f"execute time"
            )
            return
        if dep.pin_override:
            versioned_node.status = DependencyStatus.IN_USE
            versioned_node.removable = False
            versioned_node.reason = (
                f"pin override ({dep.pin_override_kind}): "
                f"{dep.pin_override_target or 'load-bearing substitute for an excluded transitive'}"
            )
            return
        if dep.manifest_redundant:
            versioned_node.status = DependencyStatus.IN_USE
            versioned_node.removable = False
            versioned_node.reason = (
                f"manifest declaration redundant — kept alive transitively "
                f"by {dep.redundant_parent or 'an IN_USE parent'}"
            )
            return
    if versioned_node.is_resolved:
        versioned_node.status = DependencyStatus.IN_USE
        versioned_node.removable = False
        versioned_node.reason = (
            "this is the resolved version on the classpath"
        )


# ── REQ-20 — per-coordinate version cap (SEC-NEW-39) ────────────────────────


_COORD_VERSION_CAP: int = 64


# ── Helpers ──────────────────────────────────────────────────────────────────


def _normalise(name: str) -> str:
    """Canonicalise a dep name for graph lookup (mirrors REQ-17 norm).

    Lowercased; surrounding whitespace stripped; underscore / dot /
    hyphen all collapse to hyphen so ``foo_bar``, ``foo-bar``, and
    ``foo.bar`` look up to the same node (PEP-503 normalisation +
    cross-ecosystem softening).
    """
    return re.sub(r"[-_.]+", "-", name.strip().lower())


_STATUS_ORDER: dict[DependencyStatus, int] = {
    DependencyStatus.SAFE: 0,
    DependencyStatus.UNDECLARED: 1,
    DependencyStatus.UNCERTAIN: 2,
    DependencyStatus.IN_USE: 3,
}


def _stronger(
    current: DependencyStatus | None, new: DependencyStatus
) -> DependencyStatus:
    if current is None:
        return new
    return new if _STATUS_ORDER[new] > _STATUS_ORDER[current] else current


# ── classify_canonical (legacy path — NEW-ARCH-006 centralisation) ──────────


def classify_canonical(
    deps: list[Dependency],
    graph: dict[str, set[str]],
) -> list[Dependency]:
    """Legacy canonical-only classifier (extracted from the Python analyser).

    Identical semantics to the pre-Phase-9 ``_resolve_transitive_statuses``
    formerly in ``analysers/python/source_analyser.py``. Used when an
    analyser has not yet migrated to REQ-19 (empty ``dep_edges``).

    A transitive dep's status is derived from its direct parents in
    ``graph``:

      * Any parent IN_USE  → transitive IN_USE
      * Only UNCERTAIN     → transitive UNCERTAIN
      * All parents SAFE   → transitive SAFE (orphaned)
      * No parents at all  → transitive SAFE (unreachable)

    ``imported_directly=True`` transitives are never demoted (REQ-17).
    """
    dep_by_name: dict[str, int] = {}
    for i, dep in enumerate(deps):
        dep_by_name[_normalise(dep.name)] = i

    safe_direct: set[str] = set()
    in_use_direct: set[str] = set()
    uncertain_direct: set[str] = set()
    for dep in deps:
        if dep.is_transitive or dep.is_type_stub:
            continue
        canonical = _normalise(dep.name)
        if dep.status is DependencyStatus.SAFE:
            safe_direct.add(canonical)
        elif dep.status is DependencyStatus.IN_USE:
            in_use_direct.add(canonical)
        else:
            uncertain_direct.add(canonical)
    alive_direct = in_use_direct | uncertain_direct

    def _transitive_closure(pkg: str) -> set[str]:
        visited: set[str] = set()
        stack = [pkg]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for child in graph.get(current, set()):
                if child not in visited:
                    stack.append(child)
        visited.discard(pkg)
        return visited

    transitive_to_parents: dict[str, set[str]] = {}
    for direct_name in safe_direct | alive_direct:
        closure = _transitive_closure(direct_name)
        for t in closure:
            transitive_to_parents.setdefault(t, set()).add(direct_name)

    result: list[Dependency] = []
    for dep in deps:
        if not dep.is_transitive:
            result.append(dep)
            continue
        if dep.imported_directly:
            result.append(dep)
            continue
        canonical = _normalise(dep.name)
        parents = transitive_to_parents.get(canonical, set())
        if not parents:
            result.append(
                replace(
                    dep,
                    status=DependencyStatus.SAFE,
                    reason=(
                        "transitive dependency not required by any direct "
                        "dependency"
                    ),
                )
            )
            continue
        in_use_parents = parents & in_use_direct
        uncertain_parents = parents & uncertain_direct
        if in_use_parents:
            parents_list = ", ".join(sorted(in_use_parents))
            result.append(
                replace(
                    dep,
                    status=DependencyStatus.IN_USE,
                    reason=f"transitively required by: {parents_list}",
                )
            )
        elif uncertain_parents:
            result.append(
                replace(
                    dep,
                    status=DependencyStatus.UNCERTAIN,
                    reason=(
                        "only reached via UNCERTAIN direct deps; "
                        "manual review required"
                    ),
                )
            )
        else:
            # All parents SAFE → transitive orphaned.
            result.append(
                replace(
                    dep,
                    status=DependencyStatus.SAFE,
                    reason=(
                        "only reachable via SAFE direct deps; orphaned"
                    ),
                )
            )
    return result


# ── classify_versioned (REQ-20) ─────────────────────────────────────────────


# Meta-ecosystems exempt from the ADR-012 fail-closed downgrade.
# ``unknown`` is the dataclass default; ``detected`` is the REQ-3b
# phantom-import placeholder. Neither represents a real packaging
# system with a pinning mechanism, so applying the downgrade would
# produce false UNCERTAINs on legitimate inputs.
_FAIL_CLOSED_EXEMPT: frozenset[str] = frozenset({"unknown", "detected"})


def _effective_direct_status(dep: Dependency) -> DependencyStatus:
    """Apply ADR-012 fail-closed downgrade for SAFE direct deps in
    unregistered ecosystems. Direct SAFE in an ecosystem registered in
    NEITHER pin-detector nor no-pin-mechanism set classifies as
    UNCERTAIN — never silently SAFE.

    Meta-ecosystems (``unknown`` / ``detected``) are exempt — they are
    not real packaging systems and so do not signal a missing
    pin-detector registration.
    """
    if dep.status is not DependencyStatus.SAFE:
        return dep.status
    eco = dep.ecosystem
    if eco in _FAIL_CLOSED_EXEMPT:
        return DependencyStatus.SAFE
    if has_pin_detector(eco) or has_no_pin_mechanism(eco):
        return DependencyStatus.SAFE
    return DependencyStatus.UNCERTAIN


def _all_nodes_agree_on_resolved(nodes: list[VersionedNode]) -> bool:
    """G4 — return True when every node in ``nodes`` is ``is_resolved``,
    meaning all declared expressions for the coord cover the resolved
    version. Such a coord is NOT an actual multi-version conflict
    (e.g. a range ``[1.0,2.0)`` and a soft requirement ``1.5`` both
    accept 1.5.0)."""
    if not nodes:
        return True
    return all(n.is_resolved for n in nodes)


def classify_versioned(
    deps: list[Dependency],
    dep_edges: list[DepEdge],
    *,
    resolved_versions: dict[str, str] | None = None,
    version_match: Callable[[str | None, str | None], bool] | None = None,
) -> tuple[list[Dependency], list[VersionedNode], list[str]]:
    """Run the per-version classifier (REQ-20).

    Returns ``(deps_with_updated_status, versioned_nodes,
    multi_version_coords)``. ``versioned_nodes`` is one entry per
    ``(canonical, declared_version)`` pair reachable from any edge,
    capped at :data:`_COORD_VERSION_CAP` per coordinate. The resolved
    version (if supplied) is always retained when the cap fires.

    SUC-42 pin-deferral safety is applied to every node BEFORE the
    rollup; legacy ``Dependency.status`` reflects the strongest
    per-version classification (any IN_USE → IN_USE).

    G4 — ``version_match`` (optional) compares a node's
    ``declared_version`` against the resolved version. Defaults to
    equality. Maven callers pass
    :func:`scarno.analysers.java._maven_version.declared_covers_resolved`
    so that a declared range (``[1.0,2.0)``) matches a resolved
    version inside it (``1.5``). With range matching, a coord
    whose declared expressions all cover the resolved version is
    NOT flagged as multi-version (no actual conflict).
    """
    if version_match is None:
        # Default match — equality, but two ``None`` operands are NOT
        # a match (a None-declared node with no resolved version is
        # NOT "resolved"; the caller should treat it as unresolved
        # and let the reporter fall back on Dependency.version).
        def _default_match(a: str | None, b: str | None) -> bool:
            if a is None or b is None:
                return False
            return a == b
        version_match = _default_match
    if resolved_versions is None:
        resolved_versions = {}

    # Index dependencies by normalised canonical name AND track the
    # original (display) name for each normalised key so VersionedNode
    # objects carry the user-recognisable form, not the
    # ``[-_.]+ → -`` collapsed key used internally for graph matching.
    dep_by_name: dict[str, Dependency] = {}
    display_name: dict[str, str] = {}
    for d in deps:
        nk = _normalise(d.name)
        dep_by_name.setdefault(nk, d)
        display_name.setdefault(nk, d.name)

    # Forward adjacency: parent canonical → list of (child, version).
    children_of: dict[str, list[tuple[str, str | None]]] = {}
    for e in dep_edges:
        parent_key = _normalise(e.parent) if e.parent else ""
        child_key = _normalise(e.child)
        children_of.setdefault(parent_key, []).append(
            (child_key, e.declared_version)
        )
        # Edge-emitted child names also seed display_name when the
        # corresponding Dependency wasn't supplied (e.g. a transitive
        # only present in dep_edges). Original-form first-seen wins.
        display_name.setdefault(child_key, e.child)

    # For each direct dep, propagate effective status to every
    # reachable (child, version) node. Also track per-node reason text
    # so fail-closed downgrades carry an explanation through to the
    # rendered report.
    node_status: dict[tuple[str, str | None], DependencyStatus] = {}
    node_reason: dict[tuple[str, str | None], str] = {}

    for root_child, root_version in children_of.get("", []):
        dep = dep_by_name.get(root_child)
        if dep is None:
            continue
        eff = _effective_direct_status(dep)
        downgraded = (
            dep.status is DependencyStatus.SAFE
            and eff is DependencyStatus.UNCERTAIN
        )
        downgrade_reason = (
            f"no pin-detector for ecosystem {dep.ecosystem!r} yet; "
            f"direct deps not classified SAFE until the detector lands "
            f"(REQ-21 Maven / REQ-23 npm / REQ-21b Gradle)."
            if downgraded
            else ""
        )
        root_node = (root_child, root_version)
        prev = node_status.get(root_node)
        node_status[root_node] = _stronger(prev, eff)
        if downgrade_reason and node_status[root_node] is eff:
            node_reason[root_node] = downgrade_reason
        # BFS through descendants
        visited: set[str] = set()
        stack: list[str] = [root_child]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for child_key, child_v in children_of.get(current, []):
                child_node = (child_key, child_v)
                prev_c = node_status.get(child_node)
                node_status[child_node] = _stronger(prev_c, eff)
                if downgrade_reason and node_status[child_node] is eff:
                    node_reason[child_node] = downgrade_reason
                if child_key not in visited:
                    stack.append(child_key)

    # Build VersionedNode list with pin-override safety applied.
    nodes_by_coord: dict[str, list[VersionedNode]] = {}
    for (canonical, version), status in node_status.items():
        dep = dep_by_name.get(canonical)
        # G4 — range-aware match. ``version_match`` defaults to
        # equality but Maven callers pass a range comparator so that
        # a declared expression like ``[1.0,2.0)`` matches a resolved
        # ``1.5.0`` (no actual conflict).
        is_resolved = version_match(version, resolved_versions.get(canonical))
        removable = status is DependencyStatus.SAFE
        if removable:
            reason = (
                "only reachable through unused parent(s); safe to drop this version"
            )
        else:
            reason = node_reason.get((canonical, version), "")
        node = VersionedNode(
            canonical=display_name.get(canonical, canonical),
            declared_version=version,
            status=status,
            is_resolved=is_resolved,
            removable=removable,
            reason=reason,
        )
        # G2 — always run the safety pass; the helper internally gates
        # the dep-specific pin/manifest-redundant rules on ``dep is not
        # None`` but enforces the ``is_resolved → removable=False``
        # rule unconditionally. Skipping it for purely-transitive
        # coords was the root cause of "resolved version flagged
        # removable" reports.
        apply_pin_override_safety(dep, node)
        nodes_by_coord.setdefault(canonical, []).append(node)

    # Per-coordinate version cap (SEC-NEW-39). Resolved version is
    # always retained when the cap fires.
    multi_version_coords: list[str] = []
    capped_nodes: list[VersionedNode] = []
    for coord in sorted(nodes_by_coord.keys()):
        nodes = nodes_by_coord[coord]
        if len(nodes) > _COORD_VERSION_CAP:
            nodes.sort(
                key=lambda n: (
                    0 if n.is_resolved else 1,
                    n.declared_version or "",
                )
            )
            nodes = nodes[:_COORD_VERSION_CAP]
            nodes_by_coord[coord] = nodes
        if len(nodes) > 1 and not _all_nodes_agree_on_resolved(nodes):
            # Emit the display (original) coordinate name, not the
            # normalised graph key. ``VersionedNode.canonical`` is also a
            # display name, and every consumer — the markdown / text
            # reporters and the REQ-22 ABI differ — joins these two
            # fields by equality. A normalised key here (``com-google-
            # guava:guava`` vs the node's ``com.google.guava:guava``)
            # makes that join silently miss for every dotted coordinate.
            #
            # G4 — ``_all_nodes_agree_on_resolved`` filters out the
            # case where every declared expression covers the same
            # resolved version (e.g. ``[1.0,2.0)`` and ``1.5`` both
            # resolve to 1.5.0). That isn't an actual conflict and
            # used to surface as a spurious row in the multi-version
            # table.
            multi_version_coords.append(display_name.get(coord, coord))
        capped_nodes.extend(nodes)

    # Rollup: Dependency.status = strongest per-version status.
    new_deps: list[Dependency] = []
    for dep in deps:
        canonical = _normalise(dep.name)
        coord_nodes = nodes_by_coord.get(canonical)
        if not coord_nodes:
            new_deps.append(dep)
            continue
        statuses = [n.status for n in coord_nodes]
        if any(s is DependencyStatus.IN_USE for s in statuses):
            new_status = DependencyStatus.IN_USE
        elif any(s is DependencyStatus.UNCERTAIN for s in statuses):
            new_status = DependencyStatus.UNCERTAIN
        elif any(s is DependencyStatus.UNDECLARED for s in statuses):
            new_status = DependencyStatus.UNDECLARED
        else:
            new_status = DependencyStatus.SAFE
        if new_status is dep.status:
            new_deps.append(dep)
        else:
            new_deps.append(replace(dep, status=new_status))

    return new_deps, capped_nodes, multi_version_coords
