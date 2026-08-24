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

"""Shared data models for Scarno.

Extended through Phase 2.5 (REQ-9) with polyglot fields: every
``Dependency`` carries an ``ecosystem`` tag, and ``AnalysisResult``
tracks the full set of languages scanned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# ── Polyglot foundations (REQ-9) ─────────────────────────────────────────────
#
# Canonical ecosystem identifiers. The tag is packaging-system-specific —
# ``maven`` and ``gradle`` are distinct even though both resolve to Java
# artifacts, because the tooling and lock semantics differ.

CANONICAL_ECOSYSTEMS: frozenset[str] = frozenset(
    {
        "pypi",     # Python (REQ-2)
        "maven",    # Maven artifacts (REQ-4)
        "gradle",   # Gradle deps (REQ-5)
        "npm",      # npm / yarn / pnpm / bun / Node.js (REQ-10)
        "css",      # CSS-only imports (REQ-12)
        "go",       # Go modules (REQ-13)
        "nuget",    # C# / F# / VB.NET (REQ-15)
        "detected", # REQ-3b phantom imports whose ecosystem couldn't be resolved
        "unknown",  # default placeholder
    }
)

# Maps an ecosystem tag → the detector/registry "language" key responsible
# for producing it. The ``--language`` CLI flag accepts ecosystem names
# and uses this map to decide which analyser(s) to run.
ECOSYSTEM_TO_LANGUAGE: dict[str, str] = {
    "pypi": "python",
    "detected": "python",   # phantom deps emitted by the Python analyser
    "maven": "java",
    "gradle": "java",
    "npm": "javascript",
    "css": "javascript",
    "go": "go",
    "nuget": "csharp",
}


class DependencyStatus(str, Enum):
    """Classification of a dependency's usage status."""

    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"
    IN_USE = "IN_USE"
    UNDECLARED = "UNDECLARED"


class FindingSeverity(str, Enum):
    """Severity ladder for security findings (REQ-3c)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingKind(str, Enum):
    """Categorical kind for a finding (REQ-3c)."""

    RUNTIME_PIP_INSTALL = "RUNTIME_PIP_INSTALL"
    NOTEBOOK_PIP_MAGIC = "NOTEBOOK_PIP_MAGIC"
    REMOTE_CODE_EXEC = "REMOTE_CODE_EXEC"
    DOWNLOAD_AND_EXEC = "DOWNLOAD_AND_EXEC"
    OS_SYSTEM_PIP = "OS_SYSTEM_PIP"
    DYNAMIC_IMPORT_UNVALIDATED = "DYNAMIC_IMPORT_UNVALIDATED"
    INSECURE_UNPICKLE_REMOTE = "INSECURE_UNPICKLE_REMOTE"
    SETUP_PY_DYNAMIC_DEPS = "SETUP_PY_DYNAMIC_DEPS"
    VENDORED_OVERLAP = "VENDORED_OVERLAP"
    VENDORED_ONLY = "VENDORED_ONLY"
    CURL_PIPE_SHELL = "CURL_PIPE_SHELL"
    SHELL_INJECTION_IN_INSTALL = "SHELL_INJECTION_IN_INSTALL"
    GO_REPLACE_REMOTE_URL = "GO_REPLACE_REMOTE_URL"
    UNSAFE_POINTER_USE = "UNSAFE_POINTER_USE"
    CGO_IMPORT = "CGO_IMPORT"
    EXEC_COMMAND_TAINT = "EXEC_COMMAND_TAINT"
    CUSTOM_REGISTRY = "CUSTOM_REGISTRY"
    MSBUILD_EXEC_TASK = "MSBUILD_EXEC_TASK"
    MSBUILD_USING_TASK = "MSBUILD_USING_TASK"
    DLLIMPORT_PINVOKE = "DLLIMPORT_PINVOKE"
    ASSEMBLY_LOAD_TAINT = "ASSEMBLY_LOAD_TAINT"
    PROCESS_START_TAINT = "PROCESS_START_TAINT"
    # REQ-22 — cross-version ABI diff (PR-4, --deep-inspection only).
    # ABI_RUNTIME_RISK is the high-confidence COMP-004 signal: a
    # symbol the project's source actually calls is REMOVED or
    # signature-CHANGED between the declared and resolved versions
    # of a transitive. ABI_DRIFT is the same shape of finding but
    # for symbols the source does NOT reference — useful for
    # reviewers but not a runtime hazard on its own.
    ABI_RUNTIME_RISK = "ABI_RUNTIME_RISK"
    ABI_DRIFT = "ABI_DRIFT"
    # REQ-24 / SEC-NEW-71 — emitted when --integrity-cross-check
    # detects byte-disagreement between the same artefact fetched from
    # the top-2 priority indexes for an ecosystem (after retry-once,
    # SEC-NEW-74). Suggests a compromised / MITM'd index.
    ABI_INTEGRITY_MISMATCH = "ABI_INTEGRITY_MISMATCH"


class PinOverrideKind(str, Enum):
    """REQ-19a NEW-ARCH-008 — closed enum of pin-override mechanism names.

    Each value identifies the packaging-system construct that pinned a
    direct dep in place (so SUC-42 enforcement defers to it instead of
    flagging the dep as removable). Adding a new kind requires updating
    this enum AND ``apply_pin_override_safety`` in core/classifier.py
    in the same PR — enforced by the SEC-NEW-48 enum-coverage test.

    Allocation per architecture ADR-007:

    * REQ-21 (Maven, PR-3): EXCLUSION, DEPENDENCY_MANAGEMENT
    * REQ-23 (npm, PR-5): NPM_OVERRIDES, YARN_RESOLUTIONS, PNPM_OVERRIDES
    * REQ-21b (Gradle, PR-6): GRADLE_FORCE, GRADLE_STRICTLY,
      GRADLE_CONSTRAINTS, GRADLE_EXCLUSION, GRADLE_DYNAMIC_PIN
    """

    EXCLUSION = "EXCLUSION"
    DEPENDENCY_MANAGEMENT = "DEPENDENCY_MANAGEMENT"
    # REQ-23 (PR-5) — npm / yarn / pnpm pin mechanisms.
    NPM_OVERRIDES = "NPM_OVERRIDES"
    YARN_RESOLUTIONS = "YARN_RESOLUTIONS"
    PNPM_OVERRIDES = "PNPM_OVERRIDES"
    # REQ-21b (PR-6) — Gradle DSL pin mechanisms.
    # GRADLE_DYNAMIC_PIN is special: the safety function downgrades to
    # UNCERTAIN (rather than forcing IN_USE) because the target
    # version is computed at execute-time and can't be verified
    # statically.
    GRADLE_FORCE = "GRADLE_FORCE"
    GRADLE_STRICTLY = "GRADLE_STRICTLY"
    GRADLE_CONSTRAINTS = "GRADLE_CONSTRAINTS"
    GRADLE_EXCLUSION = "GRADLE_EXCLUSION"
    GRADLE_DYNAMIC_PIN = "GRADLE_DYNAMIC_PIN"


@dataclass(frozen=True)
class DepEdge:
    """A single declared parent → child dependency edge (REQ-19).

    ``parent`` is the canonical name of the parent dep, or ``""`` for an
    edge from the project root. ``child`` is the canonical name of the
    child. ``declared_version`` is the version literal as it appeared in
    the parent's manifest (post-sanitise, capped at 64 chars per
    SEC-NEW-38); ``None`` when the manifest declared no version OR a
    version placeholder could not be resolved (REQ-19 acceptance — never
    silently drop the edge).

    Frozen so the classifier (REQ-20) can hash edges without defensive
    copies.
    """

    parent: str
    child: str
    declared_version: str | None
    scope: str = "runtime"


@dataclass(frozen=True)
class JavaSignature:
    """REQ-22 — a single public Java symbol parsed from javap output.

    Frozen + hashable so cross-version diffing reduces to set
    operations on (fqcn, member_kind, member_name, descriptor) tuples.
    ``descriptor`` is part of that key: overloads share the other
    three fields, so matching on member identity alone loses every
    deleted overload of a member that survives under a different
    parameter list (FR-272). Modifiers are tracked separately because
    they shouldn't affect "is this the same symbol" identity but DO
    contribute to the signature_diff CHANGED set when modifiers shift.
    """

    fqcn: str
    member_kind: str
    member_name: str
    descriptor: str
    modifiers: frozenset[str]


@dataclass
class VersionedNode:
    """REQ-20 — a single (canonical, declared_version) node with its
    independent classification.

    Created by ``core/classifier.py:classify_versioned`` and consumed
    by reporters that need per-version detail (the "Multiple versions
    detected" markdown section + SARIF ``TS-DEP-MULTI-VERSION`` rule).
    """

    canonical: str
    declared_version: str | None
    status: DependencyStatus
    is_resolved: bool = False
    removable: bool = False
    reason: str = ""


@dataclass
class EntryPoint:
    """A public symbol exposed by a dependency."""

    name: str
    kind: str
    used: bool
    # REQ-17 — number of source-level reference sites (call/attribute access)
    # for this symbol. Always 0 when ``used`` is False.
    usage_count: int = 0


@dataclass
class Dependency:
    """A declared (or detected) project dependency, with its classification."""

    name: str
    version: str | None
    status: DependencyStatus
    reason: str
    entry_points: list[EntryPoint] = field(default_factory=list)
    entry_points_used: int = 0
    entry_points_total: int = 0
    # Provenance string — file/section of origin (REQ-2b).
    source: str = "unknown"
    # REQ-3b: vendored copy path, if any.
    vendored_path: str | None = None
    # REQ-3b: False when UNDECLARED and the import couldn't be resolved to a distribution.
    resolved: bool = True
    # REQ-2: type stub marker.
    is_type_stub: bool = False
    # REQ-9 — polyglot: canonical ecosystem tag (CANONICAL_ECOSYSTEMS).
    ecosystem: str = "unknown"
    # True when the dep was identified as transitive (e.g. from uv.lock graph).
    is_transitive: bool = False
    # REQ-17 — True when project source imports this dep directly, regardless
    # of how it was declared. Set on transitives whose top-level import name
    # appears in the source-derived ``direct_all`` set; used by reporters to
    # surface the "promote to first-class" recommendation.
    imported_directly: bool = False
    # FR-150 — True when the dep is a direct manifest declaration
    # (``is_transitive=False``) that is also reachable as a transitive of
    # an IN_USE dep. The artifact stays on the classpath via the
    # transitive path, so the explicit manifest declaration is
    # redundant. The dep's status is IN_USE (the artifact may be needed
    # by its parent at runtime — we cannot prove otherwise without
    # reading the parent's bytecode), but reporters surface this flag
    # so the developer can prune the redundant manifest line.
    manifest_redundant: bool = False
    # FR-150 — when ``manifest_redundant`` is True, the canonical name
    # of the IN_USE parent that keeps this dep alive transitively. Used
    # in reason text and report annotations.
    redundant_parent: str | None = None
    # REQ-21 / 21b / 23 — pin-override detection (PR-2 introduces the
    # fields; PR-3 / 5 / 6 populate them via their per-ecosystem
    # detectors). When ``pin_override`` is True the classifier's
    # ``apply_pin_override_safety`` forces the matching ``VersionedNode``
    # to IN_USE (or UNCERTAIN for ``GRADLE_DYNAMIC_PIN``), regardless
    # of source-level usage. This is the load-bearing safety property
    # (SUC-42) that prevents silent-vulnerability-reintroduction
    # misclassifications.
    #
    # ``pin_override`` and ``manifest_redundant`` are mutually
    # exclusive: a dep that is load-bearing as a substitute for an
    # excluded transitive cannot simultaneously be redundant. The
    # invariant is enforced in ``__post_init__`` (NEW-ARCH-007 /
    # FR-251) and double-checked in the classifier (SEC-NEW-47).
    pin_override: bool = False
    pin_override_kind: str | None = None
    pin_override_target: str | None = None

    def __post_init__(self) -> None:
        # NEW-ARCH-007 / FR-251 — pin_override and manifest_redundant
        # are mutually exclusive. Construction-time enforcement is
        # defence-in-depth against a future code path that builds a
        # Dependency and then mutates both flags.
        if self.pin_override and self.manifest_redundant:
            raise ValueError(
                f"{self.name}: pin_override and manifest_redundant are "
                f"mutually exclusive; a load-bearing pin substitute "
                f"cannot also be manifest-redundant."
            )


@dataclass
class Finding:
    """A structured security finding (REQ-3c)."""

    rule_id: str
    kind: FindingKind
    severity: FindingSeverity
    file_path: str
    line: int
    snippet: str
    message: str
    remediation: str
    package_hint: str | None = None
    suppressed: bool = False
    # REQ-24 / FR-265 — provenance of the artefact that produced this
    # finding. ``"local"`` (default) for findings derived purely from
    # in-tree source / pre-existing cache reads — the pre-REQ-24
    # behaviour. ``"remote"`` for findings whose ABI comparison
    # depended on an artefact fetched by ``RemoteArtifactFetcher``;
    # tagging is conservative — if EITHER side of the comparison was
    # remote, the finding is remote (N-10 / closing threat-model
    # pass). Reporters use this to gate the top-of-report banner
    # (FR-266) and the ``--fail-on-remote-severity`` opt-in (FR-267).
    provenance: str = "local"


@dataclass
class AnalysisResult:
    """The full result of analysing a project."""

    project_type: str
    project_path: str
    dependencies: list[Dependency] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # REQ-9 — polyglot: every language that contributed to this result.
    # Single-language projects keep ``languages = [project_type]`` for
    # symmetry; empty only when nothing was detected.
    languages: list[str] = field(default_factory=list)
    # REQ-17 — adjacency map of dep canonical-name → set of canonical-name
    # children, used by the Markdown reporter to render the ASCII
    # dependency tree (``_render_ascii_tree``). The Mermaid renderer is
    # retained in the reporter as a defence-in-depth helper but is not
    # called from the live render path. Empty when no lock-file or
    # manifest provides graph data.
    dep_graph: dict[str, set[str]] = field(default_factory=dict)
    # REQ-19 — per-edge declared-version edges. Empty when the
    # ecosystem does not surface version-keyed edges. When supplied
    # without ``dep_graph``, the legacy ``dep_graph`` is derived from
    # ``dep_edges`` once in ``__post_init__``; explicit ``dep_graph`` is
    # preserved (additive back-compat per architecture §11.2.2).
    dep_edges: list[DepEdge] = field(default_factory=list)
    # REQ-20 — per-version classifier output. Populated by
    # ``core/classifier.py:classify_versioned`` when the analyser
    # supplies ``dep_edges``. Empty when the analyser has not yet
    # migrated to REQ-20.
    versioned_nodes: list[VersionedNode] = field(default_factory=list)
    # REQ-20 — canonical names that appear at >1 declared version.
    # Drives the "Multiple versions detected" report section.
    multi_version_coords: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Derive the legacy canonical-only ``dep_graph`` from
        # ``dep_edges`` when only the new field is supplied. Caller-supplied
        # ``dep_graph`` is preserved without overwrite.
        if self.dep_edges and not self.dep_graph:
            derived: dict[str, set[str]] = {}
            for e in self.dep_edges:
                if e.parent:  # skip synthetic root edges
                    derived.setdefault(e.parent, set()).add(e.child)
            self.dep_graph = derived
