# REQ-20 — Per-Version Classification and Resolved-Version Marker

## Overview

A given coordinate (`groupId:artifactId` / npm name / etc.) may
appear in the resolved graph at multiple **declared** versions —
diamond dependencies, npm nested packages, Gradle constraints. REQ-20
classifies each declared version **independently** as
`SAFE` / `UNCERTAIN` / `IN_USE` based on whether *any* parent path
reaching that specific version is `IN_USE`. The version that the
package manager actually picks at resolution time ("nearest wins" /
`overrides` / Gradle `force()`) is rendered with a visual marker so
the developer can see at a glance which one is on the classpath.

A new "Multiple versions detected" report section lists every
coordinate present at >1 declared version with its declared versions,
the resolved version, and per-version removability. The motivating
goal: **reduce SBOM noise so vulnerability scanners aren't flooded
with versions of a library that aren't actually shipped.**

---

## Problem Statement

Two gaps that REQ-19 alone does not close:

- **Classification today is per-canonical-name, not per-version.**
  `_resolve_transitive_statuses` (REQ-17 §5b) marks `X` IN_USE if any
  parent path is IN_USE. Once REQ-19 surfaces `X@1.1` and `X@1.2` as
  distinct nodes, the classification must follow — `X@1.2` reachable
  only via unused parents *can* be safely removed even when `X@1.1`
  stays IN_USE through a different path.
- **Resolved version is invisible.** Maven's "nearest wins", npm's
  `overrides`, Gradle's `force` / `strictly`: each of these picks one
  version to actually deploy. The user reading the tree cannot tell
  which version is on the classpath. Without this, "remove X@1.2 from
  the SBOM" advice is unsafe — the user might inadvertently remove
  the *resolved* version and leave a phantom requirement.

Why SBOM noise matters: every version listed in an SBOM is a
candidate for vulnerability matching. A coordinate present at four
declared versions, only one of which is actually on the classpath,
generates 4× the CVE alerts of which 3× are noise. CRA-readiness
(see `COMP-004`) directly benefits.

---

## Solution

### 1. Data-model changes

```python
@dataclass
class VersionedNode:
    """A (canonical, declared_version) node with its independent classification."""

    canonical: str
    declared_version: str | None
    status: DependencyStatus              # SAFE / UNCERTAIN / IN_USE / UNDECLARED
    is_resolved: bool = False             # True iff this is the version the
                                          # package manager actually picked
    removable: bool = False               # True iff status == SAFE AND no
                                          # IN_USE parent path reaches this version
    reason: str = ""                      # human-readable narrative


@dataclass
class AnalysisResult:
    ...
    # REQ-20 — per-version classification map. Empty when REQ-19
    # dep_edges is empty (i.e. the ecosystem hasn't yet been
    # extended).
    versioned_nodes: list[VersionedNode] = field(default_factory=list)

    # REQ-20 — coordinates present at >1 declared version. Used by
    # the "Multiple versions detected" report section. Empty when no
    # diamond is present.
    multi_version_coords: list[str] = field(default_factory=list)
```

### 2. Classification algorithm

```
for each (canonical, declared_version) node V in versioned_nodes:
    parent_paths = all paths from a root to V via dep_edges
    if any path's parents are all IN_USE deps:
        V.status = IN_USE
        V.removable = False
    elif all paths are reachable but every path contains a SAFE parent:
        V.status = SAFE
        V.removable = True
        V.reason = "only reachable through unused parent(s); safe to drop this version"
    else:
        V.status = UNCERTAIN
        V.removable = False
```

The parent-status lookup uses the existing
`_resolve_transitive_statuses` machinery, but it now keys on
`(canonical, declared_version)` instead of `canonical`. The original
canonical-only classification on `Dependency` is preserved as the
**any-version-IN_USE** rollup (so existing reporters that read
`Dependency.status` see the same answer they always did).

### 3. Resolved-version detection

| Ecosystem | How we know which version was resolved |
|---|---|
| **Maven** | `mvn dependency:tree` output (already invoked by REQ-4 paths) reports the resolved version per coordinate. Where the tool is unavailable, fall back to "nearest wins" rule against the dep_edges shortest path. |
| **Gradle** | `gradle dependencies` output already shows `requested -> resolved`; the right-hand side is the resolved version. `gradle.lockfile` overrides this when present. |
| **npm** | `package-lock.json` records the actual installed version per package path; the *root-level* installed version is the "resolved" version for the coordinate. yarn.lock / pnpm-lock.yaml: same rule (the entry whose path is the package's root install). |

If the ecosystem returns no resolved version (rare, e.g. corrupt
lockfile), `is_resolved=False` on every node for that coordinate
and the report annotates the coordinate as "resolved version
unknown".

### 4. "Multiple versions detected" report section

Markdown reporter renders, immediately after the dependency tree:

```markdown
## Multiple versions detected

| Coordinate | Declared versions | Resolved | Removable |
|---|---|---|---|
| com.example:x | 1.1, **1.2 (resolved)**, 1.3 | 1.2 | 1.3 (only via unused alpha) |
| react | 18.2.0, **18.3.1 (resolved)** | 18.3.1 | 18.2.0 (only via unused legacy-mod) |
```

JSON / SARIF: `multi_version_coords` plus the `versioned_nodes`
array. SARIF rule `TS-DEP-MULTI-VERSION` with severity `note`.

### 5. Visual resolved-version marker in the tree

Tree renderer extension to REQ-19's per-edge labels:

```
  ├── alpha@2.0
  │   └── x@1.1
  └── beta@3.0
      └── x@1.2  ← resolved          (bold + arrow marker)
```

The marker is plain ASCII (`← resolved`) so it survives in
copy/paste and non-ANSI terminals. In the diff-fenced markdown
block, the resolved row uses a `+` prefix (renders green) whereas
removable-but-redundant rows use `-` (renders red). UNCERTAIN rows
keep `!`.

### 6. Per-coordinate version count cap (`SEC-NEW-39`)

A coordinate with > 64 declared versions is treated as adversarial
input. The classifier caps `versioned_nodes` for that coordinate at
64 entries, sorted by `(is_resolved DESC, declared_version)` so the
resolved version is never dropped. An error is recorded:

```
"coordinate <name> has >64 declared versions; truncated to first 64"
```

This prevents a crafted lockfile from creating a massive cross-product
in the parent-path traversal.

---

## Use Cases

```
UC-20a: Diamond — version 1.2 only used by unused parent
Actor: Maven developer.
Goal: See that x@1.2 is flagged removable while x@1.1 stays IN_USE.
Preconditions: pom.xml direct deps alpha (used) and beta (unused);
  alpha → x 1.1, beta → x 1.2; resolved version is 1.1 (nearest wins).
Main flow:
  1. REQ-19 emits both edges with their declared versions.
  2. _resolve_transitive_statuses keys on (canonical, version).
  3. x@1.1 is IN_USE (via alpha); x@1.2 is SAFE removable (via beta only).
  4. Resolved-version marker on x@1.1.
Postcondition: user sees they can drop beta AND remove x@1.2 from
  any pinned dep-management without affecting runtime.

UC-20b: npm overrides change the resolved version
Actor: Frontend dev.
Goal: See that overrides bumped lodash to 4.17.21 even though most
  parents declared 4.17.15.
Main flow:
  1. package.json `overrides: { lodash: "4.17.21" }`.
  2. package-lock.json records resolved 4.17.21.
  3. Tree shows lodash@4.17.15 nodes (declared) AND a separate
     lodash@4.17.21 ← resolved node.
  4. "Multiple versions detected" lists lodash with declared 4.17.15,
     resolved 4.17.21, removable: 4.17.15 (transitively reachable but
     never the picked version — dropped at install time anyway).

UC-20c: All declared versions used (no removability)
Actor: Polyglot developer.
Goal: Confirm that when every version of x has at least one IN_USE
  parent path, NO version is flagged removable.
Main flow:
  1. Both alpha (used) and beta (used) declare x at distinct versions.
  2. Classifier marks both x@1.1 and x@1.2 IN_USE.
  3. multi_version_coords still lists x for the user's awareness, but
     "Removable" column shows "—".
Postcondition: report doesn't generate a false-positive removal recommendation.
```

---

## Abuse Cases

```
SAC-42: False-positive removal of a pinned version
Linked threat: T-28
Attacker: Not malicious — this is a classifier-correctness threat
  rather than an external attacker. The "abuser" is a misclassification
  bug that propagates into developer action.
Goal: Cause Scarno to recommend removing a version that is in
  fact the resolved one and on the classpath.
Trigger: A direct <dependency> appears unused at the source level
  (no imports), but it is the resolved version due to a
  <dependencyManagement> pin (REQ-21 territory). REQ-20 must NOT mark
  this declared version SAFE/removable; instead it must DEFER to
  REQ-21's pinning detection and tag the version with status=IN_USE,
  reason="pinned via <dependencyManagement>".
Mitigated by: SUC-42 — the classification rule explicitly checks
  `manifest_redundant` (FR-150) and pinning flags (REQ-21) before
  promoting any direct dep version to SAFE. When in doubt, classify
  as UNCERTAIN.
OWASP: A04:2021 — Insecure Design (incorrect trust boundary).

SAC-43: State-explosion via crafted lockfile with many versions per coord
Linked threat: T-28
Attacker: External (crafts a package-lock.json with hundreds of
  versions of one coordinate via deeply nested transitives).
Goal: Cause path-traversal classifier to scale O(versions × parent_paths).
Mitigated by: SEC-NEW-39 (per-coordinate version cap of 64) plus the
  SEC-NEW-37 edge cap inherited from REQ-19.
OWASP: A05:2021 — Security Misconfiguration (resource exhaustion).
```

---

## Privacy

```
PT-12: Per-version disclosure of internal coordinates in SBOM-relevant output
LINDDUN: Disclosure
Affected data: same canonical names as REQ-17 — adding versions
  doesn't add personal data.
Likelihood: Low.
Impact: Low.

PUC-11: All version strings remain sanitised (REQ-19 SUC-40)
Mitigates: PT-12 (defence-in-depth)
Privacy control: VersionedNode.declared_version inherits the
  REQ-19 SEC-NEW-38 sanitiser. No new data category.
PbD principle: Privacy embedded into design.
```

---

## Performance

```
PERF-011: Per-version classification scaling
- For a graph of N coordinates, V total declared versions, E edges:
  classification is O(V + E) thanks to memoised parent-path lookups.
- Hard caps: SEC-NEW-37 (50 000 edges), SEC-NEW-39 (64 versions
  per coord) bound worst case.
- Real-world budget: 1000-dep Maven project with ~5 diamonds adds
  < 100 ms vs the REQ-19 baseline.
- "Multiple versions detected" table render: O(coordinates) — bounded
  by the same dep-count cap as REQ-17's tree (1000 nodes).
```

---

## Security Use Cases (Countermeasures)

```
SUC-42: Classifier defers to pinning flags
Mitigates: SAC-42
Control: Before classifying a (canonical, declared_version) node SAFE,
  the classifier checks:
    - Dependency.manifest_redundant (FR-150)
    - REQ-21 pinning flags (PIN_OVERRIDE_EXCLUSION / PIN_OVERRIDE_DM)
    - REQ-23 npm-overrides pin
  If any is true, status is forced to IN_USE with the relevant pinning
  reason. Removable defaults to False.
Implementation: src/scarno/core/classifier.py (NEW module — see
  architecture §11.4 / ADR-006). The earlier reference to
  src/scarno/core/detector.py was a Phase-1 misnomer; the existing
  detector.py is the project-type detector and is unrelated to
  classification. The new core/classifier.py extracts the previously
  Python-only _resolve_transitive_statuses (analysers/python/source_analyser.py:1165)
  into a single shared, version-aware classifier so every ecosystem
  receives uniform SUC-42 enforcement.
OWASP ASVS: §1.4.1 Trust boundary verification.

SUC-43: Per-coordinate version cap
Mitigates: SAC-43
Control: SEC-NEW-39 caps versions per coordinate at 64 with explicit
  truncation note in errors[].
Implementation: src/scarno/core/classifier.py (NEW module — see
  architecture §11.4 / ADR-006). Co-located with SUC-42 enforcement;
  the earlier Phase-1 reference to core/detector.py was a misnomer.
OWASP ASVS: §11.1.4 Resource limits.

SUC-44: SBOM-noise reporting
Mitigates: COMP-004 (CRA SBOM clarity, not a security threat per se)
Control: "Multiple versions detected" section explicitly labels which
  declared versions are removable AND which is resolved, so SBOM
  consumers can suppress noise without losing fidelity.
Implementation: src/scarno/reporters/markdown_reporter.py +
  json_reporter + sarif_reporter (rule TS-DEP-MULTI-VERSION).
```

---

## Threat Model Additions

| ID | Threat | Mitigation |
|---|---|---|
| T-28 | Per-version classifier produces a false-positive removal for a pinned/managed version OR is exhausted by a crafted multi-version lockfile. | SUC-42 (defer to pinning flags) + SUC-43 (SEC-NEW-39 version cap) + SEC-NEW-37 inherited from REQ-19. |
| T-29 | Resolved-version detector reads stale or tampered `gradle dependencies` / `mvn dependency:tree` output. | Existing subprocess hardening (argv-only, shell=False, timeout, JAVA_HOME pinning) — no new code path. |

---

## SRTM (REQ-20)

| Req ID | Description | Test File |
|---|---|---|
| FR-200 | `VersionedNode` dataclass + AnalysisResult.versioned_nodes | `tests/unit/test_req20_models.py` |
| FR-201 | Per-version classification: SAFE only when all parent paths SAFE | `tests/unit/test_req20_classify.py::test_diamond_partial_safe` |
| FR-202 | Per-version classification: IN_USE if any parent path IN_USE | `tests/unit/test_req20_classify.py::test_diamond_partial_in_use_promotes` |
| FR-203 | Resolved-version detection (Maven via dependency:tree) | `tests/unit/test_req20_resolved_maven.py` |
| FR-204 | Resolved-version detection (Gradle via dependencies output) | `tests/unit/test_req20_resolved_gradle.py` |
| FR-205 | Resolved-version detection (npm/yarn/pnpm lockfile) | `tests/unit/test_req20_resolved_npm.py` |
| FR-206 | "Multiple versions detected" markdown section | `tests/unit/test_req20_multi_version_section.py` |
| FR-207 | SARIF rule TS-DEP-MULTI-VERSION emission | `tests/unit/test_req20_sarif.py` |
| SEC-NEW-39 | Per-coordinate version cap (64) | `tests/security/test_req20_version_cap.py` |
| PERF-011 | Classifier scales O(V + E); 1000-dep + 5 diamonds < 100 ms | `tests/performance/test_req20_classify_perf.py` |

---

## Acceptance Criteria

- [ ] Given alpha (IN_USE) → x@1.1 and beta (SAFE) → x@1.2, when
  classification runs, then x@1.1 is IN_USE and x@1.2 is SAFE
  removable.
- [ ] Given both alpha (IN_USE) → x@1.1 and beta (IN_USE) → x@1.2,
  when classification runs, then BOTH x versions are IN_USE; the
  multi_version_coords list still names x but Removable column = "—".
- [ ] Given a Maven project where x@1.2 is the resolved version,
  when the tree renders, then exactly one node carries the
  `← resolved` marker.
- [ ] Given an npm project with `overrides: { lodash: "4.17.21" }`,
  when classification runs, then 4.17.21 is the resolved-version
  marker target and the classifier marks 4.17.21 IN_USE; declared
  4.17.15 nodes are tagged removable IF AND ONLY IF no IN_USE parent
  path reaches them, AND REQ-23 pinning flags are not set.
- [ ] Given a coordinate with 100 declared versions in a synthetic
  lockfile, when classification runs, then versioned_nodes for that
  coordinate has exactly 64 entries (resolved version retained), and
  errors[] contains the truncation note.
- [ ] Given a direct <dependency>X</dependency> with no source-level
  use AND <dependencyManagement> pinning X to its version, when
  classification runs, then X@<pinned-version> is IN_USE (NOT SAFE)
  with reason mentioning the dependencyManagement pin (REQ-21).
- [ ] Given the SARIF reporter, when multi-version coordinates exist,
  then exactly one TS-DEP-MULTI-VERSION result per coordinate is
  emitted with severity `note`.

---

## Out of Scope (REQ-20)

- **Auto-removal of safe-redundant versions.** REQ-20 reports them;
  the human (or a follow-up REQ) decides when to write the SBOM
  output.
- **Pinning detection itself** — that's REQ-21 (Maven) / REQ-21b
  (Gradle) / REQ-23 (npm). REQ-20 only consumes their flags.
- **ABI compatibility analysis across versions.** REQ-22 covers
  cross-version method/class diffs.
- **PyPI / Go / NuGet / CSS multi-version awareness.** Same as REQ-19:
  forward-compatible structure but no extraction yet.

---

## Limitations

- **Maven nearest-wins is approximated** when `mvn dependency:tree`
  is unavailable. The fallback walks `dep_edges` and picks the
  shortest path — this matches Maven 3.x in practice but does not
  honour `<exclusions>` precisely.
- **Gradle resolved versions** depend on the configuration the user
  asked Scarno to inspect. We do not currently aggregate across
  configurations; each configuration's classification stands alone.
- **npm peer dependencies** are not modelled as parent edges; they
  do not contribute to per-version classification.
- **Build-time-only deps** (Maven `<scope>provided</scope>`,
  npm devDependencies pre-REQ-17 `--exclude-dev`) are still
  classified per-version under their own scope; they are NOT
  promoted to "removable for runtime SBOM" because their lifecycle
  is build-time, not runtime.
