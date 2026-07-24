# REQ-19 — Per-Edge Version Labels in the Dependency Tree

## Overview

Every edge in the dependency tree must carry the **declared version**
of the child as it appears in the parent's manifest. The same library
declared at two different versions by two different parents must
render as **two distinct nodes** in the tree, not collapse onto one.
This is the substrate REQ-20 builds on (per-version classification
and removability) and REQ-22 reads from (cross-version ABI diff).

Scope:

- **Maven** — root POM `<dependency>` elements and the
  `<dependencies>` section of each cached POM walked by
  `MavenPomResolver._build_transitive_graph` (REQ-17b §FR-165).
- **Gradle** — `gradle dependencies` output for every configuration
  in scope and the lockfile (`gradle.lockfile`) when present.
- **npm** — `package-lock.json` v2/v3, `yarn.lock` (Berry and
  classic), `pnpm-lock.yaml` v6/v7/v9.
- Other ecosystems (PyPI, Go, NuGet, CSS) keep current behaviour —
  per-edge versions are not yet sourced; the tree continues to render
  with declared-version labels on top-level nodes only.

---

## Problem Statement

Three observable gaps in the current dependency tree:

- **`AnalysisResult.dep_graph` is `dict[str, set[str]]` keyed only on
  canonical name.** A child node has no way to know what version its
  parent declared. The reporter compensates by appending `@version`
  on the *root-level* dep label only (`markdown_reporter.py:268`).
  Transitive nodes lose version information entirely.
- **Two parents declaring different versions of the same library
  collapse into one tree node.** A diamond like
  `A -> X@1.1` and `B -> X@1.2` renders as a single `X` child of
  whichever of `A`/`B` was visited first, hiding the version
  divergence the user needs to act on.
- **SBOM-relevant data is silently lost.** SBOM consumers (Syft,
  CycloneDX, SPDX) expect each declared coordinate at its declared
  version; reducing the graph to canonical names destroys that
  fidelity.

Why this matters for downstream REQs:

- REQ-20 cannot classify "X@1.2 is unused" without first knowing
  there are two distinct edges into X.
- REQ-22 cannot diff ABIs across declared versions if the graph
  doesn't tell us which versions are declared.
- REQ-21/23's pinning detection needs to compare a direct
  `<dependency>X@1.3</dependency>` to a transitive edge declaring
  `X@1.2`; without per-edge versions the comparison is meaningless.

---

## Solution

### 1. Data-model changes (`src/scarno/models.py`)

```python
@dataclass(frozen=True)
class DepEdge:
    """A single declared parent → child edge with the declared version."""

    parent: str          # canonical name of the parent (or "" for root edges)
    child: str           # canonical name of the child
    declared_version: str | None   # e.g. "1.2.3", "^4.0", "[1.0,2.0)"; None when omitted
    scope: str = "runtime"         # "runtime" / "test" / "provided" / "compile" / "dev"

    def __post_init__(self) -> None:
        # Defensive: reject control chars / oversize via __setattr__-style pattern
        ...


@dataclass
class AnalysisResult:
    ...
    # REQ-19 — per-edge declared-version edges. Empty when the
    # ecosystem does not surface version-keyed edges. The legacy
    # ``dep_graph`` (canonical → set of canonical) remains populated
    # for backwards compatibility and is computed from
    # ``dep_edges`` when only the new field is supplied.
    dep_edges: list[DepEdge] = field(default_factory=list)
```

`dep_graph` (the existing canonical→canonical map) **remains** so
REQ-17 acceptance criteria do not regress. When `dep_edges` is
populated, `dep_graph` is derived from it as
`{e.parent: {e.child for e in dep_edges if e.parent == p}}`.

### 2. Per-ecosystem extraction

| Ecosystem | Source of declared-version edges | New code path |
|---|---|---|
| **Maven** | Walked POMs already loaded by `MavenPomResolver`. Each `<dependency>` element of every walked POM yields one `DepEdge(parent_gav.canonical, child_gav.canonical, child_gav.version, scope)`. Property-resolved versions follow REQ-17b §"Maven property resolution". | `analysers/java/maven.py:_emit_dep_edges` |
| **Gradle** | Parse `gradle dependencies` per configuration (already executed for FR-070 et al). Each `+--- group:artifact:requested -> resolved` line yields `(parent, child, requested_version)`. Where `gradle.lockfile` is present, prefer it (deterministic). | `analysers/java/gradle.py:_emit_dep_edges` |
| **npm** | `package-lock.json` v2/v3 `packages.<path>.dependencies` mapping → edges; `yarn.lock` resolved entries; `pnpm-lock.yaml` `packages.<key>.dependencies`. The version on the *child* side is whatever the lockfile recorded as `version`, NOT the semver range. | `analysers/javascript/dep_file_parser.py:_emit_dep_edges` |

### 3. Reporter changes

`markdown_reporter._render_ascii_tree` (currently
`markdown_reporter.py:317`) gains a `dep_edges` parameter and prefers
it over the legacy `dep_graph`. Tree node identity becomes
`(canonical, declared_version)` so `X@1.1` and `X@1.2` render as two
sibling subtrees:

```
  org.example:lib                       (root)
  ├── alpha@2.0
  │   └── x@1.1                         (declared by alpha)
  └── beta@3.0
      └── x@1.2                         (declared by beta — distinct node)
```

Edge-level hover behaviour is text-only (no JS):
```
  ├── x@1.1   (declared by alpha@2.0, scope=runtime)
```

JSON / SARIF reporters dump `dep_edges` verbatim; consumers that
only know about `dep_graph` continue to read the canonical-only
field.

### 4. Version-string sanitisation (`SEC-NEW-38`)

Declared-version strings are user-controlled (they originate from
the project's manifests and lockfiles). Before reaching any reporter
they pass through a new helper:

```python
_DECLARED_VERSION_MAX_LEN = 64

def sanitise_declared_version(value: str | None) -> str | None:
    """Bound a declared-version string and strip control / Mermaid-active chars.
    Returns None when the input is None or sanitises to empty."""
    if value is None:
        return None
    text = sanitise(value)                            # existing helper
    text = text.replace("\n", " ").replace("\r", " ")
    text = text[:_DECLARED_VERSION_MAX_LEN]
    return text or None
```

Applied at edge-emission time so the rest of the pipeline can trust
the field. Mirrors the existing label-sanitiser approach
(`_mermaid_label`).

### 5. Lockfile-size hard cap (`SEC-NEW-37`)

`package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` are the only
new file types whose entire content drives edge emission. Per-file
caps:

| Cap | Value | Justification |
|---|---|---|
| `_LOCKFILE_MAX_BYTES` | **8 MiB** | Largest seen in real npm projects: ~6 MiB (`react-native` monorepos). 8 MiB headroom; rejects adversarial files. |
| `_LOCKFILE_MAX_EDGES` | **50 000** | Maven graphs in real projects rarely exceed ~5 k edges; 50 k absorbs npm monorepos. Beyond this, edge emission stops and an error is recorded. |

Caps are enforced in the file reader before parsing.

---

## Use Cases

```
UC-19a: Maven diamond at distinct versions
Actor: Maven developer reviewing Scarno output.
Goal: See that direct dep `alpha` brings in `x@1.1` and direct dep
  `beta` brings in `x@1.2`, rendered as two distinct subtrees.
Preconditions: pom.xml declares alpha 2.0 and beta 3.0 with
  transitive dependencies on x at 1.1 and 1.2 respectively.
Main flow:
  1. Maven analyser builds the transitive graph from ~/.m2 cache
     (REQ-17b §FR-165).
  2. Each transitive dependency is emitted as a DepEdge with the
     declared <version> from the parent POM.
  3. Markdown reporter renders alpha@2.0 → x@1.1 and beta@3.0 → x@1.2
     as siblings.
Postconditions: the user can see both versions and act on each.

UC-19b: npm lockfile-derived edges
Actor: Frontend developer.
Goal: See the same sub-tree distinction across nested transitives.
Preconditions: package-lock.json v3 with `react@18.2.0` and a sub-dep
  resolving `scheduler@0.23.0` and another `scheduler@0.23.2`.
Main flow:
  1. dep_file_parser walks `packages.<path>.dependencies`.
  2. Each entry produces one DepEdge.
  3. The tree shows two scheduler nodes with distinct versions.

UC-19c: Gradle resolution with `requested -> resolved` mismatch
Actor: Gradle developer auditing dependency overrides.
Goal: Confirm the tree shows the declared (requested) version on the
  edge, not a silently-substituted resolved one.
Preconditions: build.gradle declares `implementation("a:b:1.0")` but
  Gradle resolves `a:b:1.5` due to constraint conflict resolution.
Main flow:
  1. `gradle dependencies` output contains `a:b:1.0 -> 1.5`.
  2. Edge emitter records DepEdge(declared_version="1.0").
  3. REQ-20 will subsequently mark "1.5" as the resolved version.
```

---

## Abuse Cases

```
SAC-40: Crafted pom.xml <version> with control characters / Mermaid tokens
Linked threat: T-27
Attacker: External (commits a poisoned pom.xml to a target repo Scarno
  is asked to scan, e.g. via a PR-comment workflow).
Goal: Inject ANSI escapes / newlines / Mermaid-reserved tokens into the
  declared-version field, breaking the rendered Markdown report or smuggling
  fake content into a CI bot's PR comment.
Attack flow:
  1. <version>1.0\n[click n_0 "javascript:..."]</version>
  2. Without sanitisation, the rendered tree row contains a Mermaid click
     directive in viewers that follow it.
Mitigated by: SEC-NEW-38 (sanitise_declared_version).
OWASP: A03:2021 — Injection.

SAC-41: Adversarial package-lock.json with 1M+ edges
Linked threat: T-27
Attacker: External (commits a synthetic package-lock.json).
Goal: Cause Scarno to consume O(N) memory parsing edges where N is
  attacker-chosen.
Attack flow:
  1. Lockfile contains 1M synthetic packages, each with 50 dependencies.
  2. Without a cap, edge-list builds a 50M-element list in memory.
Mitigated by: SEC-NEW-37 (_LOCKFILE_MAX_BYTES + _LOCKFILE_MAX_EDGES).
OWASP: A05:2021 — Security Misconfiguration (resource exhaustion).
```

---

## Privacy Threats and Use Cases

```
PT-11: Edge-leak of internal package paths via dep_edges JSON dump
LINDDUN: Disclosure
Affected data: internal coordinate names (e.g. `com.acme.private:tools`)
  that the project owner did not intend to expose outside their build.
Likelihood: Medium — JSON / SARIF outputs already include canonical
  names today (existing exposure surface, not new).
Impact: Low — same scope as REQ-17.
GDPR relevance: not applicable (project metadata, not personal data).

PUC-10: Sanitised version strings in all reporter outputs
Mitigates: PT-11 (defence-in-depth, not the primary mitigation)
Privacy control: declared-version strings pass through sanitise() and
  the SEC-NEW-38 length cap before any reporter touches them. No new
  data category is added beyond what REQ-17 already exposes.
PbD principle: Privacy embedded into design.
```

---

## Performance Use Cases

```
PERF-010: Tree render with version-keyed nodes
- 1000-dep / 5000-edge project: tree render time within 25% of the
  REQ-17 baseline. Node identity is now (canonical, version) so the
  hash key gets longer but the hash count is bounded by the same edge
  cap.
- O(n + e) where n = unique (canonical, version) pairs, e = edges.
- Cap: 50 000 edges (SEC-NEW-37) hard-rejects pathological lockfiles.
- npm package-lock.json parse: < 500 ms for 8 MiB lockfile (the
  practical upper bound).
```

---

## Security Use Cases (Countermeasures)

```
SUC-40: declared-version sanitiser
Mitigates: SAC-40
Control: every DepEdge.declared_version is produced by
  sanitise_declared_version() (SEC-NEW-38). Reporter code MUST NOT
  bypass the field.
Implementation: src/scarno/security.py — new helper alongside
  existing sanitise().
OWASP ASVS: §5.2.1 Output encoding.

SUC-41: lockfile and edge caps
Mitigates: SAC-41
Control: SEC-NEW-37 caps. Caps are file-size pre-check (before
  parse) AND edge-count post-check (during emit). Either trips the
  same sanitised "lockfile too large" error and edge emission stops;
  the rest of analysis continues so the user gets a partial report.
Implementation: src/scarno/analysers/javascript/dep_file_parser.py
  + src/scarno/analysers/java/maven.py.
OWASP ASVS: §11.1.4 Resource limits.
```

---

## Threat Model Additions

| ID | Threat | Mitigation |
|---|---|---|
| T-27 | Lockfile / POM-derived version strings reach reporters with control or Mermaid-active characters; oversized lockfiles cause memory exhaustion. | SEC-NEW-37 (size + edge caps), SEC-NEW-38 (sanitise_declared_version), reuse of existing _mermaid_label sanitiser at render time. |

---

## SRTM (REQ-19)

| Req ID | Description | Test File |
|---|---|---|
| FR-190 | `DepEdge` dataclass with declared_version + scope | `tests/unit/test_req19_models.py` |
| FR-191 | Maven `_emit_dep_edges` records declared `<version>` per `<dependency>` | `tests/unit/test_req19_maven_edges.py` |
| FR-192 | Gradle dependency-output parser yields DepEdge with requested version | `tests/unit/test_req19_gradle_edges.py` |
| FR-193 | npm package-lock.json v2/v3, yarn.lock, pnpm-lock.yaml edge emission | `tests/unit/test_req19_npm_edges.py` |
| FR-194 | Markdown reporter renders distinct (canonical, version) nodes | `tests/unit/test_req19_tree_render.py` |
| FR-195 | Backwards-compat: dep_graph derived from dep_edges when both populated | `tests/unit/test_req19_compat.py` |
| SEC-NEW-37 | `_LOCKFILE_MAX_BYTES` + `_LOCKFILE_MAX_EDGES` enforced | `tests/security/test_req19_lockfile_caps.py` |
| SEC-NEW-38 | `sanitise_declared_version` strips control + Mermaid-active chars | `tests/security/test_req19_version_sanitise.py` |
| PERF-010 | 1000-dep / 5000-edge tree render within 25% of REQ-17 baseline | `tests/performance/test_req19_tree_render_perf.py` |

---

## Acceptance Criteria

- [ ] Given a Maven project where `alpha 2.0` brings in `x 1.1` and
  `beta 3.0` brings in `x 1.2`, when Scarno runs, then
  `AnalysisResult.dep_edges` contains both edges with their distinct
  declared versions and the markdown tree renders both `x` nodes.
- [ ] Given an npm `package-lock.json v3` with two paths declaring
  `scheduler` at 0.23.0 and 0.23.2, when analysis completes, then
  `dep_edges` contains both edges and the rendered tree shows both.
- [ ] Given a Gradle output line `a:b:1.0 -> 1.5`, when edge emission
  runs, then `DepEdge.declared_version == "1.0"` (NOT 1.5).
- [ ] Given a `<version>1.0\n[click ...]</version>` in pom.xml, when
  the rendered tree is produced, then the version label contains no
  newline and no `click` substring.
- [ ] Given a `package-lock.json` of 9 MiB, when analysis runs, then
  the lockfile is rejected with a sanitised error and the rest of
  the analysis still produces a partial report.
- [ ] Given an ecosystem that does not yet emit dep_edges (e.g.
  PyPI), when the markdown reporter runs, then `dep_edges` is empty
  and the legacy `dep_graph` rendering path is used unchanged
  (REQ-17 acceptance criteria do not regress).
- [ ] Given any `dep_edges` payload, the JSON output validates as
  `json.loads`-parseable and SARIF output validates against
  SARIF 2.1.0.

---

## Out of Scope (REQ-19)

- **Per-version classification.** REQ-19 only labels edges; deciding
  whether `X@1.1` is SAFE while `X@1.2` is IN_USE is REQ-20.
- **Resolved-version marker.** Visually distinguishing the version
  Maven/npm actually picks at resolution time is REQ-20.
- **PyPI / Go / NuGet / CSS edge emission.** Not in scope until those
  ecosystems' lockfile parsers are extended in a future REQ. The
  models.py field is forward-compatible.
- **Per-edge usage counts.** REQ-17's `usage_count` already lives on
  the entry-point side; edges remain count-free.

---

## Limitations

- **Yarn classic (v1) lockfiles** declare versions in a less
  structured form than v2/v3; we parse them best-effort and skip
  malformed entries with a warning.
- **`pnpm-lock.yaml` v5 and earlier** are not supported; v6+ is
  required for full edge emission. Earlier versions emit a warning
  and fall through to canonical-only rendering.
- **Maven property unresolved versions** (`<version>${x.version}</version>`
  where the property is undefined) are emitted as `declared_version=None`
  rather than being silently dropped.
- **Gradle dynamic versions** (`1.+`, `latest.release`) are recorded
  literally; REQ-20's "resolved version" marker is what tells the
  user what was actually picked.