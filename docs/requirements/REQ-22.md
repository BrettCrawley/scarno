# REQ-22 — Cross-Version ABI Diff for Source-Imported Transitives

## Overview

When project source imports a transitive lib `X` directly **and**
the dep graph contains multiple declared versions of `X`
(REQ-19 / REQ-20 territory), runtime behaviour depends on which
version Maven actually puts on the classpath. If the source code
calls `X.method()` and that method exists in declared `v1.2` but was
removed in resolved `v1.3`, the project will throw
`NoSuchMethodError` at runtime — silently passing static analysis
and unit tests that exercise different surfaces.

REQ-22 detects this by reading the JARs from `~/.m2/repository`,
extracting public class / method / field signatures with `javap`,
and diffing against the resolved version. Where the diff intersects
the symbols the project source actually calls, a HIGH-severity
runtime-risk finding is emitted.

**This feature is gated behind `JvmSourceAnalyser(deep_inspection=True)`.**
The default fast path (JAR class-list listing without `javap`)
remains untouched per the established performance baseline
(`feedback_javap_fast_path`).

**Maven only.** Gradle support follows REQ-21b's sequencing.

---

## Problem Statement

The current Java analyser knows:

- Which classes / packages a transitive lib provides (REQ-17b
  `_enumerate_jar_entry_points` over the JAR's class list).
- Which symbols project source calls (REQ-17 `usage_count`).
- Which transitives are imported directly by source (REQ-17
  `imported_directly`).

What it does NOT know:

- Whether the **method-level surface** of the transitive changed
  between the version a parent declared and the version Maven
  actually resolved.
- Whether any of those changes intersects the source's call set.

Concrete failure mode:

```xml
<!-- pom.xml -->
<dependency>
  <groupId>com.thirdparty</groupId>
  <artifactId>helper</artifactId>
  <version>1.2.0</version>     <!-- declared by us -->
</dependency>
<dependency>
  <groupId>com.thirdparty</groupId>
  <artifactId>other</artifactId>
  <version>4.0.0</version>     <!-- transitively pulls helper 1.5.0 -->
</dependency>
```

`helper 1.5.0` removed `Helper.utilityMethod()` that our source
calls. `mvn compile` succeeds (compiles against 1.2.0's API). At
runtime, Maven's "nearest wins" resolves to 1.5.0 and we get a
`NoSuchMethodError`.

REQ-22 catches this before runtime.

---

## Solution

### 1. Activation gate

```python
class JvmSourceAnalyser(BaseAnalyser):
    def __init__(self, *, deep_inspection: bool = False) -> None:
        self.deep_inspection = deep_inspection
        # ... existing init ...

    def analyse(self, ...) -> AnalysisResult:
        result = super().analyse(...)
        if self.deep_inspection:
            self._cross_version_abi_diff(result)
        return result
```

CLI surface (new flag):

```text
--deep-inspection            Enable deep JAR / bytecode inspection (slower).
                              Required for REQ-22 cross-version ABI diff.
```

`_RunOptions.deep_inspection: bool = False`. Default off — never
spawn `javap` per the established perf feedback.

### 2. Cross-version ABI diff algorithm

```
For each coordinate C in versioned_nodes where:
    - len(declared versions) >= 2
    - source code imports a class from C (per imported_directly + symbols)
    - resolved version is known
do:
    resolved_jar = locate_jar_in_m2(C, resolved_version)
    if not resolved_jar:
        # Resolved JAR not cached; emit "resolved version not in m2 cache" note and continue.
        continue

    resolved_signatures = javap_public_signatures(resolved_jar)

    for each declared version V (other than resolved):
        declared_jar = locate_jar_in_m2(C, V)
        if not declared_jar:
            # Skip with a "v<V> not cached" note.
            continue

        declared_signatures = javap_public_signatures(declared_jar)

        diff = signature_diff(declared_signatures, resolved_signatures)
        # diff yields: ADDED, REMOVED, CHANGED (signature mismatch)

        for each project source call site that maps to a symbol in C:
            if symbol in diff.REMOVED or diff.CHANGED:
                emit Finding(
                    severity=HIGH,
                    kind=RUNTIME_RISK,
                    message=f"{symbol} called by source, exists in declared {V} but {action} in resolved {resolved_version}",
                    package_hint=C.canonical,
                )

        for each non-source-referenced diff entry:
            emit Finding(severity=MEDIUM, ...)
```

#### 2a. Diff matching granularity (FR-272)

Symbols match on **identity first, descriptor second**. Identity is
`(fqcn, member_kind, member_name)`; within one identity in one
version, `descriptor` is unique (Java forbids two overloads sharing a
parameter list, and `javap` renders the parameter list only), so
`(identity, descriptor)` is a sound full key.

For an identity present on both sides, let `gone` be the declared
descriptors absent from the resolved side, `new` the resolved
descriptors absent from the declared side, and `shifted` the
descriptors present on both whose `modifiers` differ:

| Case | Bucket |
|---|---|
| identity only in declared | all its signatures → REMOVED |
| identity only in resolved | all its signatures → ADDED |
| member not overloaded on either side, its one descriptor differs | resolved-side signature → CHANGED |
| otherwise, each of `gone` | REMOVED |
| otherwise, each of `new` | ADDED |
| each of `shifted` | resolved-side signature → CHANGED |

The not-overloaded case is the "retyped parameter" reading that keeps
a lone signature change out of REMOVED + ADDED. Once a member is
overloaded, pairing a deleted descriptor with an unrelated added one
is a guess, and it would report the surviving signature rather than
the one the caller compiled against. Every other deleted descriptor
is a symbol the JVM can no longer resolve — a `NoSuchMethodError` —
and must reach REMOVED even when sibling overloads survive.

Collapsing an identity to a single representative signature (the
pre-fix behaviour) made deleted overloads invisible to
`TS-ABI-RUNTIME-RISK` and made CHANGED depend on set-iteration order.
See `docs/SCARNO-BUG-signature-diff.md`.

### 3. Signature extraction (`javap`)

We invoke `javap -public -c <jar>` ONLY for jars within
`~/.m2/repository` after `resolve_and_confine`. Output is parsed
into a structured form:

```python
@dataclass
class JavaSignature:
    fqcn: str               # "com.thirdparty.Helper"
    member_kind: str        # "method" | "field" | "constructor" | "class"
    member_name: str        # "utilityMethod"
    descriptor: str         # JVM type descriptor "(Ljava/lang/String;)I"
    modifiers: frozenset[str]  # {"public", "static"}
```

Extraction caps:

| Cap | Value | Justification |
|---|---|---|
| `_JAVAP_PER_JAR_TIMEOUT_S` | **30 s** | Existing pattern; absorbs slow JARs. |
| `_JAVAP_MAX_JARS_PER_RUN` | **128** | Hard cap on cross-version inspection per analysis run; beyond this, additional coordinates emit a "skipped, cap reached" note. (Bumped from 64 to absorb larger multi-version-conflict sets surfaced once REQ-24's remote-fetch wiring landed.) |
| `_JAVAP_MAX_SIGNATURES_PER_JAR` | **50 000** | Largest standard library JARs. |

### 4. ~/.m2 cache reads

Every JAR read goes through `safe_jar_entries()` (entry / byte caps)
AND `resolve_and_confine(path, root=~/.m2/repository)`. The cache
root is determined from `MAVEN_HOME`/`M2_HOME` env vars or the
default `~/.m2/repository`. If the cache root is not a directory,
REQ-22 disables itself with a single sanitised error.

JAR location:

```python
def _m2_jar_path(coord: Coordinate, version: str) -> Path:
    # ~/.m2/repository/<group_with_slashes>/<artifact>/<version>/<artifact>-<version>.jar
    return resolve_and_confine(
        m2_root / coord.group.replace(".", "/") / coord.artifact / version /
        f"{coord.artifact}-{version}.jar",
        root=m2_root,
    )
```

### 5. Reporter integration

Markdown reporter, after the "Multiple versions detected" section
(REQ-20):

```markdown
## Cross-version ABI risks (deep inspection)

### com.thirdparty:helper

Declared 1.2.0; Resolved 1.5.0.

#### Runtime risk (HIGH)

- `Helper.utilityMethod(String): int` — called by your source, exists
  in declared 1.2.0 but **REMOVED** in resolved 1.5.0.
  Project call site: `src/main/java/.../UsesHelper.java:42`.

#### Other ABI changes (MEDIUM)

- `Helper.legacyMethod()` — REMOVED in 1.5.0 (not called by your source).
- `Helper.newMethod(int, String)` — ADDED in 1.5.0.
- `Helper.changedMethod(...)` — signature CHANGED.
```

JSON: per-coordinate `abi_diff` array. SARIF: rule
`TS-ABI-RUNTIME-RISK` (severity error) and `TS-ABI-DRIFT` (severity
note) under the existing `TS-DEP-*` namespace.

### 6. Privacy-conscious cache enumeration

`~/.m2` may contain coordinates a user does not wish to disclose
(internal artifacts cached during local builds). REQ-22 reads only
the JARs for coordinates **already present** in the project's
dep_edges — it does not enumerate the cache wholesale. Findings
mention only the coordinate that was already in the project's
declared graph.

---

## Use Cases

```
UC-22a: Source calls a method removed in resolved version
Actor: Java developer.
Goal: Scarno flags the runtime risk before the user ships.
Preconditions:
  - dep_edges declares helper 1.2.0 directly and helper 1.5.0
    transitively (via "other 4.0").
  - resolved version is 1.5.0 (nearest-wins or via REQ-20 detector).
  - source calls Helper.utilityMethod(...).
  - Helper.utilityMethod was REMOVED in 1.5.0.
  - both jars are in ~/.m2 cache.
  - --deep-inspection flag set.
Main flow:
  1. _cross_version_abi_diff iterates coordinates with multi versions.
  2. For helper, fetches signatures from helper-1.2.0.jar and
     helper-1.5.0.jar.
  3. Diff shows utilityMethod REMOVED in 1.5.0.
  4. Cross-references with source call set -> match.
  5. Emits Finding(HIGH, RUNTIME_RISK).
Postcondition: report tells the user exactly which method, which
  call site, and which version transition.

UC-22b: Resolved JAR not in m2 cache
Actor: CI environment with a sparse cache.
Goal: Scarno degrades gracefully.
Main flow:
  1. _m2_jar_path(coord, resolved) does not exist.
  2. REQ-22 records a "resolved version not cached for <coord>; skipping ABI diff" note.
  3. Other coordinates with cached jars are still diffed.
Postcondition: no crash; user is told what was skipped.
```

---

## Abuse Cases

```
SAC-48: Crafted JAR triggers javap CPU exhaustion
Linked threat: T-32
Attacker: External (commits a malicious dep that ships a hostile JAR
  with a deeply-nested constant pool / synthetic class load).
Goal: Stall analysis when --deep-inspection is enabled.
Mitigated by: SUC-50 — _JAVAP_PER_JAR_TIMEOUT_S=30s; argv-only
  invocation; existing JAVA_HOME pinning.
OWASP: A05:2021.

SAC-49: Path traversal via crafted coordinate during m2 lookup
Linked threat: T-33
Attacker: External (commits a pom.xml with a dep coordinate whose
  groupId contains `..` segments — extends T-21 to the REQ-22 reader).
Goal: Cause _m2_jar_path to resolve outside ~/.m2/repository.
Mitigated by: SUC-51 — resolve_and_confine on every constructed
  path; reuse of existing _validate_gav (T-21).
OWASP: A01:2021.

SAC-50: Cache enumeration disclosure
Linked threat: T-34
Attacker: Local user (or a CI step run by an untrusted plugin) who
  inspects Scarno output for evidence of which internal
  artifacts the user has cached.
Goal: Learn private coordinates from ~/.m2 that aren't part of the
  scanned project.
Mitigated by: REQ-22's "only-coords-already-in-graph" rule (no
  wholesale enumeration); PUC-12 sanitises any error path that might
  leak unrelated cache contents.
OWASP: A09:2021 — Security Logging and Monitoring Failures (info
  disclosure variant).
```

---

## Privacy

```
PT-13: Disclosure of unrelated ~/.m2 cache contents via error paths
LINDDUN: Disclosure
Affected data: filenames / coordinates of cached artifacts that are
  NOT part of the analysed project.
Likelihood: Low — would require an unhandled FileNotFoundError or
  similar to leak directory listings.
Impact: Medium — internal/private artifact names may carry signal
  about what the user works on.
GDPR relevance: project metadata, not personal data; corporate
  confidentiality concern.

PUC-12: Sanitised error output for cache reads
Mitigates: PT-13
Privacy control: All errors from _m2_jar_path / safe_jar_entries
  pass through sanitise() and never include the raw path that was
  attempted; they include only the coordinate that triggered the
  read.
PbD principle: Privacy embedded into design.
```

---

## Performance

```
PERF-014: Deep inspection runtime budget (opt-in)
- Per JAR: javap invocation < 30 s (timeout cap).
- Per analysis run: < 128 JARs total inspected (SEC-NEW-43 cap).
- Project with 5 multi-version coordinates × 2 versions each = 10
  jars: total deep-inspection time < 60 s wall clock typical.
- The user opts in via --deep-inspection so latency is acceptable;
  default path remains the fast JAR class-list path
  (feedback_javap_fast_path).

PERF-015: ABI-diff algorithm scaling
- Signature extraction: O(classes × methods) per jar, capped at
  _JAVAP_MAX_SIGNATURES_PER_JAR=50 000.
- Diff: O(signatures) sorted-merge. No quadratic behaviour.
- Cross-reference with source call set: O(call_sites × log(diff))
  via dictionary lookup.
```

---

## Security Use Cases

```
SUC-50: javap subprocess hardening reuse
Mitigates: SAC-48
Control: Existing _invoke_javap_safe (T-22) wraps every javap call
  with shell=False, validated argv, JAVA_HOME-pinned binary,
  10s base timeout (extended to _JAVAP_PER_JAR_TIMEOUT_S=30s by the
  REQ-22 differ wrapper). REQ-22 adds NO new javap invocation site —
  it reuses the existing wrapper.
Implementation: src/scarno/analysers/java/source_analyser.py:JvmSourceAnalyser._invoke_javap_safe
  (called via dependency injection from
  src/scarno/analysers/java/abi_diff.py:CrossVersionAbiDiffer).
  The earlier Phase-1 reference to src/scarno/security.py was a
  misnomer; per architecture ADR-008 the helper stays a method of
  JvmSourceAnalyser (it carries Java-specific helpers like
  _resolve_javap_binary and _is_valid_java_identifier that don't belong
  in the generic security module). NEW-ARCH-011 (REQ-19a) is the
  invariant that prevents the differ from re-spawning subprocess.
OWASP ASVS: §11.1.4 + §1.4.1.

SUC-51: Path confinement for m2 reads
Mitigates: SAC-49
Control: Every constructed JAR path passes through
  resolve_and_confine(path, root=m2_root) AND _validate_gav before
  any FS read. Coordinates with traversal characters never reach
  the path constructor.
Implementation: src/scarno/analysers/java/abi_diff.py (new
  module, owned by the JVM analyser).
OWASP ASVS: §12.3.1.

SUC-52: Coordinate-restricted cache reads
Mitigates: SAC-50, PT-13
Control: REQ-22's reader only enumerates JARs for coordinates
  already present in the project's dep_edges. It NEVER walks ~/.m2
  to discover other coordinates. Errors from missing JARs include
  only the requested coordinate, never directory listings.
Implementation: src/scarno/analysers/java/abi_diff.py.

SUC-53: Per-run JAR cap
Mitigates: SAC-48 amplification
Control: SEC-NEW-43 _JAVAP_MAX_JARS_PER_RUN=128. Beyond this,
  remaining coordinates are skipped with a sanitised note.
```

---

## Threat Model Additions

| ID | Threat | Mitigation |
|---|---|---|
| T-32 | Crafted JAR triggers javap CPU / memory exhaustion when --deep-inspection is enabled. | Existing _invoke_javap_safe controls (T-22) + SEC-NEW-43 (per-run cap) + 30s per-JAR timeout. |
| T-33 | Coordinate-shaped path traversal during ~/.m2 jar lookup. | resolve_and_confine + _validate_gav reuse from T-21. |
| T-34 | Information disclosure of unrelated ~/.m2 cache contents via error paths. | SUC-52 (coord-restricted reads) + PUC-12 (sanitised error output). |

---

## Compliance

```
COMP-004: CRA / SBOM runtime-risk surfacing
Origin: REQ-22 cross-version ABI diff
Scope: EU CRA Annex II (security properties; vulnerability handling).
Rationale: A SBOM that lists multiple versions of a coordinate is
  noisier than necessary for vulnerability scanners. REQ-19/20
  reduce that noise; REQ-22 adds the inverse — a high-confidence
  runtime-risk callout that a NoSuchMethodError-class failure is
  imminent on a specific version transition. This is information
  the SBOM alone cannot communicate.
Implementation: emitted as Finding(severity=HIGH, kind=RUNTIME_RISK)
  via the existing Finding pipeline; SARIF rule TS-ABI-RUNTIME-RISK.
Tests: tests/integration/test_req22_compliance_signal.py.
```

---

## SRTM (REQ-22)

| Req ID | Description | Test File |
|---|---|---|
| FR-230 | --deep-inspection CLI flag plumbed to JvmSourceAnalyser | `tests/unit/test_req22_cli.py` |
| FR-231 | _m2_jar_path constructs a confined cache path | `tests/unit/test_req22_m2_path.py` |
| FR-232 | javap_public_signatures parses javap -public output | `tests/unit/test_req22_javap_parse.py` |
| FR-233 | signature_diff yields ADDED / REMOVED / CHANGED sets | `tests/unit/test_req22_diff.py` |
| FR-234 | Source call-set cross-reference produces RUNTIME_RISK Findings | `tests/unit/test_req22_runtime_risk.py` |
| FR-235 | Markdown / JSON / SARIF reporting integration | `tests/unit/test_req22_reporters.py` |
| FR-236 | "JAR not cached" graceful skip with note | `tests/unit/test_req22_missing_jar.py` |
| FR-272 | signature_diff matches at descriptor granularity; a deleted overload of a surviving member is reported | `tests/unit/test_req22_diff.py` |
| FR-273 | signature_diff output is invariant under PYTHONHASHSEED | `tests/unit/test_req22_diff_determinism.py` |
| FR-274 | ABI findings name the overload (descriptor in message) and sort totally | `tests/unit/test_req22_finding_sort.py` |
| SEC-NEW-42 | _JAVAP_PER_JAR_TIMEOUT_S = 30s enforced | `tests/security/test_req22_timeout.py` |
| SEC-NEW-43 | _JAVAP_MAX_JARS_PER_RUN = 128 enforced | `tests/security/test_req22_jar_cap.py` |
| SEC-NEW-44 | resolve_and_confine + _validate_gav on m2 path construction | `tests/security/test_req22_traversal.py` |
| PERF-014 | Deep inspection 5×2 jar project < 60s | `tests/performance/test_req22_perf.py` |
| COMP-004 | RUNTIME_RISK Finding emitted with HIGH severity for source-referenced removals | `tests/integration/test_req22_compliance_signal.py` |

---

## Acceptance Criteria

- [ ] Given --deep-inspection is OFF (default), when analysis runs,
  then NO javap subprocess is spawned for ABI-diff purposes (the
  existing fast path controls this; verified via subprocess mock).
- [ ] Given --deep-inspection is ON and a project with helper
  declared 1.2.0 + transitively 1.5.0, both cached, source calling
  Helper.utilityMethod that 1.5.0 removes, when analysis runs, then
  exactly one Finding(HIGH, RUNTIME_RISK) is emitted referencing the
  call site, the symbol, declared 1.2.0, and resolved 1.5.0.
- [ ] Given --deep-inspection is ON but the resolved JAR is not
  cached, when analysis runs, then a sanitised "resolved version
  not cached" note appears in errors[] and analysis still completes.
- [ ] Given --deep-inspection is ON and a coordinate has 5 declared
  versions all cached, when analysis runs, then signature_diff is
  computed against the resolved version 4 times (one per non-resolved
  declared version) within the 128-jar cap.
- [ ] Given a malicious POM with `<groupId>../../etc</groupId>`,
  when REQ-22 attempts to resolve _m2_jar_path, then the path is
  rejected by _validate_gav before any FS read.
- [ ] Given a JAR whose javap invocation exceeds 30 s, when analysis
  runs, then the timeout fires, a sanitised error is recorded, and
  remaining coordinates are still processed.
- [ ] Given the SARIF reporter, when RUNTIME_RISK findings exist,
  then exactly one TS-ABI-RUNTIME-RISK result per finding is emitted
  with severity `error` (mapped from HIGH).

---

## Out of Scope (REQ-22)

- **Network fetches.** REQ-22 reads ~/.m2 only; if a JAR isn't
  cached, the diff is skipped, never fetched. (`_FETCH_NEVER` is
  the contract.)
- **Bytecode-level dataflow analysis.** We diff public signatures,
  not behaviour. A method whose signature is unchanged but
  semantics changed is invisible to REQ-22.
- **Internal / non-public symbols.** `javap -public` is the gate; we
  don't read package-private surface.
- **Gradle.** Sequenced after REQ-21b.
- **npm equivalents.** npm doesn't have a JVM-class-level signature
  surface; package-version drift is more naturally checked via
  semver + tests.
- **Auto-bumping the declared version.** REQ-22 reports; the human
  decides.

---

## Limitations

- **Non-Maven JAR caches** (Gradle's `~/.gradle/caches/modules-2`,
  Coursier's `~/.cache/coursier`) are NOT walked by REQ-22 in this
  iteration. A future REQ may extend the search.
- **Multi-release JARs** (META-INF/versions/N/) may surface
  signatures multiple times across version classifiers; we read the
  base classpath entries (META-INF/versions/0).
- **Shaded / relocated artifacts** carry a different package path
  in the resolved JAR than declared; the diff treats them as
  distinct surfaces (correct, but noisy).
- **Synthetic / lambda / inner classes** are excluded from the
  diff to reduce noise.
- **Annotation-only API changes** are surfaced when modifiers
  differ but `javap -public` does not always show every annotation
  shift; treat REQ-22 as a strong-but-incomplete signal.
- **JAR signature parsing errors** are recorded and the affected
  coordinate is skipped; analysis does not crash.
