# REQ-21 — Maven Pinning and Exclusion-Override Detection

## Overview

A direct `<dependency>` declaration in a Maven `pom.xml` whose source
usage looks zero must NOT be flagged for removal when it is in fact
**substituting** for a transitive dependency that has been excluded
or pinned. Two patterns matter:

1. **Exclusion-override** — some other transitive `Y` declares
   `<exclusions><exclusion>X</exclusion></exclusions>`, AND a direct
   `<dependency>X</dependency>` exists at the same coordinate. The
   direct entry replaces the excluded transitive (commonly used to
   substitute a vulnerable version with a patched one).
2. **dependencyManagement pin** — a `<dependencyManagement>` entry
   forces `X` to a specific version with no source usage of `X`,
   AND `X` is reached via the transitive graph. The DM entry exists
   to lock a runtime version, not to add a new dep.

Both flag the direct/managed entry as **PIN_OVERRIDE** so it is
not flagged for removal and the report explains the substitution.
Gradle equivalents are **REQ-21b**; npm overrides are **REQ-23**.

---

## Problem Statement

`Dependency.manifest_redundant` (FR-150) handles the *opposite* case:
a direct dep that is also reachable transitively through an IN_USE
parent — the manifest line is redundant and can be pruned. REQ-21
handles the inverse case: a direct dep that *appears* unused but is
actually load-bearing because it substitutes for an excluded or
managed transitive.

Without REQ-21, Scarno would:

- Recommend removing `<dependency>X</dependency>` because no source
  imports it.
- The user removes it.
- Maven re-resolves and either falls back to the *unexcluded*
  transitive of `X` (the vulnerable version the developer was
  patching around), OR the artifact disappears from the classpath
  and `Y`'s runtime behaviour breaks.

The first failure is a **silent vulnerability reintroduction** —
the most dangerous failure mode of any dependency-pruning tool.

---

## Solution

### 1. Maven manifest model extensions

```python
@dataclass
class MavenManagedEntry:
    """A row in <dependencyManagement>."""
    group: str
    artifact: str
    version: str | None
    scope: str = "runtime"


@dataclass
class MavenExclusion:
    """An <exclusion> declared by some parent on a transitive."""
    parent_coord: str       # "group:artifact:version" of the transitive owner
    excluded_group: str
    excluded_artifact: str


@dataclass
class Dependency:
    ...
    # REQ-21 — set when this dep is detected as a pinning override of an
    # excluded or managed transitive. Mutually exclusive with
    # ``manifest_redundant`` (which is the opposite finding). Both flags
    # set on the same dep is a bug.
    pin_override: bool = False
    pin_override_kind: str | None = None    # "EXCLUSION" | "DEPENDENCY_MANAGEMENT"
    pin_override_target: str | None = None  # narrative — which transitive's
                                            # exclusion this substitutes for, or
                                            # the DM entry that pinned it
```

### 2. Detection algorithm

```
For each direct <dependency> X with no source-level usage:
    # Pattern (a): exclusion-override
    if any walked POM Y declares <exclusion>X</exclusion>:
        X.pin_override = True
        X.pin_override_kind = "EXCLUSION"
        X.pin_override_target = f"substitutes for excluded transitive of {Y.coord}"
        X.status = IN_USE  # never SAFE
        X.reason = "Maven exclusion-override pin: {target}"
        continue

    # Pattern (b): dependencyManagement pin
    dm_entry = root_pom.dependencyManagement.find(X.group, X.artifact)
    if dm_entry and X is reached via dep_edges (i.e. some transitive depends on X):
        X.pin_override = True
        X.pin_override_kind = "DEPENDENCY_MANAGEMENT"
        X.pin_override_target = f"pinned via <dependencyManagement> to {dm_entry.version}"
        X.status = IN_USE
        X.reason = "Maven dependencyManagement pin: {target}"
```

The walked POMs (REQ-17b §FR-165) already contain
`<dependency>` and `<exclusion>` data; REQ-21 adds an extraction
pass for `<dependencyManagement>` entries on the **root POM**
(parent POMs are merged via existing property-resolution machinery).

### 3. Report integration

Markdown reporter renders, in the "In use" section above the
existing checklist:

```markdown
### Pinning overrides (Maven)

These direct dependencies are kept on the classpath as substitutes
for excluded or managed transitives. Removing them would silently
re-introduce the substituted version.

- `org.example:patched-x` — exclusion-override for transitive
  `com.lib:vulnerable-y` (excluded `org.example:vulnerable-x`)
- `org.acme:locked-z` — dependencyManagement pin to 1.4.2; reached
  transitively via `com.thirdparty:other`
```

JSON: `pin_override` / `pin_override_kind` / `pin_override_target`
fields per Dependency. SARIF: rule `TS-DEP-PIN-OVERRIDE-MAVEN`
with severity `note`.

### 4. Interaction with REQ-20

REQ-20's classifier (SUC-42) already defers to pinning flags. The
contract:

- A direct dep with `pin_override=True` is forced to status `IN_USE`
  regardless of source-level usage.
- The `(canonical, declared_version)` node for the pinned coordinate
  is also `IN_USE` and `removable=False` in `versioned_nodes`.
- REQ-20's "Multiple versions detected" table annotates the
  resolved version with `(pinned)` when REQ-21 detected it.

### 5. Exclusion / DM pattern caps (`SEC-NEW-40`)

| Cap | Value | Justification |
|---|---|---|
| `_MAX_EXCLUSIONS_PER_DEP` | **128** | Real-world max observed: ~30. 128 absorbs spring-boot-starter-style patterns. |
| `_MAX_DM_ENTRIES` | **2048** | Aggregated across parent POM hierarchy; spring-boot-dependencies has ~1500. |

Beyond these, parsing emits a sanitised error and stops adding
exclusions / DM entries (existing entries are kept and analysis
continues so a partial pin-override report is still produced).

---

## Use Cases

```
UC-21a: Exclusion-override (the canonical "patched X" pattern)
Actor: Java developer using Scarno on a project that pins a
  patched version of a vulnerable transitive.
Goal: Scarno must NOT recommend removing the patched direct dep.
Preconditions:
  - pom.xml direct dep `org.example:lib-y:2.0` declares
    `<exclusions><exclusion>org.example:vulnerable-x</exclusion></exclusions>`.
  - pom.xml direct dep `org.example:patched-x:1.5` exists at the same
    GA coordinate as the excluded transitive.
  - Source code never imports `org.example.x`.
Main flow:
  1. Maven analyser discovers the exclusion in lib-y's manifest line.
  2. It also finds direct dep patched-x at the same GA coordinate.
  3. Pattern (a) triggers: patched-x.pin_override = True;
     pin_override_kind = "EXCLUSION".
  4. Status forced to IN_USE; report explains the substitution.
Postcondition: no false-positive removal recommendation; user is told
  WHY the dep is kept.

UC-21b: dependencyManagement pin (Spring BOM style)
Actor: Java developer using a Spring Boot BOM.
Goal: Scarno must keep the BOM-managed pin even if no source
  code in the project imports the managed coordinate.
Preconditions:
  - parent POM imports `spring-boot-dependencies` BOM.
  - Root pom.xml `<dependencyManagement>` pins `com.fasterxml.jackson.core:jackson-databind`
    to a specific version.
  - `jackson-databind` is reached transitively via another dep.
  - Source code never directly imports jackson-databind.
Main flow:
  1. Maven analyser parses <dependencyManagement>.
  2. jackson-databind is reachable transitively — pattern (b) triggers.
  3. The Dependency object for jackson-databind has pin_override=True;
     status=IN_USE; pin_override_kind="DEPENDENCY_MANAGEMENT".
Postcondition: BOM-style pins do not appear in the SAFE list.
```

---

## Abuse Cases

```
SAC-44: Silent vulnerability reintroduction via false-positive removal
Linked threat: T-30
Attacker: Not external — the threat is a tool-induced developer
  action. The "abuser" is the Scarno output recommending removal
  of a load-bearing pin.
Goal: Cause the developer to delete a direct <dependency> that
  substitutes for an excluded vulnerable transitive, so the next
  Maven resolve pulls the vulnerable version back onto the classpath.
Trigger: Without REQ-21, any direct dep with no source-level use is
  a candidate for removal recommendation.
Mitigated by: SUC-45 (pattern-(a) detection) + SUC-46 (pattern-(b)
  detection). Where REQ-21 cannot make a high-confidence call, status
  defaults to UNCERTAIN with an explicit note.
OWASP: A06:2021 — Vulnerable and Outdated Components.

SAC-45: Adversarial pom.xml with thousands of <exclusions>
Linked threat: T-30
Attacker: External (commits a poisoned pom.xml to a target repo).
Goal: Cause O(N×M) behaviour in the exclusion-matcher (N exclusions
  × M direct deps).
Mitigated by: SEC-NEW-40 caps (_MAX_EXCLUSIONS_PER_DEP=128,
  _MAX_DM_ENTRIES=2048).
OWASP: A05:2021 — Security Misconfiguration.
```

---

## Privacy

REQ-21 introduces no new data category — exclusion targets and DM
versions are already in scope as project metadata. PUC-10 (REQ-19)
sanitisation applies to all version strings emitted by REQ-21 paths.

---

## Performance

```
PERF-012: Pinning detection scaling
- For a project with D direct deps, T transitives, X exclusions:
  pattern (a) is O(D × X) bounded by SEC-NEW-40 caps.
- Pattern (b) is O(D) — a single dictionary lookup per direct dep
  in <dependencyManagement>.
- Real-world budget: spring-boot-style project (1500 DM entries,
  ~30 direct deps): pin-override pass < 50 ms.
- No subprocesses; no network; no FS reads beyond the POMs already
  walked by REQ-17b.
```

---

## Security Use Cases (Countermeasures)

```
SUC-45: Exclusion-override pattern (a) detection
Mitigates: SAC-44 (pattern (a) variant)
Control: When walking POMs, collect all <exclusion> entries and
  index them by (excluded-group, excluded-artifact). For every direct
  dep without source-level use, look up the index. A match flips the
  dep to pin_override=True with kind=EXCLUSION.
Implementation: src/scarno/analysers/java/maven.py:_detect_pin_overrides.
OWASP ASVS: §1.4.1 Trust boundary verification.

SUC-46: dependencyManagement pin pattern (b) detection
Mitigates: SAC-44 (pattern (b) variant)
Control: Parse root <dependencyManagement> after POM property
  resolution. For every direct dep without source-level use that is
  also reached transitively (per dep_edges), check the DM index.
  A match flips the dep to pin_override=True with kind=DEPENDENCY_MANAGEMENT.
Implementation: src/scarno/analysers/java/maven.py:_detect_pin_overrides.
OWASP ASVS: §1.4.1.

SUC-47: SEC-NEW-40 caps
Mitigates: SAC-45
Control: Per SEC-NEW-40 above. Caps are enforced at parse time,
  before the matcher runs.
Implementation: src/scarno/analysers/java/maven.py.
OWASP ASVS: §11.1.4 Resource limits.
```

---

## Threat Model Additions

| ID | Threat | Mitigation |
|---|---|---|
| T-30 | Pinning detection misses a real exclusion-override or DM pin, leading to silent vulnerability reintroduction OR is exhausted by adversarial exclusion lists. | SUC-45 + SUC-46 + SEC-NEW-40 caps + UNCERTAIN-on-doubt fallback. |

---

## SRTM (REQ-21)

| Req ID | Description | Test File |
|---|---|---|
| FR-210 | Maven `<exclusions>` collected from walked POMs into an index | `tests/unit/test_req21_exclusions_index.py` |
| FR-211 | Pattern (a) detection: direct dep matches an excluded transitive | `tests/unit/test_req21_pattern_a.py` |
| FR-212 | Maven `<dependencyManagement>` parsed from root POM after property resolution | `tests/unit/test_req21_dm_parse.py` |
| FR-213 | Pattern (b) detection: direct dep is DM-pinned and reached transitively | `tests/unit/test_req21_pattern_b.py` |
| FR-214 | REQ-20 classifier defers to pin_override (status forced IN_USE) | `tests/unit/test_req21_classifier_integration.py` |
| FR-215 | Markdown / JSON / SARIF report sections for pin-overrides | `tests/unit/test_req21_reporters.py` |
| SEC-NEW-40 | Exclusion + DM caps (_MAX_EXCLUSIONS_PER_DEP=128, _MAX_DM_ENTRIES=2048) | `tests/security/test_req21_caps.py` |
| PERF-012 | Pinning detection < 50 ms on spring-boot-style project | `tests/performance/test_req21_perf.py` |

---

## Acceptance Criteria

- [ ] Given a pom.xml with a <dependency> declaring an <exclusion>
  on `org.example:vulnerable-x` AND a direct <dependency>
  `org.example:patched-x` at the same GA coord, when analysis runs,
  then `patched-x` has `pin_override=True`,
  `pin_override_kind="EXCLUSION"`, status=IN_USE, and is NOT in any
  SAFE / removable list.
- [ ] Given a Spring Boot BOM-style project where
  `jackson-databind` is in <dependencyManagement> and reachable
  transitively but not imported by source, when analysis runs, then
  `jackson-databind` has `pin_override=True`,
  `pin_override_kind="DEPENDENCY_MANAGEMENT"`, status=IN_USE.
- [ ] Given a pin-override dep, when REQ-20 classifies, then the
  matching `(canonical, declared_version)` entry in `versioned_nodes`
  is IN_USE with reason mentioning the pin.
- [ ] Given a pom.xml with 200 <exclusions> entries on one
  transitive, when analysis runs, then exactly 128 are retained,
  errors[] contains the truncation note, and analysis still completes.
- [ ] Given a direct dep that is BOTH unused at source AND is the
  only path to a coordinate (no exclusion, no DM entry), when
  analysis runs, then `pin_override=False` and the dep can still be
  flagged SAFE per existing rules (REQ-21 must not over-flag).
- [ ] Given a direct dep flagged `manifest_redundant=True` (FR-150),
  when REQ-21 evaluates it, then it does NOT also set
  `pin_override=True` (the two are mutually exclusive). A
  defensive assertion catches the contradiction in CI.
- [ ] Given the SARIF reporter, when pin-overrides exist, then a
  `TS-DEP-PIN-OVERRIDE-MAVEN` rule result is emitted per pinned dep
  with severity `note`.

---

## Out of Scope (REQ-21)

- **Gradle equivalents** — REQ-21b.
- **npm overrides / yarn resolutions / pnpm.overrides** — REQ-23.
- **Detection of inappropriate pinning** (e.g. a pin to a vulnerable
  version) — out of Scarno's mandate; SBOM scanners are the
  correct tool.
- **Auto-removal of stale exclusions** (an exclusion whose target is
  no longer transitively reachable) — could be a future REQ.
- **`<dependencyManagement>` entries that are NOT reached
  transitively** — they're harmless DM declarations; REQ-21 doesn't
  flag them at all.

---

## Limitations

- **`<exclusion>` wildcards** (`<artifactId>*</artifactId>`) are
  partially supported: a wildcard exclusion of `*` for a given
  group flags every direct dep at that group as a potential
  pin-override, then defers to UNCERTAIN if no other signal narrows
  it.
- **Profile-activated <dependencyManagement>** — only the active
  profile's DM entries are considered. Profiles that activate based
  on the OS / JDK that Scarno is running on are honoured;
  `-P` profiles the user did not request are skipped.
- **Imported BOMs** — `<dependencyManagement>` blocks of type
  `pom`+scope `import` are walked one level deep. Nested BOM imports
  (BOM A imports BOM B which imports BOM C) follow the existing
  1000-node cap.
- **Same-GA-coord but different version of an excluded transitive
  vs the direct pin** — pattern (a) intentionally matches on
  (group, artifact) only, not version. The substitution semantic is
  "this artifact instead of the transitive's choice"; the version
  difference is the entire point.
