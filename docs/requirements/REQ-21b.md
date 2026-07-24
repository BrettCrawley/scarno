# REQ-21b — Gradle Pinning Detection

## Overview

Gradle's analogues of Maven's `<exclusions>` and
`<dependencyManagement>` (REQ-21) are scattered across several DSL
constructs in `build.gradle` / `build.gradle.kts`:

- `force()` inside a `resolutionStrategy { }` block.
- `strictly("X")` inside a version constraint.
- `resolutionStrategy.eachDependency { ... }` closures that
  rewrite versions.
- `constraints { }` blocks pinning a coordinate to a specific
  version.
- `exclude(group: "...", module: "...")` on a configuration or a
  specific dependency.

REQ-21b applies the same flagging logic as REQ-21 (Maven): a direct
dep that *appears* unused must NOT be flagged for removal when it
acts as a substitute for an excluded transitive or is held in place
by a constraint / force / strict pin.

This REQ is **scoped separately** because Gradle's Groovy / Kotlin
DSL is open-ended — closures can compute version strings at
execution time. We do NOT execute the build; we parse statically and
explicitly mark anything dynamic as `UNCERTAIN`.

**Sequencing: REQ-21b is a later PR than REQ-21 / REQ-22 / REQ-23.**

---

## Problem Statement

Without REQ-21b, Gradle projects suffer the same
silent-vulnerability-reintroduction failure as Maven (SAC-44):
Scarno recommends removing a direct dep that, in fact, replaces
an excluded vulnerable transitive. Gradle's DSL surface is broader
than Maven's, which is why we sequence it after the others — the
parsing approach has to be conservative.

The five Gradle constructs to detect, in plain DSL form:

```kotlin
// 1. force() in resolutionStrategy
configurations.all {
    resolutionStrategy {
        force("com.example:patched-x:1.5")
    }
}

// 2. strictly() in version constraint
implementation("com.example:patched-x") {
    version { strictly("1.5") }
}

// 3. resolutionStrategy.eachDependency { ... } rewrite
configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "com.example" && requested.name == "x") {
            useVersion("1.5")
        }
    }
}

// 4. constraints { } block
dependencies {
    constraints {
        implementation("com.example:patched-x:1.5") {
            because("CVE-2024-XXXX patched in 1.5")
        }
    }
}

// 5. exclude on a dep or configuration
implementation("com.lib:y:2.0") {
    exclude(group = "com.example", module = "vulnerable-x")
}
```

Each maps onto the same pin_override semantics introduced by REQ-21.

---

## Solution

### 1. Static-only Gradle DSL parser

We extend the existing Gradle parser (`analysers/java/gradle.py`)
with a tree-sitter Groovy / Kotlin walker that finds the constructs
above and emits structured records:

```python
@dataclass
class GradleForceDirective:
    group: str
    artifact: str
    version: str | None
    source: str   # "resolutionStrategy.force" | "strictly" | "eachDependency.useVersion" | "constraints"

@dataclass
class GradleExclusion:
    parent_dep_coord: str | None  # which dep declared the exclude (None when configuration-level)
    excluded_group: str
    excluded_artifact: str
```

Anything that the parser can't statically resolve (a closure
computing the version from a property file at execution time) is
emitted as a synthetic record with `version=None` and `dynamic=True`,
which downgrades any matched direct dep to `UNCERTAIN` rather than
forcing IN_USE.

### 2. Detection

```
For each direct dep X with no source-level usage:
    # Pattern (a): exclusion-override
    if any GradleExclusion matches X.group + X.artifact:
        X.pin_override = True
        X.pin_override_kind = "GRADLE_EXCLUSION"
        X.status = IN_USE

    # Pattern (b'): force / strictly / constraints / useVersion
    if any GradleForceDirective matches X.group + X.artifact:
        if directive.dynamic:
            X.status = UNCERTAIN
            X.pin_override_kind = "GRADLE_DYNAMIC_PIN"
            X.reason = "Gradle DSL pin appears to be computed dynamically; manual review required"
        else:
            X.pin_override = True
            X.pin_override_kind = f"GRADLE_{directive.source.upper()}"
            X.status = IN_USE
```

### 3. Report integration

Markdown reporter "Pinning overrides" section gains a Gradle
sub-table:

```markdown
### Pinning overrides (Gradle)

- `com.example:patched-x` — force() in resolutionStrategy of
  `:app` configuration
- `com.lib:patched-z` — constraints {} block; reason: "CVE-2024-XXXX"
- `com.acme:dynamic-y` — UNCERTAIN: pin appears dynamic, please review
```

### 4. Safety against open-ended DSL (`SEC-NEW-41`)

| Cap | Value | Justification |
|---|---|---|
| `_GRADLE_MAX_FORCE_DIRECTIVES` | **256** | Empirically way above any real project. |
| `_GRADLE_MAX_EXCLUSIONS` | **256** | Same. |
| `_GRADLE_PARSE_TIMEOUT_S` | **8 s** | Tree-sitter Groovy / Kotlin parse per file. |

The parse timeout reuses the existing tree-sitter timeout pattern
established in REQ-17.

### 5. Per-script-language behaviour

| Build script | Parser approach |
|---|---|
| `build.gradle` (Groovy) | tree-sitter-groovy walker |
| `build.gradle.kts` (Kotlin DSL) | tree-sitter-kotlin walker — already used elsewhere in the codebase |
| `settings.gradle(.kts)` | walked for `pluginManagement` / `dependencyResolutionManagement.versionCatalogs` blocks (advisory only — these supply default versions, they don't pin) |
| `gradle/libs.versions.toml` | parsed for the `[versions]` table; values are referenced by alias from the build scripts |
| `gradle.lockfile` | already parsed by REQ-19; supplies the resolved version |

---

## Use Cases

```
UC-21c: force() pin in resolutionStrategy
Actor: Gradle developer with a security-patched dep.
Goal: Scarno keeps `patched-x` even though no source imports it.
Preconditions: build.gradle.kts has
  configurations.all { resolutionStrategy { force("com.example:patched-x:1.5") } }
  and direct dep `com.example:patched-x` declared.
Main flow:
  1. Gradle parser detects the force() directive.
  2. Direct dep matches the directive's group + artifact.
  3. pin_override=True, kind="GRADLE_FORCE", status=IN_USE.
Postcondition: no false-positive removal recommendation.

UC-21d: dynamic version pin (UNCERTAIN fallback)
Actor: Gradle developer with a closure that computes versions from
  a properties file.
Goal: Scarno does not silently misclassify the pinned dep.
Preconditions: build.gradle has
  resolutionStrategy.eachDependency { details ->
      if (details.requested.group == "com.lib") {
          details.useVersion(loadVersion("com.lib"))   // dynamic
      }
  }
Main flow:
  1. Parser sees a useVersion() call whose argument is not a literal.
  2. Emits GradleForceDirective with dynamic=True.
  3. Matching direct dep gets status=UNCERTAIN with explicit reason.
Postcondition: report tells the user to review manually.
```

---

## Abuse Cases

```
SAC-46: Gradle DSL evasion of pin detector
Linked threat: T-31
Attacker: Not malicious — same threat shape as SAC-44; the failure
  mode is misclassification due to DSL constructs the static parser
  doesn't recognise.
Mitigated by: SUC-48 — anything the parser can't fully understand
  is downgraded to UNCERTAIN (never silently treated as removable).
OWASP: A04:2021 — Insecure Design.

SAC-47: Adversarial Gradle script with deeply nested closures
Linked threat: T-31
Attacker: External (commits a poisoned build.gradle).
Goal: Stall analysis via tree-sitter parse on a hostile DSL.
Mitigated by: SEC-NEW-41 — _GRADLE_PARSE_TIMEOUT_S=8s plus directive
  count caps.
OWASP: A05:2021 — Security Misconfiguration.
```

---

## Privacy

No new data category. Gradle DSL contents are project-internal
metadata, already in scope.

---

## Performance

```
PERF-013: Gradle pin-detection scaling
- Per-file: bounded by SEC-NEW-41 _GRADLE_PARSE_TIMEOUT_S=8s.
- Per-project: O(scripts × directives); typical project < 10
  scripts × 50 directives → < 100 ms total.
- Parse-failure path: a single "parser failed; skipping" warning,
  analysis continues without Gradle pin data.
```

---

## Security Use Cases

```
SUC-48: UNCERTAIN-on-doubt fallback for dynamic Gradle DSL
Mitigates: SAC-46
Control: any GradleForceDirective with dynamic=True downgrades the
  matched direct dep to UNCERTAIN. Reason text explicitly says the
  user should review manually.
Implementation: src/scarno/analysers/java/gradle.py:_detect_pin_overrides.

SUC-49: Gradle parser caps and timeout
Mitigates: SAC-47
Control: SEC-NEW-41 caps; tree-sitter parse timeout reuses existing
  pattern.
Implementation: src/scarno/analysers/java/gradle.py.
OWASP ASVS: §11.1.4 Resource limits.
```

---

## Threat Model

| ID | Threat | Mitigation |
|---|---|---|
| T-31 | Gradle DSL static analysis fails to detect a pin (silent vulnerability reintroduction) OR is exhausted by adversarial DSL. | SUC-48 (UNCERTAIN fallback) + SUC-49 (caps + timeout) + tree-sitter sandbox. |

---

## SRTM (REQ-21b)

| Req ID | Description | Test File |
|---|---|---|
| FR-220 | Tree-sitter Groovy walker emits GradleForceDirective for force() | `tests/unit/test_req21b_force.py` |
| FR-221 | Walker emits directive for strictly() in version block | `tests/unit/test_req21b_strictly.py` |
| FR-222 | Walker emits directive for constraints {} block | `tests/unit/test_req21b_constraints.py` |
| FR-223 | Walker emits directive for resolutionStrategy.eachDependency.useVersion | `tests/unit/test_req21b_each_dependency.py` |
| FR-224 | Walker emits GradleExclusion for exclude(group, module) | `tests/unit/test_req21b_exclude.py` |
| FR-225 | Dynamic-pin downgrade to UNCERTAIN | `tests/unit/test_req21b_dynamic.py` |
| SEC-NEW-41 | Directive caps + parse timeout | `tests/security/test_req21b_caps.py` |
| PERF-013 | Gradle pin-detection per project < 100 ms | `tests/performance/test_req21b_perf.py` |

---

## Acceptance Criteria

- [ ] Given a build.gradle.kts with `force("com.example:patched-x:1.5")`
  and direct dep `com.example:patched-x`, when analysis runs, then
  pin_override=True, kind="GRADLE_FORCE", status=IN_USE.
- [ ] Given a `constraints { implementation("com.lib:z:1.4") }`
  block, when analysis runs, then `com.lib:z` has pin_override=True
  with kind="GRADLE_CONSTRAINTS".
- [ ] Given an `exclude(group: "com.example", module: "vulnerable-x")`
  inside a dep block AND a direct `com.example:patched-x` dep, when
  analysis runs, then patched-x has pin_override=True with
  kind="GRADLE_EXCLUSION".
- [ ] Given a useVersion() call with a non-literal argument, when
  analysis runs, then the matched dep is UNCERTAIN with an explicit
  "manual review" reason.
- [ ] Given a build.gradle with > 256 force() directives, when
  analysis runs, then exactly 256 are processed and errors[]
  contains the truncation note.
- [ ] Given a build.gradle whose tree-sitter parse exceeds 8 s, when
  analysis runs, then a sanitised parse-timeout error is recorded
  and analysis continues without Gradle pin data (NO crash).
- [ ] Given the SARIF reporter, when Gradle pin-overrides exist, then
  rule `TS-DEP-PIN-OVERRIDE-GRADLE` results are emitted per pinned dep.

---

## Out of Scope (REQ-21b)

- **Build-script evaluation.** Scarno never executes Gradle.
- **Init scripts** (`init.gradle`, `init.gradle.kts`) — they live
  outside the project root and Scarno's confinement model
  excludes them.
- **`buildSrc`-defined DSL extensions.** A `buildSrc` plugin that
  re-exports a custom `force()`-like helper is treated as opaque;
  the user gets UNCERTAIN.
- **Composite builds** — only the root project's build scripts are
  walked; included builds are out of scope until a future REQ.
- **Detection of inappropriate Gradle pins** — same out-of-scope
  rule as REQ-21.

---

## Limitations

- **Groovy's dynamic typing** means the parser may miss DSL forms
  that pass through `Object` references or use `methodMissing`. We
  accept under-detection rather than over-detection, and rely on the
  UNCERTAIN downgrade.
- **Version catalogs** (`libs.versions.toml`) supply default
  versions but do not pin — REQ-21b does not flag a coord as
  pin_override merely because it appears in a version catalog.
- **Plugin-injected configurations** (Spring Boot Gradle plugin,
  Android Gradle Plugin) may add force directives we cannot see
  without running the build. AGP/Spring users should treat REQ-21b's
  Gradle output as a starting point.
- **Kotlin DSL `kotlin { }` block** is parsed as Kotlin, but we do
  not interpret KMP-specific configuration variants (`commonMain`,
  `iosMain`, etc.) — they're treated as additional configurations.
