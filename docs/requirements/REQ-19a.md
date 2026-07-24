# REQ-19a — Phase-9 Architecture-Derived Requirements (NEW-ARCH-006..011)

## Overview

Six requirements surfaced by Phase-2 (security-architect) work
against REQ-19..REQ-23. They are **architectural invariants** rather
than user-visible features: each one closes a class of failure that
would otherwise let SUC-42 (the load-bearing pin-deferral safety
property in REQ-20) be silently bypassed, or let backwards
compatibility break for downstream consumers.

These are fed back through Phase-1 per the secure-by-design
workflow's feedback loop. The corresponding architecture references
are:

- `docs/scarno-security-architecture.md` §11.4 — classifier
  extraction.
- `docs/scarno-security-architecture.md` §11.11 ADR-006..011 —
  architecture decisions.
- `docs/scarno-security-architecture.md` §11.12 — the
  surfaced-requirements table this file expands on.

The PR sequencing in `docs/scarno-security-architecture.md` §11.9
implies which PR each requirement lands with:

| ID | Lands with | Test home |
|---|---|---|
| NEW-ARCH-006 | PR-2 (REQ-20) | `tests/unit/test_arch_classifier_centralisation.py` |
| NEW-ARCH-007 | PR-3 (REQ-21) | `tests/unit/test_arch_pin_redundant_mutex.py` |
| NEW-ARCH-008 | PR-3 (REQ-21) — extended in PR-5 (REQ-23) and PR-6 (REQ-21b) | `tests/unit/test_arch_pin_kind_enum.py` |
| NEW-ARCH-009 | PR-1 (REQ-19) — extended at every subsequent PR | `tests/integration/test_back_compat.py` |
| NEW-ARCH-010 | PR-4 (REQ-22) | `tests/security/test_arch_threadpool_cap.py` |
| NEW-ARCH-011 | PR-4 (REQ-22) | `tests/security/test_arch_javap_dependency_injection.py` |

---

## NEW-ARCH-006 — Single shared classifier

**Type:** SEC + FR. **Allocations:** SEC-NEW-46 + FR-250.

### Statement

`src/scarno/core/classifier.py` is the **only** module that
propagates transitive dependency status through the dep graph.
Every analyser (Maven, Gradle, JS, Python, Go, C#, CSS) MUST
invoke `classify_versioned()` (or `classify_canonical()` for the
back-compat path) at the end of its `analyse()` method.
Re-implementing transitive-status propagation locally is a build
break — enforced by an import-graph test (TA-arch-006).

### Context (problem closed)

Today `_resolve_transitive_statuses` lives only at
`analysers/python/source_analyser.py:1165`. Every other ecosystem
emits `Dependency.status` from source-usage analysis and never
propagates anything. REQ-20 introduces per-version classification
that MUST run for every ecosystem the user asks for; if any
ecosystem skips the classifier, that ecosystem silently bypasses
SUC-42 and produces SAFE recommendations on pinned deps —
the canonical silent-vulnerability-reintroduction failure (SAC-44).

### Use case

```
UC-24: New ecosystem analyser is added (e.g. Ruby / Bundler)
Actor: Scarno contributor.
Goal: New analyser produces correct per-version classification
  without re-implementing the propagation logic.
Preconditions: New analyser populates Dependency objects + dep_edges
  + (optionally) resolved_versions.
Main flow:
  1. Author writes RubyAnalyser.analyse() which produces deps + edges.
  2. Author calls classify_versioned(deps, edges, resolved_versions=...).
  3. Classifier writes back per-version status, removable flags, and
     applies SUC-42 pin-deferral safety automatically.
Postcondition: SUC-42 enforcement is uniform across ecosystems
  without per-ecosystem code review burden.
```

### Abuse case

```
SAC-53: Per-ecosystem classifier divergence
Linked threat: T-36
Attacker type: Not external — class of bugs that propagates into
  developer action.
Goal: A new analyser (or a future refactor of an existing one)
  re-implements transitive propagation locally, accidentally skipping
  the SUC-42 pin-deferral check, leading to silent vulnerability
  reintroduction in that ecosystem.
Mitigated by: SUC-57 — import-graph test asserts every analyser's
  analyse() method ultimately calls into core/classifier.py.
OWASP: A04:2021 — Insecure Design.
```

### Countermeasure

```
SUC-57: Classifier-API uniformity test
Mitigates: SAC-53
Control: tests/unit/test_arch_classifier_centralisation.py imports
  every registered analyser, runs analyse() against a tiny fixture
  that produces deterministic deps + edges, and asserts the result's
  versioned_nodes is non-empty (which it cannot be unless
  classify_versioned ran). A second sub-test greps the analyser
  source files and rejects any new occurrence of "_resolve_transitive"
  or in-line per-version classification logic outside of
  core/classifier.py.
Implementation: src/scarno/core/classifier.py + the test.
OWASP ASVS: §1.4.1 Trust boundary verification.
Residual risk: a deeply non-standard new analyser that bypasses
  BaseAnalyser entirely could escape the test. Mitigated by the
  registry contract (core/registry.py) requiring BaseAnalyser
  subclassing.
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| FR-250 | `core/classifier.py` exposes `classify_versioned`, `classify_canonical`, `apply_pin_override_safety` | `tests/unit/test_arch_classifier_api.py::test_public_surface` |
| SEC-NEW-46 | Every registered analyser routes through `core/classifier.py` | `tests/unit/test_arch_classifier_centralisation.py` |

---

## NEW-ARCH-007 — `pin_override` / `manifest_redundant` mutual exclusion

**Type:** SEC + FR. **Allocations:** SEC-NEW-47 + FR-251.

### Statement

`Dependency.__post_init__` MUST raise `ValueError` when both
`pin_override` and `manifest_redundant` are True. The classifier
(`core/classifier.py`) MUST also assert the same invariant on entry
to `apply_pin_override_safety`. Construction-time enforcement is
defence-in-depth against a future code path that builds a
`Dependency` and then mutates both flags.

### Context (problem closed)

The two flags mean opposite things:

- `pin_override=True` — direct dep is **load-bearing**, kept on the
  classpath because it substitutes for an excluded transitive
  (REQ-21 / 21b / 23). Status forced to IN_USE.
- `manifest_redundant=True` (FR-150) — direct dep is **redundant**
  because the artifact stays alive transitively. The manifest
  declaration can be deleted; the artifact stays IN_USE via the
  parent.

A dep with both flags True is an internal contradiction; whichever
flag wins by accident produces a wrong recommendation in the
report.

### Use case

```
UC-25: Detector populates one of the two flags
Actor: REQ-21/21b/23 detector OR FR-150 detector.
Goal: Set its flag without colliding with the other detector's flag.
Main flow:
  1. FR-150 redundant-detector runs first; flips manifest_redundant=True
     for any direct dep that's transitively reachable.
  2. REQ-21 pin-detector runs second; before flipping pin_override=True,
     it inspects manifest_redundant. If True, the dep is logically a
     manifest-redundant case (the direct line can be removed because the
     transitive carries the artifact); pin_override is NOT set.
Postcondition: at most one flag is True; the post-init assertion never fires.
```

### Abuse case

```
SAC-54: Mutually-exclusive flags both set due to detector ordering bug
Linked threat: T-36
Attacker type: Not external — internal correctness bug.
Goal: Cause silent misclassification when a refactor reorders the two
  detectors or adds a third detector that doesn't know about the
  invariant.
Mitigated by: SUC-58 — post-init assertion fails fast at construction
  time, surfacing the bug as a CI break rather than a wrong report.
OWASP: A04:2021 — Insecure Design.
```

### Countermeasure

```
SUC-58: Post-init mutex assertion
Mitigates: SAC-54
Control: Dependency.__post_init__ raises ValueError when both flags
  are True. Tests construct Dependency objects with both flags and
  assert ValueError is raised.
Implementation: src/scarno/models.py:Dependency.__post_init__ +
  src/scarno/core/classifier.py:apply_pin_override_safety
  (defence-in-depth).
OWASP ASVS: §1.4.1.
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| FR-251 | `Dependency.__post_init__` rejects (pin_override=True, manifest_redundant=True) | `tests/unit/test_arch_pin_redundant_mutex.py::test_post_init_rejects_both` |
| SEC-NEW-47 | Classifier asserts the invariant on entry | `tests/unit/test_arch_pin_redundant_mutex.py::test_classifier_asserts` |

---

## NEW-ARCH-008 — `pin_override_kind` is a closed enum

**Type:** SEC + FR. **Allocations:** SEC-NEW-48 + FR-252.

### Statement

`Dependency.pin_override_kind` is typed as a closed string enum with
exactly these values:

```
EXCLUSION                    (REQ-21 Maven)
DEPENDENCY_MANAGEMENT        (REQ-21 Maven)
GRADLE_FORCE                 (REQ-21b)
GRADLE_STRICTLY              (REQ-21b)
GRADLE_CONSTRAINTS           (REQ-21b)
GRADLE_EXCLUSION             (REQ-21b)
GRADLE_DYNAMIC_PIN           (REQ-21b — UNCERTAIN downgrade, NOT IN_USE force)
NPM_OVERRIDES                (REQ-23)
YARN_RESOLUTIONS             (REQ-23)
PNPM_OVERRIDES               (REQ-23)
```

Adding a new mechanism MUST land an enum value AND a corresponding
branch in `apply_pin_override_safety` in the same PR. A
branch-coverage test enforces the constraint: every enum value must
appear in the safety function's source.

### Context (problem closed)

If a contributor adds (say) `BUN_OVERRIDES` to the enum but forgets
to teach `apply_pin_override_safety` about it, the safety function
falls through and the matched dep is classified per the classifier's
default rule — which can promote it to SAFE. A pin-mechanism
addition would silently bypass SUC-42 in production.

### Use case

```
UC-26: Adding a new pin mechanism (future)
Actor: Scarno contributor adding Bun overrides support.
Goal: New mechanism is wired through the safety function in a
  single, reviewable PR.
Main flow:
  1. Author adds BUN_OVERRIDES to PinOverrideKind enum.
  2. Author adds matching branch to apply_pin_override_safety.
  3. Branch-coverage test passes; safety function recognises the new
     kind; SUC-42 enforcement extends.
Postcondition: no silent bypass.
```

### Abuse case

```
SAC-55: Enum drift bypasses pin-deferral safety
Linked threat: T-36
Attacker type: Not external — internal regression class.
Goal: A future PR adds an enum value but skips the safety function
  update; the classifier falls through and a pinned dep gets
  recommended for removal.
Mitigated by: SUC-59 — branch-coverage test compares enum values
  against the safety function's branch keys.
OWASP: A04:2021 — Insecure Design.
```

### Countermeasure

```
SUC-59: Enum-coverage test for safety function
Mitigates: SAC-55
Control: tests/unit/test_arch_pin_kind_enum.py iterates every
  PinOverrideKind enum value, constructs a synthetic Dependency
  with that kind, and asserts apply_pin_override_safety either
  forces IN_USE (most kinds) or downgrades to UNCERTAIN
  (GRADLE_DYNAMIC_PIN). A missed branch fails the test by leaving
  the test fixture's status at the default value.
Implementation: src/scarno/models.py (the enum) +
  src/scarno/core/classifier.py (the safety function).
OWASP ASVS: §1.4.1.
Residual risk: a contributor could mark the enum value as
  DEPRECATED to skip the test; mitigated by code review rather
  than tooling.
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| FR-252 | `PinOverrideKind` enum closed; values match ADR-007 | `tests/unit/test_arch_pin_kind_enum.py::test_enum_values` |
| SEC-NEW-48 | Every enum value has a matching branch in the safety function | `tests/unit/test_arch_pin_kind_enum.py::test_safety_branch_coverage` |

---

## NEW-ARCH-009 — Backwards-compatibility regression suite

**Type:** SEC + FR. **Allocations:** SEC-NEW-49 + FR-253.

### Statement

`tests/integration/test_back_compat.py` MUST load a frozen pre-Phase-9
fixture (saved AnalysisResult JSON, plus the rendered text / json /
sarif / markdown reports) and assert the current code base produces
the same output shape. "Same shape" means:

- Every JSON key present in the pre-Phase-9 output is still present.
- Every SARIF rule ID present in the pre-Phase-9 output is still
  present.
- Text and markdown reports' line counts and section headings match
  on a non-Phase-9-feature project (one that doesn't trigger
  multi-version, pinning, or ABI sections).

New keys / rules / sections are allowed (they're additive). Removing
or renaming any pre-existing key / rule / section is a regression.

### Context (problem closed)

The Phase-9 backwards-compatibility contract (§11.7 in the
architecture doc) is explicit: any consumer reading `dep_graph` +
`Dependency.status` must continue to work. Without an automated
regression test, future refactors can silently break that promise
(rename a JSON key, drop a SARIF rule, change a section heading) —
breaking GitHub Actions / dashboards / SARIF ingestors that pin to
those names.

### Use case

```
UC-27: CI consumer pins to a specific JSON key
Actor: A downstream CI script that reads `dep_graph` from the JSON output.
Goal: The script keeps working after Phase 9 lands.
Main flow:
  1. The pre-Phase-9 fixture's JSON has key "dep_graph".
  2. test_back_compat.py asserts the same key still exists in current output.
  3. Any refactor that drops the key fails CI before merge.
Postcondition: no surprise breakage for downstream automation.
```

### Abuse case

```
SAC-56: Silent breaking change in reporter wire format
Linked threat: T-36
Attacker type: Not external — refactor-induced regression.
Goal: A Phase-9 PR (or any future PR) renames a JSON key or SARIF
  rule, breaking downstream consumers without warning.
Mitigated by: SUC-60 — regression suite asserts shape equivalence
  on every PR.
OWASP: A08:2021 — Software and Data Integrity Failures (output-shape
  drift variant).
```

### Countermeasure

```
SUC-60: Wire-format regression suite
Mitigates: SAC-56
Control: tests/integration/test_back_compat.py loads the
  tests/fixtures/back_compat/pre_phase9.json fixture, runs each
  reporter against the saved AnalysisResult, and diffs the rendered
  output against tests/fixtures/back_compat/pre_phase9.<ext>. Mismatches
  fail the test with the diff in the assertion message.
Implementation: tests/integration/test_back_compat.py +
  fixture files captured at the merge of the PR before PR-1 (REQ-19).
OWASP ASVS: §10.3.3 Output integrity.
Residual risk: the fixture is captured once and only catches changes
  vs that snapshot. Updating the fixture (allowed when the team
  intentionally evolves the wire format) is a deliberate act
  reviewed in PR — not a silent drift.
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| FR-253 | Frozen pre-Phase-9 fixtures exist for json / sarif / text / markdown reporters | `tests/integration/test_back_compat.py::test_fixtures_present` |
| SEC-NEW-49 | All four reporters produce the same shape against the frozen fixture | `tests/integration/test_back_compat.py::test_shape_equivalence` |

---

## NEW-ARCH-010 — REQ-22 thread-pool cap and locked counter

**Type:** SEC + PERF. **Allocations:** SEC-NEW-50 + PERF-017.

### Statement

`CrossVersionAbiDiffer` (REQ-22, `analysers/java/abi_diff.py`) MUST
use `ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 1))`.
The per-run JAR cap counter (`SEC-NEW-43`,
`_JAVAP_MAX_JARS_PER_RUN=128`) MUST be incremented under a
`threading.Lock` so the cap is exact under concurrent execution.
The findings list MUST also be appended under a lock.

### Context (problem closed)

The architecture chose parallelism (ADR-010) to bring 32-min
worst-case wall clock down to ~4 min. Without an enforced worker
cap, an adversarial input that triggers many coordinates could
spawn an unbounded number of `javap` subprocesses (fork-bomb).
Without a locked counter, the cap is approximate — multiple workers
could read the counter, all see "still under cap", all increment,
and exceed the cap by up to (workers - 1) jars.

### Use case

```
UC-28: 128-jar deep-inspection run on a multi-core CI
Actor: CI executor running Scarno --deep-inspection.
Goal: The run completes within the wall-clock budget AND respects
  SEC-NEW-43.
Main flow:
  1. CrossVersionAbiDiffer.diff_all queues 128 work items.
  2. ThreadPoolExecutor(max_workers=8) runs them concurrently.
  3. Each worker takes the cap_lock before deciding whether to
     proceed; the 129th item finds the cap reached and returns early.
  4. Findings are accumulated under findings_lock.
Postcondition: exactly 128 jars inspected; at most 8 concurrent
  javap processes; zero data races on the findings list.
```

### Abuse case

```
SAC-57: Adversarial multi-coordinate input causes process flood
Linked threat: T-37
Attacker type: External (commits a pom.xml that declares 1000+
  multi-version coordinates).
Goal: Cause Scarno --deep-inspection to spawn an unbounded
  number of javap processes.
Mitigated by: SUC-61 — fixed worker cap of min(8, cpu_count) plus
  the per-run cap of 128 (SEC-NEW-43, established in REQ-22).
OWASP: A05:2021 — Security Misconfiguration (resource exhaustion).
```

### Countermeasure

```
SUC-61: Bounded thread pool + locked cap counter
Mitigates: SAC-57
Control: ThreadPoolExecutor instantiated with
  max_workers=min(8, os.cpu_count() or 1). Cap counter incremented
  under threading.Lock; findings list appended under a separate
  threading.Lock. Tests verify:
    - the executor's _max_workers attribute equals the expected cap
    - 100 concurrent calls to the increment helper produce exactly
      64 cap-passes and 36 cap-rejects.
Implementation: src/scarno/analysers/java/abi_diff.py.
OWASP ASVS: §11.1.4 Resource limits + §10.2.1 Concurrent access.
Residual risk: each javap process can still consume CPU within its
  30s timeout; the worker cap bounds the parallel CPU footprint to
  roughly 8 cores' worth of work.
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| SEC-NEW-50 | Worker cap = `min(8, os.cpu_count() or 1)` enforced | `tests/security/test_arch_threadpool_cap.py::test_worker_cap` |
| PERF-017 | Locked counter is exact under 100 concurrent attempts | `tests/security/test_arch_threadpool_cap.py::test_counter_atomic` |

---

## NEW-ARCH-011 — `_invoke_javap_safe` dependency-injection invariant

**Type:** SEC. **Allocations:** SEC-NEW-51.

### Statement

`CrossVersionAbiDiffer` (REQ-22) MUST receive `_invoke_javap_safe`
as an injected callable in its constructor. The differ module
(`analysers/java/abi_diff.py`) MUST NOT import `subprocess`, MUST
NOT call `os.execvp` / `os.spawnXX`, and MUST NOT instantiate its
own `subprocess.Popen`. The single javap invocation site stays at
`analysers/java/source_analyser.py:JvmSourceAnalyser._invoke_javap_safe`,
where the existing hardening (argv-only, `shell=False`, JAVA_HOME
pinning, 10s base timeout) lives.

### Context (problem closed)

ADR-008 settled that `_invoke_javap_safe` stays a method of
`JvmSourceAnalyser` rather than moving to `security.py`. The risk
is that a future contributor "simplifies" the differ by importing
`subprocess` directly and re-implementing the call — bypassing
SEC-NEW-09 (Java identifier validation), SEC-NEW-12 (JAVA_HOME
binding), and the existing 10s timeout. REQ-22 wraps the injected
callable with a 30s budget (SEC-NEW-42) but reuses the
single-invocation-site hardening as the trust kernel.

### Use case

```
UC-29: Differ runs javap exclusively through the injected callable
Actor: CrossVersionAbiDiffer instance.
Goal: Every signature extraction goes through the JvmSourceAnalyser
  hardening.
Main flow:
  1. JvmSourceAnalyser constructs the differ with
     invoke_javap=self._invoke_javap_safe.
  2. The differ's _javap_public_signatures wraps each call with the
     30s SEC-NEW-42 budget but never instantiates subprocess.
  3. Argv validation, JAVA_HOME pin, shell=False all reused.
Postcondition: trust kernel for javap is one function, not two.
```

### Abuse case

```
SAC-58: Differ re-implements javap call, bypassing hardening
Linked threat: T-22 (existing — javap subprocess hardening)
Attacker type: Not external — refactor-induced regression.
Goal: A future PR refactors abi_diff.py to "just use subprocess"
  and accidentally drops Java-identifier validation, JAVA_HOME
  pinning, or shell=False.
Mitigated by: SUC-62 — module-import test rejects any
  ``import subprocess`` (or analogue) in abi_diff.py; differ
  constructor signature requires the callable so the regression
  surfaces at construction time.
OWASP: A04:2021 — Insecure Design.
```

### Countermeasure

```
SUC-62: Differ-module import-graph guard
Mitigates: SAC-58
Control: tests/security/test_arch_javap_dependency_injection.py
  parses src/scarno/analysers/java/abi_diff.py via the ast
  module and rejects any Import / ImportFrom node referencing
  "subprocess", "os.execvp", "os.execve", "os.spawnv", "os.spawnve",
  "os.posix_spawn", "popen", or "asyncio.subprocess". A second
  sub-test asserts CrossVersionAbiDiffer.__init__ has the
  invoke_javap parameter as required (no default).
Implementation: src/scarno/analysers/java/abi_diff.py +
  the test.
OWASP ASVS: §1.4.1 Trust boundary verification.
Residual risk: a contributor could route through a third module
  that imports subprocess; covered by code review of new modules
  under analysers/java/.
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| SEC-NEW-51 | `analysers/java/abi_diff.py` does not import `subprocess` (or analogues); `CrossVersionAbiDiffer.__init__` requires `invoke_javap` | `tests/security/test_arch_javap_dependency_injection.py` |

---

## NEW-ARCH-012 — Pin-detector registry contract

**Type:** SEC + FR. **Allocations:** SEC-NEW-57 + FR-254.
**Origin:** Architecture ADR-012 (`docs/scarno-security-architecture.md`
§11.15.6).

### Statement

Every ecosystem analyser MUST call exactly one of
`register_pin_detector(ecosystem)` OR
`register_no_pin_mechanism(ecosystem)` in
`src/scarno/core/classifier.py` at module-import time. A test
in `tests/unit/test_arch_pin_detector_registry.py` asserts that
the union of the two registered sets equals the set of registered
languages from `core/registry.py` — no ecosystem may be silently
absent from both.

### Context (problem closed)

ADR-012 introduces a fail-closed default: the classifier downgrades
direct-dep SAFE → UNCERTAIN for any ecosystem registered in
neither set. The registry is module-level mutable state populated
at import time (analogous to `core/registry.py`'s analyser
registry). The risk is that a future analyser is added to
`core/registry.py` but its module forgets to register with the
classifier — its classifications then default to UNCERTAIN
forever. Functionally safe (no silent vulnerability reintroduction)
but a significant report-quality regression that may not be
noticed until users complain.

### Use case

```
UC-30: New ecosystem analyser is added (future, e.g. Bundler / Cargo)
Actor: Scarno contributor.
Goal: New analyser's pin-detection posture is explicit and auditable.
Preconditions: New analyser module subclasses BaseAnalyser and calls
  core.registry.register("bundler", BundlerAnalyser).
Main flow:
  1. Author adds the new analyser file under analysers/bundler/.
  2. Author imports core.classifier and calls EITHER
     register_pin_detector("bundler") OR
     register_no_pin_mechanism("bundler") at module top level.
  3. Test_arch_pin_detector_registry runs in CI — passes because
     registered_languages() == pin_detectors | no_pin_mechanisms.
Postcondition: classifier behaviour for the new ecosystem is
  explicit; reviewers see the choice in the diff.
```

### Abuse case

```
SAC-59: Ecosystem registered with analyser registry but not with classifier
Linked threat: T-36 (refactor-induced regression class)
Attacker type: Not external — internal regression class.
Goal: A new analyser ships with deps classified UNCERTAIN by default
  forever (no SAFE recommendations possible) without anyone noticing
  during code review.
Trigger: Author copy-pastes core.registry.register() but forgets
  the corresponding classifier registration.
Mitigated by: SUC-63 — symmetric-registry test asserts the two
  sets together cover every registered language; CI fails until the
  registration is added.
OWASP: A04:2021 — Insecure Design (silent functional regression).
```

### Countermeasure

```
SUC-63: Symmetric pin-detector registry test
Mitigates: SAC-59
Control: tests/unit/test_arch_pin_detector_registry.py imports every
  module under src/scarno/analysers/ (forcing module-import
  registrations to fire), then asserts:
    set(core.registry.registered_languages()) ==
        core.classifier._PIN_DETECTOR_REGISTRY |
        core.classifier._NO_PIN_MECHANISM_REGISTRY
  AND that the two sets are disjoint (no ecosystem may register
  both — they are mutually exclusive choices).
Implementation: src/scarno/core/classifier.py +
  src/scarno/analysers/*/__init__.py (one register call each).
OWASP ASVS: §1.4.1 Trust boundary verification.
Residual risk: a contributor could add an analyser without going
  through core/registry.register(); covered by NEW-ARCH-006's
  centralisation test (SUC-57).
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| FR-254 | `register_pin_detector` + `register_no_pin_mechanism` API in `core/classifier.py` | `tests/unit/test_arch_pin_detector_registry.py::test_registry_api` |
| SEC-NEW-57 | Symmetric coverage: `registered_languages == pin_detectors ∪ no_pin_mechanisms`; the two sets are disjoint | `tests/unit/test_arch_pin_detector_registry.py::test_symmetric_coverage` |

---

## NEW-ARCH-013 — `safe_subprocess_run` is the only sanctioned subprocess call site

**Type:** SEC + FR. **Allocations:** SEC-NEW-58 + FR-255.
**Origin:** Architecture ADR-013 (`docs/scarno-security-architecture.md`
§11.15.7).

### Statement

Outside the legacy `_invoke_javap_safe` method on `JvmSourceAnalyser`
(deferred-refactor per ADR-013), the codebase MUST NOT call
`subprocess.run`, `subprocess.Popen`, `os.execvp`, `os.execve`,
`os.spawn*`, `os.popen`, `os.posix_spawn*`, or
`asyncio.subprocess.*` directly. Every subprocess invocation goes
through `security.safe_subprocess_run`. Per-binary helpers
(`_invoke_mvn_safe`, `_invoke_gradle_safe`, `_invoke_javap_safe`
post-refactor) compose the primitive with binary-specific
resolution and argv allowlist.

A test in `tests/security/test_arch_subprocess_call_sites.py`
parses every `*.py` file under `src/scarno/` via the `ast`
module and rejects any matching `Call` node, with one
explicitly-listed grandfathered exception
(`src/scarno/analysers/java/source_analyser.py:_invoke_javap_safe`)
until the deferred refactor lands.

### Context (problem closed)

ADR-013 establishes `safe_subprocess_run` as the canonical
subprocess wrapper. It enforces `shell=False`, mandatory timeout,
and optional binary-root confinement (mirrors `resolve_and_confine`).
Per-binary helpers compose it with allowlist-validated argv. The
risk is that a future PR "simplifies" by importing `subprocess`
directly and re-implementing the call — bypassing argv allowlist,
binary pinning, and the timeout enforcement. A test catches this
at PR-review time rather than at exploit-time.

### Use case

```
UC-31: A future PR adds a new subprocess invocation
Actor: Scarno contributor.
Goal: New subprocess is hardened uniformly without re-implementing
  argv-allowlist + binary-pin + timeout.
Preconditions: A feature requires invoking a new external binary
  (e.g. cargo, go, dotnet).
Main flow:
  1. Author adds analysers/<eco>/_invoke_<eco>_safe(argv_tail) helper
     that composes safe_subprocess_run.
  2. Author adds the binary's home env-var pin (mirrors SEC-NEW-12 /
     SEC-NEW-52).
  3. Author specifies the argv allowlist for each call site.
  4. test_arch_subprocess_call_sites.py passes; new direct
     subprocess.run calls in PR diff would fail.
Postcondition: hardening posture extends uniformly; no per-binary
  drift.
```

### Abuse case

```
SAC-60: Future PR re-implements subprocess invocation, bypassing hardening
Linked threat: T-36 (refactor-induced regression class)
Attacker type: Not external — internal regression class.
Goal: A future PR drops argv-allowlist / binary-root confinement /
  timeout in pursuit of a "simpler" implementation.
Trigger: Contributor unfamiliar with the safe_subprocess_run pattern
  imports subprocess directly. Existing per-binary helper
  (_invoke_mvn_safe / _invoke_gradle_safe / future _invoke_X_safe)
  is bypassed.
Mitigated by: SUC-64 — AST-scan test rejects any Call node matching
  the disallowed list, with one explicit grandfathered exception
  for the legacy javap helper.
OWASP: A04:2021 — Insecure Design + A08:2021 — Software and Data
  Integrity Failures.
```

### Countermeasure

```
SUC-64: Subprocess-call-site AST scan
Mitigates: SAC-60
Control: tests/security/test_arch_subprocess_call_sites.py walks
  every *.py file under src/scarno/, parses each via ast.parse,
  and walks the tree looking for Call nodes whose .func.attr (or
  .func.id) matches the disallowed names listed in the statement
  above. Each match is checked against an allowlist; the only
  permitted match is _invoke_javap_safe in
  analysers/java/source_analyser.py at the line range that
  encloses the existing helper. Any other match fails the test
  with file:line and the suggested replacement
  (safe_subprocess_run + per-binary helper pattern).
Implementation: src/scarno/security.py:safe_subprocess_run +
  the AST scan test + grandfather entry for the legacy javap helper
  with a comment pointing at the deferred-refactor follow-up.
OWASP ASVS: §1.4.1 + §11.1.4 Resource limits.
Residual risk: a contributor could route through a third-party
  library that itself spawns subprocesses (e.g. a dependency of
  Scarno). The AST scan is over src/scarno/ only;
  third-party subprocess use is outside its scope and bounded by
  pyproject.toml's pinned dependency set.
```

### SRTM rows

| Req ID | Description | Test File |
|---|---|---|
| FR-255 | `security.safe_subprocess_run` API: shell=False, mandatory timeout, optional binary-root confinement | `tests/unit/test_safe_subprocess_run.py` |
| SEC-NEW-58 | Subprocess-call-site AST scan rejects direct `subprocess.run` / `Popen` / `os.execv*` / `os.spawn*` / `os.popen` / `asyncio.subprocess.*` outside the grandfathered javap helper | `tests/security/test_arch_subprocess_call_sites.py` |

---

## Threat Model Additions

| ID | Threat | Mitigation |
|---|---|---|
| T-36 | Class of refactor-induced regressions: divergent classifier (SAC-53), mutex-flag collision (SAC-54), enum drift (SAC-55), wire-format silent break (SAC-56), pin-detector registration omission (SAC-59), direct-subprocess re-implementation (SAC-60). | SUC-57 (centralisation test), SUC-58 (post-init mutex), SUC-59 (enum-coverage test), SUC-60 (back-compat regression suite), SUC-63 (symmetric pin-detector registry), SUC-64 (subprocess-call-site AST scan). |
| T-37 | Adversarial multi-coordinate input triggers unbounded `javap` process flood. | SUC-61 (worker cap + locked counter) on top of SEC-NEW-43 (per-run jar cap). |

---

## Refined Requirements (additions only)

These six entries are appended to the existing refined-requirements
list maintained at `docs/scarno-security-privacy-analysis.md`
§19.7. No prior requirements are dropped.

| New ID | Type | Origin |
|---|---|---|
| FR-250 | FR | NEW-ARCH-006 |
| FR-251 | FR | NEW-ARCH-007 |
| FR-252 | FR | NEW-ARCH-008 |
| FR-253 | FR | NEW-ARCH-009 |
| FR-254 | FR | NEW-ARCH-012 |
| FR-255 | FR | NEW-ARCH-013 |
| SEC-NEW-46 | SEC | NEW-ARCH-006 |
| SEC-NEW-47 | SEC | NEW-ARCH-007 |
| SEC-NEW-48 | SEC | NEW-ARCH-008 |
| SEC-NEW-49 | SEC | NEW-ARCH-009 |
| SEC-NEW-50 | SEC | NEW-ARCH-010 |
| SEC-NEW-51 | SEC | NEW-ARCH-011 |
| SEC-NEW-57 | SEC | NEW-ARCH-012 |
| SEC-NEW-58 | SEC | NEW-ARCH-013 |
| PERF-017 | PERF | NEW-ARCH-010 |

(Fifteen new SRTM rows total — eleven from the original Phase-1
follow-up plus four added by Phase-1 follow-up #2 for NEW-ARCH-012
+ NEW-ARCH-013. The SRTM marker count rolls forward as described
in `docs/scarno-security-privacy-analysis.md` §20 and §21.)

---

## Privacy

No new data category. The architecture-derived requirements
operate on internal program state (Dependency objects, classifier
output, subprocess invocation) rather than personal data. Existing
PUC-10..12 sanitisation continues to apply.

---

## Acceptance Criteria

- [ ] Given any analyser added to the registry, when its
  `analyse()` runs against a non-empty fixture, then
  `versioned_nodes` is populated (proves NEW-ARCH-006).
- [ ] Given a `Dependency(pin_override=True, manifest_redundant=True)`
  construction, when `__post_init__` runs, then `ValueError` is
  raised (proves NEW-ARCH-007).
- [ ] Given the `PinOverrideKind` enum, when the safety-function
  branch-coverage test runs, then every enum value triggers a
  recognised branch (proves NEW-ARCH-008).
- [ ] Given the frozen pre-Phase-9 fixture, when each reporter runs
  against it, then every JSON key, SARIF rule ID, and section
  heading present pre-Phase-9 is still present (proves NEW-ARCH-009).
- [ ] Given a 200-coordinate concurrent diff_all invocation, when
  the cap counter is queried, then it equals exactly 128 jars
  inspected (proves NEW-ARCH-010).
- [ ] Given `analysers/java/abi_diff.py`, when its AST is parsed,
  then no Import / ImportFrom node references `subprocess` or any
  process-spawn analogue (proves NEW-ARCH-011).
- [ ] Given the set of registered languages in `core/registry.py`,
  when `tests/unit/test_arch_pin_detector_registry.py` runs, then
  every language appears in EXACTLY ONE of the
  `_PIN_DETECTOR_REGISTRY` or `_NO_PIN_MECHANISM_REGISTRY` sets
  (proves NEW-ARCH-012).
- [ ] Given every `*.py` file under `src/scarno/`, when the
  AST scan in `tests/security/test_arch_subprocess_call_sites.py`
  runs, then no `Call` node matches `subprocess.run` /
  `subprocess.Popen` / `os.execv*` / `os.spawn*` / `os.popen` /
  `asyncio.subprocess.*` outside the grandfathered
  `_invoke_javap_safe` location (proves NEW-ARCH-013).

---

## Out of Scope (REQ-19a)

- **Lifting `_invoke_javap_safe` to `security.py`.** ADR-008
  rejected this. NEW-ARCH-011 is the inverse safeguard.
- **Per-PR back-compat fixtures.** A single pre-Phase-9 fixture is
  sufficient; rolling fixtures per-PR was considered and rejected
  as too noisy.
- **Generalising the back-compat regression to non-reporter wire
  formats.** Out of scope; reporters are the public contract.
