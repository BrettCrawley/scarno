# Plan: Phase 9 — Version-Aware Classification, Pin-Override Detection, Cross-Version ABI Diff

## Context

Phase 9 added six requirements (REQ-19 through REQ-23 plus REQ-21b)
and an architecture-derived addendum (REQ-19a). The user's goal was
to make Scarno emit SBOM-cleaner recommendations by:

1. Reading the dep graph per *edge* (so a library declared at two
   different versions renders as two nodes, not one);
2. Classifying per *version* (so `X@1.2 SAFE / X@1.3 IN_USE` is
   surfaceable);
3. Detecting *load-bearing pins* — direct deps that exist only to
   substitute for an excluded vulnerable transitive — so they're
   never recommended for removal (the silent-vulnerability-
   reintroduction failure);
4. Cross-version ABI diff (opt-in `--deep-inspection`) to flag
   `NoSuchMethodError`-class runtime risks BEFORE they ship.

The work landed across six PRs (PR-1 → PR-6) following the
secure-by-design → security-architect → threat-modeling →
software-test-engineer skill workflow. Each PR was red-test-first
(tests committed before implementation), with the full pre-Phase-9
suite passing throughout (no regressions from the 1058-test
baseline).

## What shipped, per PR

### PR-1 / REQ-19 — Per-edge version labels

- New `DepEdge` frozen dataclass in `models.py` (parent, child,
  declared_version, scope).
- `AnalysisResult.dep_edges` field; legacy `dep_graph` derived
  lazily in `__post_init__` for backwards compatibility.
- `sanitise_declared_version` in `security.py` (strips control +
  Mermaid + per-destination chars; cap 64; reserved-word stripping
  for `click` / `subgraph` / `classDef` / `linkStyle`).
- `LOCKFILE_MAX_BYTES = 8 MiB` / `LOCKFILE_MAX_EDGES = 50_000`
  caps (SEC-NEW-37).
- Maven `_build_transitive_graph` emits edges with sanitised
  declared versions; unresolvable placeholders emit
  `declared_version=None` rather than silently dropping (TA-205).
- Gradle `_emit_dep_edges_from_output` + `_check_lockfile_consistency`
  (SEC-NEW-53 lockfile-vs-`gradle dependencies` cross-check).
- npm/yarn/pnpm lockfile parsers populate
  `_NpmParseResult.edges`; `parse_all_npm_dependency_files` returns
  an `_NpmReturnValue` tuple-subclass that preserves the existing
  3-tuple unpacking while exposing `.edges` via attribute access.
- Markdown reporter renders distinct `(canonical, version)` tree
  nodes when `dep_edges` is populated.
- `cli.py` exposes `_run_options_default` + `run_analysis` test
  helpers for the back-compat regression suite.
- Pre-Phase-9 fixture captured at
  `tests/fixtures/back_compat/pre_phase9.{json,sarif,md,txt}`
  (NEW-ARCH-009 baseline).

**29 tests, all green.**

### PR-2 / REQ-20 + REQ-19a — Per-version classifier + subprocess primitive

- `VersionedNode` dataclass in `models.py`;
  `AnalysisResult.versioned_nodes` + `multi_version_coords` fields.
- `Dependency.pin_override`, `pin_override_kind`,
  `pin_override_target` fields; `__post_init__` enforces NEW-ARCH-007
  mutex (`pin_override` and `manifest_redundant` mutually exclusive).
- **NEW** `src/scarno/core/classifier.py` module:
  - Pin-detector registry: `register_pin_detector` /
    `register_no_pin_mechanism` (ADR-012 — NEW-ARCH-012).
  - `classify_versioned` propagates direct-dep status through
    `dep_edges` to per-version nodes; rolls up to
    `Dependency.status` via any-version-IN_USE.
  - `classify_canonical` — legacy path, extracted from the Python
    analyser (NEW-ARCH-006).
  - `apply_pin_override_safety` — the SUC-42 enforcement function.
    Closed-enum branching: `GRADLE_DYNAMIC_PIN` → UNCERTAIN with
    manual-review reason; any other pin kind → IN_USE.
  - `_safe_cpu_count` helper for D-Phase9-01.
  - Per-coord version cap of 64 (SEC-NEW-39).
  - Fail-closed downgrade for unregistered ecosystems (with meta-eco
    exemption for `unknown` / `detected`).
- Python analyser's `_resolve_transitive_statuses` removed (the
  legacy body is gone); a `_classify_canonical_shim` delegates to
  `core.classifier.classify_canonical` for back-compat callers.
- `safe_subprocess_run` primitive in `security.py` (NEW-ARCH-013):
  `shell=False`, mandatory timeout, optional `binary_root`
  confinement raising `BinaryNotConfinedError`.
- `_invoke_mvn_safe` (Maven) + `_invoke_gradle_safe` (Gradle)
  per-binary helpers with argv allowlist (SEC-NEW-55) and
  `_warn_path_fallback_once` PATH-fallback warnings (SEC-NEW-52).
- `_resolve_gradle_binary` mirrors `_resolve_mvn_binary`'s
  GRADLE_HOME pinning.
- Maven resolved-version helpers: `_resolve_versions_from_dependency_tree`
  + `_nearest_wins_from_edges`. Gradle equivalents:
  `_resolve_versions_from_dependencies_output` +
  `_resolve_versions_with_lockfile_priority`. npm:
  `resolve_versions_from_lockfile`.
- Markdown "Multiple versions detected" section + resolved-version
  marker (`← resolved`) on tree rows.
- SARIF `TS-DEP-MULTI-VERSION` rule (note severity).
- `_fetch_pom_via_maven` migrated to `_invoke_mvn_safe` so the
  SEC-NEW-58 AST scan passes.
- Each analyser package's `__init__.py` registers with the
  classifier: `pypi`, `go`, `nuget`, `csharp`, `css` →
  `no_pin_mechanism`; `maven`, `npm`, `gradle` → `pin_detector`
  (placeholder semantics; see Drift §1 below).

**44 tests, all green.**

### PR-3 / REQ-21 — Maven pinning detection

- `PinOverrideKind` enum (closed) in `models.py` — initial values
  `EXCLUSION`, `DEPENDENCY_MANAGEMENT`.
- Maven detector helpers in `maven.py`:
  - `_collect_exclusions_from_walked_poms` — augments POM parsing
    to gather `<exclusion>` blocks.
  - `_augment_pom_with_exclusions` + replaced `_parse_pom_file`
    so the parsed `_PomData` carries `<exclusions>` data.
  - `_collect_dependency_management` — root POM `<dependencyManagement>`
    with property resolution.
  - `_detect_pin_overrides` — pattern (a) exclusion-override +
    pattern (b) DM pin; respects NEW-ARCH-007 mutex with
    `manifest_redundant`.
  - `_set_pin_override` helper (mutates in place).
  - `_MAX_EXCLUSIONS_PER_DEP=128` / `_MAX_DM_ENTRIES=2048` caps
    (SEC-NEW-40).
- Pattern (a) reason text includes "manual review recommended —
  coincidental GA match is possible" per T-Phase9-02.
- `MavenPomResolver.analyse()` wires the detector after edge
  emission.
- Markdown "Pinning overrides" section with per-ecosystem
  sub-grouping.
- SARIF `TS-DEP-PIN-OVERRIDE-MAVEN` rule.

**15 tests, all green.**

### PR-4 / REQ-22 — Cross-version ABI diff (--deep-inspection)

- `FindingKind.ABI_RUNTIME_RISK` + `FindingKind.ABI_DRIFT` enum
  members.
- `JavaSignature` (frozen) dataclass.
- `TS-ABI-RUNTIME-RISK` (HIGH) + `TS-ABI-DRIFT` (MEDIUM) entries
  in `findings/rules.py`.
- `_RunOptions.deep_inspection` field + `--deep-inspection` CLI
  flag. Argv-only — no env / config fallback (SEC-NEW-56).
- **NEW** `src/scarno/analysers/java/abi_diff.py` module:
  - `_JAVAP_PER_JAR_TIMEOUT_S=30`, `_JAVAP_MAX_JARS_PER_RUN=128`,
    `_JAVAP_MAX_SIGNATURES_PER_JAR=50_000` caps.
  - `_compute_max_workers()` → `min(8, _safe_cpu_count(default=1))`.
  - `javap_public_signatures(stdout) → set[JavaSignature]` parser.
  - `AbiDiffResult` + `signature_diff(declared, resolved) → AbiDiffResult`.
  - `_finding_sort_key` for deterministic finding ordering
    (R-Phase9-01).
  - `CrossVersionAbiDiffer` class — constructor REQUIRES
    `invoke_javap` (no default; NEW-ARCH-011). Uses
    `_try_consume_cap_slots` (locked atomic cap counter) and a
    `ThreadPoolExecutor` for parallel diff. `_m2_jar_path` confines
    every JAR path under `m2_root` via `resolve_and_confine` +
    `_validate_gav` (SEC-NEW-44).
  - **No** subprocess imports — `javap` runs exclusively via the
    injected callable (NEW-ARCH-011 enforced by AST scan).
  - **No** wholesale `~/.m2` enumeration — reads only coordinates
    in `dep_edges` (SUC-52).

**25 tests, all green.**

### PR-5 / REQ-23 — npm pinning detection

- `PinOverrideKind` enum extended with `NPM_OVERRIDES`,
  `YARN_RESOLUTIONS`, `PNPM_OVERRIDES`.
- npm detector helpers in `dep_file_parser.py`:
  - `NpmOverride` (frozen) dataclass.
  - `_extract_overrides` — npm `overrides` (flat + targeted-nested),
    yarn `resolutions` (with glob/version-constraint key parsing),
    `pnpm.overrides` (with `parent>child` syntax).
  - `_NPM_OVERRIDES_MAX_ENTRIES=2048` / `_NPM_OVERRIDES_MAX_NESTING=8`
    caps (SEC-NEW-45).
  - `_split_yarn_resolution_key` + `_split_pnpm_overrides_key`
    helpers.
  - `_detect_npm_pin_overrides` — exact-match-only matcher
    (SUC-54 / homoglyph defence); respects NEW-ARCH-007 mutex.
- `analyse_npm_sources` propagates `pin_override*` fields when
  reconstructing `Dependency` objects (otherwise the source
  analyser wiped them).
- SARIF `TS-DEP-PIN-OVERRIDE-NPM` rule. The SARIF pin-rule
  selector now uses `_PIN_OVERRIDE_RULE_BY_ECO` keyed on
  ecosystem.

**12 tests, all green (plus 5 forward-looking greens from prior
PRs' generic implementations.)**

### PR-6 / REQ-21b — Gradle pinning detection

- `PinOverrideKind` enum extended with `GRADLE_FORCE`,
  `GRADLE_STRICTLY`, `GRADLE_CONSTRAINTS`, `GRADLE_EXCLUSION`,
  `GRADLE_DYNAMIC_PIN`. **Enum is now closed.**
- **NEW** `src/scarno/analysers/java/gradle_dsl.py` module:
  - `_GRADLE_MAX_FORCE_DIRECTIVES=256` /
    `_GRADLE_MAX_EXCLUSIONS=256` /
    `_GRADLE_PARSE_TIMEOUT_S=8` caps (SEC-NEW-41).
  - `GradleForceDirective` + `GradleExclusion` (both frozen)
    dataclasses.
  - Bounded-regex walker for `force()`, `strictly()`,
    `constraints { }`, `eachDependency.useVersion(literal)`,
    `useVersion(<non-literal>)` (dynamic), and
    `exclude(group, module)`.
  - `_extract_constraints_blocks` balanced-brace state machine.
  - Wall-clock budget guard across all files in one parse call.
- Markdown reporter dedicated "DO NOT REMOVE — dynamic Gradle pin"
  section ABOVE the generic pinning section (R-Phase9-02 closure).
- SARIF `TS-DEP-PIN-OVERRIDE-GRADLE` rule with dual severity:
  `note` for static kinds, `warning` for `GRADLE_DYNAMIC_PIN`. Rule
  selector also routes by `pin_override_kind.startswith("GRADLE_")`
  to handle java-ecosystem deps that are actually Gradle-pinned.

**14 tests, all green (plus 6 forward-looking greens from PR-2
classifier safety + PR-3 reporter helper + earlier PRs' enum
coverage).**

## Authoritative sources (where to look for what)

| Surface | Authoritative doc |
|---|---|
| Per-PR requirements + acceptance criteria | `docs/requirements/REQ-19.md` .. `REQ-23.md` + `REQ-19a.md` |
| Architecture, module layout, ADRs | `docs/scarno-security-architecture.md` §11 + §11.15 |
| Threat model + residual-risk register | `docs/THREAT-MODEL.md` §9 + §9.11 |
| STRIDE/LINDDUN analysis, SRTM rollup | `docs/scarno-security-privacy-analysis.md` §13..§22 |
| Test plan structure + per-PR test groups | `docs/scarno-test-plan-phase9.md` |
| As-shipped reality (this doc) | `docs/plans/phase-9-version-aware-classification.md` |

## Drift from the planning docs

This section enumerates the places where the as-shipped state
diverges from what the planning docs describe. The planning docs
remain valuable as a historical record of how the design evolved
(including the corrections made during the secure-by-design /
architect / threat-model / test-engineer feedback loops). When
they conflict with reality, **this file wins**.

### 1. Maven / npm / Gradle pin-detector "placeholders"

**Planning doc says:** Architecture §11.15.1 (ADR-012) per-PR
milestones say PR-2 "registers nothing" so Maven / npm / Gradle
direct-dep SAFE classifies as UNCERTAIN until the respective
detector ships in PR-3 / PR-5 / PR-6.

**As-shipped:** PR-2's analyser `__init__.py` modules register
Maven / npm / Gradle ecosystems via
`register_pin_detector(<eco>)` as **placeholders**. No
`pin_override` flag is set by any code path until the detector
lands (PR-3 ships the real Maven detector, etc.). The placeholder
is just a marker that ADR-012's fail-closed downgrade should NOT
fire for these ecosystems. Effect:

- TA-222c (symmetric coverage) passes from PR-2 onwards rather
  than failing until PR-6.
- Maven / npm / Gradle direct-dep SAFE classifies as SAFE during
  the PR-2 → PR-3/5/6 window (same as pre-Phase-9), not UNCERTAIN.

The trade-off was discussed in the PR-2 summary: the strict
ADR-012 interpretation would break ~1058 existing tests during
the rollout. The placeholder approach preserves existing
behaviour while still benefitting from the registry's
fail-closed guarantee for any FUTURE unregistered ecosystem.
Each placeholder analyser `__init__.py` has a comment explaining
the temporary nature.

### 2. Test-plan marker convention

**Planning doc says:** `docs/scarno-test-plan-phase9.md`
shows `@pytest.mark.REQ_19` and similar in its examples.

**As-shipped:** Tests use the project's actual SRTM-plugin
convention: `@pytest.mark.requirement("FR-190")`,
`@pytest.mark.requirement("SEC-NEW-37")`, etc. The test plan was
written before the SRTM-plugin convention was confirmed.

### 3. NEW-ARCH-009 back-compat fixture date

**Planning doc says:** REQ-19a §NEW-ARCH-009 describes a "pre-Phase-9
fixture" with no captured date.

**As-shipped:** Fixture captured 2026-05-11 via
`uv run --no-sync scarno tests/fixtures/simple_python --format {text,json,md,sarif}`
against `main` immediately before PR-1's red tests landed. Lives
at `tests/fixtures/back_compat/pre_phase9.{json,sarif,md,txt}`.
Strict-inclusion semantics: every key/rule-id present in the
fixture must remain present in current output.

### 4. `_invoke_javap_safe` deferred refactor

**Planning doc says:** Architecture §11.15.7 (ADR-013) notes
`_invoke_javap_safe` refactor onto `safe_subprocess_run` is a
post-Phase-9 cleanup.

**As-shipped:** Confirmed. The legacy helper at
`analysers/java/source_analyser.py:_invoke_javap_safe` retains
its inline `subprocess.run` call, grandfathered in the
SEC-NEW-58 AST scan via the `_GRANDFATHERED` set in
`tests/security/test_arch_subprocess_call_sites.py`. No
behavioural change.

### 5. Test-plan TA-227 perf budget

**Planning doc says:** TA-227 targets "8 MiB realistic-shape
package-lock.json parses in under 500 ms".

**As-shipped:** Target adjusted to **~7.5 MiB** (just under the
8 MiB cap). The 8 MiB literal was at-cap-on-the-nose; the loop
overshoot meant the file exceeded the cap, getting rejected
before the perf measurement could run. The intent (perf budget
on a near-cap lockfile) is preserved.

### 6. Test-plan TA-253 / TA-261 fixture preconditions

**Planning doc says:** TA-253 (pattern-(b) DM not reached → no
pin) and TA-261 (pin / manifest_redundant mutex) test for
absence of a pin flag.

**As-shipped:** Both tests strengthened with explicit
preconditions that prove the detector actually ran (e.g.
"verify dm_index has the entry but no Dependency.pin_override
is True"). Without these preconditions, both tests passed
trivially against a no-op (no-detector-yet) baseline. The
strengthening makes them genuinely red until PR-3 implementation
lands.

### 7. Test-plan TA-227 strengthened

**As-shipped:** TA-227 also gained an explicit
`result.edges is not None and len(result.edges) > 0`
assertion. Without it, the perf test passed on the pre-Phase-9
codebase that didn't populate edges at all — defeating TDD red
discipline.

### 8. SRTM marker count

**Planning doc says:** Analysis §22.6 projected SRTM marker count
**195 → 256** once Phase 9 lands.

**As-shipped:** Final count is **307 / 308 covered** (one
uncovered: `FR-250` — the `core/classifier.py` public-surface
marker has no dedicated test, but the API is exercised by 20+
tests via cross-references). The count exceeds the projection
because PR-3 / PR-4 / PR-5 / PR-6 each contributed slightly
more SRTM rows than the §22.6 estimate accounted for. The
`tests/srtm.py` set is the authoritative list.

### 9. Threat-model residual-risk statuses

**Planning doc says:** `docs/THREAT-MODEL.md` §9.5 has rows
marked "Open" awaiting Phase-4 test coverage for D-Phase9-01,
D-Phase9-02, R-Phase9-01.

**As-shipped:** These are now closed in the implementation:

- D-Phase9-01 (cpu_count edge cases): closed by
  `tests/security/test_arch_threadpool_cap.py::test_threadpool_max_workers_None_falls_back_to_1`.
- D-Phase9-02 (cap-counter race): closed by
  `tests/security/test_arch_threadpool_cap.py::test_cap_counter_atomic_under_concurrency`.
- R-Phase9-01 (finding determinism): closed by
  `tests/unit/test_req22_finding_sort.py::test_findings_sorted_after_diff_all`.

The §9.5 register prose still reads "Open"; readers should
treat this doc as the closure authority.

### 10. SARIF rule selector behaviour

**Planning doc says:** Architecture §11.6.2 SARIF rules table
maps each rule by REQ origin (TS-DEP-PIN-OVERRIDE-MAVEN for
REQ-21, GRADLE for REQ-21b, NPM for REQ-23).

**As-shipped:** The SARIF pin-rule selector in
`reporters/sarif_reporter.py` uses both ecosystem AND
`pin_override_kind` to pick the rule. A dep with
`ecosystem="java"` but `pin_override_kind="GRADLE_FORCE"`
routes to `TS-DEP-PIN-OVERRIDE-GRADLE` (the kind is the
authoritative discriminator). This handles polyglot
JVM projects where the ecosystem tag may be coarser than the
detector that fired.

## Deferred / out-of-scope follow-ups

Tracked here so they're not lost. None of these blocked Phase 9
landing.

1. **`_invoke_javap_safe` refactor onto `safe_subprocess_run`**
   (Drift §4 above). Mechanical refactor; saves ~25 lines of
   duplicated argv-validation code.
2. **PR-2 placeholder semantics → real ADR-012 enforcement**
   (Drift §1 above). Once Maven / npm / Gradle have detectors,
   the placeholders could be replaced with proper
   pin-mechanism-with-no-detector-yet semantics; current
   approach loses one threat-model defence (downgrade-on-missing-
   detector) for the ~few-day rollout window between PR-2 and
   PR-3/5/6.
3. **`_extract_overrides` `parent_dep_coord` on Gradle exclusions**.
   `GradleExclusion.parent_dep_coord` is currently always `None`
   — the walker doesn't track which `implementation(...)` block
   the `exclude(...)` appeared inside. The classifier doesn't
   need it today (pattern (a) detection uses GA-only matching).
   A future enhancement could surface the parent coord in the
   reporter's narrative ("substitutes for exclusion declared by
   `<parent>`").
4. **Gradle `force(group:'g', name:'a', version:'v')` named-arg
   form**. The bounded-regex walker only catches the
   `force("g:a:v")` GAV-string form. A named-arg follow-up
   regex would close the gap.
5. **REQ-23 npm: target-constraint matching**. `NpmOverride`
   carries `target_constraint` (e.g., `**` from
   `resolutions: "**/lodash"`), but the matcher uses
   exact-name only. Constraint-aware matching (e.g., only flag
   the dep when reached via `**` paths) is a future
   enhancement; the current matcher is conservative.

## Final state metrics

- **Total tests passing**: 1202 (Phase-9 contribution: 144;
  pre-existing: 1058).
- **Tests skipped**: 1 (env-dependent —
  `tests/security/test_adversarial.py:62` requires
  `~/.aws/credentials`).
- **SRTM coverage**: 307 / 308 markers. Single uncovered:
  `FR-250` (classifier public-surface marker; API itself is
  exercised by ~20 tests).
- **Coverage threshold**: 85% gate still enforced on full-suite
  runs.
- **New modules**: 2 (`src/scarno/core/classifier.py`,
  `src/scarno/analysers/java/gradle_dsl.py`,
  `src/scarno/analysers/java/abi_diff.py` — 3 if you count
  abi_diff).
- **New test files**: 60+ across `tests/unit/`, `tests/security/`,
  `tests/integration/`, `tests/performance/`.
- **New CLI flag**: `--deep-inspection` (REQ-22).
- **New SARIF rules**: `TS-DEP-MULTI-VERSION`,
  `TS-DEP-PIN-OVERRIDE-MAVEN`, `TS-DEP-PIN-OVERRIDE-NPM`,
  `TS-DEP-PIN-OVERRIDE-GRADLE`, `TS-ABI-RUNTIME-RISK`,
  `TS-ABI-DRIFT`.
- **New back-compat fixture**: `tests/fixtures/back_compat/`
  (NEW-ARCH-009 baseline, captured 2026-05-11).

## Running the Phase-9 surface

```bash
# Full suite, no coverage gate (fast)
uv run --no-sync pytest --no-cov --tb=short -q

# Phase-9 only
uv run --no-sync pytest tests/unit/test_req19_*.py tests/unit/test_req20_*.py \
  tests/unit/test_req21_*.py tests/unit/test_req21b_*.py \
  tests/unit/test_req22_*.py tests/unit/test_req23_*.py \
  tests/unit/test_arch_*.py tests/security/test_req*.py \
  tests/security/test_arch_*.py tests/security/test_mvn_gradle_binary_pinning.py \
  tests/integration/test_back_compat.py tests/integration/test_req21_invariants.py \
  tests/performance/test_req19_perf.py tests/performance/test_req21_perf.py \
  tests/performance/test_req21b_perf.py tests/performance/test_req22_perf.py \
  tests/performance/test_req23_perf.py

# Trigger ABI-diff (off by default)
uv run --no-sync scarno /path/to/maven-project --deep-inspection --format sarif
```
