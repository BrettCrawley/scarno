# Scarno — Phased Development Plan

This plan sequences the requirement set into delivery phases. It is TDD-first: the test suite is stood up before any production code so every subsequent phase is a red → green cycle traced to the SRTM. Requirement files currently in the repo:

| File | Scope |
|---|---|
| `REQ-1` … `REQ-7` | Core (Python + Maven/Gradle/JVM + reporter) |
| `REQ-2b`, `REQ-2c`, `REQ-3b`, `REQ-3c` | Phase 1.5 — Conda / containers / phantom imports / security findings |
| `REQ-6b`, `REQ-8` | Phase 4 — tree-sitter JVM parsing + GitHub Action packaging |
| `REQ-9` | Phase 2.5 — polyglot foundations (ecosystem field, registry, multi-lang orchestrator) |
| `REQ-10`, `REQ-11`, `REQ-12` | Phase 5 — JS / TS / CSS / Node.js |
| `REQ-13`, `REQ-14` | Phase 6 — Go |
| `REQ-15`, `REQ-16` | Phase 7 — C# / F# / VB.NET (NuGet) |

**Current status:** Phases 0a + 0b + 1 + 1.5 + 2 + 2.5 + 3 + **4** complete. 443 tests collect; 186 / 186 SRTM IDs covered; mypy strict (29 files) + bandit `-ll` + SRTM + coverage (76.44% ≥ 75% floor) green; **333 tests passing**. **Tree-sitter-backed JVM source parser (REQ-6b) eliminates comment / Javadoc / string-literal false positives** that plagued the Phase 2 regex scanner; graceful fallback to regex when grammars aren't available. **Composite GitHub Action (REQ-8) delivered** — one-step SARIF upload to Code Scanning, sticky PR Markdown comment, per-finding workflow-command annotations, and job summary. Phase 5 (REQ-10/11/12 JS/TS/CSS/Node.js) is the next implementation phase.

---

## Phase 0a — Test harness & SRTM wiring ✅ COMPLETE

Land the testing infrastructure before any production code so every later line of code is written against a failing test that traces to a requirement.

**Delivered:**

- `tests/` tree in place (`unit/`, `integration/`, `security/`, `performance/`, `test_cli_smoke.py`)
- `tests/conftest.py` with shared fixtures (`runner`, `fixtures_dir`, `tmp_project`, `make_result`, `safe_dep`, `in_use_dep`, `uncertain_dep`)
- Fixture projects: `simple_python/` populated; `python_malicious/*`, `python_traversal/`, `java_malicious/*`, `java_simple/`, `gradle_simple/`, `gradle_malicious/*`, `report/*` exist as documented stubs — the adversarial payloads are built in-test via `tmp_path` to avoid committing literal escape bytes or bomb XML
- Phase 1.5 fixture directories (`findings_*/`, `phantom_imports/`, `vendored/`, `environment_malicious/`) are NOT yet created — their tests also use `tmp_path`; stub directories will be added on demand in Phase 1.5 if golden-file tests are introduced
- Custom pytest markers registered in `pyproject.toml`: `requirement`, `security`, `integration`, `performance`, `srtm`
- SRTM coverage reporter (`tests/srtm_plugin.py` + `tests/srtm.py`): harvests `@pytest.mark.requirement(...)` markers, emits JSON via `--srtm-report=<path>`, fails CI via `--srtm-fail-on-gap`
- `.github/workflows/ci.yml` jobs: `test` (pytest + cov), `srtm-coverage`, `typecheck` (mypy strict), `bandit`, `pip-audit`, `opengrep`
- `src/scarno/` package skeleton (22 modules, `py.typed`) — all runtime symbols raise `NotImplementedError` so the red baseline is honest
- `src/scarno/models.py` extended with the Phase 1.5 model surface (`DependencyStatus.UNDECLARED`, `Finding`, `FindingSeverity`, `FindingKind`, new `Dependency` fields) so REQ-2b/2c/3b/3c tests collect without waiting for their phase
- Phase 1.5 module stubs pre-created: `findings/rules.py` (populated rule catalogue, 13 rules), `findings/__init__.py`, `analysers/python/container_ci_parser.py`, `analysers/python/notebook_parser.py`
- Runtime dep `pyyaml` + dev-dep `types-PyYAML` pre-added (REQ-2b/2c will need them)

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| `pytest --collect-only` | 205 tests collect, 0 import errors |
| SRTM coverage (`--srtm-fail-on-gap`) | 99 / 99 requirements covered, exit 0 |
| `mypy --strict src/scarno` | 0 errors across 18 files |
| `bandit -r src/` | 0 issues |
| Red baseline visible | yes — ~180 failing tests tracing to unimplemented requirements |

---

## Phase 0b — Foundation (REQ-1) under TDD ✅ COMPLETE

Everything downstream plugs into the contracts defined here. Package scaffold, `pyproject.toml`, CI pipeline, and model dataclasses existed as Phase 0a stubs — Phase 0b turned them from "raises `NotImplementedError`" to "green tests".

**Delivered:**

- Typer single-command CLI (`--format`, `--output`, `--verbose`; exit codes 0/1/2; root-privilege warning; sanitised exception path) in `src/scarno/cli.py`
- `core/detector.detect_project_type` — indicator-file dispatch with Java-wins + stderr warning
- Full `security.py` primitives: `resolve_and_confine`, `check_file_size`, `strip_ansi` (CSI / OSC / DCS / SOS / PM / APC), `strip_control_chars`, `sanitise`, `check_root_privilege`, `safe_jar_entries` (ZIP-bomb guards)
- `TextReporter` — full section rendering (`SAFE TO REMOVE` / `UNCERTAIN` / `UNDECLARED` / `IN USE` + `WARNINGS`), entry-point summary, `✓` used-symbol prefix, sanitisation pass on every user string
- `JsonReporter` — full schema (`scarno_version`, `analysis_timestamp` (ISO-8601 UTC), `project_type`, `project_path`, `dependencies` with `entry_points`, `errors`, `findings`) via `json.dumps(ensure_ascii=False)` — no f-string construction
- `PythonAnalyser` — minimal pyproject.toml + requirements.txt stub reader so smoke tests see `requests`/`boto3` as `UNCERTAIN` (REQ-2 replaces this fully)
- `JavaAnalyser` — stub returning empty deps (REQ-4/5/6 replace)
- `AGENTS.md` — agent orientation (overview, layout, extension points, data model, CLI conventions, security rules, testing, CI, out-of-scope)
- `docs/THREAT-MODEL.md` — unified threat model (STRIDE analysis, architecture diagram, risk register) covering all language analysers + HTML scanner

**SRTM rows flipped from red to green:** FR-001, FR-002, FR-003, FR-030, FR-032, FR-033, SEC-002, SEC-003, SEC-004, SEC-005, SEC-013, SEC-NEW-02, SEC-NEW-03, SEC-NEW-04, SEC-NEW-05, SEC-NEW-10, SEC-NEW-11, T-07, I-01, GAP-06, ARCH-SEC-001, ARCH-SEC-002, ARCH-SEC-004, ARCH-PERF-001, R-01, PRV-002 (partial), PRV-003 (partial).

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| Phase 0b-scoped test files | 100% green (79 tests across 6 files) |
| Adversarial tests in Phase-0b scope (ANSI, markup, XXE sanitisation, root, injection) | 10 passed |
| `mypy --strict` | 0 errors across 22 source files |
| `bandit -r src/` | 0 issues |
| SRTM gate (`--srtm-fail-on-gap`) | exit 0, 99 / 99 covered |
| `scarno <path>` end-to-end | works on `simple_python` fixture — emits valid JSON with `requests`/`boto3` |

The ~100 remaining failing tests all trace to REQ-2 / REQ-3 / REQ-4 / REQ-5 / REQ-6 / REQ-7 and Phase 1.5 requirements — the intended red baseline for subsequent phases.

---

## Phase 1 — Python MVP (REQ-2 + REQ-3 + REQ-7) ✅ COMPLETE

First phase that produces a genuinely useful, shippable product. Python is the fastest path to trust: no JAR discovery, no bytecode, no build-system resolver. REQ-7 reporter landed in Phase 0b already, so Phase 1 was essentially REQ-2 + REQ-3.

**Delivered:**

- `src/scarno/analysers/python/dep_file_parser.py` — all 8 formats (requirements.txt with `-r` / `-c` includes, depth cap 10, cycle detection; `pyproject.toml` PEP 621 + Poetry `[tool.poetry.dependencies]` + groups; `setup.py` AST-only with variable dereferencing; `setup.cfg` via `configparser`; `Pipfile` TOML; `Pipfile.lock` JSON; `poetry.lock` + `uv.lock` `[[package]]` TOML)
- PEP 503 name normalisation + precedence-based deduplication + version-conflict warnings
- Type-stub detection (`types-*`, `*-stubs`, typing-* packages) with runtime-dep cross-reference
- Stdlib exclusion via `sys.stdlib_module_names`
- `src/scarno/analysers/python/source_analyser.py` — AST-based import detection across `.py` files; direct / from / aliased imports; `importlib.import_module` / `__import__` / `importlib.util.find_spec` literal + non-literal dynamic heuristics; entry-point enumeration for IN_USE deps with usage cross-reference; file-size + symlink-escape guards
- `src/scarno/analysers/python/import_aliases.py` — alias table (`pil→pillow`, `cv2→opencv-python`, `sklearn→scikit-learn`, etc.)
- `PythonAnalyser.analyse()` wires REQ-2 → REQ-3 → AnalysisResult

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| `test_dep_file_parser.py` | 19 / 19 ✅ |
| `test_source_analyser.py` | 12 / 12 ✅ |
| `test_reporters.py` | 18 / 18 ✅ (landed in Phase 0b) |
| Python-path adversarial (ANSI, control chars, rich markup, circular `-r`, traversal) | 15 / 15 ✅ |
| End-to-end on `simple_python` fixture | `boto3` → SAFE, `requests` → IN_USE with entry-point surface (1/48 used) |
| `mypy --strict` | 0 errors across 23 source files |
| `bandit -r src/` | 0 issues |
| SRTM gate | 99 / 99 covered |

The tool now outputs trustworthy analysis:

```
SAFE TO REMOVE (1)
  - boto3==1.26.0
    Reason: no import or usage found in source files

IN USE (1)
  - requests==2.31.0
    Reason: imported as 'requests' in project source
    Entry points: 1 / 48 used
      ✓ requests.get  (function)
```

v0.1 (Python-only, ready to dogfood) is reachable from here by pointing Scarno at a real project.

---

## Phase 1.5 — Ghost-dep & supply-chain coverage (REQ-2b + REQ-2c + REQ-3b + REQ-3c) ✅ COMPLETE

Closes the largest accuracy and trust gaps in the Python MVP before adding Java complexity. The existing REQ-2 / REQ-3 only look at Python-packaging-native declarative files plus AST imports — which misses Conda projects, containerised apps, notebook users, phantom transitive imports, and code that installs packages at runtime. These four requirements close those gaps and add a structured `Finding` surface for suspicious install & code-execution patterns.

**Delivered:**

- **REQ-2b** — `dep_file_parser.py` extended with: Conda `environment.yml` / `environment.yaml` (`yaml.safe_load`, nested `pip:` section, `python` pseudo-dep excluded); PEP 518 `[build-system].requires`; PEP 735 `[dependency-groups]` with `include-group` cycle detection; `source` provenance populated for every parser path
- **REQ-2c** — `src/scarno/analysers/python/container_ci_parser.py`: `Dockerfile` / `Containerfile` / `*.Dockerfile` with multi-line `RUN` continuation + ReDoS-safe regex + line-length cap; `.github/workflows/*.yml`, `.gitlab-ci.yml` (`yaml.safe_load`); `tox.ini` with interpolation cycle detection; `noxfile.py` AST-only `session.install(...)` extraction (never executes the file)
- **REQ-3b** — `source_analyser.py` extended with: `UNDECLARED` status for phantom imports via `importlib.metadata.packages_distributions()`; vendored-directory detection (`vendor/`, `_vendor/`, `third_party/`, `thirdparty/`, `site-packages/`) populates `Dependency.vendored_path`; Jupyter `.ipynb` code-cell AST extraction via `notebook_parser.py` (magics stripped before AST parse)
- **REQ-3c** — `src/scarno/findings/{rules.py,engine.py,config.py}`: 13-rule catalogue across 8 `FindingKind`s (runtime pip install, notebook magics, remote code exec, download-and-exec, os.system pip, unvalidated dynamic import, insecure unpickle, setup.py dynamic deps, vendored overlap/only, curl-pipe-shell, shell-injection). Intra-procedural taint pass: network source (`urlopen`, `requests.get`, `os.getenv`, `os.environ`, `sys.argv`, `input`) → execution sink (`exec`/`eval`/`os.system`/`subprocess`/`pickle.load`). Inline `# scarno: allow TS-XX-NNN` suppression + `[tool.scarno.findings].suppress` config (unknown IDs warn). Snippets sanitised (ANSI + control chars stripped) and truncated to 200 chars. Scope-aware AST walker prevents double-counting across nested functions
- **REQ-7 reporter / CLI extensions** — text reporter renders `SECURITY FINDINGS (N)` section with severity markers and remediation; JSON reporter already emits `findings` array; CLI exit code `3` for HIGH/CRITICAL findings; new `--fail-on-severity {LOW,MEDIUM,HIGH,CRITICAL}` flag; new `--show-suppressed` flag

**Phase 1.5 pre-reqs — ✅ already landed in Phase 0a:**

- `pyyaml` in runtime deps + `types-PyYAML` in dev deps
- `src/scarno/findings/__init__.py` + `findings/rules.py` — rule catalogue populated with the 13 REQ-3c rule IDs (`TS-SI-001..006`, `TS-CE-001..006`, `TS-DS-001`) as `Rule` dataclass instances; `apply_rules(...)` stub raises `NotImplementedError`
- `src/scarno/analysers/python/container_ci_parser.py` — `parse_container_and_ci_deps(project_path)` stub
- `src/scarno/analysers/python/notebook_parser.py` — `extract_code_cells(path)` stub
- `Finding`/`FindingSeverity`/`FindingKind`/`DependencyStatus.UNDECLARED` already in `models.py`

**Phase 1.5 opens with zero infrastructure prep** — first commit is `un-skip test_req2b_extended_formats.py` + make tests green.

**REQ-7 amendment (reporter contract) — implement alongside REQ-3b/3c as their tests require:**

- New output sections: `UNDECLARED (N)` between UNCERTAIN and IN USE; `SECURITY FINDINGS (N)` after UNDECLARED
- JSON: new `findings` array; `status: "UNDECLARED"` values accepted in `dependencies[]`
- CLI: exit code `3`; `--fail-on-severity {LOW,MEDIUM,HIGH,CRITICAL}` flag; `--show-suppressed` flag

Red → green per requirement, in this sub-order:

1. Un-skip `test_req2b_extended_formats.py` (9 tests) → implement **REQ-2b** → green
   - Conda `environment.yml` parser (YAML, `safe_load` only)
   - PEP 518 `[build-system].requires` table
   - PEP 735 `[dependency-groups]` with `include-group` cycle detection
   - `Dependency.source` provenance populated for every parser path
2. Un-skip `test_req2c_container_ci.py` (11 tests) → implement **REQ-2c** → green
   - `Dockerfile` / `Containerfile` `RUN pip install` extraction (anchored regex, line-length cap)
   - `.github/workflows/*.yml`, `.gitlab-ci.yml`, `tox.ini`, `noxfile.py` extraction
   - Multi-line `RUN` continuation handling; `curl … | sh` surfaced as a REQ-3c finding
3. Un-skip `test_req3b_phantom_imports.py` (7 tests) → implement **REQ-3b** → green
   - `DependencyStatus.UNDECLARED` wired through classification + reporter
   - `importlib.metadata.packages_distributions()` lookup for unresolved imports
   - Vendored-directory detection (`vendor/`, `_vendor/`, `third_party/`, in-repo `site-packages/`)
   - `.ipynb` cell AST extraction
4. Un-skip `test_req3c_findings.py` (20 tests) → implement **REQ-3c** → green
   - Rule table in `src/scarno/findings/rules.py` (13 rules across 8 kinds)
   - Intra-procedural taint pass (network source → exec/eval/system/subprocess sink)
   - Inline (`# scarno: allow TS-XX-NNN`) and config-based (`[tool.scarno.findings]`) suppression
   - New exit code `3` for HIGH/CRITICAL findings; `--fail-on-severity` + `--show-suppressed` flags
   - Extend the text and JSON reporters to render the `SECURITY FINDINGS` section and `findings` array
5. Un-skip relevant rows from `test_adversarial.py` (YAML bomb in workflow, Dockerfile ReDoS, noxfile dynamic install, curl-pipe-shell, `SEC-NEW-13..18`) → green

**Why before Java:** every one of these hits the Python MVP user's real projects — ignoring them means Scarno ships saying "requests is safe to remove" to someone whose Dockerfile reinstalls it at build time. Java users won't care about Python ghost-dep coverage either way.

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| `test_req2b_extended_formats.py` | 9 / 9 ✅ |
| `test_req2c_container_ci.py` | 11 / 11 ✅ |
| `test_req3b_phantom_imports.py` | 7 / 7 ✅ |
| `test_req3c_findings.py` | 20 / 20 ✅ |
| `mypy --strict` | 0 errors across 25 source files |
| `bandit -r src/ -ll` | 0 MEDIUM+ issues |
| SRTM gate | 99 / 99 covered |
| End-to-end Conda + Dockerfile + curl-pipe-shell + subprocess-pip-install + exec-of-network fixture | 3 unique findings emitted, exit code 3 |

Example end-to-end output on a project with `subprocess.run(["pip","install","foo"])`, `exec(requests.get(...).text)`, `curl ... \| sh` in Dockerfile, and a phantom `import pandas`:

```
SAFE TO REMOVE (4)
  - boto3, hatchling, pytest, flask
UNDECLARED (1)
  - pandas
    Reason: imported as 'pandas' but neither declared nor installed
IN USE (1)
  - requests==2.31.0 — Entry points: 1 / 48 used  ✓ requests.get
SECURITY FINDINGS (3)
 !! [HIGH] TS-SI-001  main.py:6   Runtime pip install via subprocess
 !! [CRITICAL] TS-CE-001  main.py:10   exec() applied to a network response
 !! [HIGH] TS-CE-005  Dockerfile:3   curl … | sh pattern
```

v0.2 territory — Scarno is now safe to recommend to teams whose projects live outside pure-`pyproject.toml` conventions.

---

## Phase 2 — Maven + JVM Analysis (REQ-4 + REQ-6) ✅ COMPLETE

**Delivered:**

- **REQ-4** — `src/scarno/analysers/java/maven.py`: single + multi-module POM parsing (`xml.etree.ElementTree`), parent chain traversal, `<dependencyManagement>` merging, `${project.version}` / `${project.groupId}` + user-defined property resolution, BOM imports recorded as warnings (no ~/.m2 / no network), `<modules>` discovery with cycle detection, parent-POM `<relativePath>` confined to project root's parent directory
- **DOCTYPE rejection** pre-parse — XXE + billion-laughs blocked without adding `defusedxml` dep (SEC-NEW-01, T-02, D-02)
- **REQ-6** — `src/scarno/analysers/java/source_analyser.py`: `.java` + `.kt` source scanning, direct-import prefix matching with `groupId` + alias table (`com.google.guava:guava → com.google.common`, Jackson, Joda, Commons, SLF4J, Reactor, MySQL connector, etc.), DI annotation detection (`@Autowired` / `@Bean` / `@Component` / `@Service` / `@Repository` / `@Controller` / `@RestController` / `@Configuration` / `@Qualifier` / `@Inject` / `@Resource`), `Class.forName` + `ClassLoader.loadClass` reflection → UNCERTAIN, `javap` subprocess (shell=False, 10s timeout, strict Java identifier validation, JAVA_HOME-confined resolution)
- `JavaAnalyser` wires REQ-4 → REQ-6 pipeline

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| `test_maven.py` | 6 / 6 ✅ |
| `test_jvm_source_analyser.py` | 12 / 12 ✅ |
| Adversarial XML + javap + resource-bound tests | 20 / 20 ✅ |
| `mypy --strict` | 0 errors across 27 source files |
| `bandit -ll` | 0 Medium+ findings (B314 suppressed with rationale — DOCTYPE rejection provides equivalent protection) |
| Coverage floor | 75.95% ≥ 75% |
| SRTM gate | 108 / 108 covered |

Example end-to-end output on a Maven project with Spring + Guava + Jackson:

```
SAFE TO REMOVE (1)
  - junit:junit==4.13.2 — no reference found in source files
UNCERTAIN (1)
  - com.fasterxml.jackson.core:jackson-databind==2.15.0 — referenced via Class.forName
IN USE (2)
  org.springframework:spring-core, com.google.guava:guava
```

v0.3 territory — Scarno now supports the three most common ways production teams manage Python *and* Java dependencies.

---

## Phase 2.5 — Polyglot Foundations (REQ-9) ✅ COMPLETE

Foundational refactor so Phase 5 (JS/TS/CSS) and Phase 6 (Go) and Phase 7 (C#) drop in cleanly. No new language analysers added; this phase was strictly infrastructure.

**Delivered:**

- `Dependency.ecosystem: str` field on the model (default `"unknown"`); all existing analysers emit `"pypi"` or `"maven"`; REQ-3b phantom imports that can't resolve to a distribution use `"detected"`
- `AnalysisResult.languages: list[str]` + `CANONICAL_ECOSYSTEMS` + `ECOSYSTEM_TO_LANGUAGE` in `models.py`
- `detect_project_types(path) -> list[str]` added; legacy `detect_project_type` retained as thin wrapper with the REQ-1-contract warning
- `src/scarno/core/registry.py` — self-registration pattern; `PythonAnalyser` and `JavaAnalyser` register at import time; hard-coded `_select_analyser` removed from `cli.py`
- CLI orchestrator runs **every** registered analyser for every detected language and merges results; detected-but-unregistered languages (Phase 5/6/7 placeholders) show in `languages` with a warning
- New `--language` / `-L` CLI flag (repeatable) accepting ecosystem names (`pypi`, `maven`, `gradle`, `npm`, `css`, `go`, `nuget`); validates; filters both analysers and merged deps
- Text + Markdown reporters group per-status blocks by ecosystem sub-heading when `len(languages) > 1`; single-language output byte-identical to pre-REQ-9
- JSON reporter emits top-level `languages` array; SARIF reporter emits `run.properties.languages`
- New test files: `test_registry.py` (8 tests), `test_polyglot_detector.py` (10 tests), `test_polyglot_reporter.py` (6 tests) — plus `--language` coverage in `test_cli.py`

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| `test_req9_polyglot_foundations.py` + `test_registry.py` + `test_polyglot_detector.py` + `test_polyglot_reporter.py` | 35 / 35 ✅ |
| Full suite | 286 pass / 11 fail (all Phase 3/4) / 5 skip / 43 xfailed |
| `mypy --strict` | 0 errors across 28 files |
| `bandit -ll` | 0 Medium+ findings |
| SRTM gate | 168 / 168 covered |
| Coverage | 77.36% ≥ 75% (bumped since new code added) |
| End-to-end polyglot demo (Python + Maven) | Correct ecosystem-grouped output; `--language pypi` and `--language maven` filter correctly |

Example polyglot output on a Python + Maven project:

```
SAFE TO REMOVE (2)
  [maven] (1)
    - junit:junit==4.13.2
  [pypi] (1)
    - boto3==1.26.0

IN USE (2)
  [maven] (1)
    com.google.guava:guava
  [pypi] (1)
    - requests==2.31.0
```

---

## Phase 3 — Gradle + Kotlin (REQ-5) ✅ COMPLETE

**Delivered:**

- `src/scarno/analysers/java/gradle.py` — full `GradleBuildResolver` with:
  - Groovy DSL (`build.gradle`) and Kotlin DSL (`build.gradle.kts`)
  - 15 configuration keywords (`implementation`, `api`, `compileOnly`, `compileOnlyApi`, `runtimeOnly`, `testImplementation`, `testRuntimeOnly`, `testCompileOnly`, `androidTestImplementation`, `debugImplementation`, `releaseImplementation`, `annotationProcessor`, `kapt`, `ksp`, `classpath`)
  - Literal coordinates (`implementation 'group:name:version'` / `implementation("group:name:version")`)
  - Interpolated versions (`"${versionVar}"`) resolved from `ext.foo = '...'` (Groovy) / `val foo = "..."` (Kotlin)
  - Version-catalog accessors (`libs.guava`) resolving `gradle/libs.versions.toml` `[versions]` + `[libraries]` tables with `version.ref`, shorthand `"group:name:version"`, and module-plus-version forms
  - Multi-module discovery via `settings.gradle(.kts)` `include(...)` / `include '...'` with path confinement
  - Comment stripping (`//` line + `/* */` block) before token-oriented regex pass
- ReDoS-safe parser: per-line length cap (64 KB), bounded-quantifier regexes, **`_EXT_ASSIGN_RE` does not accept bare identifiers** — the ReDoS-vulnerable alternative discovered in adversarial testing was removed (deliberately restricted to `ext.`/`val`/`var` qualified forms)
- `JavaAnalyser` dispatches Maven + Gradle when both are present, merges deps by `group:artifact`, then runs `JvmSourceAnalyser` uniformly — no changes needed in the source-side analyser (REQ-6 handles gradle-sourced deps via the existing alias table)

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| `test_gradle.py` | 9 / 9 ✅ |
| Gradle ReDoS adversarial (`TestGradleReDoS::test_gradle_redos_payload_completes_within_time`) | pass (< 0.05s after regex hardening, was 15.38s before fix) |
| `mypy --strict` | 0 errors across 28 files |
| `bandit -ll` | 0 Medium+ findings |
| SRTM gate | 186 / 186 covered |
| Coverage | 77.64% ≥ 75% |

**End-to-end demo** on a Gradle Kotlin-DSL multi-module project with `libs.versions.toml`:

```
SAFE TO REMOVE (2)
  - junit:junit==4.13.2
  - com.fasterxml.jackson.core:jackson-databind==2.15.0

IN USE (2)
  com.google.guava:guava, org.springframework:spring-core
```

Exit 1 (SAFE deps found). The multi-module `module-a/build.gradle.kts` was discovered via `settings.gradle.kts` `include(...)`; `libs.guava` / `libs.spring.core` accessors resolved via the root-level `gradle/libs.versions.toml`; `@Autowired` DI annotation promoted `spring-core` to IN_USE despite no direct class-import prefix match; alias table caught `com.google.common.* → com.google.guava:guava`.

---

## Phase 4 — Post-v1 hardening (REQ-6b + REQ-8) ✅ COMPLETE

**Delivered:**

- **REQ-6b** — `src/scarno/analysers/java/ast_extractor.py` using `tree-sitter` + `tree-sitter-java` + `tree-sitter-kotlin`. `extract_java(source)` and `extract_kotlin(source)` return `ExtractedFacts(imports, annotations, reflective_literals)` walked off the AST — comments, Javadoc, and string literals are genuine node types so they're skipped without regex ambiguity. `JvmSourceAnalyser._extract_facts` delegates to AST when `AST_AVAILABLE` is `True`; falls back to the Phase 2 regex extractors gracefully when grammars aren't available. `node.text` typed as `bytes | None` correctly handled.
- **REQ-8** — `action.yml` at repo root: composite action declaring 11 inputs + 8 outputs, installing Scarno via `pip install` (no `curl | sh` — dog-fooding TS-CE-005), running primary + Markdown + JSON reports, routing SARIF through `github/codeql-action/upload-sarif@v3`, posting a sticky PR Markdown comment with the `<!-- scarno-report -->` marker and edit-in-place `gh api` logic, emitting per-finding `::error` / `::warning` / `::notice` workflow commands, and writing the Markdown report to `$GITHUB_STEP_SUMMARY`. `.github/workflows/action-smoke.yml` self-tests the action against the `simple_python` fixture and verifies output shape + SARIF structure.

**Exit criteria — met:**

| Gate | Actual |
|------|--------|
| `test_req6b_tree_sitter.py` | 7 / 7 ✅ (was 6 pass / 1 fail before tree-sitter landed) |
| `test_req8_github_action.py` | 6 / 6 ✅ (was 0 pass / 2 fail + 4 skipped) |
| `test_jvm_source_analyser.py` + `test_maven.py` + `test_gradle.py` | all still green — no regressions from AST switchover |
| `mypy --strict` | 0 errors across 29 source files |
| `bandit -ll` | 0 Medium+ findings |
| SRTM gate | 186 / 186 covered |
| Coverage | 76.44% ≥ 75% |

**End-to-end demo** — Maven project with `@Autowired` ONLY inside a comment, Javadoc, and string literal:

```
// @Autowired — this is a comment, tree-sitter must NOT match
/**
 * @Autowired inside Javadoc also must NOT match.
 * Class.forName("fake.Impl") in Javadoc must NOT match either.
 */
public class MyService {
    private String doc = "@Autowired is only used in docs";
}
```

Result:

```
SAFE TO REMOVE (1)
  - org.springframework:spring-core==6.0.0
    Reason: no reference found in source files
```

Under the Phase 2 regex scanner, `spring-core` would have been IN_USE (false positive); under Phase 4's AST path, it's correctly SAFE TO REMOVE.

**Unscoped (add requirements when prioritised):**

- Auto-removal / code rewriting (once SAFE classifications have earned trust)
- IDE plugin (VS Code / IntelliJ)
- CVE enrichment on detected deps (integrate with OSV / GHSA)
- Groovy DSL Gradle coverage beyond the Kotlin-DSL v1 scope
- Performance tuning on very large monorepos; incremental / cached analysis
- SBOM export (CycloneDX / SPDX)
- GitLab CI component equivalent to REQ-8
- Typosquat / name-similarity database for UNDECLARED deps
- Inter-procedural taint analysis (extends REQ-3c's intra-procedural pass)

---

## Phase 5 — JavaScript / TypeScript / CSS (REQ-10 + REQ-11 + REQ-12) ✅ COMPLETE

Status: Complete (2026-04-16). Phase-5 gate: 393 passed / 0 failed, 76.38 % coverage, SRTM 186 / 186, mypy clean, bandit clean (0 High/Medium).

Depends on Phase 2.5 (REQ-9) being complete — every JS/TS/CSS dep is emitted with `ecosystem="npm"` via the polyglot registry.

1. `test_javascript_dep_file_parser.py` red → implement **REQ-10** → green
   - `package.json` (deps + devDeps + peerDeps + optionalDeps)
   - Lock files: `package-lock.json`, `npm-shrinkwrap.json`, yarn v1, yarn Berry, `pnpm-lock.yaml`, `bun.lock` (not `bun.lockb` — text only)
   - Deno: `deno.json(c)` imports map, `deno.lock`
   - Lock-file-wins precedence + version-conflict warnings
   - `postinstall` script detected and surfaced as Finding (TS-SI-007 MEDIUM → HIGH)
2. `test_javascript_source_analyser.py` red → implement **REQ-11** → green
   - Tree-sitter-javascript + tree-sitter-typescript grammars
   - ESM static + dynamic imports, CJS `require`, TS reference directives, `import type`
   - `tsconfig.json` `paths` resolution — mapped specifiers don't fire phantom detection
   - Entry-point enumeration from `node_modules/<pkg>/exports`
   - Rule catalogue extensions: TS-SI-007..011 (postinstall, custom registry, child_process.exec, new Function, fetch→eval)
3. `test_css_analyser.py` red → implement **REQ-12** → green
   - `@import` / `@use` / `url()` extraction across `.css` / `.scss` / `.sass` / `.less`
   - Webpack `~` prefix handled
   - Remote `@import url(https://...)` → Finding TS-CE-007
   - `file://` URL → Finding TS-CE-008
4. Phase-5 adversarial tests: YAML bomb in `pnpm-lock.yaml`, deep JSON in `package-lock.json`, `.npmrc` registry override, `postinstall` exfil pattern.

**Exit criteria:** a React or Vue project produces a trustworthy SAFE/UNDECLARED/IN_USE report with JS frameworks correctly IN_USE; postinstall hooks surface as Findings; CSS-only imports resolve to the right npm package.

---

## Phase 5 covers Node.js too

Phases 5 touches REQ-10 + REQ-11 + REQ-12. The npm ecosystem is Node.js's package manager — REQ-10 parses every `package.json` (whether frontend React, Next.js full-stack, Express backend, NestJS monorepo, CLI tool, or Electron app), and REQ-11 recognises CommonJS + ESM + Node core modules + `node:`-prefixed imports + yarn PnP + npm workspaces. There is no separate "Node.js phase".

---

## Phase 6 — Go (REQ-13 + REQ-14) ✅ COMPLETE

Status: Complete (2026-04-17). Phase-6 gate: 486 passed / 0 failed, 77.51 % coverage, SRTM 186 / 186, mypy clean, all Go adversarial + fixture tests green.

Depends on Phase 2.5 (REQ-9). Self-contained ecosystem with its own build system.

1. `test_go_mod_parser.py` red → implement **REQ-13** → green
   - `go.mod`: `require`, `replace`, `exclude`, `retract`, `// indirect` marker
   - `go.sum` for version resolution
   - `vendor/modules.txt` cross-check
   - `replace` to remote URL → Finding TS-DS-002
2. `test_go_source_analyser.py` red → implement **REQ-14** → green
   - Tree-sitter-go AST walk
   - Blank imports (`_`) and dot imports (`.`) always IN_USE
   - `_test.go` files → separate test-scope import set; reporter shows `[test]` subsection
   - `vendor/` directory scan skipped; module list from `vendor/modules.txt`
   - Build tags treated as active (conservative `go mod tidy` behaviour)
   - Rule catalogue: TS-SI-012 (unsafe.Pointer), TS-SI-013 (cgo), TS-CE-009 (exec.Command + taint)
3. Phase-6 adversarial tests: `go.mod` with replace → local path escape, `//go:build` with millions of combinations, extremely long module paths.

**Exit criteria:** a Gin / Echo / stdlib Go project produces a trustworthy report; blank drivers (`_ "github.com/lib/pq"`) never mis-classified as SAFE; test-only deps segregated in the report.

---

## Phase 7 — C# / F# / VB.NET (REQ-15 + REQ-16) ✅ COMPLETE

Status: Complete (2026-04-17). Phase-7 gate: 538 passed / 0 failed, 77.80 % coverage, SRTM 186 / 186, mypy clean, all C# adversarial + fixture tests green.

Depends on Phase 2.5 (REQ-9). The NuGet ecosystem has its own dep-file shape (MSBuild XML) and syntax quirks (`global using`, CPM, Razor directives), so it gets its own phase.

1. `test_csharp_manifest_parser.py` red → implement **REQ-15** → green
   - `*.csproj` / `*.fsproj` / `*.vbproj` `<PackageReference>` parsing (stdlib `xml.etree` + DOCTYPE rejection)
   - Central Package Management via `Directory.Packages.props` + `Directory.Build.props`
   - Legacy `packages.config`
   - `*.sln` multi-project discovery
   - `packages.lock.json` resolves versions from ranges
   - `nuget.config` custom-registry Finding (TS-SI-015)
   - MSBuild `<Exec>` / `<UsingTask>` Findings (TS-SI-016, TS-SI-017)
2. `test_csharp_source_analyser.py` red → implement **REQ-16** → green
   - tree-sitter-c-sharp AST walk
   - `using` (regular / static / alias / global) + Razor `@using` preprocessing
   - Namespace → NuGet alias table (shared-framework expansion: `Microsoft.AspNetCore.App`, `Microsoft.NETCore.App`)
   - Reflection: `Type.GetType` / `Assembly.Load*` → UNCERTAIN or Finding
   - ASP.NET / MEF attribute DI detection
   - Test-only dep segregation (xUnit / MSTest / NUnit → `[test]` sub-section)
   - `[DllImport]` → Finding TS-SI-018
3. Phase-7 adversarial tests: XXE in `*.csproj`, circular project refs in `*.sln`, `Directory.Build.props` escape, deep inheritance chain.

**Exit criteria:** an ASP.NET Core + EF Core project produces a trustworthy report; MVC controllers discovered via `[ApiController]` without a matching explicit `using`; legacy `packages.config` projects parse correctly; reflection-heavy code (DI containers, plugin loaders) classified UNCERTAIN rather than SAFE.

---

## Dependency graph at a glance

- REQ-1 → everything
- REQ-2 → REQ-3 → REQ-2b, REQ-2c, REQ-3b, REQ-3c
- REQ-4, REQ-5 → REQ-6 → REQ-6b (AST refactor, Phase 4)
- REQ-3, REQ-6 → REQ-7 (ships with Phase 1 once REQ-3 is done; Phase 1.5 / 2 / 3 reuse it)
- REQ-3b, REQ-3c → REQ-7 extensions (UNDECLARED section, SECURITY FINDINGS section, exit code 3)
- REQ-7 (SARIF + Markdown) → REQ-8 (GitHub Action wraps the CLI; Phase 4)
- **REQ-9 (Phase 2.5) → REQ-10/11/12 (Phase 5 JS/TS/CSS) and REQ-13/14 (Phase 6 Go)** — polyglot foundation unblocks both

**Critical path to v0.1:** Phase 0a → Phase 0b → Phase 1 (Python-only release). This is the earliest point at which the tool solves a real problem end-to-end and is worth dogfooding.

**Critical path to trustworthy v0.2:** + Phase 1.5. Closes the ghost-dep false-positive class (Docker, Conda, Jupyter, vendored code) and adds the `Finding` surface for suspicious install & code-execution patterns. This is the earliest point at which the Python story is safe to recommend to teams whose projects live outside pure-`pyproject.toml` conventions.

---

## Per-requirement workflow (inside any phase)

For each requirement inside a phase:

1. Un-skip (or add) the SRTM-tagged tests → watch them fail
2. Implement the minimum code to turn them green
3. Refactor for clarity / reuse
4. Confirm the SRTM-coverage report shows the row as covered before moving on

**Why this ordering matters:**

- Every implementation PR has an obvious pass/fail gate — the test(s) tagged to its SRTM row(s)
- The SRTM-coverage CI job makes "forgot to cover requirement X" a build break rather than a review-time catch
- Security tests land *with* the code they constrain, not after — XXE protection is driven by the XXE fixture test, not bolted on later
- `test_cli_smoke.py` stays green from Phase 0b onward, giving a continuous end-to-end signal