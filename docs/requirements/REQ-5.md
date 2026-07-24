# Gradle Build File Parser

## Overview
Implement `GradleBuildResolver` in `src/depruner/analysers/java/gradle.py` — a `BaseAnalyser` subclass that extracts declared dependencies from Gradle projects. Mirrors the structure and conventions of `MavenPomResolver` (REQ-4): filesystem-only, regex/string parsing, no Groovy or Kotlin interpreter, returns a flat `list[Dependency]` with `status=UNCERTAIN` and `entry_points=[]`.

## Problem Statement
Gradle projects declare dependencies across multiple files and DSLs (Groovy and Kotlin), with versions scattered across `ext` blocks, `buildscript` blocks, and version catalogs. Without parsing these sources together, dependency extraction is incomplete or produces incorrect versions.

## Solution
Parse `build.gradle` and `build.gradle.kts` files using regex, resolve version references from `ext`/`buildscript` blocks and `libs.versions.toml`, and discover submodule build files via `settings.gradle`/`settings.gradle.kts`. All extracted dependencies are returned as `UNCERTAIN` with empty `entry_points`; usage classification is deferred to REQ-6.

## Functional Requirements

### Class Contract
- Class `GradleBuildResolver` subclasses `BaseAnalyser` in `src/depruner/analysers/java/gradle.py`
- `supports(project_path: str) -> bool` returns `True` when the directory contains `build.gradle` or `build.gradle.kts`
- `analyse(project_path: str) -> AnalysisResult` returns an `AnalysisResult` with `project_type="java"`, a flat deduplicated `list[Dependency]`, and any parse warnings in `errors`
- Never raises unhandled exceptions — catch all parse errors, append a message to `errors`, and continue

### Build File Discovery
- Root build file: `build.gradle` (Groovy DSL) or `build.gradle.kts` (Kotlin DSL) at `project_path`
- Multi-module discovery: parse `settings.gradle` or `settings.gradle.kts` to extract `include(...)` / `include "..."` directives; for each included module, resolve its subdirectory and parse its own `build.gradle` / `build.gradle.kts` if present
- All submodule build files are parsed with the same logic as the root; results are merged into a single flat list

### Dependency Declaration Parsing
Parse `dependencies { ... }` blocks in both DSLs. Recognise these configuration keywords as dependency declarations (treat all as equivalent for extraction purposes):

| Configuration                  | Example (Groovy)                                                      | Example (Kotlin DSL)                                                   |
| ------------------------------ | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `implementation`               | `implementation 'com.google.guava:guava:32.1.2-jre'`                  | `implementation("com.google.guava:guava:32.1.2-jre")`                  |
| `api`                          | `api 'org.springframework:spring-core:6.0.0'`                         | `api("org.springframework:spring-core:6.0.0")`                         |
| `compileOnly`                  | `compileOnly 'org.projectlombok:lombok:1.18.28'`                      | `compileOnly("org.projectlombok:lombok:1.18.28")`                      |
| `runtimeOnly`                  | `runtimeOnly 'com.h2database:h2:2.1.214'`                             | `runtimeOnly("com.h2database:h2:2.1.214")`                             |
| `testImplementation`           | `testImplementation 'junit:junit:4.13.2'`                             | `testImplementation("junit:junit:4.13.2")`                             |
| `testRuntimeOnly`              | `testRuntimeOnly 'org.junit.platform:junit-platform-launcher'`        | `testRuntimeOnly("org.junit.platform:junit-platform-launcher")`        |
| `annotationProcessor`          | `annotationProcessor 'org.mapstruct:mapstruct-processor:1.5.5.Final'` | `annotationProcessor("org.mapstruct:mapstruct-processor:1.5.5.Final")` |
| `classpath` (in `buildscript`) | `classpath 'com.android.tools.build:gradle:8.1.0'`                    | `classpath("com.android.tools.build:gradle:8.1.0")`                    |

Dependency coordinates follow Maven GAV format: `group:artifact:version`. `version` is optional (may be managed externally).

### Version Resolution

Resolve version references in this priority order:

1. **Inline literal** — `"com.example:foo:1.2.3"` → version is `1.2.3`
2. **`ext` / `buildscript.ext` variable** — `ext.guavaVersion = '32.1.2-jre'` followed by `implementation "com.google.guava:guava:${guavaVersion}"` → resolve variable from the `ext` map collected during parsing
3. **`libs.versions.toml` version catalog** — `implementation(libs.guava)` or `implementation libs.guava` → look up the alias in `gradle/libs.versions.toml`; extract `version` from the `[versions]` table and `group`/`name` from the `[libraries]` table
4. **Unresolvable** — if the version cannot be determined after the above steps, set `version=None` and append a warning to `errors`: `"Could not resolve version for <group>:<artifact> in <file>"`

### Version Catalog Parsing (`gradle/libs.versions.toml`)
- File location: `<project_path>/gradle/libs.versions.toml`
- Parse `[versions]`, `[libraries]`, and `[plugins]` TOML tables using regex/string parsing (no external TOML library)
- `[libraries]` entries map an alias to `{ module = "group:artifact", version.ref = "versionAlias" }` or `{ group = "...", name = "...", version.ref = "..." }`
- `[versions]` entries map a version alias to a version string
- Aliases use kebab-case (e.g., `google-guava`); Gradle accesses them as `libs.google.guava` (dots replace hyphens)

### Deduplication
- A dependency is identified by `(group, artifact)` — the `name` field in `Dependency` stores `group:artifact`
- When the same `(group, artifact)` appears in multiple submodules or configurations, keep one entry; if versions differ, keep the first encountered and append a warning to `errors`: `"Duplicate dependency <group>:<artifact> with conflicting versions: <v1>, <v2>"`

### Output Contract
Every extracted dependency is returned as:
- `status = DependencyStatus.UNCERTAIN`
- `reason = "Gradle dependency — usage analysis pending"`
- `entry_points = []`
- `entry_points_used = 0`
- `entry_points_total = 0`

## Data Model

**GradleBuildResolver** (new class)
- `project_path: str` — resolved absolute path to project root
- Internal state (not exposed): `_ext_vars: dict[str, str]`, `_catalog: dict[str, tuple[str, str | None]]` (alias → (module, version))

**Parsed intermediate** (internal, not a public model):
- `_RawDep` — `(group: str, artifact: str, version: str | None, source_file: str)`

## Technical Requirements

- **Parser**: regex and string operations only — no `groovy`, `kotlin`, or TOML parser libraries
- **No subprocess**: never execute `gradle`, `gradlew`, or any shell command
- **No network**: all resolution is filesystem-only
- **Path safety**: resolve all file paths with `pathlib.Path.resolve()`; skip any path that escapes `project_path` and log a warning
- **Encoding**: read all files as UTF-8; on `UnicodeDecodeError`, skip the file and append to `errors`
- **Type safety**: fully typed; `mypy --strict` must pass with no errors
- **Registration**: add `GradleBuildResolver` to the analyser registry in `src/depruner/core/detector.py` alongside `MavenPomResolver`

## Test Fixtures

Create fixture projects under `tests/fixtures/`:

| Fixture                   | Contents                                                                                  | Expected output                                   |
| ------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `simple_gradle_groovy/`   | `build.gradle` with 3 inline-versioned `implementation` deps                              | 3 `UNCERTAIN` dependencies, correct versions      |
| `simple_gradle_kotlin/`   | `build.gradle.kts` with 2 inline-versioned deps                                           | 2 `UNCERTAIN` dependencies                        |
| `gradle_ext_vars/`        | `build.gradle` with `ext.fooVersion` and `${fooVersion}` interpolation                    | Version resolved from `ext` block                 |
| `gradle_version_catalog/` | `build.gradle.kts` + `gradle/libs.versions.toml` with 2 catalog aliases                   | Versions resolved from catalog                    |
| `gradle_multimodule/`     | `settings.gradle` including `:core` and `:web`; each submodule has its own `build.gradle` | Flat merged list from both modules, no duplicates |

## Out of Scope
- Groovy DSL `settings.gradle` dynamic module discovery (only `include "..."` / `include(...)` string literals are parsed — programmatic includes are ignored with a warning)
- `buildSrc/` and composite builds
- Plugin version resolution from `plugins { }` blocks (plugins are not reported as dependencies)
- Entry point enumeration — deferred to REQ-6
- Dependency version conflict resolution beyond first-seen deduplication

## Acceptance Criteria
- [] Given a directory with `build.gradle`, When `GradleBuildResolver.supports()` is called, Then it returns `True`
- [] Given a directory with `build.gradle.kts` and no `build.gradle`, When `GradleBuildResolver.supports()` is called, Then it returns `True`
- [] Given a directory with neither Gradle file, When `GradleBuildResolver.supports()` is called, Then it returns `False`
- [] Given `simple_gradle_groovy` fixture, When `analyse()` is called, Then the result contains exactly 3 `UNCERTAIN` dependencies with correct `group:artifact` names and inline versions
- [] Given `simple_gradle_kotlin` fixture, When `analyse()` is called, Then the result contains exactly 2 `UNCERTAIN` dependencies with correct versions
- [] Given `gradle_ext_vars` fixture, When `analyse()` is called, Then the dependency version is resolved from the `ext` block, not left as `None`
- [] Given `gradle_version_catalog` fixture, When `analyse()` is called, Then catalog alias references are resolved to their `group:artifact:version` coordinates
- [] Given `gradle_multimodule` fixture, When `analyse()` is called, Then dependencies from both `:core` and `:web` submodules appear in a single flat list with no duplicates
- [] Given the same `group:artifact` appears in two submodules with different versions, When `analyse()` is called, Then one entry is returned and `errors` contains a conflicting-versions warning
- [] Given a version reference that cannot be resolved, When `analyse()` is called, Then `version=None` is set for that dependency and `errors` contains a resolution warning
- [] Given any Gradle project, When `analyse()` is called, Then every returned `Dependency` has `status=UNCERTAIN`, `entry_points=[]`, `entry_points_used=0`, and `entry_points_total=0`
- [] Given a `build.gradle` that raises a parse error mid-file, When `analyse()` is called, Then the error is caught, appended to `AnalysisResult.errors`, and the method returns without raising
- [] Given a path in `settings.gradle` that would escape `project_path` via traversal, When `analyse()` is called, Then the path is skipped and a warning is appended to `errors`
- [] Given `GradleBuildResolver` is registered in `detector.py`, When the detector scans a directory containing `build.gradle`, Then it selects the Java analyser (which includes `GradleBuildResolver`)
- [] Given `mypy --strict src/depruner` is run after implementing this class, Then it exits with code `0` and reports no type errors in `gradle.py`
- [] Given `pytest tests/` is run, Then all new Gradle fixture tests pass