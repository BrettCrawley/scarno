# JVM Source & Bytecode Analyser

## Overview
Implement `JvmSourceAnalyser` in `src/depruner/analysers/java/source_analyser.py` — a `BaseAnalyser` subclass that classifies each `UNCERTAIN` dependency from REQ-4/REQ-5 as `IN_USE`, `UNCERTAIN`, or `SAFE` by scanning `.java`/`.kt` source files and compiled `.class` bytecode, and by enumerating public entry points from dependency JARs via `javap`.

## Problem Statement
`MavenPomResolver` and `GradleBuildResolver` return every dependency as `UNCERTAIN` with empty `entry_points`. Without source and bytecode analysis, Depruner cannot distinguish genuinely unused dependencies from those consumed via DI annotations, reflection, or Kotlin-specific patterns — the exact false-positive surface that makes existing tools untrustworthy.

## Solution
Enumerate public entry points from each dependency's JAR using `javap -public -classpath`. Cross-reference those entry points against `.java`/`.kt` source text and `.class` bytecode constant pools. Apply DI annotation detection and reflection heuristics to produce a confidence-scored classification for every dependency.

## Functional Requirements

### Class Contract
- Class `JvmSourceAnalyser` subclasses `BaseAnalyser` in `src/depruner/analysers/java/source_analyser.py`
- `supports(project_path: str) -> bool` returns `True` when the directory contains at least one `.java` or `.kt` file (recursive search)
- `analyse(project_path: str, dependencies: list[Dependency]) -> AnalysisResult` accepts the flat dependency list from REQ-4/REQ-5, classifies each, and returns an updated `AnalysisResult`
- Never raises unhandled exceptions — catch all errors, append to `errors`, and continue

### Source File Discovery
- Recursively collect all `.java` and `.kt` files under `project_path`
- Skip paths that escape `project_path` (symlink traversal); append a warning to `errors` and continue
- Read all files as UTF-8; on `UnicodeDecodeError`, skip the file and append to `errors`

### JAR Entry Point Enumeration
- For each dependency, locate its JAR on the local filesystem using this priority order:
  1. Maven local repository at `~/.m2/repository/<group>/<artifact>/<version>/<artifact>-<version>.jar` (group path uses `/` not `.`)
  2. Gradle cache at `~/.gradle/caches/modules-2/files-2.1/<group>/<artifact>/<version>/**/<artifact>-<version>.jar` (glob search)
  3. Any `.jar` file under `project_path` whose filename matches `<artifact>-<version>.jar` or `<artifact>.jar`
- If no JAR is found, set `entry_points=[]`, classify as `UNCERTAIN`, append a warning, and continue
- Enumerate public entry points by invoking `javap -public -classpath <jar> <classname>` for each class in the JAR
  - List classes in the JAR by reading its manifest via `zipfile` (standard library) — iterate `*.class` entries, convert path separators to `.`, strip `.class` suffix
  - Run `javap` as a subprocess with a 10-second timeout per class; on timeout or non-zero exit, skip that class and append a warning
  - Parse `javap` output to extract: public method signatures (`public <returnType> <methodName>(<params>)`), public field declarations, and public class/interface names
  - Store each as a string entry in `entry_points` on the `Dependency`

### Usage Detection — Direct References
Scan each `.java`/`.kt` source file for string matches against the entry point set:
- **Import statements**: `import com.example.Foo` — match the fully-qualified class name against entry points
- **Simple name references**: if `com.example.Foo` is in entry points and `Foo` appears as a word token in source, count as a match
- **Bytecode constant pool**: for each `.class` file under `project_path/target` or `project_path/build`, read the constant pool using `javap -verbose` and match UTF-8 constant strings against entry point class names

A dependency is classified `IN_USE` when at least one entry point is matched via any of the above methods, **unless** all matches are exclusively via reflection heuristics (see below).

### Usage Detection — DI Annotations
The following annotations indicate framework-wired usage. A dependency whose entry points include any of these annotation types, and whose annotation is referenced in source, is classified `IN_USE` with `reason` noting the DI mechanism:

| Annotation                                                                | Framework        |
| ------------------------------------------------------------------------- | ---------------- |
| `@Autowired`                                                              | Spring           |
| `@Bean`                                                                   | Spring           |
| `@Component`, `@Service`, `@Repository`, `@Controller`, `@RestController` | Spring           |
| `@Configuration`                                                          | Spring           |
| `@Inject`                                                                 | JSR-330 / Guice  |
| `@Resource`                                                               | JSR-250          |
| `@Qualifier`                                                              | Spring / JSR-330 |

Detection rule: if any source file contains the annotation string (e.g., `@Autowired`) **and** the dependency's entry points include at least one class whose fully-qualified name starts with the annotation type's origin package prefix (e.g., `org.springframework` for Spring annotations, `javax.inject` for JSR-330, `javax.annotation` for JSR-250), classify as `IN_USE`. This means: the dependency being classified must own the annotation type itself — e.g., `spring-context` is classified `IN_USE` when `@Autowired` is found in source because `@Autowired` lives in `org.springframework.beans.factory.annotation`, and `spring-context` exposes classes in `org.springframework.*`.

### Usage Detection — Reflection Heuristics
The following patterns indicate reflective usage. Matches classify the dependency as `UNCERTAIN` (not `SAFE`), never `IN_USE`:

| Pattern                                         | Match rule                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------ |
| `Class.forName(`                                | Any occurrence in source text                                      |
| `ClassLoader.loadClass(`                        | Any occurrence in source text                                      |
| `Class.forName` constant in bytecode            | UTF-8 constant pool entry matching `"Class.forName"`               |
| String literal matching a dependency class name | Quoted string in source that equals a known entry point class name |

If a dependency has both direct references (→ `IN_USE`) and reflection patterns, the direct reference wins: classify `IN_USE` and note the reflection pattern in `reason`.

### Classification Rules

| Condition                                                    | Status      | reason                                               |
| ------------------------------------------------------------ | ----------- | ---------------------------------------------------- |
| ≥1 entry point matched via direct reference or DI annotation | `IN_USE`    | `"Used via: <comma-separated match types>"`          |
| Only reflection patterns matched                             | `UNCERTAIN` | `"Possible reflective usage: <pattern>"`             |
| JAR not found                                                | `UNCERTAIN` | `"JAR not found — could not enumerate entry points"` |
| No matches found, entry points enumerated                    | `SAFE`      | `"No usages detected in source or bytecode"`         |
| No matches found, entry points empty (JAR missing)           | `UNCERTAIN` | (same as JAR not found)                              |

`entry_points` on the returned `Dependency`:
- `IN_USE`: **all** enumerated entry points from the JAR (not just matched ones); `entry_points_used` = count of entry points where `used=True`; `entry_points_total` = `len(entry_points)`. Each `EntryPoint` has `used=True` if it was matched in source/bytecode, `used=False` otherwise.
- `UNCERTAIN`: `entry_points=[]`, `entry_points_used=0`, `entry_points_total=0`
- `SAFE`: `entry_points=[]`, `entry_points_used=0`, `entry_points_total=0`

### Kotlin Support
- `.kt` files are scanned with the same regex/string patterns as `.java` files
- Kotlin import syntax (`import com.example.Foo`) is identical to Java — no special handling required
- Kotlin extension function calls (e.g., `foo.bar()` where `bar` is an extension on a dependency type) are treated as simple name references — no Kotlin compiler integration required
- Compiled Kotlin `.class` files under `build/` are processed identically to Java `.class` files via `javap`

### Output Contract
- Returns `AnalysisResult` with `project_type="java"`, updated `dependencies` list, and accumulated `errors`
- Every `Dependency` in the returned list has a non-`UNCERTAIN` status where classification was possible
- `entry_points` is populated only for `IN_USE` dependencies; always `[]` for `SAFE` and `UNCERTAIN`

## Data Model

**JvmSourceAnalyser** (new class)
- `project_path: str` — resolved absolute path to project root
- Internal state (not exposed): `_source_files: list[Path]`, `_class_files: list[Path]`, `_entry_point_index: dict[str, list[str]]` (dependency name → entry points)

**Updated Dependency fields after analysis:**
- `status`: `IN_USE`, `UNCERTAIN`, or `SAFE`
- `reason`: classification rationale string
- `entry_points`: all enumerated `EntryPoint` objects from the JAR (`IN_USE` only; `[]` for `SAFE`/`UNCERTAIN`); each has `used=True` if matched in source/bytecode, `used=False` otherwise
- `entry_points_used`: `len([e for e in entry_points if e.used])` — count of matched entry points
- `entry_points_total`: `len(entry_points)` — total enumerated entry points from JAR

## Technical Requirements
- **JAR inspection**: `zipfile` (stdlib) for class listing; `javap` subprocess for entry point enumeration and bytecode constant pool extraction
- **Source scanning**: regex and string operations only — no Java/Kotlin parser libraries
- **No network**: all resolution is filesystem-only
- **`javap` availability**: if `javap` is not on `PATH`, append a single warning to `errors` (`"javap not found on PATH — bytecode analysis skipped"`) and skip all JAR enumeration and bytecode scanning; source-only analysis still runs
- **Subprocess safety**: all `javap` calls use `subprocess.run` with `timeout=10`, `capture_output=True`, `text=True`; never use `shell=True`
- **Path safety**: resolve all paths with `pathlib.Path.resolve()`; skip any path escaping `project_path`
- **Encoding**: UTF-8 for all source files; `UnicodeDecodeError` → skip + append to `errors`
- **Type safety**: fully typed; `mypy --strict` must pass with no errors in `source_analyser.py`
- **Registration**: `JvmSourceAnalyser` is invoked by the Java analyser pipeline after `MavenPomResolver` or `GradleBuildResolver` produces the initial dependency list; wire into `src/depruner/core/detector.py`

## Test Fixtures

Create fixture projects under `tests/fixtures/java_source/`:

| Fixture                  | Contents                                                                 | Expected output                                                                  |
| ------------------------ | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| `direct_import/`         | `.java` file importing a class from a mock dependency JAR                | Dependency classified `IN_USE`, matched entry point listed                       |
| `di_autowired/`          | `.java` file with `@Autowired` referencing a Spring dependency class     | Dependency classified `IN_USE`, reason includes `"DI annotation: @Autowired"`    |
| `di_inject/`             | `.java` file with `@Inject` from `javax.inject`                          | Dependency classified `IN_USE`, reason includes `"DI annotation: @Inject"`       |
| `reflection_only/`       | `.java` file with `Class.forName("com.example.Foo")` only                | Dependency classified `UNCERTAIN`, reason includes `"Possible reflective usage"` |
| `reflection_and_direct/` | `.java` file with both `import com.example.Foo` and `Class.forName(...)` | Dependency classified `IN_USE`, reason notes reflection pattern                  |
| `no_usage/`              | `.java` file with no references to dependency classes                    | Dependency classified `SAFE`                                                     |
| `kotlin_import/`         | `.kt` file importing a dependency class                                  | Dependency classified `IN_USE`                                                   |
| `jar_not_found/`         | Dependency with no JAR on filesystem                                     | Dependency classified `UNCERTAIN`, error appended                                |
| `javap_unavailable/`     | Simulated missing `javap` (mock)                                         | Single warning appended, source-only analysis runs                               |
| `multimodule_mixed/`     | Mixed `.java` and `.kt` files across subdirectories                      | All files scanned, correct classifications across both languages                 |

Mock JARs for fixtures: create minimal valid ZIP files containing stub `.class` entries (empty files) so `zipfile` can list them; `javap` calls on these will fail gracefully and be skipped with warnings.

## Out of Scope
- Groovy source files (`.groovy`)
- Kotlin compiler integration or KSP/KAPT annotation processing
- Spring XML configuration files (`applicationContext.xml`) — annotation-based DI only
- `@Value`, `@ConditionalOnClass`, and other Spring meta-annotations beyond the listed set
- Transitive dependency analysis — only direct dependencies from REQ-4/REQ-5 are classified
- Entry point surface area report rendering — deferred to REQ-7
- Dependency scope filtering (`test`, `provided`) — all scopes analysed uniformly at this stage

## Acceptance Criteria
- [] Given a directory containing at least one `.java` file, When `JvmSourceAnalyser.supports()` is called, Then it returns `True`
- [] Given a directory containing only `.kt` files and no `.java` files, When `JvmSourceAnalyser.supports()` is called, Then it returns `True`
- [] Given a directory with no `.java` or `.kt` files, When `JvmSourceAnalyser.supports()` is called, Then it returns `False`
- [] Given the `direct_import` fixture, When `analyse()` is called, Then the dependency is classified `IN_USE` and its matched entry point appears in `entry_points`
- [] Given the `di_autowired` fixture, When `analyse()` is called, Then the dependency is classified `IN_USE` and `reason` contains `"DI annotation: @Autowired"`
- [] Given the `di_inject` fixture, When `analyse()` is called, Then the dependency is classified `IN_USE` and `reason` contains `"DI annotation: @Inject"`
- [] Given the `reflection_only` fixture, When `analyse()` is called, Then the dependency is classified `UNCERTAIN` and `reason` contains `"Possible reflective usage"`
- [] Given the `reflection_and_direct` fixture, When `analyse()` is called, Then the dependency is classified `IN_USE` and `reason` notes the reflection pattern
- [] Given the `no_usage` fixture with a JAR whose entry points were successfully enumerated, When `analyse()` is called, Then the dependency is classified `SAFE`
- [] Given the `kotlin_import` fixture, When `analyse()` is called, Then the `.kt` file is scanned and the dependency is classified `IN_USE`
- [] Given the `jar_not_found` fixture, When `analyse()` is called, Then the dependency is classified `UNCERTAIN`, `entry_points=[]`, and `errors` contains a JAR-not-found warning
- [] Given `javap` is not on `PATH`, When `analyse()` is called, Then exactly one warning `"javap not found on PATH — bytecode analysis skipped"` is appended to `errors` and source-only analysis still completes
- [] Given any dependency classified `SAFE` or `UNCERTAIN`, When its fields are inspected, Then `entry_points == []`, `entry_points_used == 0`, `entry_points_total == 0`
- [] Given any dependency classified `IN_USE`, When its fields are inspected, Then `entry_points_total > 0` and `entry_points_used <= entry_points_total`
- [] Given a source file that would raise `UnicodeDecodeError`, When `analyse()` is called, Then the file is skipped, an error is appended, and analysis continues for remaining files
- [] Given a path in the project that escapes `project_path` via symlink, When `analyse()` is called, Then the path is skipped and a warning is appended to `errors`
- [] Given a `javap` subprocess call that exceeds 10 seconds, When `analyse()` is called, Then that class is skipped with a warning and analysis continues
- [] Given `analyse()` encounters any unhandled internal exception, Then it is caught, appended to `errors`, and `analyse()` returns an `AnalysisResult` without raising
- [] Given `mypy --strict src/depruner` is run after implementing this class, Then it exits with code `0` and reports no type errors in `source_analyser.py`
- [] Given `pytest tests/` is run, Then all new JVM source analyser fixture tests pass