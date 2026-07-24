# Maven POM Hierarchy Resolver

## Overview
Implement a Maven POM parser and hierarchy resolver that traverses parent/child POM relationships, expands `<dependencyManagement>` sections (including BOM imports), and produces a flat `list[Dependency]` for every declared dependency across a single-module or multi-module Maven project.

## Problem Statement
Maven projects routinely declare dependencies without explicit versions, inheriting them from parent POMs or imported BOMs. A flat `pom.xml` parse misses these inherited declarations entirely, producing an incomplete or incorrect dependency list.

## Solution
Implement `MavenPomResolver` in `src/depruner/analysers/java/maven.py`. It resolves the full POM hierarchy — parent chain, `<dependencyManagement>`, and BOM imports — using only the local filesystem and Python's standard library `xml.etree.ElementTree`. All resolved dependencies are returned as `Dependency` objects with `status=UNCERTAIN` and `entry_points=[]`.

## Module Layout

```
src/depruner/analysers/java/
├── __init__.py
└── maven.py          # MavenPomResolver — all POM parsing logic lives here

tests/fixtures/maven/
├── single_module/            # One pom.xml, direct deps with explicit versions
├── multi_module/             # Root POM + two child modules
│   ├── pom.xml               # Parent POM with <modules>
│   ├── module-a/pom.xml
│   └── module-b/pom.xml
├── parent_inheritance/       # Child POM with <parent> block, no local version
│   ├── parent/pom.xml
│   └── child/pom.xml
└── bom_import/               # Root POM imports a BOM via scope=import, type=pom
    ├── pom.xml
    └── bom/pom.xml
```

## Functional Requirements

### POM Parsing
- Parse `pom.xml` using `xml.etree.ElementTree`; handle the Maven default namespace (`http://maven.apache.org/POM/4.0.0`) transparently — elements must be matched with and without the namespace prefix so fixtures without a namespace declaration also parse correctly.
- Extract from each POM: `groupId`, `artifactId`, `version`, `<properties>`, `<dependencyManagement>/<dependencies>`, `<dependencies>`, and `<parent>` block.
- Resolve `${property}` placeholders in `version`, `groupId`, and `artifactId` fields using the merged property map built during hierarchy traversal. Unresolvable placeholders are left as-is and a non-fatal error is appended.

### Parent POM Resolution
- When a POM contains a `<parent>` block, locate the parent POM on the local filesystem using this priority order:
  1. `<relativePath>` if present and non-empty — resolve relative to the current POM's directory.
  2. Default relative path `../pom.xml` if `<relativePath>` is absent or empty.
  3. If neither resolves to a readable file, append a non-fatal error (`"Parent POM not found for <artifactId>: <groupId>:<artifactId>:<version>"`) and continue with an empty parent contribution.
- Traverse the parent chain recursively until no further `<parent>` block exists or a cycle is detected. Cycle detection: track visited POM paths; if a path is seen twice, append a non-fatal error and stop traversal.
- Never make network requests. No Maven local repository (`~/.m2`) lookup.

### Property Inheritance
- Merge `<properties>` top-down: root ancestor properties are the base; child properties override parent properties.
- Built-in properties that must be resolved: `${project.version}` → the POM's own `<version>` (or inherited from parent if absent), `${project.groupId}` → the POM's own `<groupId>` (or inherited).

### dependencyManagement Inheritance
- Collect `<dependencyManagement>/<dependencies>` from every POM in the parent chain (root ancestor first, child last). Child entries override parent entries for the same `groupId:artifactId` key.
- A `<dependency>` entry in `<dependencyManagement>` with `<scope>import</scope>` and `<type>pom</type>` is a BOM import — resolve it using the same filesystem-only lookup as parent POMs (see BOM Resolution below).

### BOM Resolution
- Locate the BOM POM file on the local filesystem. Resolution strategy:
  1. Search for a `pom.xml` at a `<relativePath>` sibling element on the `<dependency>` node if present (non-standard extension; check for a `<relativePath>` child element of the `<dependency>` XML node and resolve it relative to the importing POM's directory).
  2. Search sibling directories of the current project root matching `<artifactId>/pom.xml`.
  3. If not found, append a non-fatal error (`"BOM not found: <groupId>:<artifactId>:<version>"`) and skip.
- Extract the BOM's `<dependencyManagement>/<dependencies>` and merge into the resolved management map (BOM entries have lower precedence than direct `<dependencyManagement>` entries in the importing POM).
- BOM POMs may themselves have parent POMs; resolve their parent chains using the same rules.

### Dependency Resolution
- For each `<dependency>` in `<dependencies>` (not `<dependencyManagement>`):
  - Look up version in the resolved `dependencyManagement` map if `<version>` is absent.
  - Apply property substitution to the final version string.
  - If version remains unresolvable after all steps, set `version=None` and append a non-fatal error.
- Produce one `Dependency` per resolved dependency:
  - `name`: `"<groupId>:<artifactId>"`
  - `version`: resolved version string or `None`
  - `status`: `DependencyStatus.UNCERTAIN`
  - `reason`: `"Maven dependency — usage analysis pending"`
  - `entry_points`: `[]`
  - `entry_points_used`: `0`
  - `entry_points_total`: `0`

**`AnalysisResult` fields:**
- `project_type`: `"java"` — always this value for Maven projects
- `project_path`: resolved absolute path passed to `analyse()`
- `dependencies`: the flat deduplicated list described above
- `errors`: non-fatal error strings accumulated during resolution
- Deduplicate by `groupId:artifactId` key. If the same artifact appears in multiple modules, include it once; if versions differ across modules, use the first encountered version and append a non-fatal warning.

### Multi-Module Projects
- Detect multi-module projects by the presence of a `<modules>` block in the root `pom.xml`.
- For each `<module>` entry, resolve the child POM at `<module>/pom.xml` relative to the root.
- Collect dependencies from all modules and merge into a single flat list (deduplication rules above apply).
- Missing module directories: append a non-fatal error and continue.

### BaseAnalyser Integration
- `MavenPomResolver` subclasses `BaseAnalyser` from `src/depruner/core/base_analyser.py`.
- `supports(project_path: str) -> bool`: returns `True` if a `pom.xml` exists directly in `project_path`.
- `analyse(project_path: str) -> AnalysisResult`: runs the full resolution pipeline and returns an `AnalysisResult`. Must never raise an unhandled exception — all errors are caught and appended to `AnalysisResult.errors`.

## Data Model Mapping

| POM field            | Dependency field     | Notes                     |
| -------------------- | -------------------- | ------------------------- |
| `groupId:artifactId` | `name`               | Colon-separated           |
| Resolved `version`   | `version`            | `None` if unresolvable    |
| —                    | `status`             | Always `UNCERTAIN`        |
| —                    | `reason`             | Fixed string (see above)  |
| —                    | `entry_points`       | Always `[]` at this stage |
| —                    | `entry_points_used`  | Always `0`                |
| —                    | `entry_points_total` | Always `0`                |

## Error Handling Contract

All errors are non-fatal. Append a descriptive string to `AnalysisResult.errors` and continue processing. Never raise from `analyse()`.

| Condition                       | Error message format                                                        |
| ------------------------------- | --------------------------------------------------------------------------- |
| Parent POM file not found       | `"Parent POM not found for <artifactId>: <groupId>:<artifactId>:<version>"` |
| BOM POM file not found          | `"BOM not found: <groupId>:<artifactId>:<version>"`                         |
| Circular parent chain           | `"Circular parent POM reference detected at <path>"`                        |
| Unresolvable `${property}`      | `"Unresolvable property '${prop}' in <groupId>:<artifactId>"`               |
| Missing module directory        | `"Module directory not found: <path>"`                                      |
| Version conflict across modules | `"Version conflict for <groupId>:<artifactId>: using <v1>, also saw <v2>"`  |
| XML parse error                 | `"Failed to parse POM at <path>: <exception message>"`                      |

## Test Fixtures & Coverage

### `tests/fixtures/maven/single_module/`
- `pom.xml` with 3 direct dependencies, all with explicit versions.
- Expected: 3 `Dependency` objects, all `UNCERTAIN`, correct `name` and `version`.

### `tests/fixtures/maven/multi_module/`
- Root `pom.xml`: `<modules>` listing `module-a` and `module-b`; `<dependencyManagement>` with 2 entries.
- `module-a/pom.xml`: 1 dependency with version from `<dependencyManagement>`.
- `module-b/pom.xml`: 1 dependency with explicit version + 1 shared with module-a.
- Expected: 3 unique `Dependency` objects (deduplication applied).

### `tests/fixtures/maven/parent_inheritance/`
- `parent/pom.xml`: defines `<properties>` with `my.lib.version=1.5.0` and `<dependencyManagement>` entry using that property.
- `child/pom.xml`: `<parent>` pointing to `../parent/pom.xml` via `<relativePath>`; declares 1 dependency with no version (resolved from parent's `<dependencyManagement>`).
- Expected: 1 `Dependency` with `version="1.5.0"`.

### `tests/fixtures/maven/bom_import/`
- `bom/pom.xml`: a BOM POM with `<dependencyManagement>` containing 2 entries.
- `pom.xml`: imports the BOM via `<scope>import</scope>` + `<type>pom</type>`; declares 1 dependency with no version (resolved from BOM).
- Expected: 1 `Dependency` with version resolved from BOM; no errors in `AnalysisResult.errors`.

### Additional unit test cases
- Missing parent POM → `errors` list contains the expected message; result still returns any directly-versioned deps.
- Missing BOM → `errors` list contains BOM-not-found message; other deps unaffected.
- Circular parent chain (A → B → A) → `errors` contains circular reference message; no infinite loop.
- Unresolvable `${placeholder}` → `version=None`, error appended.
- `supports()` returns `False` for a directory with no `pom.xml`.
- `supports()` returns `True` for a directory containing `pom.xml`.

## Out of Scope
- Maven local repository (`~/.m2`) or remote repository lookups — local filesystem only.
- `settings.xml` parsing or Maven profile activation.
- Dependency scope filtering (`test`, `provided`, `runtime`) — all scopes included at this stage; REQ-6 applies scope-aware filtering during usage analysis.
- Plugin dependency resolution (`<build><plugins>`).
- Version range syntax resolution (e.g., `[1.0,2.0)`) — treat as a literal string.
- Gradle build files — covered by REQ-5.

## Acceptance Criteria
- [] Given a directory containing `pom.xml`, When `MavenPomResolver.supports(path)` is called, Then it returns `True`
- [] Given a directory without `pom.xml`, When `MavenPomResolver.supports(path)` is called, Then it returns `False`
- [] Given the `single_module` fixture, When `analyse()` is called, Then the result contains exactly 3 `Dependency` objects all with `status=UNCERTAIN` and correct `name` and `version` values
- [] Given the `multi_module` fixture, When `analyse()` is called, Then the result contains exactly 3 unique `Dependency` objects with versions resolved from `<dependencyManagement>`
- [] Given the `parent_inheritance` fixture, When `analyse()` is called, Then the child dependency has `version="1.5.0"` resolved via parent `<dependencyManagement>` and property substitution
- [] Given the `bom_import` fixture, When `analyse()` is called, Then the dependency version is resolved from the imported BOM and `AnalysisResult.errors` is empty
- [] Given a POM whose parent file does not exist on the filesystem, When `analyse()` is called, Then `AnalysisResult.errors` contains a message matching `"Parent POM not found for"` and the result is still returned without raising
- [] Given a BOM import whose POM file does not exist on the filesystem, When `analyse()` is called, Then `AnalysisResult.errors` contains a message matching `"BOM not found:"` and other dependencies are unaffected
- [] Given a circular parent chain (A → B → A), When `analyse()` is called, Then `AnalysisResult.errors` contains a message matching `"Circular parent POM reference"` and the call returns without infinite recursion
- [] Given a POM with an unresolvable `${placeholder}` version, When `analyse()` is called, Then the corresponding `Dependency` has `version=None` and `AnalysisResult.errors` contains a message matching `"Unresolvable property"`
- [] Given a multi-module POM referencing a missing module directory, When `analyse()` is called, Then `AnalysisResult.errors` contains a message matching `"Module directory not found"` and remaining modules are still processed
- [] Given any resolved `Dependency`, When its fields are inspected, Then `entry_points == []`, `entry_points_used == 0`, `entry_points_total == 0`
- [] Given `analyse()` is called on any fixture, When an internal exception would otherwise propagate, Then it is caught, appended to `errors`, and `analyse()` returns an `AnalysisResult` without raising
- [] Given a POM using the Maven default namespace (`xmlns="http://maven.apache.org/POM/4.0.0"`), When `analyse()` is called, Then dependencies are parsed correctly without namespace-related errors
- [] Given a POM without any namespace declaration, When `analyse()` is called, Then dependencies are parsed correctly
- [] Given `mypy src/depruner` is run in strict mode, When `maven.py` is included, Then it reports no type errors
- [] Given `pytest tests/` is run, When all Maven fixture tests execute, Then all pass with no failures
