# Plan: Artifact-Based Package Discovery for Java and Python

## Context

Both Java and Python analysers suffer from the same fundamental flaw: they guess at the import-to-dependency mapping using heuristic name matching (Maven groupId prefix, PEP 503 normalization) and hardcoded alias tables, instead of inspecting the actual artifacts to discover what packages they export.

**Java example**: `commons-beanutils:commons-beanutils` has groupId `commons-beanutils`, but its classes live under `org.apache.commons.beanutils`. An `import org.apache.commons.beanutils.BeanUtils` never matches because the groupId doesn't match the package. The hardcoded `_JAVA_PACKAGE_ALIASES` table only covers ~13 popular artifacts.

**Python equivalent**: `importlib.metadata.packages_distributions()` only works for packages installed in Scarno's own environment, not the project's `.venv`. If the project uses `Pillow` but Scarno doesn't have it installed, the only fallback is the ~102-entry `IMPORT_ALIASES` table.

The fix: inspect the actual artifacts to discover the real package→dependency mapping.

## Part 1: Java — JAR-based package discovery

### Approach

For each Maven/Gradle dependency, locate its JAR and enumerate the `.class` entries to derive the Java packages it provides. Use those real package prefixes (instead of the groupId heuristic) when matching source imports.

**Resolution tiers for JAR location** (mirrors POM resolution):
1. `~/.m2/repository/<groupId-as-path>/<artifactId>/<version>/<artifactId>-<version>.jar`
2. Project `target/` directory: `<project>/target/<artifactId>-<version>.jar`

No `mvn` fallback for JARs (downloading all JARs would be too heavy — POM-only fetch is surgical, JAR fetch is not).

### Files to modify

**`src/scarno/analysers/java/source_analyser.py`**

New function: `_locate_dependency_jar(dep: Dependency) -> Path | None`
- Parse `dep.name` into groupId, artifactId; use `dep.version`
- Try `~/.m2/repository` using `_gav_to_jar_path()` (new, parallel to `_gav_to_pom_path` in maven.py)
- Try project `target/` directory
- Validate with `resolve_and_confine()`, check `MAX_FILE_BYTES`
- Return path or None

New function: `_extract_packages_from_jar(jar_path: Path) -> set[str]`
- Call `safe_jar_entries(jar_path)` to get `.class` file list
- Convert each entry like `com/example/Foo.class` → package `com.example`
- Return the set of unique packages (deduplicated)

New function: `_build_jar_package_map(deps: list[Dependency], project_root: Path, errors: list[str]) -> dict[str, set[str]]`
- For each dep, try to locate JAR → extract packages
- Returns `{dep.name: {package_prefixes}}` — e.g. `{"commons-beanutils:commons-beanutils": {"org.apache.commons.beanutils"}}`
- Cache the results so we only scan each JAR once

Modified: `_candidate_package_prefixes(key, group_id)` → add new parameter `jar_packages: dict[str, set[str]]`
- First check JAR-derived packages (authoritative)
- Fall back to groupId + alias table when JAR not available

Modified: `JvmSourceAnalyser.analyse()` flow:
- After gathering source files and extracting facts, call `_build_jar_package_map()`
- Pass the map into `_classify_dep()` (new parameter)

**`src/scarno/analysers/java/maven.py`**

New function: `_gav_to_jar_path(repo_root, g, a, v) -> Path`
- Same as `_gav_to_pom_path` but with `.jar` extension

### Entry point enumeration (javap)

Wire `_invoke_javap_safe()` into the classification for IN_USE dependencies:
- For each dep classified as IN_USE via import matching, enumerate public API via javap
- For each `.class` in the JAR, call `_invoke_javap_safe()` to get public members
- Parse javap output → `EntryPoint` objects (name, kind=class/method/field, used)
- Cross-reference with source imports to populate `entry_points_used`

New function: `_parse_javap_output(stdout: str) -> list[tuple[str, str]]`
- Parse `javap -public` output lines
- Extract public class name, public method signatures, public field names
- Return list of `(name, kind)` tuples

This is expensive (one subprocess per class), so only do it for deps that are already classified as IN_USE, and cap at a reasonable limit (e.g. 500 classes per dep).

## Part 2: Python — .venv metadata scanning

### Approach

Scan the project's `.venv/lib/pythonX.Y/site-packages/*.dist-info/top_level.txt` to build the distribution→import-name mapping. This gives us the same information as `importlib.metadata.packages_distributions()` but from the **project's** environment instead of Scarno's own.

### Files to modify

**`src/scarno/analysers/python/source_analyser.py`**

New function: `_build_venv_dist_imports_map(project_root: Path, errors: list[str]) -> DistImportsMap`
- Locate `.venv` or `venv` under `project_root`
- Find `lib/pythonX.Y/site-packages/` (glob for the python version dir)
- For each `*.dist-info` directory:
  - Extract distribution name from dir name (strip version suffix)
  - Read `top_level.txt` if it exists → each line is an import name
  - If no `top_level.txt`, fall back to reading `RECORD` and deriving top-level packages from the recorded file paths
- Return `DistImportsMap` (`{canonical_dist: {import_names}}`)
- Apply `resolve_and_confine()` to ensure we don't follow symlinks outside the venv
- Size-cap `top_level.txt` reads (these files are tiny, but defense-in-depth)

Modified: `analyse_source_files_with_findings()` (line 541):
- After `dist_imports = _build_dist_to_imports_map()` (Scarno's own env)
- Also call `venv_imports = _build_venv_dist_imports_map(root, errors)` 
- Merge: venv imports take precedence (they're from the actual project)
- `dist_imports = _merge_dist_maps(dist_imports, venv_imports)`

New function: `_merge_dist_maps(base: DistImportsMap, override: DistImportsMap) -> DistImportsMap`
- Union the import name sets for each distribution
- Override's entries supplement base (additive merge)

### Security considerations

- `.venv` path confined to project root via `resolve_and_confine()`
- `top_level.txt` capped at `MAX_FILE_BYTES` (overkill — these are <1KB — but consistent)
- `.dist-info` directory name parsed with regex to extract dist name safely
- No code execution — just reading text files (unlike `_enumerate_entry_points` which calls `importlib.import_module()`)

## Test strategy

### Java tests (`tests/unit/test_jvm_source_analyser.py`)

- `TestJarPackageExtraction` — synthetic JAR with known `.class` layout → correct packages extracted
- `TestJarLocation` — mock `_m2_repo_path` → JAR found/not-found
- `TestJarBasedClassification` — dep with non-matching groupId but matching JAR packages → correctly classified as IN_USE
- `TestJavapEntryPoints` — mock javap output → correct EntryPoint objects
- End-to-end: `commons-beanutils` style scenario (groupId ≠ package, JAR in cache, import in source → IN_USE)

### Python tests (`tests/unit/test_source_analyser.py`)

- `TestVenvDistImportsMap` — mock `.venv` with `dist-info` dirs and `top_level.txt` → correct map built
- `TestVenvMerge` — venv map supplements base map
- `TestVenvMissing` — no `.venv` dir → graceful empty map
- End-to-end: dep with non-matching name (e.g. `Pillow` → `PIL`) resolved via venv metadata → IN_USE

### Security tests (`tests/security/test_adversarial.py`)

- JAR path traversal via crafted GAV blocked
- `.venv` symlink escape blocked
- Oversized `top_level.txt` handled

### SRTM requirements

- `FR-134` — Java dependency packages discovered from JAR class entries
- `FR-135` — Python dependency imports discovered from .venv dist-info metadata
- `SEC-NEW-29` — JAR path confined to `~/.m2/repository`
- `SEC-NEW-30` — .venv metadata path confined to project root

## Verification

1. Run existing tests: `pytest tests/unit/test_maven.py tests/unit/test_jvm_source_analyser.py tests/unit/test_source_analyser.py`
2. Run new tests
3. Run full security suite: `pytest tests/security/`
4. Run SRTM coverage: all 195 requirements covered
5. Full suite: `pytest --tb=short`
