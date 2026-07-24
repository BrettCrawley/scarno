# Plan: Tiered Parent POM & BOM Resolution via Local Cache + Maven CLI

## Context

The Maven POM resolver (`src/scarno/analysers/java/maven.py`) currently resolves parent POMs only via filesystem `<relativePath>` lookups. Parent POMs that live exclusively in a remote Maven repository (e.g. `spring-boot-starter-parent`) are silently missed, causing unresolved `<dependencyManagement>` versions and properties. BOM imports (`scope=import, type=pom`) are similarly skipped with a warning.

The user wants two fallback tiers: first try the local Maven cache (`~/.m2/repository`), then fall back to `mvn dependency:get` which will fetch from whatever repository the user's Maven settings configure (including enterprise internal registries).

## Approach

Add two fallback tiers to `_locate_parent_pom()` and apply the same resolution to BOM imports:

- **Tier 0** (existing): `relativePath` on the local filesystem
- **Tier 1** (new): `~/.m2/repository/<groupId-as-path>/<artifactId>/<version>/<artifactId>-<version>.pom`
- **Tier 2** (new): `mvn dependency:get -Dartifact=<g>:<a>:<v>:pom -Dtransitive=false` to download to local cache, then re-read via Tier 1

Both tiers degrade gracefully: no `~/.m2` directory → skip Tier 1; no `mvn` binary → skip Tier 2. No new CLI flags needed.

`mvn dependency:get` is preferred over `mvn help:effective-pom` because it downloads the raw POM (preserving the parent chain walker's existing merge logic) and populates the local cache for subsequent lookups.

## Files to Modify

### 1. `src/scarno/analysers/java/maven.py`

**New imports:**
- `os`, `shutil`, `subprocess` (with `# noqa: S404`)

**New constants:**
- `_MVN_TIMEOUT_SEC = 60`
- `_GAV_COMPONENT_RE` — regex for valid Maven coordinate segments (alphanumeric, dots, hyphens, underscores)

**New module-level functions:**

| Function | Purpose |
|----------|---------|
| `_is_valid_gav_component(value: str) -> bool` | Validate a single GAV segment — reject empty, NUL bytes, path separators, `..`, shell metacharacters |
| `_validate_gav(coords: tuple[str, str, str]) -> bool` | Validate all three GAV components |
| `_m2_repo_path() -> Path` | Return `Path.home() / ".m2" / "repository"` (mockable seam) |
| `_gav_to_pom_path(repo_root, g, a, v) -> Path` | Convert GAV → Maven local repo layout path |
| `_locate_pom_in_local_cache(coords, errors) -> Path \| None` | Tier 1: look up POM in `~/.m2/repository`, confined via `resolve_and_confine()` |
| `_resolve_mvn_binary() -> str \| None` | Find `mvn` — prefer `$MAVEN_HOME/bin/mvn` (or `$M2_HOME`), fall back to `shutil.which("mvn")` |
| `_fetch_pom_via_maven(coords, errors) -> Path \| None` | Tier 2: run `mvn dependency:get`, then re-read from cache via Tier 1 |

**Modified: `_locate_parent_pom()`**

Only the "file not found" branch (currently line 477-481) falls through to Tier 1 → Tier 2. Sandbox escape and non-pom.xml errors remain hard stops (no fallback — security boundary).

```
Tier 0 fails (candidate doesn't exist)
  → Tier 1: _locate_pom_in_local_cache(parent_coords)
    → Tier 2: _fetch_pom_via_maven(parent_coords) 
      → give up, append error
```

**Modified: BOM import handling in `_resolve_module()`**

- Move the BOM loop **before** the dependency resolution loop (currently it's after — so BOM-managed versions aren't available when resolving version-less deps)
- Replace warning-only with: resolve BOM POM via Tier 1 → Tier 2, merge its `<dependencyManagement>` into `merged_managed`
- Resolve `${property}` placeholders in BOM coordinates using `merged_properties` before passing to resolution

**New method: `_resolve_bom_pom(bom, merged_properties, errors) -> _PomData | None`**

Extracts and resolves placeholders in BOM GAV, then calls Tier 1 → Tier 2 → `_parse_pom_file()`.

**Update docstring** (line 9): Remove "no `~/.m2` lookup (SEC-010)" claim, describe the tiered approach.

### 2. `tests/unit/test_maven.py`

**New test classes:**

- `TestGavValidation` — valid GAV accepted; path traversal, shell metacharacters, NUL bytes, empty strings rejected
- `TestLocalCacheResolution` — POM found in mock `.m2`, missing directory, missing file, symlink escape blocked, oversized POM skipped, end-to-end parent resolution from cache when relativePath fails
- `TestMavenCliFallback` — mvn resolved from `$MAVEN_HOME`, `$M2_HOME`, PATH; mvn not found → graceful None; mock subprocess success + cache read; timeout/error/nonzero-exit → None; invalid GAV never reaches subprocess
- `TestBomResolution` — BOM managed deps merged into child, unresolvable BOM emits warning, BOM resolution happens before dependency resolution

All tests use `tmp_path` for filesystem, `monkeypatch` for `_m2_repo_path()` / `subprocess.run` / env vars.

### 3. `tests/security/test_adversarial.py`

- `TestMavenCachePathTraversal` — GAV path traversal in `.m2` cache blocked; mvn binary symlink escape blocked

### 4. `tests/srtm.py`

Add new requirement IDs:
- `SEC-NEW-27` — GAV coordinate validation prevents path traversal in `~/.m2` lookup
- `SEC-NEW-28` — `mvn` binary resolution validates against `$MAVEN_HOME` tree
- `FR-131` — Parent POM resolved from `~/.m2/repository` local cache
- `FR-132` — Parent POM fetched via `mvn dependency:get` when local cache misses
- `FR-133` — BOM imports resolved via tiered POM resolution

## Security Considerations

- GAV components validated via regex before constructing any path or subprocess argument
- Cache paths confined to `~/.m2/repository` via `resolve_and_confine()` (catches symlinks)
- `mvn` binary confinement to `$MAVEN_HOME` tree (matches existing javap pattern)
- `subprocess.run(shell=False)` always; `timeout=60`; catches `TimeoutExpired/FileNotFoundError/OSError`
- Sandbox escape and non-pom.xml errors in Tier 0 are hard stops — never fall through to Tier 1/2

## Verification

1. Run existing tests: `pytest tests/unit/test_maven.py` — all must still pass
2. Run new tests: the new test classes
3. Run full security suite: `pytest tests/security/` 
4. Run SRTM coverage check to ensure new requirement IDs are covered
5. `pytest --tb=short` for the full suite
