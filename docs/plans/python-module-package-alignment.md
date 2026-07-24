# Plan: Lock File Graphs, CLI Tool Detection, Metadata-Based Import Resolution

## Context

Three gaps in scarno's Python dependency classification:

1. **poetry.lock graph** — Has `[package.dependencies]` tables with full graph data, but `_parse_lock_toml` ignores it. Pipfile.lock fundamentally lacks graph data (flat format) so it cannot be extended.
2. **CLI tool detection** — Packages like `gunicorn`, `celery`, `uvicorn`, `alembic` are invoked from Dockerfiles/Procfiles/shell scripts, not imported in Python source. They're falsely marked SAFE.
3. **Import name ≠ distribution name** — The static 9-entry alias table misses hundreds of packages (pyopenssl→OpenSSL, python-ldap→ldap, py-tlsh→tlsh). `importlib.metadata.packages_distributions()` can be inverted to solve this generically.

---

## Feature 1: poetry.lock Dependency Graph

### Current state
`_parse_lock_toml()` at `dep_file_parser.py:616` reads `[[package]]` entries but only extracts name+version. poetry.lock has:
```toml
[[package]]
name = "requests"
version = "2.31.0"

[package.dependencies]
certifi = ">=2017.4.17"
urllib3 = ">=1.21.1,<3"
```

### Implementation

**File:** `src/scarno/analysers/python/dep_file_parser.py`

Create `_parse_poetry_lock(path, errors) -> tuple[list[_RawDep], DepGraph]`:
- Parse all `[[package]]` entries
- For each, extract `pkg.get("dependencies")` — a dict of `{name: version_spec}`
- Build graph: `canonical_name → set(canonical deps)`
- Identify direct deps: poetry.lock doesn't have an editable root like uv.lock, so cross-reference with `pyproject.toml [tool.poetry.dependencies]` (already parsed). Deps in pyproject.toml are direct; everything else in the lock is transitive.
- Return `(raw_deps, graph)` same shape as `_parse_uv_lock`

Update `parse_all_dependency_files()`:
- Replace `_parse_lock_toml(poetry_lock, ...)` with `_parse_poetry_lock(poetry_lock, ...)`
- Merge the graph into `dep_graph` (uv.lock and poetry.lock are mutually exclusive in practice, but union if both exist)

**Pipfile.lock:** No change possible — format lacks dependency relationships. Leave as-is (all deps treated as direct, which is the conservative choice).

---

## Feature 2: CLI Tool Detection

### Problem
Packages used as CLI executables (not imported) are falsely classified as SAFE.

### Detection Sources

| Source | Pattern | Example |
|--------|---------|---------|
| Dockerfile CMD/ENTRYPOINT | `CMD ["gunicorn", ...]` or `CMD gunicorn app:app` | gunicorn, uvicorn, celery |
| Procfile | `web: gunicorn app:app` | gunicorn, celery |
| Shell scripts (*.sh in root, docker/) | `gunicorn`, `celery`, `uvicorn`, `alembic` invocations | Any CLI tool |
| pyproject.toml `[project.scripts]` | Values reference packages | The package containing the module |
| Tool config files | `gunicorn.conf.py`, `alembic.ini`, `celery.py` | Presence implies usage |

### Implementation

**New file:** `src/scarno/analysers/python/cli_tool_detector.py`

```python
def detect_cli_tool_usage(project_path: str) -> tuple[set[str], list[str]]:
    """Return (set of package names used as CLI tools, errors)."""
```

This function:
1. **Dockerfile CMD/ENTRYPOINT** — Already parsed by `container_ci_parser.py:_strip_dockerfile_prefix()` which handles CMD/ENTRYPOINT lines, but only extracts pip installs. Add new logic: extract the first word of CMD/ENTRYPOINT as a CLI tool name.
2. **Procfile** — Parse `<process>: <command> <args>`. Extract the command word.
3. **Shell scripts** — Scan `*.sh` files in project root and `docker/` for known CLI tool names.
4. **pyproject.toml `[project.scripts]`** — Already parsed by dep_file_parser for other reasons. Extract module references from script values (e.g. `"myapp.cli:main"` → the package providing `myapp`).
5. **Config file presence** — Map config files to packages:
   - `gunicorn.conf.py` / `gunicorn.py` → `gunicorn`
   - `alembic.ini` / `alembic/` → `alembic`
   - `celeryconfig.py` / `celery.py` → `celery`
   - `uwsgi.ini` → `uwsgi`
   - `.flake8` / `setup.cfg [flake8]` → `flake8`
   - `mypy.ini` / `.mypy.ini` → `mypy`
   - `pytest.ini` / `conftest.py` → `pytest`
   - `.pre-commit-config.yaml` → `pre-commit`

**CLI tool → package mapping table:**
```python
CLI_TOOL_TO_PACKAGE: dict[str, str] = {
    "gunicorn": "gunicorn",
    "uvicorn": "uvicorn",
    "celery": "celery",
    "alembic": "alembic",
    "flask": "flask",
    "django-admin": "django",
    "manage.py": "django",
    "pytest": "pytest",
    "mypy": "mypy",
    "black": "black",
    "ruff": "ruff",
    "isort": "isort",
    "pre-commit": "pre-commit",
    "uwsgi": "uwsgi",
    "daphne": "daphne",
    "hypercorn": "hypercorn",
}
```

**Integration with source_analyser.py:**

In `analyse_source_files_with_findings()`, after the import-based classification pass, call `detect_cli_tool_usage(project_path)`. For any dep that was marked SAFE but appears in the CLI tool set, upgrade to IN_USE with reason `"invoked as CLI tool in <source>"`.

---

## Feature 3: Metadata-Based Import Name Resolution

### Problem
`_import_matches_dep()` only checks normalised name equality + 9 hardcoded aliases. Hundreds of packages have different import names (pyopenssl→OpenSSL, python-ldap→ldap, etc.).

### Solution
Invert `importlib.metadata.packages_distributions()`:
- It returns `{import_name: [dist_name, ...]}` for all installed packages
- Inverting gives `{dist_name: [import_name, ...]}` — exactly what we need

### Implementation

**File:** `src/scarno/analysers/python/source_analyser.py`

Add a cached lookup function:
```python
def _build_dist_to_imports_map() -> dict[str, set[str]]:
    """Invert packages_distributions() → {canonical_dist: {import_names}}."""
    try:
        fwd = importlib.metadata.packages_distributions()
    except Exception:
        return {}
    result: dict[str, set[str]] = {}
    for import_name, dists in fwd.items():
        for dist in dists:
            canonical = _normalise(dist)
            result.setdefault(canonical, set()).add(import_name.lower())
    return result
```

Modify `_import_matches_dep()`:
```python
def _import_matches_dep(
    import_name: str, dep_canonical: str, dist_imports: dict[str, set[str]]
) -> bool:
    normalised_import = _normalise(import_name)
    if normalised_import == dep_canonical:
        return True
    # Static alias table (fallback for uninstalled packages)
    mapped = IMPORT_ALIASES.get(normalised_import)
    if mapped is not None and _normalise(mapped) == dep_canonical:
        return True
    # Metadata-based: check if this dep's known import names include our import
    known_imports = dist_imports.get(dep_canonical, set())
    if normalised_import in known_imports:
        return True
    return False
```

Call `_build_dist_to_imports_map()` once at the start of `analyse_source_files_with_findings()` and pass the map through to all matching functions.

**Keep the static alias table** as a fallback for when packages aren't installed in the analysis environment.

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/scarno/analysers/python/dep_file_parser.py` | New `_parse_poetry_lock()` with graph extraction |
| `src/scarno/analysers/python/cli_tool_detector.py` | **NEW** — CLI tool detection from Dockerfiles, Procfiles, shell scripts, configs |
| `src/scarno/analysers/python/source_analyser.py` | Integrate CLI tool detection + metadata-based import matching |
| `src/scarno/analysers/python/import_aliases.py` | Keep as-is (fallback for uninstalled packages) |

---

## Verification

1. **poetry.lock graph:** Create a test fixture with a poetry.lock containing dependencies sections. Verify transitive deps are correctly identified.
2. **CLI tool detection:** Create a fixture with `Procfile` containing `web: gunicorn app:app` and a declared `gunicorn` dep. Verify it's classified as IN_USE (not SAFE).
3. **Metadata resolution:** With `pyyaml` installed, verify `import yaml` matches the declared dep `pyyaml` via metadata without needing the static alias table.
4. **Regression:** All 784 existing tests pass.
