# Python Dependency File Parser

## Overview
Parse declared dependencies from all eight Python config formats into a unified `list[Dependency]`, deduplicated by PEP 503 canonical name. All returned dependencies carry `status=UNCERTAIN` and `reason="declared — source analysis pending"` as placeholders for REQ-3.

## Problem Statement
Python projects declare dependencies across up to eight different file formats with overlapping, conflicting, or redundant entries. Without a unified parser, the analysis engine has no reliable inventory of what a project declares as a dependency.

## Solution
A coordinator function `parse_all_dependency_files` detects which config files are present, delegates to a per-format parser, deduplicates by canonical name with lock-file precedence, and returns a merged list alongside non-fatal error strings.

## File Layout

```
src/depruner/analysers/python/
├── __init__.py          # PythonAnalyser class (replaces REQ-1 stub)
└── dep_file_parser.py   # All parsers + coordinator

tests/
├── test_dep_file_parser.py
└── fixtures/
    └── python_deps/
        ├── requirements_simple/
        ├── requirements_recursive/
        ├── pyproject_pep621/
        ├── pyproject_poetry/
        ├── setup_py/
        ├── setup_cfg/
        ├── pipfile/
        ├── uv_lock/
        ├── poetry_lock/
        └── multi_file/
```

## Public Interface

**Coordinator** (`dep_file_parser.py`)
```python
def parse_all_dependency_files(
    project_path: str,
) -> tuple[list[Dependency], list[str]]:
    ...
```
Returns `(dependencies, errors)`. Never raises; all parse failures append to `errors`.

**PythonAnalyser** (`__init__.py`) — replaces REQ-1 stub
```python
class PythonAnalyser(BaseAnalyser):
    def supports(self, project_path: str) -> bool: ...
    def analyse(self, project_path: str) -> AnalysisResult: ...
```
`analyse()` calls `parse_all_dependency_files`, wraps the result in `AnalysisResult(project_type="python", ...)`, and propagates errors.

## Per-Format Parser Specifications

### 1. `requirements.txt`

| Input pattern                                                        | Behaviour                                                                                            |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `pkg==1.0`, `pkg>=1.0`, `pkg`                                        | Parse name + version (or `None`)                                                                     |
| `# comment` or inline `# comment`                                    | Strip before parsing                                                                                 |
| `; python_version >= "3.8"` (env marker)                             | Strip marker; keep package                                                                           |
| `-r other.txt`                                                       | Resolve relative to current file; parse recursively (max depth 10; cycle detection by resolved path) |
| `-e .`, `-e git+...`                                                 | Skip silently                                                                                        |
| `https://...`, `git+...`                                             | Skip silently                                                                                        |
| Malformed line (unparseable by `packaging.requirements.Requirement`) | Append warning to `errors`; skip line                                                                |

Use `packaging.requirements.Requirement` for parsing. Do not implement a custom regex parser.

### 2. `pyproject.toml`

Parse with `tomllib` (stdlib, Python 3.11+) or `tomli` fallback.

| Section                              | Key                      | Notes                                             |
| ------------------------------------ | ------------------------ | ------------------------------------------------- |
| `[project]`                          | `dependencies`           | PEP 621 — list of PEP 508 strings                 |
| `[project.optional-dependencies]`    | all keys                 | Extras — include all groups                       |
| `[tool.poetry.dependencies]`         | all keys except `python` | Poetry main deps; value is version string or dict |
| `[tool.poetry.dev-dependencies]`     | all keys                 | Legacy Poetry dev deps                            |
| `[tool.poetry.group.*.dependencies]` | all keys                 | Poetry group deps (any group name)                |

Poetry version values: string (`"^1.0"`) → store as-is; dict with `version` key → extract `version`; dict without `version` (e.g., path dep) → store version as `None`.

If neither `[project]` nor `[tool.poetry]` is present, return empty list (not an error).

### 3. `setup.py`

Parse using `ast` module only. Never use `exec`, `eval`, or `importlib` on the file.

Target AST patterns:
- `setup(install_requires=["pkg==1.0", ...])` — list literal
- `setup(install_requires=VARIABLE)` where `VARIABLE` is assigned a list literal earlier in the same file
- `setup(extras_require={"extra": ["pkg"]})` — dict of lists

If `install_requires` is assigned from a function call, file read, or any non-literal expression: append `"setup.py: dynamic install_requires detected — dependencies may be incomplete"` to `errors` and return whatever static entries were found.

If `setup.py` is present but contains no `setup()` call: append `"setup.py: no setup() call found"` to `errors`; return empty list.

### 4. `setup.cfg`

Parse with `configparser`.

| Section                    | Key                | Notes                                        |
| -------------------------- | ------------------ | -------------------------------------------- |
| `[options]`                | `install_requires` | Multiline value; one PEP 508 string per line |
| `[options.extras_require]` | all keys           | Each value is multiline list                 |

Blank lines within multiline values are ignored. Parse each non-blank line as a PEP 508 string via `packaging.requirements.Requirement`.

### 5. `Pipfile`

Parse with `tomllib`/`tomli` (Pipfile is TOML).

| Section          | Notes             |
| ---------------- | ----------------- |
| `[packages]`     | Main dependencies |
| `[dev-packages]` | Dev dependencies  |

Value formats: `"*"` → version `None`; version string (`">=1.0"`) → store as-is; dict with `version` key → extract; dict without `version` (path/git dep) → version `None`.

### 6. `Pipfile.lock`

Parse with `json` (stdlib). Structure: `{"default": {"pkg": {"version": "==1.2.3", ...}}, "develop": {...}}`.

- Extract from both `default` and `develop` sections.
- Version field format is `"==1.2.3"` — store as `"1.2.3"` (strip `==` prefix).
- Skip the `_meta` key.

### 7. `poetry.lock`

Parse with `tomllib`/`tomli`. Structure: list of `[[package]]` entries.

Extract `name` and `version` from each entry. Ignore all other fields.

### 8. `uv.lock`

Parse with `tomllib`/`tomli`. Same `[[package]]` structure as `poetry.lock`.

Extract `name` and `version` from each entry.

## Deduplication Rules

**Name normalisation (PEP 503):** lowercase, replace `_` and `.` with `-`.

Apply before any deduplication comparison. Store the normalised name in `Dependency.name`.

**Precedence order** (highest → lowest) when the same package appears in multiple files:

1. `Pipfile.lock`
2. `poetry.lock`
3. `uv.lock`
4. `requirements.txt`
5. `pyproject.toml`
6. `setup.py`
7. `setup.cfg`
8. `Pipfile`

Keep the entry from the highest-precedence file. If the lower-precedence file has a conflicting version (both non-`None` and different after normalisation), append to `errors`:
`"Package '{name}' declared with conflicting versions: '{v1}' ({file1}) vs '{v2}' ({file2}) — using {file1} version"`.

If one version is `None` and the other is not, keep the non-`None` version silently.

## Error Handling Contract

| Condition                                  | Action                                                                                     |
| ------------------------------------------ | ------------------------------------------------------------------------------------------ |
| File exists, TOML malformed                | Append `"{filename}: TOML parse error — {detail}"` to `errors`; skip file                  |
| File exists, JSON malformed (Pipfile.lock) | Append `"{filename}: JSON parse error — {detail}"` to `errors`; skip file                  |
| `setup.py` AST parse error                 | Append `"setup.py: syntax error — {detail}"` to `errors`; skip file                        |
| `setup.py` dynamic `install_requires`      | Append warning (see §3); return static entries found                                       |
| `-r include.txt` target missing            | Append `"requirements.txt: included file not found: {path}"` to `errors`; skip include     |
| `-r` cycle detected                        | Append `"requirements.txt: circular include detected: {path}"` to `errors`; stop recursion |
| Individual malformed requirement line      | Append `"{filename}: could not parse line '{line}' — {detail}"` to `errors`; skip line     |
| No supported config file found             | Return `([], [])` — not an error at this layer (detector handles it)                       |

All errors are non-fatal. The coordinator always returns a (possibly empty) list.

## Type Stub Package Handling

Type stub packages provide type information for libraries that lack inline types. They are always considered `IN_USE` if the runtime library they annotate is present in the project — removing them breaks static analysis tooling (mypy, pyright) without causing a runtime error, but Depruner must not flag them as safe to remove unless the runtime library itself is also absent.

**Detection rules — a package is a type stub if ANY of the following are true:**

| Rule | Examples |
| ---- | -------- |
| Name matches `types-*` pattern (PyPI stub convention) | `types-requests`, `types-boto3`, `types-PyYAML` |
| Name matches `*-stubs` pattern | `django-stubs`, `sqlalchemy-stubs` |
| Name is `mypy-extensions`, `typing-extensions`, or `typing-inspect` | (typing infrastructure, always keep) |
| Package metadata contains `py.typed` marker or `*.pyi` files only | detected via lock file `category` field in `uv.lock` if present |

**Stub-to-runtime mapping:**

When a stub package is detected, attempt to resolve its corresponding runtime library:
- `types-{name}` → runtime is `{name}` (e.g., `types-requests` → `requests`)
- `{name}-stubs` → runtime is `{name}` (e.g., `django-stubs` → `django`)
- If the runtime library is present in the parsed dependency list → set stub `status=IN_USE`, `reason="type stub for '{runtime}' which is declared as a dependency"`
- If the runtime library is NOT present in the parsed dependency list → set stub `status=UNCERTAIN`, `reason="type stub for '{runtime}' but runtime package not found in declared dependencies — manual review required"`

**`Dependency` model extension:**

Add a boolean field `is_type_stub: bool = False` to the `Dependency` dataclass in `models.py`. Set to `True` for all packages identified as type stubs. REQ-3 (source analyser) must skip import scanning for type stub packages — they have no importable runtime code.

**Fixture addition — `tests/fixtures/python_deps/type_stubs/`:**
```toml
# pyproject.toml
[project]
dependencies = [
    "requests==2.31.0",
    "types-requests==2.31.0",
    "django-stubs==4.2.0",
    "boto3==1.26.0",
    "types-boto3==1.26.0",
    "types-stripe==3.0.0",   # no matching runtime dep
]
```
Expected:
- `requests` → `is_type_stub=False`, `status=UNCERTAIN`
- `types-requests` → `is_type_stub=True`, `status=IN_USE`, reason references `requests`
- `django-stubs` → `is_type_stub=True`, `status=UNCERTAIN` (no `django` in deps)
- `boto3` → `is_type_stub=False`, `status=UNCERTAIN`
- `types-boto3` → `is_type_stub=True`, `status=IN_USE`, reason references `boto3`
- `types-stripe` → `is_type_stub=True`, `status=UNCERTAIN` (no `stripe` in deps)

## All Dependencies Set to UNCERTAIN

Every `Dependency` returned by `parse_all_dependency_files` must have:
- `status = DependencyStatus.UNCERTAIN`
- `reason = "declared — source analysis pending"`
- `entry_points = []` — entry point enumeration has not been attempted at parse time
- `entry_points_used = 0`
- `entry_points_total = 0`

REQ-3 (source analyser) is responsible for updating `status` to `IN_USE` or `SAFE`. Entry point enumeration and population of `entry_points` / `entry_points_used` / `entry_points_total` is handled by a later analysis stage (REQ-3 and beyond) — the parser must not attempt to populate these fields.

## Test Fixtures

### `requirements_simple/requirements.txt`
```
requests==2.31.0
flask>=2.0
numpy  # no version pin
boto3==1.26.0 ; python_version >= "3.8"
-e .  # editable — skip
https://example.com/pkg.tar.gz  # URL — skip
```
Expected: 4 dependencies (`requests`, `flask`, `numpy`, `boto3`), 0 errors.

### `requirements_recursive/`
```
# base.txt
requests==2.31.0

# requirements.txt
-r base.txt
flask==2.3.0
```
Expected: 2 dependencies, 0 errors.

### `pyproject_pep621/pyproject.toml`
```toml
[project]
dependencies = ["requests>=2.0", "flask==2.3.0"]

[project.optional-dependencies]
dev = ["pytest>=7.0"]
```
Expected: 3 dependencies (`requests`, `flask`, `pytest`), 0 errors.

### `pyproject_poetry/pyproject.toml`
```toml
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
flask = {version = "^2.3", extras = ["async"]}

[tool.poetry.dev-dependencies]
pytest = "^7.0"

[tool.poetry.group.docs.dependencies]
sphinx = "^7.0"
```
Expected: 4 dependencies (`requests`, `flask`, `pytest`, `sphinx`); `python` excluded; 0 errors.

### `setup_py/setup.py`
```python
from setuptools import setup
setup(
    install_requires=["requests==2.31.0", "flask>=2.0"],
    extras_require={"dev": ["pytest"]},
)
```
Expected: 3 dependencies, 0 errors.

### `setup_cfg/setup.cfg`
```ini
[options]
install_requires =
    requests==2.31.0
    flask>=2.0

[options.extras_require]
dev =
    pytest>=7.0
```
Expected: 3 dependencies, 0 errors.

### `pipfile/`
```toml
# Pipfile
[packages]
requests = "*"
flask = ">=2.0"

[dev-packages]
pytest = "*"
```
```json
// Pipfile.lock
{"default": {"requests": {"version": "==2.31.0"}, "flask": {"version": "==2.3.2"}}, "develop": {"pytest": {"version": "==7.4.0"}}}
```
Expected: 3 dependencies with versions from lock file, 0 errors.

### `uv_lock/`
```toml
# pyproject.toml
[project]
dependencies = ["requests>=2.0"]
```
```toml
# uv.lock
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "certifi"
version = "2024.2.2"
```
Expected: 2 dependencies (both from lock), version from uv.lock for `requests`, 0 errors.

### `poetry_lock/`
```toml
# poetry.lock
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.7"
```
Expected: 2 dependencies, 0 errors.

### `multi_file/`
Contains `requirements.txt` (`requests==2.28.0`), `pyproject.toml` (`[project] dependencies = ["flask==2.3.0", "requests>=2.0"]`), and `Pipfile.lock` (`{"default": {"requests": {"version": "==2.31.0"}, "flask": {"version": "==2.3.2"}}}`). 

Expected: 2 dependencies; `requests` version `2.31.0` (from Pipfile.lock); `flask` version `2.3.2` (from Pipfile.lock); 1 conflict warning for `requests` in `errors`.

## Acceptance Criteria
- [] Given `requirements_simple/requirements.txt`, When `parse_all_dependency_files` is called, Then 4 `Dependency` objects are returned with names `requests`, `flask`, `numpy`, `boto3` and 0 errors
- [] Given `requirements_simple/requirements.txt`, When parsed, Then the editable install `-e .` and URL requirement are not present in the returned list
- [] Given `requirements_recursive/`, When `parse_all_dependency_files` is called, Then both `requests` and `flask` are returned and the `-r base.txt` include is resolved correctly
- [] Given a `requirements.txt` with a circular `-r` include, When parsed, Then a cycle-detection error is appended to `errors` and parsing completes without infinite recursion
- [] Given `pyproject_pep621/pyproject.toml`, When parsed, Then `requests`, `flask`, and `pytest` (from optional-dependencies) are returned and 0 errors are reported
- [] Given `pyproject_poetry/pyproject.toml`, When parsed, Then `requests`, `flask`, `pytest`, and `sphinx` are returned; the `python` key is excluded; and 0 errors are reported
- [] Given a `pyproject.toml` with no `[project]` or `[tool.poetry]` section, When parsed, Then an empty list is returned with 0 errors
- [] Given `setup_py/setup.py` with static `install_requires`, When parsed using AST, Then `requests`, `flask`, and `pytest` are returned and 0 errors are reported
- [] Given a `setup.py` where `install_requires` is assigned from a function call, When parsed, Then a dynamic-detection warning is appended to `errors` and any static entries found are still returned
- [] Given a `setup.py` with a syntax error, When parsed, Then a syntax error message is appended to `errors` and an empty list is returned
- [] Given `setup_cfg/setup.cfg`, When parsed, Then `requests`, `flask`, and `pytest` are returned and 0 errors are reported
- [] Given `pipfile/Pipfile.lock`, When parsed, Then `requests` version is `2.31.0`, `flask` version is `2.3.2`, and `pytest` version is `7.4.0`
- [] Given `pipfile/` with both `Pipfile` and `Pipfile.lock`, When `parse_all_dependency_files` is called, Then versions from `Pipfile.lock` take precedence over `Pipfile`
- [] Given `uv_lock/` with `pyproject.toml` and `uv.lock`, When parsed, Then `requests` version is `2.31.0` (from uv.lock) and `certifi` is also returned
- [] Given `poetry_lock/poetry.lock`, When parsed, Then `requests` and `urllib3` are returned with correct versions
- [] Given `multi_file/` with `requirements.txt`, `pyproject.toml`, and `Pipfile.lock`, When `parse_all_dependency_files` is called, Then exactly 2 unique dependencies are returned, `requests` version is `2.31.0` (Pipfile.lock wins), and 1 conflict warning appears in `errors`
- [] Given any two files declaring the same package with different names `My-Package` and `my_package`, When deduplicated, Then they are treated as the same package per PEP 503 normalisation
- [] Given a malformed TOML file (e.g., `pyproject.toml`), When `parse_all_dependency_files` is called, Then a descriptive parse error is appended to `errors`, the file is skipped, and other present files are still parsed
- [] Given a `Pipfile.lock` with invalid JSON, When parsed, Then a JSON parse error is appended to `errors` and parsing continues with remaining files
- [] Given a `requirements.txt` with a `-r include.txt` where `include.txt` does not exist, When parsed, Then a missing-file error is appended to `errors` and the rest of `requirements.txt` is still parsed
- [] Given any parsed dependency, When returned by `parse_all_dependency_files`, Then `status` is `DependencyStatus.UNCERTAIN` and `reason` is `"declared — source analysis pending"`
- [] Given `PythonAnalyser.analyse(project_path)` is called on any fixture, When it returns, Then the result is an `AnalysisResult` with `project_type="python"` and all dependencies have `status=UNCERTAIN`
- [] Given `PythonAnalyser.supports(project_path)` is called on a directory containing any supported config file, When evaluated, Then it returns `True`
- [] Given `PythonAnalyser.supports(project_path)` is called on a directory with only `pom.xml`, When evaluated, Then it returns `False`
- [] Given `setup.py` is parsed, When the AST visitor runs, Then no `eval()`, `exec()`, or `importlib` calls are made on the file content
- [] Given a dependency named `types-requests` is parsed alongside `requests`, When `parse_all_dependency_files` returns, Then `types-requests` has `is_type_stub=True`, `status=IN_USE`, and `reason` references `requests`
- [] Given a dependency named `django-stubs` is parsed without a corresponding `django` dependency, When `parse_all_dependency_files` returns, Then `django-stubs` has `is_type_stub=True`, `status=UNCERTAIN`, and `reason` states the runtime package was not found
- [] Given a dependency named `types-stripe` is parsed without a corresponding `stripe` dependency, When `parse_all_dependency_files` returns, Then `types-stripe` has `is_type_stub=True` and `status=UNCERTAIN`
- [] Given a non-stub dependency such as `requests`, When `parse_all_dependency_files` returns, Then `is_type_stub=False`
- [] Given the `type_stubs` fixture, When `parse_all_dependency_files` is called, Then `types-requests` and `types-boto3` are `IN_USE`, `django-stubs` and `types-stripe` are `UNCERTAIN`, and all four have `is_type_stub=True`
- [] Given a `Dependency` with `is_type_stub=True`, When passed to REQ-3 source analyser, Then import scanning is skipped for that package
- [] Given any `Dependency` returned by `parse_all_dependency_files`, When inspected, Then `entry_points` is an empty list, `entry_points_used` is `0`, and `entry_points_total` is `0`