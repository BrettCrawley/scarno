# Python Source Code Analyser

## Overview
Scan all `.py` files in a project and update each `Dependency` status to `IN_USE`, `UNCERTAIN`, or `SAFE` using AST-based import detection, alias resolution, and dynamic import heuristics. For dependencies classified as `IN_USE`, also enumerate the package's public entry points and cross-reference them against the project's source to populate `entry_points`, `entry_points_used`, and `entry_points_total` on each `Dependency`.

## Problem Statement
REQ-2 returns every declared dependency with `status=UNCERTAIN`. Without source analysis, Depruner cannot distinguish packages that are actively imported from those that are genuinely unused.

## Solution
`analyse_source_files(project_path, dependencies)` walks the project tree, parses each `.py` file with the `ast` module, maps import names to declared packages, and returns an updated dependency list with `IN_USE`, `UNCERTAIN`, or `SAFE` statuses.

## File Layout

```
src/depruner/analysers/python/
├── __init__.py            # PythonAnalyser — calls parse_all_dependency_files then analyse_source_files
├── dep_file_parser.py     # REQ-2 (unchanged)
├── source_analyser.py     # New — public fn analyse_source_files
└── import_aliases.py      # New — IMPORT_ALIASES dict

tests/
├── test_source_analyser.py
└── fixtures/
    └── python_source/
        ├── direct_import/
        ├── from_import/
        ├── dynamic_literal/
        ├── dynamic_nonliteral/
        ├── alias_import/
        ├── stdlib_excluded/
        ├── type_stub_skipped/
        ├── try_except_import/
        ├── syntax_error/
        └── gitignore/
```

## Public Interface

**`source_analyser.py`**
```python
def analyse_source_files(
    project_path: str,
    dependencies: list[Dependency],
) -> tuple[list[Dependency], list[str]]:
    ...
```
Returns `(updated_dependencies, errors)`. Never raises; all failures append to `errors`.

**`PythonAnalyser.analyse()` orchestration** (`__init__.py`)
```python
def analyse(self, project_path: str) -> AnalysisResult:
    deps, errors = parse_all_dependency_files(project_path)
    deps, source_errors = analyse_source_files(project_path, deps)
    return AnalysisResult(
        project_type="python",
        dependencies=deps,
        errors=errors + source_errors,
    )
```

## Source File Discovery

- Recursively walk `project_path` for `*.py` files using `pathlib.Path.resolve()`.
- Exclude directories: `__pycache__/`, `.venv/`, `venv/`, `.tox/`, `build/`, `dist/`, `*.egg-info/`, `.git/`.
- If `.gitignore` exists at project root, parse it with `pathspec` and exclude matching paths. If `pathspec` is not installed, log a debug warning and continue without gitignore filtering.
- Add `pathspec` to runtime dependencies in `pyproject.toml`.

## Import → Package Mapping

### Step 1 — Name normalisation
Normalise both the top-level import name and all dependency names: lowercase, replace `_` and `-` with `-`.

### Step 2 — Stdlib exclusion
Use `sys.stdlib_module_names` (Python 3.10+). For older runtimes, use a bundled fallback set. Stdlib imports are never matched to a declared dependency.

### Step 3 — Alias table (`import_aliases.py`)

| Import name     | Package name      |
| --------------- | ----------------- |
| `pil`           | `pillow`          |
| `cv2`           | `opencv-python`   |
| `sklearn`       | `scikit-learn`    |
| `bs4`           | `beautifulsoup4`  |
| `yaml`          | `pyyaml`          |
| `dateutil`      | `python-dateutil` |
| `dotenv`        | `python-dotenv`   |
| `gi`            | `pygobject`       |
| `pkg_resources` | `setuptools`      |

### Step 4 — Exact match
If the normalised top-level import name matches a normalised dependency name (after alias resolution), the dependency is a candidate for `IN_USE`.

### Step 5 — Unresolved imports
Imports that match no declared dependency and are not in stdlib are silently ignored (local module or transitive dependency).

## AST Detection Patterns

| Pattern                                                                    | AST node                            | Status      | Reason format                                                        |
| -------------------------------------------------------------------------- | ----------------------------------- | ----------- | -------------------------------------------------------------------- |
| `import X`                                                                 | `ast.Import`                        | `IN_USE`    | `imported in {file}:{line}`                                          |
| `from X import Y`                                                          | `ast.ImportFrom`                    | `IN_USE`    | `imported in {file}:{line}`                                          |
| `import X` inside `try/except ImportError`                                 | `ast.Try` body                      | `IN_USE`    | `imported in {file}:{line}`                                          |
| Type annotation referencing package (function arg, class var, return type) | `ast.AnnAssign`, `ast.arg`          | `IN_USE`    | `used as type annotation in {file}:{line}`                           |
| `importlib.import_module("literal")`                                       | `ast.Call` with string constant arg | `IN_USE`    | `dynamically imported via importlib.import_module in {file}:{line}`  |
| `__import__("literal")`                                                    | `ast.Call` with string constant arg | `IN_USE`    | `dynamically imported via __import__ in {file}:{line}`               |
| `importlib.util.find_spec("literal")`                                      | `ast.Call` with string constant arg | `IN_USE`    | `dynamically imported via importlib.util.find_spec in {file}:{line}` |
| `importlib.import_module(non_literal)`                                     | `ast.Call` with non-constant arg    | `UNCERTAIN` | `dynamic import with non-literal module name in {file}:{line}`       |
| `__import__(non_literal)`                                                  | `ast.Call` with non-constant arg    | `UNCERTAIN` | `dynamic import with non-literal module name in {file}:{line}`       |
| `importlib.util.spec_from_file_location(...)`                              | `ast.Call`                          | `UNCERTAIN` | `dynamic import with non-literal module name in {file}:{line}`       |

For dynamic calls with a string literal, extract the top-level module name (first component before `.`) and apply the same alias + dependency matching as direct imports.

## Classification Order

First match wins per dependency:

1. `is_type_stub=True` → **skip** (leave status and reason unchanged from REQ-2)
2. Direct import found → `IN_USE`
3. Type annotation found → `IN_USE`
4. Dynamic import with string literal → `IN_USE`
5. Dynamic import with non-literal → `UNCERTAIN`
6. No import or usage found → `SAFE`, reason `"no import or usage found in source files"`

If a dependency has evidence for both `IN_USE` and `UNCERTAIN` across different files, `IN_USE` takes precedence.


## Entry Point Enumeration

After status classification, for every dependency with `status=IN_USE` (and `is_type_stub=False`), enumerate its public entry points from the installed package and cross-reference them against the project's source AST.

**This step requires the package to be installed in the active Python environment.** If a package is not installed, skip enumeration silently and leave `entry_points=[]`.

### Step 1 — Enumerate public symbols

Use `importlib.import_module` to import the top-level package, then inspect its public API:

1. Collect all names from `package.__all__` if defined — this is the authoritative public API.
2. If `__all__` is absent, collect all names from `dir(package)` that do not start with `_`.
2a. **(FR-271)** Union in every symbol observed in the project's source (from `used_symbols` / `usage_counts`) even when it is absent from `__all__`/`dir()`. Module-level `__getattr__` (PEP 562) lazily provides attributes that may never appear in `dir()`; a symbol the project actually imported must still be reported as a used entry point. If `getattr` raises while resolving such a known-used symbol, surface it as `kind="unknown"` (still `used=True`) rather than dropping it.
2b. **(FR-271)** When a package defines a module-level `__getattr__` (PEP 562) with neither `__all__` nor a module-level `__dir__`, its *unused* lazy surface is not statically enumerable. Append a non-fatal `"entry_point_enumerator: {name} uses module-level __getattr__ (PEP 562) without __dir__; unused lazy attributes may be under-enumerated."` advisory to `errors` and enumerate what is observable. Reading `__all__`/`dir()` is itself wrapped so a hostile/buggy `__getattr__` cannot crash enumeration.
3. For each name, resolve the object and determine its `kind`:
   - `inspect.isfunction(obj)` or `inspect.isbuiltin(obj)` → `"function"`
   - `inspect.isclass(obj)` → `"class"`
   - `inspect.ismethod(obj)` → `"method"`
   - Non-callable, non-module → `"constant"`
   - Anything else → `"unknown"`
4. Store each as `EntryPoint(name=f"{top_level_import}.{symbol}", kind=kind, used=False)`.

**Safety constraints:**
- Never call `eval()`, `exec()`, or `subprocess` during enumeration.
- Wrap the entire enumeration in a broad `except Exception` — if introspection raises for any reason (import side effects, C extension errors, etc.), append `"entry_point_enumerator: could not enumerate {package_name} — {detail}"` to `errors` and leave `entry_points=[]`.
- Do not import packages that are not already installed; use `importlib.util.find_spec` to check presence before importing.

### Step 2 — Cross-reference against source AST

For each `IN_USE` dependency with a non-empty `entry_points` list, scan the already-parsed source ASTs (reuse the ASTs from the import detection pass — do not re-parse) for references to each entry point symbol:

**Patterns that mark an entry point as `used=True`:**

| Pattern | AST node | Example |
| ------- | -------- | ------- |
| Direct name reference after `from pkg import X` | `ast.Name` with matching `id` | `from requests import get` → `get(...)` |
| Attribute access `pkg.symbol` | `ast.Attribute` with matching `attr` on a `pkg`-bound name | `requests.get(url)` |
| Name imported via alias: `import pkg as p` then `p.symbol` | `ast.Attribute` on alias name | `import requests as r` → `r.get(url)` |

Only match symbols that were imported from the correct package — do not mark `used=True` for a symbol name that happens to collide with a local variable or a different package's export.

### Step 3 — Update convenience fields

After cross-referencing, set:
- `entry_points_used = len([e for e in entry_points if e.used])`
- `entry_points_total = len(entry_points)`

### Scoping: SAFE and UNCERTAIN dependencies

- `SAFE` dependencies: `entry_points=[]`, `entry_points_used=0`, `entry_points_total=0` (no enumeration attempted — package is unused).
- `UNCERTAIN` dependencies: `entry_points=[]`, `entry_points_used=0`, `entry_points_total=0` (enumeration not attempted — usage is ambiguous).
- Type stubs (`is_type_stub=True`): unchanged from REQ-2 defaults.

## Error Handling

| Condition                                   | Action                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------ |
| File cannot be read (permissions, encoding) | Append `"source_analyser: could not read {path} — {detail}"` to `errors`; skip file  |
| File has a syntax error                     | Append `"source_analyser: syntax error in {path} — {detail}"` to `errors`; skip file |
| `pathspec` not installed                    | Log debug warning; continue without gitignore filtering                              |
| Package not installed (entry point enum)    | Skip enumeration silently; leave `entry_points=[]`                                   |
| Introspection raises during enumeration     | Append `"entry_point_enumerator: could not enumerate {name} — {detail}"` to `errors`; leave `entry_points=[]` |

All errors are non-fatal. Analysis continues with remaining files.

## Test Fixtures

### `direct_import/`
```python
# main.py
import requests
```
Declared: `requests`, `boto3`. Expected: `requests=IN_USE`, `boto3=SAFE`.

### `from_import/`
```python
# main.py
from flask import Blueprint
```
Declared: `flask`. Expected: `flask=IN_USE`.

### `dynamic_literal/`
```python
# main.py
importlib.import_module("requests")
```
Declared: `requests`. Expected: `requests=IN_USE`.

### `dynamic_nonliteral/`
```python
# main.py
mod = "requests"
importlib.import_module(mod)
```
Declared: `requests`. Expected: `requests=UNCERTAIN`.

### `alias_import/`
```python
# main.py
from PIL import Image
```
Declared: `pillow`. Expected: `pillow=IN_USE`.

### `stdlib_excluded/`
```python
# main.py
import os, sys, json
```
Declared: `os` (hypothetical). Expected: all `SAFE` (stdlib exclusion).

### `type_stub_skipped/`
No imports in any `.py` file. Declared: `requests` (`is_type_stub=False`), `types-requests` (`is_type_stub=True`, `status=IN_USE` from REQ-2). Expected: `requests=SAFE`; `types-requests` status unchanged from REQ-2.

### `try_except_import/`
```python
# main.py
try:
    import requests
except ImportError:
    pass
```
Declared: `requests`. Expected: `requests=IN_USE`.

### `syntax_error/`
Contains `broken.py` (invalid Python) and `valid.py` (`import flask`). Declared: `flask`. Expected: `flask=IN_USE`; 1 syntax error appended to `errors`.

### `gitignore/`
```
# .gitignore
vendor/
```
`vendor/main.py` contains `import requests`. Declared: `requests`. Expected: `requests=SAFE` (vendor/ excluded by gitignore).


### `entry_point_enum/`
```python
# main.py
import requests
response = requests.get("https://example.com")
session = requests.Session()
```
Declared: `requests` (installed in test environment). Expected: `requests=IN_USE`; `entry_points` non-empty; `requests.get` has `used=True`; `requests.Session` has `used=True`; `entry_points_used >= 2`; `entry_points_total > 0`.

### `entry_point_not_installed/`
```python
# main.py
import requests
```
Declared: `requests` (NOT installed — simulate via monkeypatching `importlib.util.find_spec` to return `None`). Expected: `requests=IN_USE`; `entry_points=[]`; `entry_points_used=0`; `entry_points_total=0`; no error appended.

### `entry_point_introspection_error/`
Declared: `requests` (installed). Monkeypatch `importlib.import_module` to raise `RuntimeError("boom")` for `requests`. Expected: `requests=IN_USE`; `entry_points=[]`; 1 error appended containing `"entry_point_enumerator"` and `"boom"`.

### `entry_point_safe_dep/`
```python
# main.py
# (no imports)
```
Declared: `requests`, `boto3`. Expected: both `SAFE`; both have `entry_points=[]`, `entry_points_used=0`, `entry_points_total=0`.

## Acceptance Criteria
- [] Given `direct_import/` with `import requests` and declared deps `requests` and `boto3`, When `analyse_source_files` is called, Then `requests` has `status=IN_USE` with reason containing the filename and line number, and `boto3` has `status=SAFE`
- [] Given `from_import/` with `from flask import Blueprint` and declared dep `flask`, When `analyse_source_files` is called, Then `flask` has `status=IN_USE`
- [] Given `dynamic_literal/` with `importlib.import_module("requests")` and declared dep `requests`, When `analyse_source_files` is called, Then `requests` has `status=IN_USE` and reason references `importlib.import_module`
- [] Given `dynamic_nonliteral/` with `importlib.import_module(variable)` and declared dep `requests`, When `analyse_source_files` is called, Then `requests` has `status=UNCERTAIN` and reason states non-literal module name
- [] Given `__import__("requests")` with a string literal and declared dep `requests`, When `analyse_source_files` is called, Then `requests` has `status=IN_USE`
- [] Given `__import__(variable)` with a non-literal arg and declared dep `requests`, When `analyse_source_files` is called, Then `requests` has `status=UNCERTAIN`
- [] Given `importlib.util.find_spec("requests")` with a string literal and declared dep `requests`, When `analyse_source_files` is called, Then `requests` has `status=IN_USE`
- [] Given `importlib.util.spec_from_file_location("mod", path)` and declared dep `requests`, When `analyse_source_files` is called, Then `requests` has `status=UNCERTAIN`
- [] Given `alias_import/` with `from PIL import Image` and declared dep `pillow`, When `analyse_source_files` is called, Then `pillow` has `status=IN_USE` via the `pil→pillow` alias
- [] Given `stdlib_excluded/` with `import os, sys, json` and no non-stdlib declared deps, When `analyse_source_files` is called, Then no stdlib module is matched to any declared dependency
- [] Given `type_stub_skipped/` with `types-requests` having `is_type_stub=True`, When `analyse_source_files` is called, Then `types-requests` status and reason are identical to the values passed in (not modified)
- [] Given `try_except_import/` with `import requests` inside a `try/except ImportError` block, When `analyse_source_files` is called, Then `requests` has `status=IN_USE`
- [] Given a type annotation `def fn(client: boto3.Session)` and declared dep `boto3`, When `analyse_source_files` is called, Then `boto3` has `status=IN_USE` with reason referencing type annotation
- [] Given a dependency with both `IN_USE` evidence in one file and `UNCERTAIN` evidence in another, When `analyse_source_files` is called, Then the final status is `IN_USE`
- [] Given a declared dependency with no matching import anywhere in the project, When `analyse_source_files` is called, Then the dependency has `status=SAFE` and reason `"no import or usage found in source files"`
- [] Given `syntax_error/` with `broken.py` and `valid.py` importing `flask`, When `analyse_source_files` is called, Then `flask` has `status=IN_USE`, 1 error is appended containing the path and syntax detail, and analysis of other files completes
- [] Given an unreadable `.py` file (permission denied), When `analyse_source_files` is called, Then an error is appended with the path and detail, and analysis continues with remaining files
- [] Given `gitignore/` with `vendor/` in `.gitignore` and `vendor/main.py` importing `requests`, When `analyse_source_files` is called, Then `requests` has `status=SAFE` because `vendor/` is excluded
- [] Given a project with no `.gitignore`, When `analyse_source_files` is called, Then analysis completes without error
- [] Given `pathspec` is not installed, When `analyse_source_files` is called on a project with `.gitignore`, Then a debug warning is emitted, gitignore filtering is skipped, and analysis completes without raising
- [] Given directories `__pycache__/`, `.venv/`, `venv/`, `.tox/`, `build/`, `dist/`, `*.egg-info/`, `.git/`, When `analyse_source_files` walks the project, Then no `.py` files inside those directories are parsed
- [] Given `import cv2` and declared dep `opencv-python`, When `analyse_source_files` is called, Then `opencv-python` has `status=IN_USE` via the `cv2→opencv-python` alias
- [] Given `import sklearn` and declared dep `scikit-learn`, When `analyse_source_files` is called, Then `scikit-learn` has `status=IN_USE` via the `sklearn→scikit-learn` alias
- [] Given `import bs4` and declared dep `beautifulsoup4`, When `analyse_source_files` is called, Then `beautifulsoup4` has `status=IN_USE` via the `bs4→beautifulsoup4` alias
- [] Given `import yaml` and declared dep `pyyaml`, When `analyse_source_files` is called, Then `pyyaml` has `status=IN_USE` via the `yaml→pyyaml` alias
- [] Given `import pkg_resources` and declared dep `setuptools`, When `analyse_source_files` is called, Then `setuptools` has `status=IN_USE` via the `pkg_resources→setuptools` alias
- [] Given `analyse_source_files` is called, Then no `eval()` or `exec()` calls are made on any source file content
- [] Given `PythonAnalyser.analyse(project_path)` is called on a project with both config files and source files, When it returns, Then the result is an `AnalysisResult` with `project_type="python"` and dependency statuses reflect both REQ-2 parsing and source analysis
- [] Given `from X.Y.Z import something` and declared dep `X`, When `analyse_source_files` is called, Then `X` is matched using only the top-level module component

- [] Given `entry_point_enum/` with `import requests` and calls to `requests.get` and `requests.Session`, When `analyse_source_files` is called, Then `requests.get` and `requests.Session` have `used=True`, `entry_points_used >= 2`, and `entry_points_total > 0`
- [] Given `entry_point_enum/`, When `analyse_source_files` is called, Then entry point symbols not referenced in source have `used=False`
- [] Given `from requests import get` and source calls `get(url)`, When `analyse_source_files` is called, Then `requests.get` has `used=True` in the entry points list
- [] Given `import requests as r` and source calls `r.get(url)`, When `analyse_source_files` is called, Then `requests.get` has `used=True` in the entry points list
- [] Given `entry_point_not_installed/` where `requests` is not installed, When `analyse_source_files` is called, Then `requests` has `status=IN_USE`, `entry_points=[]`, `entry_points_used=0`, `entry_points_total=0`, and no error is appended
- [] Given `entry_point_introspection_error/` where introspection raises, When `analyse_source_files` is called, Then `entry_points=[]` and 1 error is appended containing `"entry_point_enumerator"`
- [] Given `entry_point_safe_dep/` with no imports, When `analyse_source_files` is called, Then all dependencies have `status=SAFE` and `entry_points=[]`, `entry_points_used=0`, `entry_points_total=0`
- [] Given a dependency with `status=UNCERTAIN`, When `analyse_source_files` returns, Then `entry_points=[]`, `entry_points_used=0`, and `entry_points_total=0`
- [] Given a dependency with `status=IN_USE` and a package that defines `__all__`, When entry points are enumerated, Then only symbols in `__all__` are included in `entry_points`
- [] Given a dependency with `status=IN_USE` and a package without `__all__`, When entry points are enumerated, Then symbols starting with `_` are excluded from `entry_points`
- [] Given `entry_points_used` and `entry_points_total` on any returned dependency, When inspected, Then `entry_points_used == len([e for e in entry_points if e.used])` and `entry_points_total == len(entry_points)`
- [] Given entry point enumeration runs, Then no `eval()`, `exec()`, or `subprocess` calls are made during introspection