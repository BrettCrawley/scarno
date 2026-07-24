# Phantom & Undeclared Import Reporter

## Overview
Detect imports in source code that resolve to installed packages but are **not** declared in any dependency file — and, conversely, detect installed packages that appear used in source but were never declared. These are "phantom" or "undeclared" dependencies: they work today because a transitive installed them, but they are latent breakage when the transitive goes away.

Also detect imports that resolve to **vendored/in-repo copies** of a package (common directories: `vendor/`, `third_party/`, `_vendor/`, `site-packages/` committed in-repo) so that a declared package with a matching vendored copy is flagged as potentially redundant at the dep-file level.

## Problem Statement
Today's `SAFE` / `IN_USE` / `UNCERTAIN` model only classifies **declared** dependencies. It says nothing about imports that have no declaration, which is the most common source of production breakage when an engineer removes "an unused transitive" from the lock file.

## Solution
Extend the REQ-3 `analyse_source_files` pass to emit a new kind of entry — `UNDECLARED` — representing packages imported from source but absent from the declared list. Also introduce a detection pass for vendored code.

## `DependencyStatus` Extension

Add a new enum value:

```python
class DependencyStatus(str, Enum):
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"
    IN_USE = "IN_USE"
    UNDECLARED = "UNDECLARED"   # imported but not in any dep file
```

Reporter (REQ-7) adds a new section `UNDECLARED (N)` rendered between `UNCERTAIN` and `IN USE`.

## Detection Algorithm

1. Run REQ-3 source analysis as normal; collect every top-level import name encountered across `.py` and `.ipynb` cells.
2. Normalise each import name (PEP 503).
3. For each normalised import name:
    - If stdlib → skip.
    - If it matches a declared dep (after alias resolution) → already handled by REQ-3.
    - Else → **phantom candidate**. Look it up in the active environment:
        - Use `importlib.metadata.packages_distributions()` to map import name → distribution name.
        - If found: emit `Dependency(name=<distribution>, version=<installed version>, status=UNDECLARED, reason="imported in <file>:<line> but not declared in any dependency file", source="detected:<file>")`.
        - If not found: emit `Dependency(name=<import_name>, version=None, status=UNDECLARED, reason="imported but neither declared nor installed — likely local module or typo", source="detected:<file>")`. Mark with an additional flag `resolved: bool = False` on the `Dependency`.

## Vendored-Code Detection

Scan for conventional vendor directory names at any depth under `project_path`:

| Directory name | Treatment |
|---|---|
| `vendor/`, `_vendor/`, `third_party/`, `thirdparty/` | Scanned as "vendored" |
| `site-packages/` committed inside the repo (not `.venv/site-packages/`) | Treated as vendored |

For each vendored package, check whether the **same package name** is also declared:

- Both declared AND vendored → emit a `Finding` of kind `VENDORED_OVERLAP` (see REQ-3c): `"Package <name> is both declared in <dep_file> and vendored under <vendor_path>"`.
- Vendored only → do not emit a dep entry; emit a `Finding` of kind `VENDORED_ONLY` for visibility.
- Never downgrade a declared dep to `SAFE` when a vendored copy exists without explicit confirmation — the declared dep may still be what's actually imported at runtime.

## Notebook Support

Walk for `*.ipynb` files. Parse JSON. Extract `cell.source` for every `cell.cell_type == "code"`. Apply the same AST extraction as for `.py` files. Notebook cells also run through REQ-3c's suspicious-install detection (for `!pip install ...` / `%pip install ...` magic lines).

## `Dependency` Model Additions

```python
@dataclass
class Dependency:
    ...
    resolved: bool = True    # False when UNDECLARED and not installed
    vendored_path: str | None = None   # set when a vendored copy exists
```

## Error Handling

| Condition | Action |
|-----------|--------|
| `importlib.metadata.packages_distributions()` raises | Append `"phantom_detector: distribution map lookup failed — {detail}"` to errors; continue with static import names only |
| `.ipynb` invalid JSON | Append `"notebook: invalid JSON in {path} — {detail}"`; skip file |
| `.ipynb` cell source is non-string | Skip cell |

All errors non-fatal.

## Test Fixtures

### `phantom_imports/`
```
# pyproject.toml
[project]
dependencies = ["requests==2.31.0"]

# main.py
import requests
import yaml  # pyyaml is not declared; pulled in transitively
```
Expected: `requests=IN_USE`; a second dep `pyyaml` with `status=UNDECLARED`.

### `undeclared_unresolved/`
```
# pyproject.toml
[project]
dependencies = []

# main.py
import nonexistent_module_xyz
```
Expected: `nonexistent_module_xyz` returned with `status=UNDECLARED`, `resolved=False`, `version=None`.

### `vendored/`
```
# pyproject.toml
[project]
dependencies = ["requests==2.31.0"]

# main.py
import requests

# vendor/requests/__init__.py
# (local vendored copy)
```
Expected: `requests=IN_USE`; a `Finding` of kind `VENDORED_OVERLAP` referencing both `pyproject.toml` and `vendor/requests/`.

## Acceptance Criteria
- [] Given `phantom_imports/`, When analysed, Then `pyyaml` appears with `status=UNDECLARED` and reason references the import location
- [] Given `undeclared_unresolved/`, When analysed, Then `nonexistent_module_xyz` appears with `status=UNDECLARED` and `resolved=False`
- [] Given `vendored/`, When analysed, Then `requests` is `IN_USE` AND a `VENDORED_OVERLAP` finding is emitted
- [] Given a `.ipynb` notebook with `import pandas` in a code cell and `pandas` undeclared, When analysed, Then `pandas` appears as `UNDECLARED`
- [] Given the reporter renders text output, When a result contains UNDECLARED deps, Then an `UNDECLARED (N)` section appears between `UNCERTAIN` and `IN USE`
- [] Given `importlib.metadata.packages_distributions()` raises, When analysed, Then analysis continues and a non-fatal error is appended
- [] Given a stdlib import not in any dep file, When analysed, Then it does NOT appear as `UNDECLARED`
- [] Given an alias'd import (`import cv2`), When `opencv-python` is not declared but `cv2` is installed, Then the UNDECLARED dep is named `opencv-python` (not `cv2`)
- [] Given any `Dependency` emitted with `status=UNDECLARED`, When inspected, Then `source` begins with `"detected:"`
- [] Given a project with only declared deps and no phantom imports, When analysed, Then no `UNDECLARED` entries are added
