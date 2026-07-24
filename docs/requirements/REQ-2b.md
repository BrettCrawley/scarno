# Extended Python Dependency Format Coverage

## Overview
Extend `parse_all_dependency_files` (REQ-2) to parse three additional declarative surfaces that today sit outside Scarno's view, producing false "unused" findings whenever a project uses them:

1. Conda `environment.yml` / `environment.yaml`
2. PEP 518 `[build-system].requires` in `pyproject.toml`
3. PEP 735 `[dependency-groups]` in `pyproject.toml`

## Problem Statement
`mvn dependency:analyze` analogues for Python chronically miss Conda-managed projects and build-backend requirements. A project that declares `numpy` only in `environment.yml` — or `hatchling` only in `[build-system].requires` — would be told by today's REQ-2 that those packages are undeclared (when in fact they are first-class declared dependencies, just in a format the parser doesn't look at).

## Solution
Add two new per-format parsers to `dep_file_parser.py` and extend the existing `pyproject.toml` parser to read two additional tables. All returned dependencies carry `status=UNCERTAIN` and `reason="declared — source analysis pending"`, exactly as REQ-2 dependencies do, so the REQ-3 source analyser classifies them uniformly.

## Public Interface
No signature changes. Coordinator still returns `(list[Dependency], list[str])`.

## Per-Format Specifications

### 1. `environment.yml` / `environment.yaml` (Conda)

Parse with `yaml` (PyYAML — add to runtime deps, plus `types-PyYAML` to dev deps).

| Section | Notes |
|---------|-------|
| `dependencies:` — top-level list | Each list item is either a scalar string (`"numpy=1.26"`) or a dict `{"pip": [<reqs>]}` |
| Scalar entries | Parse as `<name>[=<version>]` or `<name>[==<version>]`; split on `=` or `==`; store normalised name + version (may be `None`) |
| Nested `pip:` block | Each string is a PEP 508 requirement — delegate to `packaging.requirements.Requirement` |
| `channels:`, `variables:`, `prefix:` | Ignore |

**Python version pseudo-dep:** a scalar entry starting with `python` (e.g., `python=3.12`) is excluded, mirroring Poetry's treatment of the `python` key.

**PII handling:** the `name:` field at the top of `environment.yml` must NOT be stored in any `Dependency` object (it identifies the environment, not a package).

### 2. PEP 518 — `[build-system].requires`

Extend the existing `pyproject.toml` parser.

```toml
[build-system]
requires = ["hatchling", "setuptools>=61", "wheel"]
build-backend = "hatchling.build"
```

| Table | Key | Notes |
|-------|-----|-------|
| `[build-system]` | `requires` | List of PEP 508 strings |

Each entry is parsed via `packaging.requirements.Requirement`.

**Classification:** the returned `Dependency.reason` is `"declared in [build-system].requires — source analysis pending"`. This distinguishes them so REQ-3 can apply a **build-time-only** usage heuristic: build-system requirements often have no runtime imports and should not be reported `SAFE` without strong signal.

### 3. PEP 735 — `[dependency-groups]`

Extend the existing `pyproject.toml` parser.

```toml
[dependency-groups]
test = ["pytest>=8", "pytest-cov"]
docs = ["sphinx", {include-group = "test"}]
```

| Feature | Behaviour |
|---------|-----------|
| String entries | Parse as PEP 508 requirement |
| `{include-group = "<name>"}` | Follow the reference; max depth 10; cycle detection on visited group names |
| Unknown group reference | Append `"pyproject.toml: [dependency-groups] references unknown group '<name>'"` to `errors`; continue |

Each entry returns a `Dependency` with reason `"declared in [dependency-groups].<group> — source analysis pending"`.

## Deduplication & Precedence Updates

Update REQ-2's precedence list. New precedence order (highest → lowest):

1. `Pipfile.lock`
2. `poetry.lock`
3. `uv.lock`
4. `environment.yml` / `environment.yaml` *(new — Conda is often authoritative for data/ML projects)*
5. `requirements.txt`
6. `pyproject.toml` — `[project].dependencies` + `[project.optional-dependencies]`
7. `pyproject.toml` — `[dependency-groups]` *(new)*
8. `pyproject.toml` — `[build-system].requires` *(new — explicitly below runtime deps)*
9. `setup.py`
10. `setup.cfg`
11. `Pipfile`

## `Dependency` Model Extension

Add a single new field to the `Dependency` dataclass (already scaffolded in `models.py`):

```python
@dataclass
class Dependency:
    ...
    source: str = "unknown"   # e.g. "requirements.txt", "pyproject.toml:project",
                              # "pyproject.toml:build-system",
                              # "pyproject.toml:dependency-groups.test",
                              # "environment.yml", "environment.yml:pip"
```

This is the provenance string already implied by per-file parsers; promoting it to a dataclass field lets the reporter show *where* a dep came from, which directly answers the question "am I safe to remove this?" differently depending on whether it's a build-system requirement vs a runtime dep.

## Error Handling

| Condition | Action |
|-----------|--------|
| `environment.yml` is not valid YAML | Append `"environment.yml: YAML parse error — {detail}"`; skip file |
| `environment.yml` contains YAML anchors/aliases with unsafe tags | Parse only via `yaml.safe_load` — never `yaml.load`; on non-safe tag, append error and skip |
| `[build-system]` exists but `requires` is not a list | Append `"pyproject.toml: [build-system].requires must be a list"`; skip table |
| `[dependency-groups]` contains non-string, non-dict item | Append `"pyproject.toml: [dependency-groups].<group> contains invalid item"`; skip item |
| Cycle in `include-group` chain | Append `"pyproject.toml: [dependency-groups] cycle detected: <group1> → <group2> → <group1>"`; stop traversal |

All errors non-fatal.

## Threat Model Additions

New attack surface: YAML parser. Must use `yaml.safe_load` exclusively. A test fixture `environment_malicious/` contains YAML bomb payloads and anchor-expansion attacks; parse time must stay under 5s. Add SRTM rows:

| ID | Description |
|----|-------------|
| SEC-NEW-13 | YAML parsing must use `yaml.safe_load`; no arbitrary tag resolution |
| SEC-NEW-14 | PEP 735 `include-group` recursion depth capped at 10 |

## Acceptance Criteria
- [] Given an `environment.yml` with `dependencies: [numpy=1.26, {pip: [flask>=3]}]`, When parsed, Then `numpy` and `flask` are returned with correct versions
- [] Given `environment.yml` with `python=3.12` in its dependencies list, When parsed, Then `python` is excluded
- [] Given a malformed `environment.yml`, When parsed, Then a YAML parse error is appended and parsing continues with other files
- [] Given `environment.yml` with a YAML anchor-expansion bomb, When parsed, Then parsing terminates within 5 seconds and an error is appended
- [] Given a `pyproject.toml` with `[build-system].requires = ["hatchling"]`, When parsed, Then `hatchling` is returned with `source="pyproject.toml:build-system"`
- [] Given a `pyproject.toml` with `[dependency-groups].test = ["pytest"]`, When parsed, Then `pytest` is returned with `source="pyproject.toml:dependency-groups.test"`
- [] Given a `[dependency-groups]` table with `docs = [{include-group = "test"}]`, When parsed, Then deps from `test` appear under `docs` resolution
- [] Given a circular `include-group` chain, When parsed, Then a cycle error is appended and parsing terminates
- [] Given the same package is declared in both `environment.yml` and `pyproject.toml`, When deduplicated, Then the `environment.yml` version wins (new precedence rule)
- [] Given any `Dependency` returned by an environment.yml-backed parse, When inspected, Then `source` starts with `"environment.yml"`
- [] Given any `Dependency` returned by `parse_all_dependency_files`, When inspected, Then `source` is set to a non-empty string
- [] Given `environment.yml` has a top-level `name: mystack`, When parsed, Then `"mystack"` does not appear as a dependency name in any returned object
