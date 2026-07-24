# Project Foundation & CLI Scaffold

## Overview
Bootstrap the Scarno Python package: project structure, Typer CLI, shared data models, stub analysers, output formatters, security tooling, and GitHub Actions CI. Downstream requirements (REQ-2 through REQ-7) plug into the interfaces defined here.

## Problem Statement
No runnable entry point or shared contract exists yet. Without a foundation, parallel development of language analysers and the report engine has no consistent interface to target.

## Solution
Create a fully installable Python package with a working `scarno <path>` command, stub analysis engine returning placeholder results, and CI that enforces tests and security scans on every push.

## Project Structure

```
scarno/
├── src/
│   └── scarno/
│       ├── __init__.py
│       ├── cli.py                  # Typer entry point
│       ├── models.py               # AnalysisResult, DependencyStatus
│       ├── core/
│       │   ├── __init__.py
│       │   ├── base_analyser.py    # Abstract base class for all analysers
│       │   └── detector.py         # Project type auto-detection
│       ├── analysers/
│       │   ├── __init__.py
│       │   ├── python/
│       │   │   └── __init__.py
│       │   └── java/
│       │       └── __init__.py
│       └── reporters/
│           ├── __init__.py
│           ├── text.py
│           └── json_reporter.py
├── tests/
│   ├── __init__.py
│   ├── test_cli.py
│   ├── test_detector.py
│   ├── test_models.py
│   └── fixtures/
│       └── simple_python/          # One used dep, one unused dep
│           ├── pyproject.toml
│           └── main.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── .opengrep/
│   └── rules/                      # Custom opengrep SAST rules
├── pyproject.toml
├── THREAT_MODEL.md
├── AGENTS.md
├── SPECIFICATION.md
└── README.md
```

## Shared Data Models (`models.py`)

**DependencyStatus** (enum)
- `SAFE` — no usage detected; safe to remove
- `UNCERTAIN` — dynamic/reflective usage detected; manual review required
- `IN_USE` — confirmed usage found

**EntryPoint** (dataclass)
- `name: str` — fully-qualified symbol name (e.g. `requests.get`, `com.google.common.collect.ImmutableList`)
- `kind: str` — one of `"function"`, `"class"`, `"method"`, `"constant"` (best-effort; `"unknown"` if not determinable)
- `used: bool` — `True` if at least one call-site or reference was found in the project's source/bytecode

**Dependency** (dataclass)
- `name: str` — package/artifact name
- `version: str | None` — declared version
- `status: DependencyStatus`
- `reason: str` — human-readable explanation of classification
- `entry_points: list[EntryPoint]` — all public entry points exposed by this dependency; empty list if enumeration was not attempted or not possible
- `entry_points_used: int` — count of entry points where `used=True` (convenience field; must equal `len([e for e in entry_points if e.used])`)
- `entry_points_total: int` — count of all enumerated entry points (convenience field; must equal `len(entry_points)`)

**AnalysisResult** (dataclass)
- `project_type: str` — `"python"` or `"java"`
- `project_path: str` — resolved absolute path
- `dependencies: list[Dependency]`
- `errors: list[str]` — non-fatal warnings or parse errors

## CLI Specification (`cli.py`)

**Command:** `scarno [PATH] [OPTIONS]`

| Argument / Option | Type       | Default | Description                             |
| ----------------- | ---------- | ------- | --------------------------------------- |
| `PATH`            | positional | `.`     | Directory to analyse                    |
| `--format`        | `text\     | json`   | `text`                                  | Output format |
| `--output`        | file path  | stdout  | Write results to file instead of stdout |
| `--verbose`       | flag       | off     | Emit debug-level log lines to stderr    |

**Exit codes:**

| Code | Meaning                                                                          |
| ---- | -------------------------------------------------------------------------------- |
| `0`  | Analysis complete — no `SAFE` dependencies found                                 |
| `1`  | Analysis complete — one or more `SAFE` dependencies found                        |
| `2`  | Analysis failed (unreadable path, unsupported project type, unhandled exception) |

**Auto-detection logic** (`core/detector.py`): scan the target directory for indicator files and return the project type.

| Indicator files present                                                                     | Detected type                                                              |
| ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `pom.xml` or `build.gradle` or `build.gradle.kts`                                           | `java`                                                                     |
| `requirements.txt`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, or `uv.lock` | `python`                                                                   |
| Both sets present                                                                           | `java` (Java takes precedence; log a warning)                              |
| Neither                                                                                     | Exit code 2 with message: `"No supported project type detected in <path>"` |

## Abstract Base Class (`core/base_analyser.py`)

Every language analyser must implement:
- `supports(project_path: str) -> bool` — returns True if this analyser can handle the given directory
- `analyse(project_path: str) -> AnalysisResult` — performs analysis and returns a result

The stub implementations in `analysers/python/` and `analysers/java/` return an `AnalysisResult` with all dependencies classified as `UNCERTAIN` and `reason="stub — analysis not yet implemented"`.

## Output Formatters (`reporters/`)

**Text format** (`reporters/text.py`):
```
Scarno Analysis — <project_path>
Project type: <python|java>

SAFE TO REMOVE (1)
  - requests==2.31.0
    Reason: No import or usage found in source files
    Entry points: 0 / 32 used

UNCERTAIN (1)
  - boto3==1.26.0
    Reason: Referenced via importlib.import_module() — manual review required
    Entry points: 3 / 847 used
      ✓ boto3.client  (function)
      ✓ boto3.Session  (class)
      ✓ boto3.resource  (function)

IN USE (3)
  - flask, sqlalchemy, click
```

Entry point lines are only rendered when `entry_points` is non-empty. Used entry points are prefixed with `✓`; unused entry points are omitted from the text output (they are available in JSON). If enumeration was not attempted, the `Entry points:` line is omitted entirely.

## Packaging & Tooling (`pyproject.toml`)

- Build backend: `hatchling`
- Package source: `src/` layout
- Entry point: `[project.scripts] scarno = "scarno.cli:app"`
- Runtime dependencies: `typer`, `rich` (for text output formatting)
- Dev/test dependencies: `pytest`, `pytest-cov`, `bandit`, `pip-audit`, `mypy`
- Type stub dev dependencies: `types-setuptools` (for `pkg_resources` used in setup.py AST analysis)
- `uv sync` installs all dependencies into the managed venv
- `pip install -e .` installs the package in editable mode

## Type Stubs for Scarno's Own Codebase

Scarno is a fully typed Python codebase. A `py.typed` marker file must be present at `src/scarno/py.typed` to declare inline type support. Type stubs must be declared as dev dependencies for every runtime or dev dependency that does not ship inline types, enabling mypy/pyright to fully type-check the codebase without errors.

**Required type stub packages** (add to `[dependency-groups] dev` in `pyproject.toml`):

| Stub package | Provides types for | Notes |
| ------------ | ------------------ | ----- |
| `types-setuptools` | `setuptools` / `pkg_resources` | Used in setup.py AST analysis (REQ-2) |

**Runtime dependencies that already ship inline types** (no stub needed):

| Package | Reason |
| ------- | ------ |
| `typer` | Ships `py.typed` and full inline annotations |
| `rich`  | Ships `py.typed` and full inline annotations |

**Typing configuration** (add to `pyproject.toml`):
```toml
[tool.mypy]
strict = true
python_version = "3.12"
files = ["src/scarno"]
```

As new runtime dependencies are added in REQ-2 through REQ-7 (e.g., `tomli`, `packaging`), the implementing agent must check whether each package ships inline types or requires a `types-*` stub, and add the stub to `pyproject.toml` accordingly.

## Security Tooling

| Tool        | Purpose                                                | Scope     | Config                                  |
| ----------- | ------------------------------------------------------ | --------- | --------------------------------------- |
| `bandit`    | Python SAST — detects common security issues in source | `src/`    | `pyproject.toml [tool.bandit]`          |
| `pip-audit` | CVE scan of installed dependencies                     | full venv | run as `pip-audit` with no extra config |
| `opengrep`  | Additional SAST rules                                  | `src/`    | `.opengrep/rules/` directory            |

All three run in CI on every push and PR. A bandit or pip-audit finding at severity HIGH or CRITICAL fails the CI build. opengrep failures also fail the build.

## GitHub Actions CI (`.github/workflows/ci.yml`)

Triggers: `push` and `pull_request` on all branches.

Jobs (run in order):
1. **test** — `uv sync && pytest --cov=src/scarno tests/`
2. **typecheck** — `mypy src/scarno` (strict mode; fails on any type error)
3. **bandit** — `bandit -r src/`
4. **pip-audit** — `pip-audit`
5. **opengrep** — `opengrep scan --rules .opengrep/rules/ src/`

All jobs run on `ubuntu-latest`. Python version: 3.12.

## Threat Model (`THREAT_MODEL.md`)

The document must cover these four threat areas:

| Threat                                        | Description                                                                                                                                                                          | Mitigations                                                                                                                                                                                                             |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Supply chain — untrusted project analysis** | Scarno reads and parses files from arbitrary user-supplied directories; a malicious project could contain crafted files designed to exploit parser vulnerabilities                 | Validate all file paths before opening; never execute code from the analysed project; use safe parsers (AST, not `eval`); document that Scarno should be run in a sandboxed environment when analysing untrusted code |
| **Path traversal**                            | `--output` and `PATH` arguments accept user-supplied paths; a crafted path (`../../etc/passwd`) could read or overwrite sensitive files                                              | Resolve all paths with `pathlib.Path.resolve()`; reject paths that escape the intended working directory for reads; warn when `--output` targets a path outside the current working directory                           |
| **Output injection**                          | Dependency names and versions from `pyproject.toml` / `pom.xml` appear verbatim in reports; a crafted dependency name could inject terminal escape sequences or break JSON structure | Sanitise dependency names before rendering in text output (strip ANSI escape sequences); use a proper JSON serialiser (never string interpolation) for JSON output                                                      |
| **Privilege escalation in CI**                | Running Scarno as root in a CI container gives it unnecessary access to the host filesystem                                                                                        | Document that Scarno must not run as root; CI workflow must use a non-root user; add a runtime check that logs a warning if `os.getuid() == 0`                                                                        |

## Coding Agent Guide (`AGENTS.md`)

`AGENTS.md` lives at the repo root and is the primary orientation document for any AI coding agent (Claude, Codex, Cursor, etc.) working on this codebase. It must cover:

**Sections required:**

1. **Project Overview** — one paragraph describing what Scarno does, who it's for, and the confidence-scoring model (SAFE / UNCERTAIN / IN_USE)
2. **Repository Layout** — annotated directory tree (same as the Project Structure section of this requirement) so the agent knows where everything lives
3. **Architecture & Extension Points** — how to add a new language analyser:
   - Subclass `BaseAnalyser` in `src/scarno/analysers/<lang>/`
   - Implement `supports()` and `analyse()`
   - Register the analyser in `src/scarno/core/detector.py`
4. **Data Model Contract** — description of `DependencyStatus`, `EntryPoint`, `Dependency`, and `AnalysisResult`; emphasise that all analysers must return an `AnalysisResult` and must never raise unhandled exceptions (catch and append to `errors` list instead); note that `entry_points` may be an empty list when enumeration was not attempted, and that `entry_points_used` / `entry_points_total` must always be kept consistent with the `entry_points` list
5. **CLI Conventions** — exit codes (0/1/2), output goes to stdout, debug/warnings go to stderr, `--verbose` enables debug logging
6. **Security Rules** — non-negotiable constraints every agent must follow:
   - Never use `eval()`, `exec()`, or `subprocess` on content from the analysed project
   - Always resolve paths with `pathlib.Path.resolve()` before opening files
   - Strip ANSI escape sequences from dependency names before rendering in text output
   - Use `json.dumps()` (never f-strings) for JSON output
   - Log a warning if `os.getuid() == 0`
7. **Testing Conventions** — run `uv sync && pytest --cov=src/scarno tests/`; fixture projects live in `tests/fixtures/`; smoke tests use `typer.testing.CliRunner`
8. **CI Pipeline** — describe the four jobs (test, bandit, pip-audit, opengrep) and what causes each to fail
9. **Out of Scope (do not implement)** — auto-removal/code rewriting, IDE plugin, CVE enrichment; link to SPECIFICATION.md for full scope

## Full Tool Specification (`SPECIFICATION.md`)

`SPECIFICATION.md` lives at the repo root and is the single authoritative reference for the complete behaviour of Scarno across all requirements (REQ-1 through REQ-7). It is written for both human developers and AI coding agents.

**Sections required:**

1. **Introduction** — what Scarno is, the problem it solves, and why existing tools (mvn dependency:analyze, pipreqs) fall short
2. **Confidence Model** — define the three classification levels:
   - `SAFE` — no usage detected by any analysis method; safe to remove
   - `UNCERTAIN` — dynamic, reflective, or declarative usage detected; manual review required
   - `IN_USE` — confirmed direct usage found in source or bytecode
3. **CLI Reference** — full command syntax, all arguments and options (PATH, --format, --output, --verbose), all exit codes with their meanings
4. **Project Type Detection** — the full detection table (indicator files → detected type, precedence rules, error case)
5. **Python Analysis** (REQ-2 & REQ-3 scope):
   - Supported config files: `requirements.txt`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`
   - Source analysis: AST-based import detection, dynamic import heuristics (`importlib.import_module`, `__import__`, `importlib.util.spec_from_file_location`)
   - DI pattern detection: `dependency-injector` container declarations, `inject` decorators
   - Classification rules: direct import → IN_USE; dynamic/reflective import → UNCERTAIN; no import found → SAFE
6. **Java/Kotlin Analysis** (REQ-4, REQ-5 & REQ-6 scope):
   - Maven: POM hierarchy traversal (parent POM resolution, `<dependencyManagement>`, BOM imports via `import` scope)
   - Gradle: `build.gradle` and `build.gradle.kts` parsing, multi-module project support
   - Source analysis: direct class/method references, annotation scanning (`@Autowired`, `@Bean`, `@Component`, `@Inject`, `@Resource`, `@Qualifier`)
   - Bytecode analysis: ASM-based class reference scanning of compiled `.class` files
   - Reflection heuristics: `Class.forName()`, `ClassLoader.loadClass()`, string literals matching dependency package prefixes → UNCERTAIN
   - Kotlin: `.kt` source file scanning alongside `.java`
7. **Report Engine** (REQ-7 scope):
   - Text format: section headers (SAFE TO REMOVE, UNCERTAIN, IN USE), per-dependency name/version/reason, entry point summary line (`X / Y used`) when enumeration data is present, used entry point symbols prefixed with `✓`; unused entry points omitted from text (available in JSON only)
   - JSON format: full `AnalysisResult` serialisation schema including the `entry_points` array per dependency, with each `EntryPoint` serialised as `{name, kind, used}`; field names and types documented
   - Output injection prevention: ANSI stripping for text, `json.dumps()` for JSON; entry point symbol names must also be sanitised before text rendering
8. **Security Model** — summary of the four threat areas from THREAT_MODEL.md with mitigations
9. **Extension Guide** — how to add a new language analyser (mirrors AGENTS.md section 3)
10. **Out of Scope** — auto-removal, IDE plugin, CVE enrichment, Groovy DSL Gradle (Kotlin DSL only for v1)

## End-to-End Smoke Test

Fixture project at `tests/fixtures/simple_python/`:
- `pyproject.toml` declares two dependencies: `requests` (used) and `boto3` (unused)
- `main.py` imports `requests` but not `boto3`

The smoke test (`tests/test_cli.py`) invokes the CLI via `typer.testing.CliRunner`, passes `--format json`, and asserts:
- Exit code is `0` or `1` (not `2`)
- Output is valid JSON
- `boto3` appears in the result (status may be `UNCERTAIN` for the stub — the test asserts presence, not final classification)
- `requests` appears in the result

This test passes with stub analysers and continues to pass as real analysers are wired in.

## Out of Scope
- Real analysis logic — stubs only; REQ-2 through REQ-7 implement the engines
- Auto-fix or dependency removal
- IDE plugin or web interface
- CVE enrichment in reports

## Acceptance Criteria
- [] Given the repo is cloned and `uv sync` is run, When a developer runs `pip install -e .`, Then `scarno --help` prints usage without error
- [] Given a directory containing `pyproject.toml`, When `scarno <path>` is run, Then the detector returns project type `python`
- [] Given a directory containing `pom.xml`, When `scarno <path>` is run, Then the detector returns project type `java`
- [] Given a directory containing both `pom.xml` and `pyproject.toml`, When `scarno <path>` is run, Then the detector returns `java` and logs a warning to stderr
- [] Given a directory with no supported indicator files, When `scarno <path>` is run, Then the CLI exits with code `2` and prints `"No supported project type detected"`
- [] Given a valid project directory, When `scarno <path> --format json` is run, Then stdout is valid JSON that deserialises into an object with `project_type`, `project_path`, and `dependencies` fields
- [] Given a valid project directory, When `scarno <path> --format text` is run, Then stdout contains at least one of the section headers: `SAFE TO REMOVE`, `UNCERTAIN`, or `IN USE`
- [] Given `--output report.json` is passed, When the command completes, Then the file `report.json` is created and contains the same content that would have been printed to stdout
- [] Given `--verbose` is passed, When the command runs, Then debug lines are emitted to stderr (not stdout) and do not corrupt the primary output
- [] Given the stub analyser is active, When any project is analysed, Then all dependencies are classified as `UNCERTAIN` with reason containing `"stub"`
- [] Given the `simple_python` fixture, When the smoke test runs via `pytest`, Then the test passes, exit code is not `2`, and both `requests` and `boto3` appear in the JSON output
- [] Given a push or PR to any branch, When GitHub Actions runs, Then all five jobs (test, typecheck, bandit, pip-audit, opengrep) execute and the workflow fails if any job fails
- [] Given `pytest --cov=src/scarno tests/` is run, When the suite completes, Then coverage is reported without error (no minimum threshold enforced at this stage)
- [] Given `THREAT_MODEL.md` exists at repo root, When it is opened, Then it contains sections covering supply chain, path traversal, output injection, and privilege escalation threats with mitigations for each
- [] Given Scarno is run as root, When the CLI starts, Then a warning is printed to stderr: `"Warning: running as root is not recommended"`
- [] Given a dependency name containing ANSI escape sequences, When text output is rendered, Then the escape sequences are stripped and do not appear in the terminal output
- [] Given `--format json` is used and a dependency name contains special characters, When the output is parsed, Then the JSON is valid and the dependency name is correctly escaped
- [] Given `AGENTS.md` exists at repo root, When it is opened, Then it contains sections covering project overview, repository layout, architecture & extension points, data model contract, CLI conventions, security rules, testing conventions, CI pipeline, and out-of-scope items
- [] Given `SPECIFICATION.md` exists at repo root, When it is opened, Then it contains sections covering introduction, confidence model, CLI reference, project type detection, Python analysis, Java/Kotlin analysis, report engine, security model, extension guide, and out-of-scope items
- [] Given `src/scarno/py.typed` exists, When the package is installed, Then mypy and pyright recognise Scarno as a typed package
- [] Given `mypy src/scarno` is run in strict mode, When the command completes, Then it exits with code `0` and reports no type errors
- [] Given `types-setuptools` is declared as a dev dependency, When `uv sync` is run, Then the stub package is installed and mypy resolves `pkg_resources` types without error
- [] Given a `Dependency` is constructed with an `entry_points` list, When `entry_points_used` and `entry_points_total` are accessed, Then they equal the count of `used=True` entries and the total list length respectively
- [] Given `--format json` is run and entry point data is present, When the output is parsed, Then each dependency object contains `entry_points`, `entry_points_used`, and `entry_points_total` fields
- [] Given `--format text` is run and a dependency has non-empty `entry_points`, When the output is rendered, Then an `Entry points: X / Y used` summary line appears and each used symbol is listed with a `✓` prefix
- [] Given a new runtime dependency is added to `pyproject.toml`, When it does not ship inline types, Then a corresponding `types-*` stub package must also be added to the dev dependencies