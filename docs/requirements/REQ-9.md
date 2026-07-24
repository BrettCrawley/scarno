# Polyglot Foundations

## Overview
Extend the Scarno foundations so multiple language ecosystems can coexist in a single analysis run. No new language analysers are added here — this requirement is **purely foundational**, scheduled for Phase 2.5 (between Phase 2's Maven/JVM and Phase 3's Gradle) so that REQ-10..14 (JS/TS, CSS, Go) plug in cleanly without retrofitting the core.

## Problem Statement
Today:

- `detect_project_type` returns a single string — `"java"` or `"python"` or `None` — and Java wins outright when both are present.
- `Dependency` has no ecosystem field; a dep called `react` (npm) and `react-native-web` (pypi) would appear identical in the JSON output.
- The CLI's `_select_analyser` picks exactly **one** analyser; polyglot monorepos (Python backend + JS frontend + Go sidecar) get only the first-detected language analysed.
- Reporters don't segment findings by ecosystem; a 1000-dep monorepo would render one flat list.

Adding JS/TS/CSS/Go in that shape would mean retrofitting each of those concerns four times. Do it once here.

## Solution
Introduce an explicit ecosystem axis across the core model, detector, orchestrator, and reporters. Extend the analyser registry so new languages register themselves without touching `cli.py`.

## Scope (what changes)

### 1. `Dependency.ecosystem` field

```python
@dataclass
class Dependency:
    name: str
    version: str | None
    status: DependencyStatus
    reason: str
    ...
    ecosystem: str = "unknown"  # new — e.g. "pypi", "maven", "npm", "go"
```

Canonical ecosystem values (enforce via constant set in `models.py`):

| Value | Meaning |
|---|---|
| `pypi` | Python (REQ-2) |
| `maven` | Maven artifacts (REQ-4) |
| `gradle` | Gradle deps (REQ-5; may alias to `maven` for reporting) |
| `npm` | npm / yarn / pnpm / bun / Node.js (REQ-10) |
| `css` | CSS-only deps — discriminated from npm (REQ-12) |
| `go` | Go modules (REQ-13) |
| `nuget` | C# / F# / VB.NET NuGet packages (REQ-15) |
| `detected` | REQ-3b phantom imports whose ecosystem couldn't be resolved |

Every existing analyser updates its emitted deps to carry the appropriate value:
- `PythonAnalyser` → `ecosystem="pypi"` (exception: phantom-import deps keep `"detected"`)
- `MavenPomResolver` → `ecosystem="maven"`
- `GradleBuildResolver` (when it lands in Phase 3) → `ecosystem="gradle"`

Existing tests that compare `Dependency` values need minor updates; the field defaults to `"unknown"` so old-shape fixtures still construct.

### 2. `AnalysisResult.languages` field + canonical `project_type`

```python
@dataclass
class AnalysisResult:
    project_type: str  # unchanged meaning: primary / dominant language
    project_path: str
    dependencies: list[Dependency] = ...
    errors: list[str] = ...
    findings: list[Finding] = ...
    languages: list[str] = field(default_factory=list)  # all detected
```

`project_type` stays for compatibility with existing JSON consumers and the CLI's smoke tests. `languages` is the authoritative "which ecosystems were scanned" list.

### 3. Detector returns **all** applicable types

Replace the single-string return with a list-returning function. Keep the old helper as a backward-compat thin wrapper:

```python
def detect_project_types(project_path: str | Path) -> list[str]:
    """Return all applicable types (may be empty)."""

def detect_project_type(project_path: str | Path) -> str | None:
    """Return the primary type (first element of detect_project_types).
    Retained for REQ-1 smoke tests and external consumers."""
```

Indicator-file table extended for Phase 5 / 6 / 7 readiness (but the corresponding analysers don't have to exist yet — they're plugged in by REQ-10 / REQ-13 / REQ-15):

| File(s) | Detected type |
|---|---|
| `pom.xml`, `build.gradle`, `build.gradle.kts` | `java` |
| `pyproject.toml`, `requirements.txt`, `setup.py`, `setup.cfg`, `Pipfile*`, `poetry.lock`, `uv.lock`, `environment.yml` | `python` |
| `package.json`, `yarn.lock`, `pnpm-lock.yaml`, `package-lock.json`, `bun.lockb`, `deno.json`, `deno.jsonc`, `tsconfig.json`, `jsconfig.json` | `javascript` |
| `.css`, `.scss`, `.sass`, `.less` present **without** any JS indicator | `css` |
| `go.mod`, `go.sum` | `go` |
| `*.csproj`, `*.fsproj`, `*.vbproj`, `*.sln`, `global.json`, `Directory.Packages.props`, `packages.config`, `packages.lock.json`, `nuget.config` | `csharp` |

The "both sets present" precedence rule is gone — we now analyse everything applicable.

### 4. Analyser registry + orchestrator

Replace the hard-coded `_select_analyser` dispatch with a registry:

```python
# src/scarno/core/registry.py (new)

_ANALYSERS: dict[str, type[BaseAnalyser]] = {}

def register(language: str, cls: type[BaseAnalyser]) -> None: ...
def get_analyser(language: str) -> BaseAnalyser | None: ...
def analysers_for(languages: list[str]) -> list[BaseAnalyser]: ...
```

Each analyser module registers itself at import time:

```python
# src/scarno/analysers/python/__init__.py
from scarno.core.registry import register
register("python", PythonAnalyser)
```

CLI orchestrator becomes:

```python
languages = detector.detect_project_types(project_path)
if not languages:
    raise _CliError("No supported project type detected ...")

aggregate_deps: list[Dependency] = []
aggregate_errors: list[str] = []
aggregate_findings: list[Finding] = []
for analyser in registry.analysers_for(languages):
    result = analyser.analyse(str(project_path))
    aggregate_deps.extend(result.dependencies)
    aggregate_errors.extend(result.errors)
    aggregate_findings.extend(result.findings)

merged = AnalysisResult(
    project_type=languages[0],  # primary — first-detected
    project_path=str(project_path),
    dependencies=aggregate_deps,
    errors=aggregate_errors,
    findings=aggregate_findings,
    languages=languages,
)
```

### 5. Reporter updates

- **Text reporter**: when `len(result.languages) > 1`, sub-section each status block by ecosystem. Example:
  ```
  SAFE TO REMOVE (3)
    [pypi]
      - boto3==1.26.0
    [npm]
      - lodash@4.17.21
      - left-pad@1.3.0
  ```
  Single-language projects render unchanged.
- **JSON reporter**: `languages` array at the top level; every dep object already has `ecosystem` (from the model change).
- **Markdown reporter**: `## Suggested removals (SAFE)` gets per-ecosystem `### [npm]` sub-headings only when multi-language.
- **SARIF reporter**: `properties.ecosystem` on each result; driver `rules` array gains `TS-DEP-SAFE-NPM`, `TS-DEP-SAFE-GO` variants only if useful (a single rule per status is simpler — ecosystem is a property).

### 6. `--language` / `-L` CLI filter

```
--language LANG      Restrict analysis to one ecosystem
                     (pypi, maven, gradle, npm, css, go).
                     May be passed multiple times.
```

Useful in monorepos where CI pipelines want per-language gating:
```yaml
- run: scarno . --language pypi --fail-on-severity HIGH
- run: scarno . --language npm --fail-on-severity CRITICAL
```

When omitted, behaviour is unchanged from today (analyse everything detected).

### 7. Exit-code semantics

Unchanged — `3 > 1 > 0`. `2` on failure. Exit codes look at merged results across all ecosystems.

### 8. Security considerations (across the foundation)

| Concern | Mitigation |
|---|---|
| Detection uses `Path.exists()` — a crafted symlink could trick the detector | Detection only reads existence, never opens; analyser-level confinement catches the open path |
| Multiple analysers in sequence could amplify timeouts | Keep per-analyser timeouts separate; document total budget |
| Registry is a global mutable dict | Read-only after module import; register only at import time; document in `AGENTS.md` |

### 9. Documentation / SRTM

- `AGENTS.md` section 3 ("How to add a new language analyser") gets rewritten around the registry pattern.
- `Specification.md` "Key Functionality" section lists the six ecosystems.
- New SRTM rows:

| ID | Description |
|---|---|
| FR-096 | `Dependency.ecosystem` populated for every emitted dep |
| FR-097 | `detect_project_types` returns a list of applicable types |
| FR-098 | Orchestrator runs every registered analyser whose language was detected |
| FR-099 | `AnalysisResult.languages` populated with all scanned ecosystems |
| FR-100 | Reporters group by ecosystem when `len(languages) > 1` |
| FR-101 | `--language` CLI filter restricts analysis to the named ecosystem |
| FR-102 | Registry-based analyser lookup (no hard-coded dispatch in `cli.py`) |

## File Layout

```
src/scarno/
├── cli.py                              # refactored orchestrator (no direct class refs)
├── models.py                           # + Dependency.ecosystem + AnalysisResult.languages
├── core/
│   ├── detector.py                     # + detect_project_types(...)
│   └── registry.py                     # NEW — analyser registration
├── analysers/
│   ├── python/__init__.py              # register("python", PythonAnalyser)
│   └── java/__init__.py                # register("java", JavaAnalyser)
└── reporters/                          # each reporter gains per-ecosystem grouping

tests/
├── unit/test_registry.py               # NEW — registration / lookup tests
├── unit/test_polyglot_detector.py      # NEW — multi-language indicator tests
├── unit/test_polyglot_reporter.py      # NEW — grouping rendering tests
└── unit/test_cli.py                    # + --language flag tests
```

## Acceptance Criteria
- [] Given a project with both `pyproject.toml` and `go.mod`, When detector runs, Then `detect_project_types` returns `["python", "go"]` (order deterministic)
- [] Given the same project, When the CLI analyses it, Then both language analysers run and the merged `AnalysisResult` contains deps from each with correct `ecosystem` values
- [] Given `--language pypi` on a polyglot project, When the CLI runs, Then only Python deps appear in the report; Go analyser is not invoked
- [] Given any existing Phase 0b→2 fixture, When analysed after REQ-9 lands, Then the report is byte-identical to the pre-REQ-9 output (minus the new `ecosystem` / `languages` fields in JSON)
- [] Given a polyglot result rendered as text, When multiple ecosystems are present, Then each status section shows `[<ecosystem>]` sub-headings and dep counts per ecosystem
- [] Given a new language analyser is dropped into `src/scarno/analysers/<lang>/`, When it calls `register("<lang>", MyAnalyser)`, Then `cli.py` requires no changes and the CLI automatically dispatches to it
- [] Given the registry, When `get_analyser("nonexistent")` is called, Then it returns `None` rather than raising
- [] Given the `--language` flag is passed an unknown ecosystem, When the CLI runs, Then it exits with code 2 and lists the valid ecosystem names
- [] Given REQ-9 lands, When `mypy --strict` runs, Then no type regressions appear
- [] Given REQ-9 lands, When the SRTM gate runs, Then all FR-096..102 IDs are covered

## Out of Scope
- Actual JS/TS/CSS/Go analysers — those are Phase 5 (REQ-10, REQ-11, REQ-12) and Phase 6 (REQ-13, REQ-14).
- Ecosystem-specific rule IDs in SARIF (we use a properties flag rather than rule-id variants).
- Per-ecosystem `--fail-on-severity` thresholds — that's a Phase 4 extension if users ask for it.
