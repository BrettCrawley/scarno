/# Security and Privacy by Design Analysis: Scarno

Date: 2026-04-19
Version: 2.0
Frameworks: STRIDE · LINDDUN · OWASP Top 10 · GDPR / Privacy by Design
Regulatory scope: Assessed below — minimal regulatory exposure; primary risks are supply-chain and local filesystem

---

## Executive Summary

Scarno is a polyglot developer CLI tool that performs static analysis of Python, Java/Kotlin, JavaScript/TypeScript/Node.js, Go, C#/.NET, CSS, and HTML/template projects to identify unused dependencies. It reads arbitrary user-supplied project directories, parses dependency manifests and source code (using tree-sitter native grammars for JS/TS, Go, and C#), optionally invokes `javap` on JARs, scans HTML and 30+ template formats for CDN script/stylesheet references, and produces confidence-scored reports in text, JSON, Markdown, and SARIF 2.1.0 formats. A polyglot orchestrator coordinates multi-ecosystem analysis with `--language` filtering. A GitHub Action (composite) integrates with CI via SARIF upload and PR comments. A findings engine applies 30+ security rules including taint analysis, postinstall hook detection, custom registry detection, unsafe.Pointer usage, cgo, DllImport, Process.Start, Assembly.Load, and more.

The threat surface is broader than initial versions: Scarno parses untrusted file content (XML, TOML, JSON, YAML, Python AST, bytecode, CSS, HTML, Go modules, MSBuild csproj) and renders output to terminals, CI pipelines, SARIF consumers, and PR comments. The primary security risks are:

1. **Path traversal** — a malicious project could use symlinks or `../` sequences in dependency paths to read files outside the intended directory.
2. **Output injection** — ANSI escape sequences or control characters embedded in dependency names could hijack terminal output or corrupt CI logs.
3. **Supply-chain / XML / TOML injection** — malformed or adversarial input to parsers (xml.etree.ElementTree, tomllib, ast) could cause denial of service or unexpected behaviour.
4. **Privilege escalation warning omission** — Scarno must warn when run as root to avoid inadvertent privileged filesystem access.
5. **subprocess misuse** — the `javap` invocation must be strictly sandboxed (no shell=True, fixed timeout, no project code execution).
6. **JSON/YAML depth bombs** — deeply nested package-lock.json or YAML anchor bombs in pnpm-lock.yaml could exhaust memory.
7. **XML External Entity (XXE) in MSBuild** — C# .csproj files with DOCTYPE declarations could trigger entity expansion.
8. **CDN URL exfiltration** — HTML templates referencing CDN scripts could leak project identity or serve malicious JS.
9. **Postinstall script abuse** — package.json lifecycle scripts could execute arbitrary commands.
10. **Custom registry hijack** — .npmrc or nuget.config pointing at attacker-controlled registries.
11. **Go module replace redirect** — go.mod replace directives pointing at malicious remote URLs.
12. **MSBuild task injection** — Exec/UsingTask elements in .csproj executing arbitrary commands.
13. **Tree-sitter grammar supply chain** — malicious native grammar wheels from PyPI.

Privacy exposure is minimal: Scarno processes source code and dependency metadata, neither of which constitutes personal data in standard developer usage. GDPR applicability is negligible. CRA and NIS2 are assessed as out of scope for this pure CLI developer tool. CDN URLs referenced in HTML templates could potentially leak project identity if included in public reports.

Key findings:
- 6 functional requirements gaps identified (telemetry opt-out, lock file integrity, XML entity expansion, ZIP bomb guard, ANSI stripping in JSON, root-privilege warning).
- 23 STRIDE threats catalogued, 11 high severity.
- 8 LINDDUN privacy threats catalogued, all low/negligible risk.
- 27 security abuse cases, 8 privacy abuse cases.
- 31+ refined requirements produced (original REQ-1 through REQ-16 expanded).

---

## 1. Assumptions and Context

### 1.1 Deployment Assumptions

| ID | Assumption |
|----|-----------|
| A-01 | Scarno runs on developer workstations (macOS, Linux) and in GitHub Actions CI containers (ubuntu-latest). |
| A-02 | The analysed project directory is user-supplied and must be treated as potentially untrusted or adversarially crafted. |
| A-03 | Scarno is invoked by the same OS user who owns the project directory; running as root is abnormal and must be warned. |
| A-04 | No network access occurs during analysis; all resolution is filesystem-only. |
| A-05 | `javap` is the only subprocess spawned; it operates on JAR files from Maven/Gradle caches, not on project source code. |
| A-06 | Output is consumed by: terminal (human), CI log aggregators, piped shell commands, and downstream tools parsing JSON output. |
| A-07 | Scarno is stateless: no persistent database, no user accounts, no session state. |
| A-08 | PyPI distribution; the package itself may be a supply-chain target. |
| A-09 | Source code of analysed projects may contain secrets (API keys in source files), but Scarno must not transmit or log these. |
| A-10 | Scarno does not authenticate callers; it is a single-user CLI tool. |
| A-11 | Tree-sitter native grammars (tree-sitter-javascript, tree-sitter-go, tree-sitter-c-sharp, etc.) are loaded from PyPI wheels; these contain compiled shared libraries. |
| A-12 | HTML and template files (30+ formats including Jinja2, EJS, Handlebars, Razor, etc.) are parsed for CDN dependency extraction (script src, stylesheet href). |

### 1.2 Trust Assumptions

| Boundary | Trusted? | Notes |
|----------|----------|-------|
| Scarno source code (installed from PyPI) | Trusted after installation | Supply-chain risk at install time |
| User-supplied `<path>` argument | Untrusted | May be adversarially crafted |
| Dependency manifest files (requirements.txt, pom.xml, etc.) | Untrusted | Attacker-controlled content |
| Source files (.py, .java, .kt) | Untrusted | Parsed via AST/regex only, never executed |
| JAR files in ~/.m2, ~/.gradle | Partially trusted | Controlled by Maven/Gradle ecosystem |
| `javap` binary | Trusted | Standard JDK tool; PATH must not be hijacked |
| stdout/stderr | Partially trusted | Output may be parsed by CI; injection risk |
| CI environment variables | Trusted | Set by CI operator |
| JS manifest files (package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb, deno.json) | Untrusted | Attacker-controlled content; may contain postinstall hooks, custom registries |
| Go manifest files (go.mod, go.sum) | Untrusted | Attacker-controlled content; may contain replace directives pointing at remote URLs |
| C# XML files (.csproj, nuget.config, Directory.Build.props) | Untrusted | MSBuild XML with potential DOCTYPE/XXE, Exec tasks, UsingTask elements |
| HTML/template files (.html, .ejs, .hbs, .j2, .cshtml, etc.) | Untrusted | May contain CDN script/stylesheet references to malicious endpoints |
| Tree-sitter grammar wheels (PyPI) | Trusted after installation | Supply-chain risk at install time; contain native shared libraries |
| CDN URLs referenced in HTML | Untrusted | External URLs; may point to malicious JavaScript or tracking endpoints |

### 1.3 Security Properties Required

- **Confidentiality:** Scarno must not exfiltrate source code content or secrets embedded in source files.
- **Integrity:** Analysis results must faithfully represent the project state; adversarial files must not produce false results that suppress real warnings.
- **Availability:** Resource exhaustion attacks (ZIP bombs, deeply nested XML, huge files) must be bounded.
- **Non-execution:** Scarno must never execute code from the analysed project by any mechanism.
- **Non-disclosure of CDN URLs in error messages:** CDN URLs extracted from HTML templates must not appear in error messages or tracebacks, as they could reveal project identity or internal infrastructure.

### 1.4 Regulatory Context

| Regulation | Applicability | Rationale |
|-----------|--------------|-----------|
| GDPR | Negligible | No PII processed; source code metadata is not personal data in standard use. Edge case: source code may contain developer names in comments — not systematically collected. |
| CRA (EU Cyber Resilience Act) | Likely out of scope | Scarno is a pure software CLI developer tool with no embedded/firmware component. Flag for legal review before EU market placement. |
| NIS2 | Not applicable | Scarno is not an essential or important entity operator. |
| PSTI (UK) | Not applicable | No connected consumer product. |
| SOC 2 | Not applicable | No SaaS service. |

---

## 2. Requirements Classification and Gap Analysis

### 2.1 Classified Requirements

#### Functional Requirements (FR-XXX)

| ID | Source | Description |
|----|--------|-------------|
| FR-001 | REQ-1 | CLI entrypoint: `scarno <path> [--format text\|json] [--output file] [--verbose]` |
| FR-002 | REQ-1 | Exit codes: 0 (no SAFE deps), 1 (SAFE deps found), 2 (failure) |
| FR-003 | REQ-1 | Shared data models: DependencyStatus, EntryPoint, Dependency, AnalysisResult |
| FR-004 | REQ-1 | Abstract BaseAnalyser with supports() and analyse() |
| FR-005 | REQ-2 | Parse requirements.txt with -r includes, cycle detection, max depth 10 |
| FR-006 | REQ-2 | Parse pyproject.toml (PEP 621 and Poetry) |
| FR-007 | REQ-2 | Parse setup.py (AST only) |
| FR-008 | REQ-2 | Parse setup.cfg, Pipfile, Pipfile.lock, poetry.lock, uv.lock |
| FR-009 | REQ-2 | PEP 503 name normalisation |
| FR-010 | REQ-2 | Deduplication with lock-file precedence |
| FR-011 | REQ-2 | Type stub detection (types-*, *-stubs) |
| FR-012 | REQ-3 | AST-based import detection across all .py files |
| FR-013 | REQ-3 | Import alias table (PIL→pillow, cv2→opencv-python, etc.) |
| FR-014 | REQ-3 | Stdlib exclusion via sys.stdlib_module_names |
| FR-015 | REQ-3 | Dynamic import heuristics (importlib, __import__) |
| FR-016 | REQ-3 | Entry point enumeration via importlib.import_module |
| FR-017 | REQ-3 | gitignore support via pathspec |
| FR-018 | REQ-4 | Maven POM hierarchy resolution (xml.etree.ElementTree, no network) |
| FR-019 | REQ-4 | Parent POM resolution, property inheritance, dependencyManagement |
| FR-020 | REQ-4 | Multi-module Maven project support |
| FR-021 | REQ-5 | Gradle build.gradle / build.gradle.kts parsing (regex/string only) |
| FR-022 | REQ-5 | settings.gradle multi-module discovery |
| FR-023 | REQ-5 | libs.versions.toml catalog version resolution |
| FR-024 | REQ-6 | JAR lookup: ~/.m2 → ~/.gradle/caches → project_path |
| FR-025 | REQ-6 | Entry point enumeration via javap subprocess (timeout=10s, shell=False) |
| FR-026 | REQ-6 | Source scanning: import statements, simple name references, bytecode constant pools |
| FR-027 | REQ-6 | DI annotation detection (@Autowired, @Bean, @Component, etc.) |
| FR-028 | REQ-6 | Reflection heuristics: Class.forName(), ClassLoader.loadClass() → UNCERTAIN |
| FR-029 | REQ-6 | Kotlin .kt file scanning |
| FR-030 | REQ-7 | TextReporter and JsonReporter (pure functions, no I/O) |
| FR-031 | REQ-7 | Text output: section order SAFE→UNCERTAIN→IN_USE→WARNINGS |
| FR-032 | REQ-7 | JSON: full AnalysisResult serialisation, json.dumps(indent=2, ensure_ascii=True) |
| FR-033 | REQ-7 | --output flag writes to file; exit codes 0/1/2 |

#### Security Requirements (SEC-XXX)

| ID | Source | Description |
|----|--------|-------------|
| SEC-001 | REQ-1 | Never use eval(), exec(), or subprocess on content from the analysed project |
| SEC-002 | REQ-1 | Always resolve paths with pathlib.Path.resolve() before opening files |
| SEC-003 | REQ-1 | Strip ANSI escape sequences from dependency names before rendering text output |
| SEC-004 | REQ-1 | Use json.dumps() (never f-strings) for JSON output |
| SEC-005 | REQ-1 | Log a warning if os.getuid() == 0 |
| SEC-006 | REQ-1 | GitHub Actions CI: bandit, pip-audit, opengrep jobs |
| SEC-007 | REQ-1 | THREAT_MODEL.md covering supply chain, path traversal, output injection, privilege escalation |
| SEC-008 | REQ-2 | setup.py parsed via AST only, never eval/exec |
| SEC-009 | REQ-2 | requirements.txt -r include cycle detection, max depth 10 |
| SEC-010 | REQ-4 | XML parsing via xml.etree.ElementTree only, no network |
| SEC-011 | REQ-5 | No Groovy/Kotlin interpreter, no subprocess for Gradle parsing |
| SEC-012 | REQ-6 | javap: timeout=10s, no shell=True, never on project source code |
| SEC-013 | REQ-7 | ANSI stripping applied before text rendering |

#### Privacy Requirements (PRV-XXX)

| ID | Source | Description |
|----|--------|-------------|
| PRV-001 | REQ-1 | No telemetry, no data exfiltration; analysis is fully local |
| PRV-002 | REQ-3 | Source file content is parsed but never stored or transmitted |
| PRV-003 | REQ-7 | JSON output contains only dependency metadata, not source code content |

#### Performance Requirements (PERF-XXX)

| ID | Source | Description |
|----|--------|-------------|
| PERF-001 | REQ-2 | requirements.txt -r include depth capped at 10 to prevent stack overflow |
| PERF-002 | REQ-6 | javap subprocess timeout = 10 seconds |

#### Compliance Requirements (COMP-XXX)

| ID | Source | Description |
|----|--------|-------------|
| COMP-001 | REQ-1 | THREAT_MODEL.md required |
| COMP-002 | Regulatory | CRA applicability assessed as likely out of scope; flag for review |
| COMP-003 | Regulatory | GDPR: no PII processing; no data protection impact assessment required |

### 2.2 Gap Analysis

The following security and privacy requirements are NOT covered by REQ-1 through REQ-16 but are required by the threat analysis:

| Gap ID | Gap Description | Risk | Proposed Requirement |
|--------|----------------|------|---------------------|
| GAP-01 | XML External Entity (XXE) expansion not explicitly prevented in POM parsing | HIGH | SEC-NEW-01: Disable DTD processing and external entity resolution in xml.etree.ElementTree |
| GAP-02 | No ZIP bomb protection for JAR inspection | HIGH | SEC-NEW-02: Cap decompressed JAR entry sizes at 50 MB; limit total entries inspected to 10,000 |
| GAP-03 | ANSI stripping specified for text output but not for JSON field values | MEDIUM | SEC-NEW-03: Apply control character sanitisation to all string fields before json.dumps() |
| GAP-04 | No maximum file size limit for source files parsed by AST | MEDIUM | SEC-NEW-04: Skip files > 10 MB with a warning; log to stderr |
| GAP-05 | No explicit symlink escape check after path resolution | HIGH | SEC-NEW-05: After pathlib.Path.resolve(), verify resolved path is still within the project root |
| GAP-06 | os.getuid() check not portable to Windows; no fallback | LOW | SEC-NEW-06: Wrap os.getuid() in try/except AttributeError; on Windows use ctypes.windll.shell32.IsUserAnAdmin() |
| GAP-07 | No integrity verification of pip-audit/bandit findings in CI | LOW | COMP-NEW-01: Pin CI tool versions and use hash verification |
| GAP-08 | No documented handling of deeply nested XML (stack overflow risk) | MEDIUM | SEC-NEW-07: Set recursion limit or use iterparse for POM parsing |
| GAP-09 | No JSON parse depth limit for package-lock.json | HIGH | SEC-NEW-20: Cap JSON parse depth to prevent memory exhaustion from deeply nested structures |
| GAP-10 | No YAML bomb protection for pnpm-lock.yaml | HIGH | SEC-NEW-21: Use yaml.safe_load; reject anchor/alias expansion beyond configurable limit |
| GAP-11 | No detection of postinstall hooks in package.json | MEDIUM | SEC-NEW-22: Flag postinstall/preinstall hooks via findings rule TS-SI-007 |
| GAP-12 | No detection of custom registry overrides in .npmrc or nuget.config | MEDIUM | SEC-NEW-23: Flag custom registry URLs via findings rules TS-SI-008, TS-SI-015 |
| GAP-13 | No line-length cap for go.mod module paths | MEDIUM | SEC-NEW-24: Cap module path line length at 1024 characters |
| GAP-14 | No DOCTYPE/XXE rejection for C# .csproj files | HIGH | SEC-NEW-25: Reject .csproj files containing DOCTYPE declarations |
| GAP-15 | No detection of MSBuild Exec/UsingTask elements | HIGH | SEC-NEW-26: Flag Exec and UsingTask elements via findings rules TS-SI-016, TS-SI-017 |
| GAP-16 | No detection of CSS remote @import or file:// URLs | MEDIUM | SEC-NEW-27: Flag remote @import and file:// URLs via findings rules TS-CE-007, TS-CE-008 |
| GAP-17 | Tree-sitter grammar wheels contain native code; no integrity verification | MEDIUM | SEC-NEW-28: Pin grammar wheel versions with hash constraints |
| GAP-18 | CDN URLs from HTML templates may appear in error messages | LOW | SEC-NEW-29: Exclude CDN URLs from error messages and tracebacks |
| GAP-19 | No detection of go.mod replace directives pointing at remote URLs | MEDIUM | SEC-NEW-30: Flag remote replace directives via findings rule TS-DS-002 |

---

## 3. Use Cases

### 3.1 Primary Use Cases

| UC-ID | Name | Actor | Description | Trust Boundary Crossed |
|-------|------|-------|-------------|------------------------|
| UC-01 | Analyse Python project | Developer/CI | Run `scarno ./myproject` on a Python project | User supplies path; manifest files and source files are untrusted input |
| UC-02 | Analyse Maven project | Developer/CI | Run `scarno ./myproject` on a Maven project with pom.xml | POM hierarchy traversal; parent POMs may reference external paths |
| UC-03 | Analyse Gradle project | Developer/CI | Run `scarno ./myproject` on a Gradle project | build.gradle content is untrusted |
| UC-04 | JVM bytecode analysis | Developer/CI | Scarno invokes `javap` on JAR from ~/.m2 or ~/.gradle | Scarno process → javap subprocess |
| UC-05 | Generate JSON report | Developer/CI | `scarno ./myproject --format json --output report.json` | Output written to user-specified file path |
| UC-06 | Generate text report to terminal | Developer | `scarno ./myproject` — text output to stdout | ANSI output to terminal; possible terminal emulator injection |
| UC-07 | CI pipeline integration | CI system | GitHub Actions runs scarno; exit code used to gate PR merge | CI reads exit code and stdout/JSON output |
| UC-08 | Run with elevated privileges | Developer (abnormal) | Developer runs `sudo scarno ./myproject` | Process runs as root; heightened filesystem access |
| UC-09 | Analyse malicious project | Attacker | Attacker supplies crafted project directory to Scarno | All parser inputs are adversarial |

### 3.2 Trust Boundary Crossings

```
[Developer / CI] ──(path argument)──→ [Scarno CLI]
                                            │
                        ┌───────────────────┼───────────────────┐
                        ↓                   ↓                   ↓
              [Dependency Parsers]   [Source Analysers]   [Report Engine]
                        │                   │                   │
                        ↓                   ↓                   ↓
              [Project Filesystem]   [Project Filesystem]  [stdout / file]
                        │
                        ↓
              [javap subprocess] ←── [JAR from ~/.m2 / ~/.gradle]
```

Trust boundaries:
- B1: CLI argument intake (path, output file path, format flag)
- B2: Filesystem read boundary (project root → parser)
- B3: Scarno process → javap subprocess
- B4: Report engine → stdout/file (terminal/CI consumption)

---

## 4. Threat Analysis

### 4.1 Security Threats (STRIDE)

#### Spoofing

| ID | Component | Threat | Severity | Likelihood | Notes |
|----|-----------|--------|----------|------------|-------|
| S-01 | PATH resolution | Attacker places a malicious `javap` binary earlier in PATH than the JDK binary | HIGH | LOW | If developer machine is compromised or PATH is manipulated via project .env loading |
| S-02 | pyproject.toml | Crafted dependency name that collides with a stdlib module name after normalisation, spoofing it as "in use" | MEDIUM | MEDIUM | PEP 503 normalisation + stdlib exclusion must be applied consistently |

#### Tampering

| ID | Component | Threat | Severity | Likelihood | Notes |
|----|-----------|--------|----------|------------|-------|
| T-01 | requirements.txt | -r include chain redirecting to files outside project root | HIGH | MEDIUM | Symlink or `../../etc/passwd` path in -r directive |
| T-02 | pom.xml | XML with external entity (XXE) referencing sensitive local files | HIGH | MEDIUM | xml.etree.ElementTree does not expand external entities by default in Python 3.8+, but explicit disabling is best practice |
| T-03 | pom.xml | Deeply nested XML causing parser stack overflow / denial of service | HIGH | LOW | Python's xml.etree is recursive |
| T-04 | setup.py | AST with crafted node that causes ast.parse() to raise unexpected exception or produce malformed tree | MEDIUM | LOW | Could suppress real dependencies if error is silently swallowed |
| T-05 | JAR file | ZIP bomb delivered as a dependency JAR in ~/.m2 | HIGH | LOW | Decompressed content could exhaust disk/memory |
| T-06 | --output path | Path traversal in --output argument: `--output ../../.ssh/authorized_keys` | HIGH | MEDIUM | Output file written to unintended location |
| T-07 | symlinks | Project directory contains symlinks pointing outside the root | HIGH | MEDIUM | After Path.resolve(), resolved path must still be under project root |
| T-08 | build.gradle | Regex injection — crafted Gradle file with content designed to match unintended patterns | LOW | LOW | Regex-only parsing limits exposure |

#### Repudiation

| ID | Component | Threat | Severity | Likelihood | Notes |
|----|-----------|--------|----------|------------|-------|
| R-01 | CI pipeline | No audit trail of what version of Scarno produced a given report | LOW | HIGH | Report should include Scarno version and timestamp |
| R-02 | --output file | File overwrite is silent; no record of previous content | LOW | MEDIUM | Acceptable for CLI tool; note in documentation |

#### Information Disclosure

| ID | Component | Threat | Severity | Likelihood | Notes |
|----|-----------|--------|----------|------------|-------|
| I-01 | Error messages | Exception tracebacks may include filesystem paths or file content fragments | MEDIUM | HIGH | Stack traces must be sanitised before output in non-verbose mode |
| I-02 | --verbose mode | Verbose output may include source code snippets containing secrets (API keys in comments) | MEDIUM | MEDIUM | Verbose output must be scoped to metadata only, not raw source content |
| I-03 | JSON report | If source code content is accidentally included in AnalysisResult, it appears in JSON output | MEDIUM | LOW | AnalysisResult schema must not include raw source content fields |
| I-04 | javap stdout | javap output may include class constant pool strings that contain sensitive values | LOW | LOW | Bytecode analysis operates on class metadata, not string values |

#### Denial of Service

| ID | Component | Threat | Severity | Likelihood | Notes |
|----|-----------|--------|----------|------------|-------|
| D-01 | requirements.txt | Circular -r include chain consuming infinite recursion / stack | HIGH | MEDIUM | Cycle detection at depth 10 required (FR-005) |
| D-02 | pom.xml | Billion laughs XML entity expansion attack | HIGH | LOW | Requires explicit DTD/entity disabling |
| D-03 | JAR inspection | ZIP bomb inside JAR causes disk exhaustion | HIGH | LOW | Decompressed size cap required |
| D-04 | AST parsing | Extremely large .py file (100 MB+) causing memory exhaustion | MEDIUM | LOW | File size cap required |
| D-05 | javap | javap hangs on malformed/crafted JAR | MEDIUM | MEDIUM | 10-second timeout mitigates; SIGKILL must be sent |
| D-06 | Multi-module Maven | Deeply nested module hierarchy causing excessive filesystem traversal | MEDIUM | LOW | Module depth limit required |

#### Elevation of Privilege

| ID | Component | Threat | Severity | Likelihood | Notes |
|----|-----------|--------|----------|------------|-------|
| E-01 | Root execution | Scarno run as root reads files the normal user cannot, then includes paths in output | HIGH | LOW | os.getuid() == 0 warning required |
| E-02 | --output file | Writing output to a sensitive system file via path traversal (see T-06) | HIGH | MEDIUM | Path resolution + boundary check |
| E-03 | javap subprocess | If shell=True were used, command injection via JAR path containing shell metacharacters | CRITICAL | LOW | shell=False enforced in spec; must be verified in implementation |
| E-04 | symlink attack | Symlink in project directory pointing to /etc/shadow; resolved path read by Scarno | HIGH | MEDIUM | Path boundary check after resolve() |

### 4.2 Privacy Threats (LINDDUN)

#### Linkability

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| L-01 | If Scarno output is logged by CI and contains project-internal package names, those names could be linked to proprietary internal infrastructure | LOW | Dependency names in output are already known to the developer; CI log access is controlled by the operator |

#### Identifiability

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| ID-01 | Developer names in source code comments or docstrings could theoretically be surfaced in verbose output | LOW | Scarno does not extract or output source code content; only dependency names and analysis metadata |

#### Non-repudiation (LINDDUN)

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| NR-01 | No mechanism to prevent a CI operator from falsely claiming a Scarno report was not produced | NEGLIGIBLE | Out of scope for a developer CLI tool |

#### Detectability

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| DT-01 | The set of dependencies in a project could reveal proprietary technology choices if the JSON report is shared externally | LOW | Operator responsibility; Scarno does not publish output |

#### Disclosure of Information

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| DI-01 | Source code containing API keys in string literals could be included in verbose output or error messages | MEDIUM | Verbose mode must be scoped to metadata; error messages must not include raw file content |
| DI-02 | Filesystem paths in error tracebacks may reveal directory structure of developer machine | LOW | Sanitise tracebacks in non-verbose mode |

#### Unawareness

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| U-01 | Developer is unaware that Scarno reads all .py files in the project, including test fixtures with hardcoded credentials | LOW | Document clearly in README; scope is consistent with stated function |

#### Non-compliance

| ID | Threat | Severity | Notes |
|----|--------|----------|-------|
| NC-01 | If Scarno were to add telemetry without consent, it would violate GDPR Article 6 | HIGH (conditional) | No telemetry is present or planned; PRV-001 covers this |

---

## 5. Abuse Cases

### 5.1 Security Abuse Cases

| ID | Name | OWASP Category | Attack Vector | Impact | Mitigation Reference |
|----|------|---------------|--------------|--------|---------------------|
| SAC-01 | Path traversal via -r include | A01:2021 Broken Access Control | requirements.txt contains `-r ../../../../etc/passwd` | Read arbitrary files | SEC-002, GAP-05, SEC-NEW-05 |
| SAC-02 | XXE via pom.xml | A05:2021 Security Misconfiguration | pom.xml declares DOCTYPE with external entity to `/etc/shadow` | Read sensitive files | GAP-01, SEC-NEW-01 |
| SAC-03 | ZIP bomb via JAR | A06:2021 Vulnerable Components | Malformed JAR with recursive compression | Disk/memory exhaustion | GAP-02, SEC-NEW-02 |
| SAC-04 | ANSI injection in dependency name | A03:2021 Injection | Dependency named `\x1b[2J\x1b[H` injected via requirements.txt | Clear terminal screen; hide output | SEC-003 |
| SAC-05 | Output path traversal | A01:2021 Broken Access Control | `--output ../../.ssh/authorized_keys` | Overwrite sensitive files | SEC-002 |
| SAC-06 | Billion laughs XML | A06:2021 Vulnerable Components | pom.xml with deeply nested entity references | CPU/memory exhaustion | SEC-NEW-01 |
| SAC-07 | Symlink escape | A01:2021 Broken Access Control | Symlink in project pointing to `/etc/hosts` | Read out-of-scope files | SEC-002, SEC-NEW-05 |
| SAC-08 | Large AST file | A06:2021 Vulnerable Components | 500 MB .py file in project | Memory exhaustion | SEC-NEW-04 |
| SAC-09 | Circular -r includes | A06:2021 Vulnerable Components | requirements.txt includes itself | Stack overflow / infinite loop | FR-005 (depth cap) |
| SAC-10 | javap PATH hijack | A08:2021 Software Integrity Failures | Malicious javap on PATH before JDK | Arbitrary code execution in javap process | SEC-012, S-01 |
| SAC-11 | Malicious setup.py AST | A03:2021 Injection | setup.py with crafted AST triggering ast.parse exception | Exception reveals traceback with paths | SEC-001, SEC-008, I-01 |
| SAC-12 | JSON output injection via control chars | A03:2021 Injection | Dependency name containing `\n`, `\r`, null bytes | Corrupt JSON output parsed by CI | SEC-004, SEC-NEW-03 |
| SAC-13 | Deeply nested pom.xml | A06:2021 Vulnerable Components | pom.xml with 10,000 levels of nesting | Stack overflow in xml.etree recursive parse | SEC-NEW-07, GAP-08 |
| SAC-14 | Gradle regex denial of service | A06:2021 Vulnerable Components | build.gradle with ReDoS-triggering content | CPU exhaustion via backtracking | FR-021 (regex-only) |
| SAC-15 | Root privilege file read | A01:2021 Broken Access Control | `sudo scarno ./project` reads /etc/shadow via symlink | Sensitive system file disclosure | SEC-005, E-01 |
| SAC-16 | Module cycle in Maven multi-module | A06:2021 Vulnerable Components | pom.xml with circular module references | Infinite traversal | FR-019 (cycle detection) |
| SAC-17 | Supply chain via PyPI package | A08:2021 Software Integrity Failures | Malicious Scarno version published to PyPI | Arbitrary code execution on developer machine | SEC-006 (pip-audit, bandit) |
| SAC-20 | Postinstall exfil via package.json | A08:2021 Software Integrity Failures | Attacker crafts package.json with postinstall script that exfiltrates environment variables or source code via curl/wget | Data exfiltration at npm install time | SUC-20 (TS-SI-007) |
| SAC-21 | npm registry override via .npmrc | A08:2021 Software Integrity Failures | Attacker places .npmrc in project overriding npm registry to serve malicious packages to downstream developers | Installation of malicious packages | SUC-21 (TS-SI-008) |
| SAC-22 | go.mod replace redirect | A08:2021 Software Integrity Failures | Attacker uses go.mod replace directive to redirect a legitimate module path to a malicious remote URL | Build fetches attacker-controlled Go module | SUC-22 (TS-DS-002) |
| SAC-23 | Rogue NuGet feed via nuget.config | A08:2021 Software Integrity Failures | Attacker crafts nuget.config to point at rogue NuGet feed serving backdoored packages | Installation of malicious .NET packages | SUC-23 (TS-SI-015) |
| SAC-24 | MSBuild Exec with curl\|sh | A03:2021 Injection | Attacker embeds MSBuild Exec task with `curl \| sh` payload in .csproj file | Arbitrary code execution during dotnet build | SUC-24 (TS-SI-016/017) |
| SAC-25 | CSS @import tracking/exfil | A03:2021 Injection | Attacker uses CSS @import url() to reference tracking pixel endpoint or exfiltration URL | Privacy violation; data exfiltration via CSS side-channel | SUC-25 (TS-CE-007/008) |
| SAC-26 | Malicious CDN script in HTML template | A08:2021 Software Integrity Failures | Attacker plants CDN script tag in HTML template pointing at malicious JavaScript hosted on attacker-controlled CDN | Arbitrary JS execution in end-user browser | SUC-26 |
| SAC-27 | Malicious tree-sitter grammar wheel | A08:2021 Software Integrity Failures | Attacker publishes malicious tree-sitter grammar wheel on PyPI containing backdoored native shared library | Arbitrary code execution when Scarno loads grammar | SUC-27 |
| SAC-28 | JSON depth bomb in package-lock.json | A06:2021 Vulnerable Components | Attacker crafts deeply nested package-lock.json (thousands of levels) to exhaust memory during JSON parsing | Memory exhaustion / denial of service | SUC-28 (SEC-NEW-20) |
| SAC-29 | YAML anchor bomb in pnpm-lock.yaml | A06:2021 Vulnerable Components | Attacker places YAML anchor bomb (billion laughs equivalent) in pnpm-lock.yaml | CPU/memory exhaustion during YAML parsing | SUC-29 (SEC-NEW-21) |

### 5.2 Privacy Abuse Cases

| ID | Name | PbD Principle Violated | Description | Impact |
|----|------|----------------------|-------------|--------|
| PAC-01 | Verbose output exposes API key | Privacy by Default | `--verbose` output includes source code line containing `API_KEY = "secret"` | Secret exposed in CI log |
| PAC-02 | Traceback exposes file path | Data Minimisation | Exception traceback includes full path to developer's home directory | Path disclosure |
| PAC-03 | Developer name in dep metadata | Identifiability | pyproject.toml `[tool.poetry] authors = ["Jane Doe"]` surfaced in verbose output | PII in output |
| PAC-04 | JSON report logs to CI | Visibility and Transparency | JSON report including internal package names stored in CI logs indefinitely | Proprietary info disclosure |
| PAC-05 | Future telemetry without consent | Consent / Lawful basis | Hypothetical: Scarno v2 adds usage telemetry without opt-in | GDPR Article 6 violation |
| PAC-06 | Error message includes source snippet | Data Minimisation | Parser error includes the offending line from source file | Source code in error output |
| PAC-07 | CDN URLs leak project identity | Data Minimisation | CDN URLs in HTML templates (e.g. internal CDN hostnames) included in SARIF or Markdown reports shared externally reveal project identity or internal infrastructure | Proprietary infrastructure disclosure |
| PAC-08 | SARIF report contains internal package names | Visibility and Transparency | SARIF report uploaded to GitHub contains internal/private package names from JS/Go/C# ecosystems | Internal package names exposed via GitHub Security tab |

---

## 6. Counter-Use Cases

### 6.1 Security Use Cases (Countermeasures)

| ID | Countermeasure | Threats Addressed | Implementation |
|----|---------------|------------------|----------------|
| SUC-01 | Path boundary enforcement | T-01, T-06, T-07, E-02, E-04, SAC-01, SAC-05, SAC-07 | After `Path(user_input).resolve()`, assert `resolved.is_relative_to(project_root_resolved)`. Apply to: all -r includes, all POM relativePath values, --output path. |
| SUC-02 | XXE prevention | T-02, D-02, SAC-02, SAC-06 | Call `xml.etree.ElementTree.XMLParser(resolve_entities=False)` or equivalent. Wrap parse in try/except xml.etree.ElementTree.ParseError. |
| SUC-03 | ZIP bomb guard | D-03, SAC-03 | In zipfile iteration, track cumulative uncompressed bytes. If entry.file_size > 50 MB or total > 500 MB, stop and log warning. |
| SUC-04 | ANSI/control char stripping | SAC-04, SAC-12 | Apply `re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', s)` for text output. Apply `''.join(c for c in s if c.isprintable() or c in '\t\n')` for JSON field values. |
| SUC-05 | File size cap for AST parsing | D-04, SAC-08 | `if path.stat().st_size > 10_485_760: log_warning(); continue` |
| SUC-06 | javap subprocess hardening | D-05, E-03, SAC-10 | `subprocess.run(['javap', ...], shell=False, timeout=10, capture_output=True)`. Resolve javap path via `shutil.which('javap')`. |
| SUC-07 | Root warning | E-01, SAC-15 | `if hasattr(os, 'getuid') and os.getuid() == 0: sys.stderr.write("WARNING: Scarno running as root...\n")` |
| SUC-08 | Traceback sanitisation | I-01, I-02, PAC-02 | In non-verbose mode, catch all exceptions at top level and log `str(e)` only (no traceback). In verbose mode, log full traceback to stderr only. |
| SUC-09 | Circular include detection | D-01, SAC-09 | Track visited paths as a set of resolved absolute paths during -r traversal. |
| SUC-10 | JSON safety | SAC-12 | Always use `json.dumps()`. Never f-string JSON. Apply control char sanitisation to all string fields. |
| SUC-11 | Version metadata in output | R-01 | Include `scarno_version` and `analysis_timestamp` in AnalysisResult and JSON report. |
| SUC-12 | XML parse depth limit | T-03, SAC-13 | Use `xml.etree.ElementTree.iterparse()` instead of recursive parse for POM files. Limit tree depth during traversal. |
| SUC-13 | setup.py AST-only | SAC-11 | `ast.parse(source)` only. Never eval(). Catch `SyntaxError` and `ValueError` non-fatally. |
| SUC-14 | javap path verification | SAC-10 | Verify `shutil.which('javap')` resolves to a path within standard JDK directories; warn if unusual. |
| SUC-15 | Dependency name normalisation | S-02 | Apply PEP 503 normalisation before stdlib comparison. Normalise aliases before import mapping. |
| SUC-16 | Input length bounds | General DoS | Cap dependency name length at 256 chars; skip longer names with warning. |
| SUC-17 | CI toolchain pinning | SAC-17 | Pin bandit, pip-audit, opengrep versions in CI. Use hash verification where supported. |
| SUC-20 | JS postinstall hook detection | SAC-20 | Findings rule TS-SI-007 flags package.json scripts containing postinstall, preinstall, or prepare hooks that execute arbitrary commands. |
| SUC-21 | .npmrc custom registry detection | SAC-21 | Findings rule TS-SI-008 flags .npmrc files that override the default npm registry with a custom URL. |
| SUC-22 | go.mod replace directive detection | SAC-22 | Findings rule TS-DS-002 flags go.mod replace directives that point at remote URLs rather than local paths. |
| SUC-23 | nuget.config custom package source detection | SAC-23 | Findings rule TS-SI-015 flags nuget.config files containing custom package sources other than nuget.org. |
| SUC-24 | MSBuild Exec/UsingTask detection | SAC-24 | Findings rules TS-SI-016 and TS-SI-017 flag .csproj files containing Exec tasks or UsingTask elements that could execute arbitrary commands. |
| SUC-25 | CSS remote @import / file:// URL detection | SAC-25 | Findings rules TS-CE-007 and TS-CE-008 flag CSS @import directives referencing remote URLs or file:// protocol. |
| SUC-26 | HTML CDN script/stylesheet inventory | SAC-26 | HTML/template scanner extracts all external script src and stylesheet href URLs from 30+ template formats for supply-chain inventory. |
| SUC-27 | Tree-sitter grammar wheel integrity | SAC-27 | Tree-sitter grammar wheels installed from PyPI should be pinned with hash verification; warn if grammar loading fails unexpectedly (potential tampering indicator). |
| SUC-28 | JSON depth bomb defence | SAC-28 | SEC-NEW-20: Cap JSON parse depth for package-lock.json to prevent memory exhaustion from deeply nested structures. |
| SUC-29 | YAML bomb defence | SAC-29 | SEC-NEW-21: Use safe YAML loader (yaml.safe_load) for pnpm-lock.yaml; reject anchor/alias expansion beyond configurable limit. |
| SUC-30 | Go module path line-length cap | SAC-30 | SEC-NEW-24: Cap go.mod module path line length to prevent ReDoS or buffer abuse in module path parsing. |
| SUC-31 | C# csproj DOCTYPE/XXE rejection | SAC-31 | SEC-NEW-25: Reject .csproj files containing DOCTYPE declarations; disable DTD processing and external entity resolution in MSBuild XML parsing. |

### 6.2 Privacy Use Cases (Privacy Controls)

| ID | Privacy Control | PbD Principle | Threats Addressed | Implementation |
|----|----------------|--------------|------------------|----------------|
| PUC-01 | Verbose output scoped to metadata only | Data Minimisation | PAC-01, PAC-03 | --verbose increases logging of file paths and counts, but never outputs raw source code lines |
| PUC-02 | Error messages contain no source content | Data Minimisation | PAC-06 | Exception handlers sanitise messages; offending content is replaced with `[content redacted]` |
| PUC-03 | No telemetry, no network calls | Privacy by Default | PAC-05, NC-01 | No telemetry code; verified by bandit and opengrep rules |
| PUC-04 | AnalysisResult schema excludes source content | Privacy by Default | I-03, PAC-01 | Schema review: only dependency names, versions, statuses, reasons, entry point names — no source code |
| PUC-05 | Author metadata not extracted from pyproject.toml | Data Minimisation | PAC-03 | Parser extracts only dependency-relevant fields; author/maintainer fields ignored |
| PUC-06 | THREAT_MODEL.md documents privacy posture | Openness / Transparency | NC-01 | Publicly available documentation of data handling |
| PUC-07 | CDN URLs not disclosed in error messages | Data Minimisation | DI-03, PAC-07 | CDN URLs extracted from HTML templates are not included in error messages or tracebacks; they appear only in structured findings output |
| PUC-08 | SARIF output contains only dependency and findings metadata | Privacy by Default | I-03 | SARIF 2.1.0 output schema excludes source code content; only rule IDs, locations, and messages are included |
| PUC-09 | Go/JS/C# source content parsed but never stored | Data Minimisation | PRV-002 | Tree-sitter-based source analysis operates on AST nodes; raw source content is not retained or transmitted |

---

## 7. Refined Requirements

The following is the complete requirements list incorporating all original requirements plus gap-identified new requirements:

### Security Requirements (Complete)

| ID | Status | Description |
|----|--------|-------------|
| SEC-001 | Original | Never use eval(), exec(), or subprocess on analysed project content |
| SEC-002 | Original | Always resolve paths with pathlib.Path.resolve() before opening files |
| SEC-003 | Original | Strip ANSI escape sequences from dependency names before text rendering |
| SEC-004 | Original | Use json.dumps() (never f-strings) for JSON output |
| SEC-005 | Original | Log warning if os.getuid() == 0 |
| SEC-006 | Original | CI: bandit, pip-audit, opengrep jobs |
| SEC-007 | Original | THREAT_MODEL.md required |
| SEC-008 | Original | setup.py parsed via AST only |
| SEC-009 | Original | requirements.txt -r cycle detection, max depth 10 |
| SEC-010 | Original | XML parsing via xml.etree.ElementTree, no network |
| SEC-011 | Original | No subprocess for Gradle/Groovy/Kotlin parsing |
| SEC-012 | Original | javap: timeout=10s, shell=False |
| SEC-013 | Original | ANSI stripping before text rendering |
| SEC-NEW-01 | **NEW** | Disable DTD processing and external entity resolution in xml.etree.ElementTree; wrap all XML parsing in ParseError handlers |
| SEC-NEW-02 | **NEW** | Cap decompressed JAR entry size at 50 MB; cap total entries inspected at 10,000 |
| SEC-NEW-03 | **NEW** | Apply control character sanitisation to all string fields before json.dumps() |
| SEC-NEW-04 | **NEW** | Skip .py/.java/.kt files larger than 10 MB with a stderr warning |
| SEC-NEW-05 | **NEW** | After Path.resolve(), verify resolved path is within the intended root directory; reject with warning if not |
| SEC-NEW-06 | **NEW** | Wrap os.getuid() in try/except AttributeError for Windows portability |
| SEC-NEW-07 | **NEW** | Use iterparse() for POM XML parsing; limit traversal depth to 100 levels |
| SEC-NEW-08 | **NEW** | Cap dependency name length at 256 characters; skip longer values with warning |
| SEC-NEW-09 | **NEW** | In non-verbose mode, suppress exception tracebacks; output only sanitised error message to stderr |
| SEC-NEW-10 | **NEW** | Include scarno_version and analysis_timestamp in all output formats |
| SEC-NEW-11 | **NEW** | Verify javap path via shutil.which(); warn if resolved path is unusual |
| SEC-NEW-20 | **NEW** | Cap JSON parse depth for package-lock.json; reject files exceeding depth limit with warning |
| SEC-NEW-21 | **NEW** | Use yaml.safe_load for pnpm-lock.yaml; reject anchor/alias expansion beyond configurable limit to prevent YAML bombs |
| SEC-NEW-22 | **NEW** | Detect and flag postinstall/preinstall hooks in package.json scripts (findings rule TS-SI-007) |
| SEC-NEW-23 | **NEW** | Detect and flag custom registry URLs in .npmrc and nuget.config (findings rules TS-SI-008, TS-SI-015) |
| SEC-NEW-24 | **NEW** | Cap go.mod module path line length at 1024 characters; skip longer lines with warning |
| SEC-NEW-25 | **NEW** | Reject .csproj files containing DOCTYPE declarations; disable DTD processing and external entity resolution in MSBuild XML parsing |
| SEC-NEW-26 | **NEW** | Detect and flag MSBuild Exec and UsingTask elements in .csproj files (findings rules TS-SI-016, TS-SI-017) |
| SEC-NEW-27 | **NEW** | Detect and flag CSS @import directives referencing remote URLs or file:// protocol (findings rules TS-CE-007, TS-CE-008) |
| SEC-NEW-28 | **NEW** | Tree-sitter grammar wheels must be pinned with version constraints; warn on unexpected grammar loading failures |
| SEC-NEW-29 | **NEW** | CDN URLs extracted from HTML templates must not appear in error messages or exception tracebacks |
| SEC-NEW-30 | **NEW** | Detect and flag go.mod replace directives pointing at remote URLs (findings rule TS-DS-002) |

### Privacy Requirements (Complete)

| ID | Status | Description |
|----|--------|-------------|
| PRV-001 | Original | No telemetry; fully local analysis |
| PRV-002 | Original | Source file content parsed but never stored or transmitted |
| PRV-003 | Original | JSON output contains only dependency metadata |
| PRV-NEW-01 | **NEW** | Verbose output must not include raw source code lines |
| PRV-NEW-02 | **NEW** | Error messages must not include raw source code content |
| PRV-NEW-03 | **NEW** | pyproject.toml author/maintainer fields must not be extracted or included in output |
| PRV-NEW-04 | **NEW** | CDN URLs from HTML templates must not appear in error messages; only in structured findings output |
| PRV-NEW-05 | **NEW** | SARIF output must contain only dependency metadata and findings; no raw source code content |
| PRV-NEW-06 | **NEW** | Tree-sitter-based source analysis (JS/TS, Go, C#) must not retain or transmit raw source content |

### Compliance Requirements (Complete)

| ID | Status | Description |
|----|--------|-------------|
| COMP-001 | Original | THREAT_MODEL.md required |
| COMP-002 | Original | CRA: likely out of scope; flag for legal review |
| COMP-003 | Original | GDPR: no PII; no DPIA required |
| COMP-NEW-01 | **NEW** | Pin CI tool versions (bandit, pip-audit, opengrep) with hash verification |
| COMP-NEW-02 | **NEW** | Document data handling in README: what files are read, what is output, no telemetry statement |

---

## 8. Security Requirements Traceability Matrix

| Req ID | Description (Short) | Use Cases | STRIDE Threats | Abuse Cases | Countermeasures | Test IDs |
|--------|--------------------|-----------|--------------|-----------|-----------------| ---------|
| SEC-001 | No eval/exec/subprocess on project code | UC-01..09 | E-03 | SAC-10, SAC-11 | SUC-06, SUC-13 | FST-01, SAT-01, SAT-02 |
| SEC-002 | Path.resolve() before open | UC-01..09 | T-01, T-06, T-07 | SAC-01, SAC-05, SAC-07 | SUC-01 | FST-02, SAT-03, SAT-04, SAT-05 |
| SEC-003 | ANSI strip in text output | UC-06, UC-07 | None direct | SAC-04 | SUC-04 | FST-03, SAT-06 |
| SEC-004 | json.dumps() only | UC-05, UC-07 | None direct | SAC-12 | SUC-10 | FST-04, SAT-07 |
| SEC-005 | Root warning | UC-08 | E-01 | SAC-15 | SUC-07 | FST-05, SAT-08 |
| SEC-008 | setup.py AST only | UC-01 | T-04 | SAC-11 | SUC-13 | FST-06, SAT-09 |
| SEC-009 | -r cycle detection | UC-01 | D-01 | SAC-09 | SUC-09 | FST-07, SAT-10 |
| SEC-010 | XML ElementTree only | UC-02 | T-02, T-03, D-02 | SAC-02, SAC-06 | SUC-02 | FST-08, SAT-11 |
| SEC-012 | javap shell=False, timeout=10s | UC-04 | D-05, E-03 | SAC-10 | SUC-06 | FST-09, SAT-12 |
| SEC-NEW-01 | Disable XML DTD/entities | UC-02, UC-09 | T-02, D-02 | SAC-02, SAC-06, SAC-13 | SUC-02, SUC-12 | SAT-11, SAT-13 |
| SEC-NEW-02 | ZIP bomb guard | UC-04, UC-09 | D-03 | SAC-03 | SUC-03 | SAT-14 |
| SEC-NEW-03 | Control char sanitisation in JSON | UC-05, UC-07 | None direct | SAC-12 | SUC-04, SUC-10 | FST-04, SAT-07 |
| SEC-NEW-04 | File size cap 10 MB | UC-01..03, UC-09 | D-04 | SAC-08 | SUC-05 | SAT-15 |
| SEC-NEW-05 | Path boundary check post-resolve | UC-01..09 | T-01, T-07, E-04 | SAC-01, SAC-07 | SUC-01 | SAT-03, SAT-04, SAT-16 |
| SEC-NEW-07 | iterparse + depth limit for XML | UC-02, UC-09 | T-03, D-02 | SAC-13 | SUC-12 | SAT-13 |
| SEC-NEW-09 | Traceback suppression in non-verbose | UC-01..09 | I-01 | PAC-02, PAC-06 | SUC-08 | PVT-01 |
| PRV-001 | No telemetry | All | None | PAC-05 | PUC-03 | PVT-02 |
| PRV-NEW-01 | Verbose: no source code lines | UC-01..03 | I-02 | PAC-01, PAC-03 | PUC-01 | PVT-03 |
| PRV-NEW-02 | Errors: no source content | UC-01..09 | I-01 | PAC-06 | PUC-02 | PVT-04 |

---

## 9. Test Artifacts

### 9.1 Functional Security Tests

| ID | Test Name | What It Verifies | Expected Result |
|----|-----------|-----------------|----------------|
| FST-01 | no_exec_in_analyser | No eval/exec call exists in analyser code | bandit B307/B102 passes; code review confirms |
| FST-02 | path_resolve_called | Path.resolve() called before every file open | Code review / AST grep of source |
| FST-03 | ansi_stripped_text_output | ANSI sequences in dep name do not appear in text output | Output contains no ESC sequences |
| FST-04 | json_dumps_used | All JSON output uses json.dumps() | Output is valid JSON; no f-string JSON construction in source |
| FST-05 | root_warning_emitted | Running as root emits warning to stderr | stderr contains "WARNING" string when uid==0 |
| FST-06 | setup_py_ast_only | setup.py parser uses ast.parse(), not exec() | bandit B102; code review |
| FST-07 | circular_include_detected | requirements.txt with circular -r stops at depth 10 | No infinite loop; warning in output |
| FST-08 | xml_no_network | POM parser does not make network connections | Mock network; assert no socket calls |
| FST-09 | javap_no_shell | javap subprocess called with shell=False | subprocess.run mock asserts shell=False |
| FST-10 | exit_codes_correct | Exit code 0/1/2 per spec | Integration test with known projects |
| FST-11 | version_in_output | JSON output includes scarno_version | Parsed JSON has version field |

### 9.2 Security Attack Tests

| ID | Attack Scenario | Test Input | Expected Behaviour |
|----|----------------|-----------|-------------------|
| SAT-01 | Eval in setup.py | `setup.py` containing `eval(open('secret.txt').read())` | Parsed via AST; eval() call detected as AST node but NOT executed; dep list extracted from static assignments only |
| SAT-02 | Subprocess in setup.py | `setup.py` calling `subprocess.run(...)` | Not executed; AST-only parse ignores runtime calls |
| SAT-03 | Path traversal in -r | `requirements.txt` with `-r ../../../../etc/passwd` | Warning logged; /etc/passwd not read; analysis continues |
| SAT-04 | Symlink outside root | Project contains symlink → `/etc/hosts` | Resolved path outside project root rejected; warning logged |
| SAT-05 | --output traversal | `--output ../../.ssh/authorized_keys` | Error; output path outside allowed scope rejected |
| SAT-06 | ANSI in dep name | requirements.txt: `\x1b[2J\x1b[Hmalicious==1.0` | Text output shows sanitised name; no terminal clearing |
| SAT-07 | Control chars in JSON | Dependency named `foo\x00\nbar` | JSON output has sanitised string; json.loads() succeeds |
| SAT-08 | Root execution | Run test as root (or mock os.getuid() → 0) | stderr contains root warning |
| SAT-09 | Malformed setup.py AST | `setup.py` with syntax error | SyntaxError caught; non-fatal; warning in output |
| SAT-10 | Deep -r chain | 11 levels of -r includes | Stops at depth 10; warning emitted |
| SAT-11 | XXE in pom.xml | pom.xml with `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Entity not expanded; file not read; ParseError or silent ignore |
| SAT-12 | javap timeout | Malformed JAR causing javap to hang | Process killed after 10s; TimeoutExpired caught; warning logged |
| SAT-13 | Deeply nested XML | pom.xml with 10,000 levels of nesting | Parser terminates without stack overflow |
| SAT-14 | ZIP bomb JAR | JAR with decompression ratio > 1000:1 | Extraction stopped; warning logged; analysis continues without bytecode |
| SAT-15 | Giant .py file | 50 MB Python source file | File skipped with warning; no memory exhaustion |
| SAT-16 | Symlink chain | Multiple chained symlinks eventually outside root | Each resolved path checked against root; all rejected |

### 9.3 Privacy Verification Tests

| ID | Test Name | What It Verifies | Expected Result |
|----|-----------|-----------------|----------------|
| PVT-01 | traceback_suppressed_non_verbose | Exception in analysis does not produce traceback in default mode | Only one-line error in stderr; no file paths in stdout |
| PVT-02 | no_network_calls | No socket/http calls during analysis | Mock socket.connect raises; never called |
| PVT-03 | verbose_no_source_lines | --verbose mode does not output source code lines | grep of verbose output finds no source code patterns |
| PVT-04 | error_no_source_content | Parser error message does not include source line content | Error message contains only file name and line number, not content |
| PVT-05 | no_author_in_output | pyproject.toml authors field not in JSON output | JSON schema check; authors key absent |
| PVT-06 | json_no_source_code | AnalysisResult JSON contains no source code fragments | Schema validation; no field contains >100 chars of source-looking content |

### 9.4 Penetration Testing Scenarios

| ID | Scenario | Technique | Target Component | Success Criteria for Defence |
|----|---------|-----------|-----------------|------------------------------|
| PEN-01 | Adversarial requirements.txt | Craft requirements.txt with ANSI, null bytes, very long names, path traversal -r directives | Python dep parser | No crash; no file read outside project; sanitised output |
| PEN-02 | Adversarial pom.xml | Craft pom.xml with XXE, billion laughs, deeply nested elements, circular parent refs | Maven POM parser | No DoS; no file disclosure; parse error non-fatal |
| PEN-03 | Adversarial build.gradle | Craft Gradle file with ReDoS patterns, very long lines, unusual version string formats | Gradle parser | No CPU hang; parse continues or fails non-fatally |
| PEN-04 | Adversarial JAR | Create ZIP bomb; JAR with malformed class files; JAR with path traversal entries (`../../`) | JVM analyser / javap | Extraction limited; javap killed on timeout; no path escape |
| PEN-05 | Adversarial setup.py | setup.py with deeply nested AST, obfuscated exec calls, macro expansion patterns | Python dep parser | AST-only; no execution; deep AST handled gracefully |
| PEN-06 | PATH manipulation | Place fake `javap` script at a PATH location before JDK | CLI entrypoint | Warning emitted; or verified path used; no arbitrary execution |
| PEN-07 | Output injection | Dependency name containing JSON control chars, ANSI, unicode RTL override | Report engine | Output is sanitised JSON and text; no terminal hijack |
| PEN-08 | --output to sensitive path | `--output /etc/cron.d/malicious` | CLI entrypoint | Path rejected or permission denied; no privileged write |
| PEN-09 | Symlink maze | Project directory with complex symlink graph some leading outside root | Filesystem traversal | All out-of-scope paths rejected; no information disclosure |
| PEN-10 | Large project stress test | Project with 100,000 Python files, 1,000 POMs | All analysers | Completes in reasonable time; no memory exhaustion; caps enforced |

---

## Appendix A: STRIDE Reference

| Letter | Threat | Security Property Violated |
|--------|--------|--------------------------|
| S | Spoofing | Authentication |
| T | Tampering | Integrity |
| R | Repudiation | Non-repudiation |
| I | Information Disclosure | Confidentiality |
| D | Denial of Service | Availability |
| E | Elevation of Privilege | Authorisation |

---

## Appendix B: LINDDUN Reference

| Letter | Threat | Privacy Property |
|--------|--------|----------------|
| L | Linkability | Data subjects' activities can be linked |
| I | Identifiability | Data subject can be identified |
| N | Non-repudiation | Data subject cannot deny action |
| D | Detectability | Existence of data can be inferred |
| D | Disclosure of information | Data exposed to unauthorised parties |
| U | Unawareness | Data subject unaware of processing |
| N | Non-compliance | Violation of legislation/policy |

---

## Appendix C: OWASP Top 10 (2021) Quick Reference

| # | Category | Relevant to Scarno |
|---|---------|----------------------|
| A01 | Broken Access Control | Path traversal, output path, symlink escape |
| A02 | Cryptographic Failures | N/A (no crypto) |
| A03 | Injection | ANSI injection, XML injection, JSON control chars |
| A04 | Insecure Design | subprocess shell=True risk, eval risk |
| A05 | Security Misconfiguration | XXE in xml.etree, default DTD expansion |
| A06 | Vulnerable Components | Parser DoS (ZIP bomb, billion laughs, ReDoS) |
| A07 | Identification/Auth Failures | N/A |
| A08 | Software Integrity Failures | Supply chain (PyPI), javap PATH hijack |
| A09 | Logging Failures | Traceback leaking paths/content |
| A10 | SSRF | N/A (no network) |

---

## Appendix D: GDPR Privacy by Design Principles

| Principle | Scarno Compliance |
|-----------|----------------------|
| 1. Proactive not reactive | Threat model created at design time |
| 2. Privacy as the default | No data collected by default; all analysis local |
| 3. Privacy embedded in design | No source content in output schema |
| 4. Full functionality | Security/privacy controls do not impair analysis |
| 5. End-to-end security | Analysis fully local; no transmission |
| 6. Visibility and transparency | THREAT_MODEL.md; open source; no hidden processing |
| 7. Respect for user privacy | Developer is the user; source code stays local |

---

## Appendix E: Regulatory Compliance Summary

| Regulation | Applicable? | Finding | Action Required |
|-----------|-------------|---------|----------------|
| GDPR (EU) 2016/679 | Minimally | No systematic PII processing. Edge case: developer names in source comments not extracted. | Document in README: "Scarno does not collect, store, or transmit personal data." |
| EU Cyber Resilience Act (CRA) | Likely not | Pure software CLI developer tool; no embedded firmware component. Software-only products may have limited CRA scope. | Flag for legal review before EU market placement via PyPI. |
| NIS2 Directive (EU) 2022/2555 | No | Scarno is not operated by an essential or important entity and is not critical infrastructure software in scope of NIS2. | None. |
| UK PSTI Act 2022 | No | No connected consumer product. | None. |
| California CCPA | No | No personal information collected; no California-resident targeting. | None. |
| SOC 2 Type II | No | Not a SaaS service. | None. |

---

## 10. REQ-17 Addendum (Phase 8) — Test Exclusion, Symbol Tally, Direct-Use Transitives, Mermaid Graph

This section extends the analysis above with the artefacts produced for REQ-17. It follows the same Phase-3 → Phase-9 layout as the parent document and is self-contained so a reviewer can read it in isolation.

### 10.1 Classified Requirements (REQ-17)

| ID | Type | Statement |
|----|------|-----------|
| FR-150 | Functional | `EntryPoint.usage_count: int` populated for every entry point; reporters render `used N×` when count > 0. |
| FR-151 | Functional | `Dependency.imported_directly: bool` set when project source imports a transitive dep directly. |
| FR-152 | Functional | Markdown reporter emits one ```mermaid block per analysis with status-coloured nodes and `dep_graph`-derived edges. |
| FR-153 | Functional | `--exclude-tests` drops test-scoped declared deps and skips test source files across all ecosystems. |
| FR-154 | Functional | `--test-paths PATTERN` (repeatable) extends the test-path matcher; bounded by count and length caps. |
| FR-155 | Functional | `--exclude-dev` (npm-only, off-by-default) drops `devDependencies` from npm dep parsing. |
| FR-156 | Functional | Directly-used transitives appear in their own markdown subsection ("Transitive — imported directly"). |
| FR-157 | Functional | When `--exclude-tests` skips test files, an info line "N test files skipped (--exclude-tests); findings within them not scanned" is appended to `errors` so the trade-off is auditable. |
| SEC-NEW-31 | Security NFR | `--test-paths` count cap (64) and per-pattern length cap (256B) prevent O(N×M) glob blow-up. |
| SEC-NEW-32 | Security NFR | Mermaid label sanitiser escapes `]`, `[`, `"`, newline, `\\`, ANSI/control chars; no `click` directive ever emitted; reserved tokens (`subgraph`, `classDef`, `linkStyle`, `style`, `end`, `---`, `===`) replaced with `&lt;reserved&gt;`. |
| SEC-NEW-33 | Security NFR | `--test-paths` patterns reject `..` segments, leading `/` (auto-strip + warn), and Windows backslash separators; matching uses `fnmatch.fnmatchcase` against confined relative paths only. |
| PRV-004 | Privacy | When `--exclude-tests` is on, the *count* of skipped test files is reported but not their paths (avoids leaking the test layout into shared reports). |
| PERF-007 | Performance | Mermaid render < 200 ms for 1000 deps; `--exclude-tests` discovery within 2× baseline at 32 user patterns; `usage_count` aggregation O(call_sites). |

### 10.2 Use Cases (REQ-17)

```
UC-17a: Production-only dep audit
Actor: Developer / CI
Goal: Get the SAFE/IN_USE picture for runtime code only, ignoring test deps and test sources.
Preconditions: Project has tests in any conventional location.
Main Flow:
  1. Operator invokes `scarno . --exclude-tests --format markdown`.
  2. CLI builds _RunOptions(exclude_tests=True, test_paths=()).
  3. Each analyser drops test-scoped declared deps and skips test source files.
  4. Markdown reporter renders Mermaid diagram + sectioned checklists.
Postconditions: Report contains only production-scope deps and source-derived classifications.
Data involved: project file tree, dep manifests, source code (non-test only).
Trust boundary crossings: Untrusted project → trusted CLI → operator's terminal/CI log.

UC-17b: Custom-layout test exclusion
Actor: Developer
Goal: Apply --exclude-tests to a project where tests live in `it/` and `e2e/`.
Preconditions: Default heuristic does not match the project's test layout.
Main Flow:
  1. Operator invokes `scarno . --exclude-tests --test-paths "it/**/*" --test-paths "e2e/**/*"`.
  2. CLI validates patterns (count, length, traversal, separator).
  3. TestScopeMatcher uses default + user patterns.
Postconditions: Custom test paths are excluded.
Trust boundary: Operator-supplied glob is partially trusted but bounded.

UC-17c: Promote a directly-used transitive
Actor: Developer reviewing the markdown report
Goal: Spot deps that source imports directly but that are pulled in via an unused parent.
Main Flow:
  1. Markdown reporter renders the "Transitive — imported directly" section first.
  2. Operator copies the listed deps into the appropriate manifest.
Postconditions: Manifest declares the dep; future runs no longer flag it as transitive-direct.

UC-17d: Visual review via Mermaid
Actor: PR reviewer (GitHub)
Goal: See the dependency hierarchy at a glance and notice large unused subtrees.
Main Flow:
  1. PR comment renders ```mermaid block via GitHub's native renderer.
  2. Reviewer reads colour-coded nodes; red subtrees are removal candidates.
Trust boundary: Markdown is consumed by an external renderer (GitHub) — injection defence is required.
```

### 10.3 Threats (STRIDE) for REQ-17

```
T-17 (Tampering / Information Disclosure): Mermaid label injection
Affected use case(s): UC-17d
Description: An attacker controls a dep name (via PyPI/npm namespace squatting or a local fork) and crafts a name containing
  Mermaid-active tokens (`"]; click n_3 "javascript:fetch('...exfil...')"`) so the rendered diagram either breaks the
  surrounding markdown or, on permissive renderers, fires a `click` event that exfiltrates session state.
Attack vector: Rendered in a PR comment, GitHub Pages site, internal wiki, or any Mermaid-aware viewer.
Likelihood: Medium — typosquat names are common; rendering surfaces are widespread.
Impact: High — XSS-equivalent in trusted CI/PR contexts.

T-18 (DoS): --test-paths glob blow-up
Affected use case(s): UC-17b
Description: An operator (mistakenly or maliciously, in an CI pipeline) supplies thousands of `--test-paths` patterns,
  causing the matcher to do O(N_files × M_patterns) work and starve CI of CPU.
Attack vector: CI configuration controlled by a contributor with PR-write access.
Likelihood: Low — operator is partially trusted, but CI configs are often editable from PRs.
Impact: Medium — wedges builds.

T-19 (Information Disclosure): Test-path echo to logs
Affected use case(s): UC-17b
Description: Verbose-mode log echoes user-supplied test-path patterns. If operator includes absolute hostnames or paths
  (despite the strip-leading-slash rule), they appear in CI logs visible to a wider audience.
Attack vector: Operator misconfiguration.
Likelihood: Low.
Impact: Low.

T-20 (Tampering): Test-path traversal / separator confusion
Affected use case(s): UC-17b
Description: Operator passes `..` segments, Windows-style backslashes, or absolute paths in `--test-paths`. The matcher
  could be fooled into matching files outside the project root or skipping unintended production sources, masking real
  unused-dep findings.
Attack vector: Operator misconfiguration or PR-side CI editing.
Likelihood: Low; Impact: Medium.
```

### 10.4 Privacy Threats (LINDDUN) for REQ-17

```
PT-09 (Disclosure): Test-tree disclosure via skipped-files-list
LINDDUN: Disclosure of information
Description: A naive implementation of FR-157 might list every skipped path in `errors`. Test paths often reveal
  internal layout (`tests/integration/customers/<customer-id>/...`) and potentially personal-data-shaped fixture
  filenames.
Affected data subjects: anyone whose name/identifier is encoded in a fixture filename.
Likelihood: Low; Impact: Low; GDPR relevance: Art. 5(1)(c) data minimisation.

PT-10 (Linkability): Mermaid graph fingerprinting a project
LINDDUN: Linkability
Description: A unique dep-graph fingerprint (specific transitive structure) shared in a public PR could re-identify
  a private fork or an internal build configuration.
Likelihood: Very Low; Impact: Low.
```

### 10.5 Abuse Cases

```
SAC-30: Mermaid label-injection via typosquat dep name
Linked threat: T-17
Attacker type: External (publishes a package name on PyPI/npm/Maven Central).
Goal: Hijack the rendering of the markdown report in a PR comment.
Attack Flow:
  1. Attacker publishes `pkg-foo` whose declared distribution name contains `"]; click n_0 "javascript:..."`.
  2. Victim project adds the typosquat by mistake; CI runs Scarno; markdown report goes into PR comment.
  3. Reviewer's browser renders the Mermaid block; injected `click` fires.
Impact if successful: Account-level XSS in the CI/PR review surface.
OWASP Top 10: A03:2021 — Injection.

SAC-31: --test-paths glob blow-up via PR-controlled CI yaml
Linked threat: T-18
Attacker type: Contributor with PR-write to .github/workflows.
Goal: Wedge CI by supplying thousands of patterns.
Attack Flow:
  1. Attacker edits the CI config to pass 4000 `--test-paths` patterns.
  2. CLI accepts (no cap) → matcher loops over N_files × M_patterns.
Impact if successful: CI runner stuck; build queue lengthens; possibly billable runner-minutes consumed.

SAC-32: Path traversal via --test-paths
Linked threat: T-17 / T-01 analogue
Attacker type: Same as SAC-31.
Goal: Match files outside the project root via crafted globs.
Attack Flow:
  1. Attacker passes `--test-paths "../../../etc/*"`.
  2. If matching uses fnmatch against absolute paths, /etc files could be classified as "test" and skipped — but
     more importantly, this signals path-handling sloppiness that a parallel attack might exploit.
Impact if successful: Confused-deputy scope leakage; doesn't read /etc but gives the attacker partial filesystem oracle.
```

```
PAC-09: Test-tree path leakage in --exclude-tests output
Linked threat: PT-09
Actor: System (Scarno itself, via FR-157 implementation).
Scenario: Scarno writes a per-file list of skipped test paths to errors[]; report is shared in a PR comment.
Affected data subjects: Anyone whose identifier is in a fixture filename.
PbD principle violated: "Privacy as the default."
Regulatory exposure: GDPR Art. 5(1)(c) data minimisation.
```

### 10.6 Security Use Cases (Countermeasures)

```
SUC-30: Mermaid label sanitiser
Mitigates: SAC-30
Security control: `_mermaid_label()` escapes `]`, `[`, `"`, newline, backslash; replaces ANSI/control chars; truncates to
  80 chars; rejects/replaces reserved Mermaid tokens. Reporter never emits a `click` directive.
Implementation notes: Single function in markdown_reporter, pure str→str. Property test: for any byte string input,
  the rendered diagram round-trips through mermaid CLI without warnings.
OWASP ASVS: §5.3.3 Output encoding; §5.1.4 Whitelist input validation.
Residual risk: A future Mermaid version may add a new active token; mitigated by reserved-token allowlist + test fixture.

SUC-31: --test-paths cap + traversal reject
Mitigates: SAC-31, SAC-32
Security control: `sanitise_test_paths()` enforces count ≤ 64, length ≤ 256B, no `..` segments, no `\\`, leading `/` stripped + warned.
Implementation notes: Centralise in `core/test_scope.py`. CLI maps `ValueError` → sanitised `_CliError` → exit 2.
OWASP ASVS: §5.1.3 Input validation.
Residual risk: An operator with shell access can still pass crazy values; the cap bounds CPU but cannot prevent voluntary CI mis-config.

SUC-32: Path-confined fnmatch
Mitigates: SAC-32
Security control: `TestScopeMatcher.is_test_path` is called with paths that have already passed `relative_to(project_root)`.
  Patterns are compared against this *relative* string only — the match operation cannot escape root because the input cannot.
Implementation notes: Document the contract on the matcher class; assert `not Path(rel).is_absolute()` at the top.
Residual risk: None.
```

### 10.7 Privacy Use Cases (Privacy Controls)

```
PUC-04: Aggregate-only test-skip reporting
Mitigates: PAC-09
Privacy control: FR-157 emits only the count, not the paths. Verbose mode (`--verbose`) is the only way to see the per-file
  list, and even then the output is sanitise()'d.
PbD principle: Privacy as the default.
GDPR: Art. 5(1)(c) data minimisation.
```

### 10.8 SRTM Rows (REQ-17)

| Req ID | Description (Short) | Use Cases | STRIDE/LINDDUN | Abuse Cases | Countermeasures | Test IDs | Priority |
|--------|--------------------|-----------|----------------|-------------|-----------------|----------|----------|
| FR-150 | EntryPoint.usage_count populated | UC-17a | — | — | — | TA-150 | High |
| FR-151 | Dependency.imported_directly | UC-17a, UC-17c | — | — | — | TA-151 | High |
| FR-152 | Mermaid block in markdown | UC-17d | T-17 | SAC-30 | SUC-30 | TA-152, TA-152s | High |
| FR-153 | --exclude-tests across ecosystems | UC-17a | — | — | — | TA-153a..f | High |
| FR-154 | --test-paths matcher | UC-17b | T-18, T-19 | SAC-31, SAC-32 | SUC-31, SUC-32 | TA-154, TA-154s | High |
| FR-155 | --exclude-dev (npm) | UC-17a | — | — | — | TA-155 | Medium |
| FR-156 | Promote subsection in markdown | UC-17c | — | — | — | TA-156 | Medium |
| FR-157 | Aggregate skip reporting | UC-17a | PT-09 | PAC-09 | PUC-04 | TA-157 | Medium |
| SEC-NEW-31 | Test-path count + length caps | UC-17b | T-18 | SAC-31 | SUC-31 | TA-154s | High |
| SEC-NEW-32 | Mermaid injection defence | UC-17d | T-17 | SAC-30 | SUC-30 | TA-152s | Critical |
| SEC-NEW-33 | Test-path traversal reject | UC-17b | T-17 (analogue) | SAC-32 | SUC-31, SUC-32 | TA-154s | High |
| PRV-004 | No test-path leak | UC-17a | PT-09 | PAC-09 | PUC-04 | TA-157 | Medium |
| PERF-007 | Mermaid + matcher perf bounds | UC-17a, UC-17d | — | — | — | TA-perf-007 | Medium |

### 10.9 Test Artifacts (REQ-17)

#### 9.1 Functional Security Tests

| ID | Test | Verifies | Pass condition |
|----|------|----------|---------------|
| TA-150 | usage_count tally — Python | `flask.Flask` called 23× → `usage_count == 23` | Equality check |
| TA-150b | usage_count — JS/TS | `lodash.debounce` called 7× | Equality check |
| TA-151 | imported_directly — Python transitive | `import lodash_clone` where parent is unused | `imported_directly==True`, status not `SAFE` |
| TA-152 | Mermaid happy-path | Markdown contains exactly one ```mermaid block before checklists | Regex match + ordering |
| TA-153a | --exclude-tests Python deps | `pyproject.toml [project.optional-dependencies] test=...` dropped | `pytest` not in result.dependencies |
| TA-153b | --exclude-tests Maven | `<scope>test</scope>` dropped | `junit` absent |
| TA-153c | --exclude-tests Gradle | `testImplementation`, `androidTestImplementation` dropped | `mockito-core` absent |
| TA-153d | --exclude-tests JS/TS sources | `tests/foo.test.ts` skipped during discovery | imports from that file absent |
| TA-153e | --exclude-tests Go | `_test.go`-only dep dropped | `testify` absent when only used in tests |
| TA-153f | --exclude-tests C# | `Foo.Tests.csproj` deps dropped | `xunit` absent |
| TA-154 | --test-paths matcher | `it/IntegrationTest.java` skipped when `--test-paths "it/**/*"` is on | Imports from that file absent |
| TA-155 | --exclude-dev (npm) | `devDependencies` dropped only when flag is on | Off-by-default semantics preserved |
| TA-156 | Markdown promote subsection | "Transitive — imported directly" section appears above "In use" | Heading order test |
| TA-157 | --exclude-tests aggregate-only reporting | errors contains exactly one summary line, no per-file paths | Line-count + content assertion |

#### 9.2 Security Attack Tests

| ID | Attack | Input | Expected |
|----|--------|-------|----------|
| TA-152s | Mermaid label injection | dep name `"]; click n_0 "javascript:alert(1)"` | Output never contains `click `; no `]` outside escaped form; mermaid CLI parses without warnings |
| TA-152s2 | Mermaid reserved-token | dep name `subgraph` / `classDef` / `linkStyle` / `style` / `---` | Replaced with `&lt;reserved&gt;` in label |
| TA-154s | --test-paths traversal reject | `--test-paths "../../etc/*"` | Exit 2; sanitised "must stay inside project root" message |
| TA-154s2 | --test-paths Windows separator | `--test-paths "tests\\*"` | Exit 2; sanitised error |
| TA-154s3 | --test-paths count cap | 65 patterns | Exit 2; "too many patterns" |
| TA-154s4 | --test-paths length cap | one pattern of 257 bytes | Exit 2; "pattern too long" |
| TA-154s5 | --test-paths leading slash | `--test-paths "/abs/p"` | Stripped; verbose-mode warning emitted |
| TA-152s3 | Mermaid no click ever | any dep name | grep `^click ` returns no lines |
| TA-perf-007 | Mermaid render perf | 1000 deps, 2000 edges (truncated to 500/2000) | render time < 200 ms |

#### 9.3 Privacy Verification Tests

| ID | Test | Verifies | Pass condition |
|----|------|----------|---------------|
| TA-157 | No per-file path leak | --exclude-tests on a project with 50 test files | errors contains "50 test files skipped"; no "tests/" string elsewhere in non-verbose output |
| TA-PRV-004 | Verbose-mode opt-in for paths | --exclude-tests + --verbose | per-file list permitted in stderr only, not stdout |

#### 9.4 Penetration Testing Scenarios

```
PEN-17a: Adversarial dep names → Mermaid
Scope: MarkdownReporter._render_mermaid path
Objectives: Render every fixture in tests/security/fixtures/req17/ and confirm rendered output is parseable by
  mermaid CLI v10+ without warnings, and no `click ` line is present.
Key abuse cases: SAC-30
Out of scope: Network-rendered Mermaid (browser XSS sandboxing varies; CLI parse is the canonical check).

PEN-17b: --test-paths fuzz
Scope: cli.py + core/test_scope.py
Objectives: Atheris fuzzing of `sanitise_test_paths` with adversarial bytes, expecting either ValueError or a
  validated tuple — never a traceback or hang.
```

### 10.10 Refined Requirements (carry-over additions)

The complete refined set above (10.1) is added to the master Requirements list. No requirements from REQ-1..REQ-16 are dropped.

---

## 11. REQ-17b Addendum (Phase 8b) — Per-Language Entry-Point Taxonomy + Path Hardening

### 11.1 New abuse cases

```
SAC-33: npm dep name traversal via crafted package.json
Linked threat: T-23
Attacker type: External (commits a package.json declaring a dep with `..` segments).
Goal: Cause Scarno to read out-of-tree `node_modules/<traversal>/package.json` and surface its
  exports field's keys in the report (CI log / PR comment).
Attack Flow:
  1. Attacker commits ``"dependencies": { "../../../../etc/some-other-app": "1.0.0" }``.
  2. Scarno's JS source analyser builds ``node_modules/<traversal>/package.json``.
  3. Without validation, OS resolves the traversal and the file is read.
Impact if successful: leaks `package.json`-shaped file structure from anywhere readable on the host.
Mitigated by: SEC-NEW-34 (validator at parse time) + SEC-NEW-32-style confinement at read.
OWASP: A01:2021 — Broken Access Control.

SAC-34: C# .sln Project reference traversal
Linked threat: T-24
Attacker type: External (commits a .sln file).
Goal: Cause Scarno to read out-of-tree `.csproj` files and surface their PackageReference data.
Attack Flow:
  1. Attacker commits ``Project("{...}") = "Foo", "..\\..\\sibling-private\\Inner.csproj", ...``.
  2. Without confinement, the resolved path escapes project root.
  3. The XML is read and PackageReference / Exec / UsingTask values reach the report.
Impact if successful: dep names, custom build commands, MSBuild property values from sibling/private
  projects leak into PR comments / SARIF dashboards.
Mitigated by: SEC-NEW-35 (resolve_and_confine).
OWASP: A01:2021 — Broken Access Control.

SAC-35: Maven transitive walker following adversarial GAV from cached POM
Linked threat: T-21
Attacker type: External (publishes a malicious POM to a registry / commits a tampered local cache entry).
Goal: Cause Scarno to read arbitrary files via `..` segments in `<groupId>` / `<version>` of a
  cached POM's `<dependencies>` block.
Attack Flow:
  1. A cached POM contains `<dependency><groupId>../../etc</groupId>...</dependency>`.
  2. Worklist re-enters with that GAV.
  3. Without strict GAV validation, file outside `~/.m2/repository` could be read.
Impact if successful: arbitrary file read constrained to XML-shaped POMs.
Mitigated by: T-21 controls — `_validate_gav` rejects bad GAVs; `resolve_and_confine` to repo root;
  DOCTYPE rejection blocks XXE; 1000-node cap bounds traversal.
OWASP: A01:2021 — Broken Access Control.
```

### 11.2 New countermeasures

```
SUC-33: npm dep-name validation
Mitigates: SAC-33
Security control: ``_is_valid_npm_name(name)`` checks the full npm spec — optional `@scope/`
  prefix, identifier-class characters only, no `..` segments, no `\\`, no leading `.` or `_`,
  ≤ 214 chars. Defense-in-depth: ``_resolve_entry_points`` ALSO confines the constructed path.
Implementation notes: ``analysers/javascript/dep_file_parser.py:_NPM_NAME_RE``,
  ``analysers/javascript/source_analyser.py:_resolve_entry_points``.
OWASP ASVS: §5.1.4 Whitelist input validation.
Residual risk: a name that *passes* the validator but contains characters that surprise a downstream
  consumer (e.g. unicode confusables) — sanitise() at the report layer is the safety net.

SUC-34: .sln project-path confinement
Mitigates: SAC-34
Security control: ``_projects_from_sln`` wraps each resolved project path in
  ``resolve_and_confine(..., root)`` and skips on PathEscapeError, emitting a sanitised
  "escapes project root" error.
Implementation notes: ``analysers/csharp/dep_file_parser.py:_projects_from_sln``.
OWASP ASVS: §12.3.1 Path traversal.

SUC-35: Maven transitive walker confinement
Mitigates: SAC-35
Security control: ``_validate_gav`` rejects coords with traversal characters before any cache
  lookup happens; ``_locate_pom_in_local_cache`` uses ``resolve_and_confine`` to bound the
  resolved path under ``~/.m2/repository``; ``_parse_pom_file`` rejects DOCTYPE pre-parse;
  1000-node visit cap bounds the worklist.
Implementation notes: ``analysers/java/maven.py:_build_transitive_graph``.
OWASP ASVS: §12.3.1 Path traversal; §6.1.1 Crypto-unsafe deserialisation analogue (XXE).
```

### 11.3 Functional requirements (FR-160 .. FR-172)

| ID | Description | Test |
|---|---|---|
| FR-160 | Java `method_invocation` walker → `kind="method"` entries | `test_java_reporting_gaps.py::test_static_method_invocation_surfaces_as_method_entry_point` |
| FR-161 | Java `object_creation_expression` → `kind="constructor"` | `test_java_reporting_gaps.py::test_new_imported_class_surfaces_as_constructor` |
| FR-162 | Java instance-method attribution via `variable_types` | `test_java_reporting_gaps.py::test_local_variable_call_attributes_to_declared_type` |
| FR-163 | Java multi-wildcard signature disambiguation via `javap` | `test_java_reporting_gaps.py::test_method_signature_disambiguates_clashing_wildcards` |
| FR-164 | Java DI / reflective activation entry points | `test_java_reporting_gaps.py::test_di_annotation_in_use_dep_has_used_entry_point` |
| FR-165 | Maven transitive `dep_graph` from `~/.m2/repository` | `test_entry_points_and_graph_e2e.py::test_maven_dep_graph_includes_transitives_from_m2_cache` |
| FR-166 | Maven `${project.version}` resolves to leaf POM | `test_java_reporting_gaps.py::test_project_version_resolves_to_child_version` |
| FR-167 | Python wildcard import + unqualified-name attribution | `test_python_reporting_gaps.py::test_wildcard_import_attributes_unqualified_calls` |
| FR-168 | Python instance-method via assignment / annotation binding | `test_python_reporting_gaps.py::test_assignment_to_constructor_binds_type` |
| FR-169 | JS named/default/namespace per-symbol tracking | `test_javascript_reporting_gaps.py::test_named_import_function_call_surfaces_with_count` |
| FR-170 | JS constructor + instance-method attribution | `test_javascript_reporting_gaps.py::test_const_assignment_to_new_binds_type` |
| FR-171 | C# constructor + method + type-binding | `test_csharp_reporting_gaps.py::test_var_assignment_to_new_binds` |
| FR-172 | Go selector / composite literal / type-binding | `test_go_reporting_gaps.py::test_short_var_decl_to_call_binds_return_type` |

### 11.4 Open-source consumer guidance

REQ-17b documents the limitations users should know about before
relying on Scarno output in production. See
`docs/requirements/REQ-17b.md` § "Aggregate limitations summary" for
the canonical list. Highlights:

1. Type inference is shallow (no promise-peeling, no chained-call
   return-type inference, no generics-with-type-parameter
   resolution).
2. Last-write-wins for variable bindings.
3. Heuristic attribution under ambiguity — over-attribution is
   preferred to silence.
4. No DLL inspection for C# (heuristic attribution only).
5. CDN-loaded HTML/CSS deps surface only as IN_USE/SAFE.
6. Reflective / dynamic invocation flags as UNCERTAIN by design.

---

## 12. REQ-18 Addendum (Phase 8c) — TypeScript First-Class Support

### 12.1 New abuse cases

```
SAC-38: @types/<traversal> dep name → runtime-target derivation
Linked threat: T-25
Attacker: External (publishes a malicious @types-prefixed name to npm).
Goal: Cause _runtime_target_for_types_stub to derive a runtime target string
  containing path-traversal characters that downstream code might use as a
  filesystem-path component.
Mitigation: SEC-NEW-34 (existing) rejects the @types/... name at parse time.
  SEC-NEW-36 (new) re-validates the derived runtime target so even if a
  future code path bypassed _deduplicate, the pairing would not establish.

SAC-39: Adversarial .d.ts file (deeply nested types)
Linked threat: T-26
Attacker: External (commits a 10MB .d.ts with deeply nested generic types).
Goal: Stall the source walk via tree-sitter parse.
Mitigation: existing PERF-006 + MAX_FILE_BYTES controls extend transparently
  to .d.ts files (they're scanned via the existing `*.ts` glob).
```

### 12.2 New countermeasures

```
SUC-38: @types runtime-target re-validation
Mitigates: SAC-38
Control: After ``_runtime_target_for_types_stub`` extracts the runtime name,
  re-validate it via ``_is_valid_npm_name``. If invalid, the pairing is
  silently dropped (the @types entry remains, just unpaired).
Implementation: ``analysers/javascript/dep_file_parser.py``.
OWASP ASVS: §5.1.4 Whitelist input validation.

SUC-39: .d.ts file-size + parse-timeout reuse
Mitigates: SAC-39
Control: .d.ts files are governed by the same MAX_FILE_BYTES and per-file
  tree-sitter parse timeout as `.ts` files. No new code path — the TS
  parser already covers them via the `*.ts` glob.
```

### 12.3 Functional requirements (FR-180 .. FR-184)

| ID | Description | Test |
|---|---|---|
| FR-180 | `@types/X` runtime-pair detection | `test_typescript_support.py::test_at_types_runtime_pair` |
| FR-181 | `import type` distinguished from runtime imports | `test_typescript_support.py::test_import_type_distinct_kind` |
| FR-182 | `.d.ts` `declare module "x"` ambient scan | `test_typescript_support.py::test_dts_ambient_module_declaration` |
| FR-183 | TS decorator entry-point kind | `test_typescript_support.py::test_ts_decorator_kind` |
| FR-184 | Scoped `@types/scope__pkg` → `@scope/pkg` mapping | `test_typescript_support.py::test_scoped_at_types_pair` |

### 12.4 Privacy

PUC-05 — type-only specifiers and ambient module names pass through
the same `sanitise()` as runtime imports before reaching any reporter.
No new exposure surface introduced by REQ-18.

---

## 13. REQ-19 Addendum (Phase 9a) — Per-Edge Version Labels

### 13.1 Executive context

REQ-19 re-keys the dependency graph so every parent → child edge
carries the *declared* version of the child as it appears in that
parent's manifest. The same library declared at two different
versions by two different parents now renders as two distinct nodes.
Maven, Gradle, and npm are in scope; PyPI / Go / NuGet / CSS keep
existing behaviour and will be extended in a future REQ.

REQ-19 is the substrate REQ-20 (per-version classification),
REQ-21/21b/23 (pinning), and REQ-22 (cross-version ABI diff) all
build on. No prior REQ requirements are dropped — the legacy
canonical-only `dep_graph` is kept for backwards compatibility and
derived from `dep_edges` when only the new field is supplied.

### 13.2 New abuse cases

```
SAC-40: Crafted version string with control / Mermaid-active characters
Linked threat: T-27
Attacker type: External (commits a poisoned pom.xml / package-lock.json).
Goal: Inject ANSI escapes / newlines / Mermaid-reserved tokens into the
  declared-version field, breaking the rendered Markdown report or smuggling
  fake content into a CI bot's PR comment.
Mitigated by: SEC-NEW-38 (sanitise_declared_version), reuse of existing
  _mermaid_label sanitiser at render time.
OWASP: A03:2021 — Injection.

SAC-41: Adversarial lockfile with millions of edges
Linked threat: T-27
Attacker type: External (commits a synthetic package-lock.json).
Goal: Cause Scarno to consume O(N) memory parsing edges where N is
  attacker-chosen.
Mitigated by: SEC-NEW-37 (_LOCKFILE_MAX_BYTES=8MiB,
  _LOCKFILE_MAX_EDGES=50000).
OWASP: A05:2021 — Security Misconfiguration.
```

### 13.3 New countermeasures

```
SUC-40: declared-version sanitiser
Mitigates: SAC-40
Control: every DepEdge.declared_version produced by
  sanitise_declared_version() (SEC-NEW-38). Reporter code MUST NOT
  bypass the field.
Implementation: src/scarno/security.py.
OWASP ASVS: §5.2.1.

SUC-41: lockfile and edge caps
Mitigates: SAC-41
Control: SEC-NEW-37 — file-size pre-check + edge-count post-check.
  Either trip stops edge emission and records a sanitised error;
  the rest of the analysis still runs.
Implementation: src/scarno/analysers/javascript/dep_file_parser.py +
  src/scarno/analysers/java/maven.py.
OWASP ASVS: §11.1.4.
```

### 13.4 Functional requirements (FR-190 .. FR-195)

| ID | Description | Test |
|---|---|---|
| FR-190 | `DepEdge` dataclass with declared_version + scope | `test_req19_models.py::test_depedge_fields` |
| FR-191 | Maven `_emit_dep_edges` records declared `<version>` per `<dependency>` | `test_req19_maven_edges.py` |
| FR-192 | Gradle dependency-output parser yields DepEdge with requested version | `test_req19_gradle_edges.py` |
| FR-193 | npm package-lock.json v2/v3, yarn.lock, pnpm-lock.yaml edge emission | `test_req19_npm_edges.py` |
| FR-194 | Markdown reporter renders distinct (canonical, version) nodes | `test_req19_tree_render.py` |
| FR-195 | Backwards-compat: dep_graph derived from dep_edges when both populated | `test_req19_compat.py` |

### 13.5 Privacy

```
PT-11: Edge-leak of internal coordinate names via dep_edges JSON dump
LINDDUN: Disclosure
Affected data: canonical names already exposed by REQ-17 (no expansion).
Likelihood: Medium; Impact: Low. Same scope as the existing exposure.

PUC-10: Sanitised version strings in all reporter outputs
Privacy control: declared-version strings inherit the sanitise() +
  SEC-NEW-38 length cap.
PbD principle: Privacy embedded into design.
```

---

## 14. REQ-20 Addendum (Phase 9b) — Per-Version Classification + Resolved Marker

### 14.1 Executive context

REQ-20 classifies each (canonical, declared_version) node
independently as SAFE / UNCERTAIN / IN_USE based on whether any
parent path reaching that specific version is IN_USE. The version the
package manager actually picks at resolution time is rendered with a
visible marker. A new "Multiple versions detected" report section
lists every coordinate present at >1 declared version with its
declared versions, the resolved version, and per-version
removability — explicitly motivated by SBOM-noise reduction
(`COMP-004`).

The classifier (`SUC-42`) defers to pinning flags from REQ-21 /
REQ-21b / REQ-23 before promoting any direct dep version to SAFE.
This is the load-bearing safety property that prevents
silent-vulnerability-reintroduction misclassifications.

### 14.2 New abuse cases

```
SAC-42: False-positive removal of a pinned version
Linked threat: T-28
Attacker type: Not external — classifier-correctness threat that
  propagates into developer action.
Goal: Cause Scarno to recommend removing a version that is in fact
  the resolved one and on the classpath (e.g. via a dependencyManagement
  pin without source-level use).
Mitigated by: SUC-42 — defer to pin_override + manifest_redundant
  flags before any SAFE classification; default to UNCERTAIN on doubt.
OWASP: A04:2021 — Insecure Design.

SAC-43: State-explosion via crafted lockfile with many versions per coord
Linked threat: T-28
Attacker type: External.
Mitigated by: SEC-NEW-39 (per-coordinate version cap of 64) +
  SEC-NEW-37 inherited from REQ-19.
OWASP: A05:2021.
```

### 14.3 New countermeasures

```
SUC-42: Classifier defers to pinning + redundant flags
Mitigates: SAC-42
Control: Before classifying a (canonical, declared_version) node SAFE,
  the classifier checks Dependency.manifest_redundant (FR-150),
  pin_override (REQ-21 / 21b / 23), and the resolved-version marker.
  Any positive flag forces IN_USE with the relevant pinning reason.
Implementation: src/scarno/core/detector.py.
OWASP ASVS: §1.4.1.

SUC-43: Per-coordinate version cap
Mitigates: SAC-43
Control: SEC-NEW-39 caps versions per coordinate at 64.
Implementation: src/scarno/core/detector.py.
OWASP ASVS: §11.1.4.

SUC-44: SBOM-noise reporting
Mitigates: COMP-004 (CRA SBOM clarity)
Control: "Multiple versions detected" section labels which declared
  versions are removable and which is resolved. SARIF rule
  TS-DEP-MULTI-VERSION carries the same data.
Implementation: src/scarno/reporters/markdown_reporter.py +
  json_reporter + sarif_reporter.
```

### 14.4 Functional requirements (FR-200 .. FR-207)

| ID | Description | Test |
|---|---|---|
| FR-200 | `VersionedNode` dataclass + AnalysisResult.versioned_nodes | `test_req20_models.py` |
| FR-201 | Per-version classification: SAFE only when all parent paths SAFE | `test_req20_classify.py::test_diamond_partial_safe` |
| FR-202 | Per-version classification: IN_USE if any parent path IN_USE | `test_req20_classify.py::test_diamond_partial_in_use_promotes` |
| FR-203 | Resolved-version detection (Maven via dependency:tree) | `test_req20_resolved_maven.py` |
| FR-204 | Resolved-version detection (Gradle via dependencies output) | `test_req20_resolved_gradle.py` |
| FR-205 | Resolved-version detection (npm/yarn/pnpm lockfile) | `test_req20_resolved_npm.py` |
| FR-206 | "Multiple versions detected" markdown section | `test_req20_multi_version_section.py` |
| FR-207 | SARIF rule TS-DEP-MULTI-VERSION emission | `test_req20_sarif.py` |

### 14.5 Privacy

```
PT-12: Per-version disclosure of internal coordinates
LINDDUN: Disclosure — same scope as REQ-17 / REQ-19 (no expansion).
Likelihood: Low; Impact: Low.

PUC-11: Version strings inherit REQ-19 sanitisation
PbD principle: Privacy embedded into design.
```

---

## 15. REQ-21 Addendum (Phase 9c) — Maven Pinning / Exclusion-Override Detection

### 15.1 Executive context

REQ-21 prevents the most dangerous failure mode of any dependency
pruner: silently recommending the removal of a direct dependency
that is actually substituting for an excluded or DM-pinned
transitive. Without REQ-21, the user removes the pin, Maven
re-resolves, and the original (often vulnerable) version reappears
on the classpath. REQ-21 detects two patterns:

- **Exclusion-override**: some transitive declares
  `<exclusions><exclusion>X</exclusion></exclusions>` and a direct
  `<dependency>X</dependency>` exists at the same group:artifact.
- **dependencyManagement pin**: the root POM forces X via
  `<dependencyManagement>` with no source-level use of X, and X is
  reached transitively.

Both flag the affected dep as `pin_override=True` with status forced
to IN_USE; reporters explain the substitution.

### 15.2 New abuse cases

```
SAC-44: Silent vulnerability reintroduction via false-positive removal
Linked threat: T-30
Attacker type: Not external — tool-induced developer action.
Goal: Cause the developer to delete a direct <dependency> that
  substitutes for an excluded vulnerable transitive.
Mitigated by: SUC-45 (pattern-(a) detection) + SUC-46 (pattern-(b)
  detection) + UNCERTAIN-on-doubt fallback.
OWASP: A06:2021 — Vulnerable and Outdated Components.

SAC-45: Adversarial pom.xml with thousands of <exclusions>
Linked threat: T-30
Mitigated by: SEC-NEW-40 caps (_MAX_EXCLUSIONS_PER_DEP=128,
  _MAX_DM_ENTRIES=2048).
OWASP: A05:2021.
```

### 15.3 New countermeasures

```
SUC-45: Exclusion-override pattern (a) detection
Mitigates: SAC-44 (pattern (a))
Control: Indexed lookup of <exclusion> entries against direct deps
  with no source-level use; match flips pin_override=True with
  kind=EXCLUSION.
Implementation: analysers/java/maven.py:_detect_pin_overrides.
OWASP ASVS: §1.4.1.

SUC-46: dependencyManagement pin pattern (b) detection
Mitigates: SAC-44 (pattern (b))
Control: Index <dependencyManagement> after property resolution;
  match against direct deps that are also reached transitively.
Implementation: analysers/java/maven.py:_detect_pin_overrides.
OWASP ASVS: §1.4.1.

SUC-47: SEC-NEW-40 caps
Mitigates: SAC-45
Control: Per SEC-NEW-40.
Implementation: analysers/java/maven.py.
OWASP ASVS: §11.1.4.
```

### 15.4 Functional requirements (FR-210 .. FR-215)

| ID | Description | Test |
|---|---|---|
| FR-210 | Maven `<exclusions>` collected into an index | `test_req21_exclusions_index.py` |
| FR-211 | Pattern (a): direct dep matches an excluded transitive | `test_req21_pattern_a.py` |
| FR-212 | Maven `<dependencyManagement>` parsed after property resolution | `test_req21_dm_parse.py` |
| FR-213 | Pattern (b): direct dep DM-pinned and reached transitively | `test_req21_pattern_b.py` |
| FR-214 | REQ-20 classifier defers to pin_override (status forced IN_USE) | `test_req21_classifier_integration.py` |
| FR-215 | Markdown / JSON / SARIF report sections for pin-overrides | `test_req21_reporters.py` |

### 15.5 Privacy

No new data category; all new strings inherit PUC-10 sanitisation.

---

## 16. REQ-21b Addendum (Phase 9d) — Gradle Pinning Detection

### 16.1 Executive context

REQ-21b carries REQ-21's semantics into Gradle: `force()`,
`strictly`, `constraints { }`, `resolutionStrategy.eachDependency`,
and configuration-level `exclude(group, module)`. Because Gradle's
Groovy / Kotlin DSL is open-ended, REQ-21b is conservative — anything
the static parser cannot fully resolve is downgraded to UNCERTAIN
(never silently classed as removable). Sequenced as a later PR
than REQ-21 / REQ-22 / REQ-23.

### 16.2 New abuse cases

```
SAC-46: Gradle DSL evasion of pin detector
Linked threat: T-31
Attacker type: Not external — same shape as SAC-44 within Gradle.
Mitigated by: SUC-48 — UNCERTAIN-on-doubt fallback when the parser
  cannot statically resolve the directive.
OWASP: A04:2021.

SAC-47: Adversarial Gradle script with deeply nested closures
Linked threat: T-31
Attacker type: External.
Mitigated by: SEC-NEW-41 — _GRADLE_PARSE_TIMEOUT_S=8s plus directive
  count caps.
OWASP: A05:2021.
```

### 16.3 New countermeasures

```
SUC-48: UNCERTAIN fallback for dynamic Gradle DSL
Mitigates: SAC-46
Control: Any GradleForceDirective with dynamic=True downgrades the
  matched direct dep to UNCERTAIN with an explicit "manual review"
  reason.
Implementation: analysers/java/gradle.py:_detect_pin_overrides.

SUC-49: Gradle parser caps + tree-sitter timeout
Mitigates: SAC-47
Control: SEC-NEW-41 — _GRADLE_MAX_FORCE_DIRECTIVES=256,
  _GRADLE_MAX_EXCLUSIONS=256, _GRADLE_PARSE_TIMEOUT_S=8s.
Implementation: analysers/java/gradle.py.
OWASP ASVS: §11.1.4.
```

### 16.4 Functional requirements (FR-220 .. FR-225)

| ID | Description | Test |
|---|---|---|
| FR-220 | Tree-sitter walker emits GradleForceDirective for force() | `test_req21b_force.py` |
| FR-221 | Walker emits directive for strictly() in version block | `test_req21b_strictly.py` |
| FR-222 | Walker emits directive for constraints {} block | `test_req21b_constraints.py` |
| FR-223 | Walker emits directive for resolutionStrategy.eachDependency | `test_req21b_each_dependency.py` |
| FR-224 | Walker emits GradleExclusion for exclude(group, module) | `test_req21b_exclude.py` |
| FR-225 | Dynamic-pin downgrade to UNCERTAIN | `test_req21b_dynamic.py` |

### 16.5 Privacy

No new data category.

---

## 17. REQ-22 Addendum (Phase 9e) — Cross-Version ABI Diff

### 17.1 Executive context

REQ-22 closes the runtime-failure gap left when source code calls
into a transitive whose declared version differs from the resolved
version: a `NoSuchMethodError`-class failure that compiles fine
against the declared API but crashes at runtime against the resolved
JAR. Implemented as a Maven-only, opt-in feature behind
`JvmSourceAnalyser(deep_inspection=True)` — `javap` is never spawned
by default per the established performance baseline
(`feedback_javap_fast_path`). Reads JARs strictly from
`~/.m2/repository`; if a version is not cached, the diff is skipped
with a sanitised note, never fetched.

REQ-22 also generates the highest-confidence compliance signal
across all six new REQs: `Finding(severity=HIGH, kind=RUNTIME_RISK)`
for any source-referenced symbol that exists in a declared version
but is REMOVED or CHANGED in the resolved version. SBOM consumers
read this through SARIF rule `TS-ABI-RUNTIME-RISK`.

### 17.2 New abuse cases

```
SAC-48: Crafted JAR triggers javap CPU exhaustion
Linked threat: T-32
Attacker type: External (commits a malicious dep with a hostile JAR).
Goal: Stall analysis when --deep-inspection is enabled.
Mitigated by: SUC-50 — _JAVAP_PER_JAR_TIMEOUT_S=30s, argv-only
  invocation, JAVA_HOME pinning (existing _invoke_javap_safe controls,
  T-22).
OWASP: A05:2021.

SAC-49: Path traversal via crafted coordinate during m2 lookup
Linked threat: T-33
Attacker type: External.
Goal: Cause _m2_jar_path to resolve outside ~/.m2/repository.
Mitigated by: SUC-51 — resolve_and_confine + reused _validate_gav
  (T-21).
OWASP: A01:2021.

SAC-50: Cache enumeration disclosure of unrelated artifacts
Linked threat: T-34
Attacker type: Local (CI step / curious user).
Goal: Learn private coordinates from ~/.m2 that aren't part of the
  scanned project.
Mitigated by: SUC-52 — coord-restricted reads (no wholesale ~/.m2
  enumeration); PUC-12 sanitises error paths.
OWASP: A09:2021.
```

### 17.3 New countermeasures

```
SUC-50: javap subprocess hardening reuse
Mitigates: SAC-48
Control: Reuse existing _invoke_javap_safe wrapper (shell=False,
  validated argv, JAVA_HOME-pinned binary, 30s timeout). REQ-22 adds
  no new javap invocation site outside this wrapper.
Implementation: src/scarno/security.py:_invoke_javap_safe.
OWASP ASVS: §11.1.4 + §1.4.1.

SUC-51: Path confinement for m2 reads
Mitigates: SAC-49
Control: Every constructed JAR path passes through
  resolve_and_confine(path, root=m2_root) AND _validate_gav before
  any FS read.
Implementation: src/scarno/analysers/java/abi_diff.py.
OWASP ASVS: §12.3.1.

SUC-52: Coordinate-restricted cache reads
Mitigates: SAC-50, PT-13
Control: Reader enumerates JARs only for coordinates already present
  in the project's dep_edges. Errors include only the requested
  coordinate, never directory listings.
Implementation: src/scarno/analysers/java/abi_diff.py.

SUC-53: Per-run JAR cap
Mitigates: SAC-48 amplification
Control: SEC-NEW-43 _JAVAP_MAX_JARS_PER_RUN=128.
```

### 17.4 Functional requirements (FR-230 .. FR-236)

| ID | Description | Test |
|---|---|---|
| FR-230 | --deep-inspection CLI flag plumbed to JvmSourceAnalyser | `test_req22_cli.py` |
| FR-231 | _m2_jar_path constructs a confined cache path | `test_req22_m2_path.py` |
| FR-232 | javap_public_signatures parses javap -public output | `test_req22_javap_parse.py` |
| FR-233 | signature_diff yields ADDED / REMOVED / CHANGED sets | `test_req22_diff.py` |
| FR-234 | Source call-set cross-reference produces RUNTIME_RISK Findings | `test_req22_runtime_risk.py` |
| FR-235 | Markdown / JSON / SARIF reporting integration | `test_req22_reporters.py` |
| FR-236 | "JAR not cached" graceful skip with note | `test_req22_missing_jar.py` |

### 17.5 Privacy

```
PT-13: Disclosure of unrelated ~/.m2 cache contents via error paths
LINDDUN: Disclosure
Affected data: filenames / coordinates of cached artifacts that are
  NOT part of the analysed project.
Likelihood: Low; Impact: Medium (corporate confidentiality).

PUC-12: Sanitised error output for cache reads
Privacy control: errors from _m2_jar_path / safe_jar_entries pass
  through sanitise(); they include only the coordinate that triggered
  the read, never the raw path attempted.
PbD principle: Privacy embedded into design.
```

### 17.6 Compliance

```
COMP-004: CRA / SBOM runtime-risk surfacing
Origin: REQ-22 cross-version ABI diff
Scope: EU CRA Annex II (security properties; vulnerability handling).
Rationale: An SBOM lists multiple versions of a coordinate but cannot
  by itself communicate that a NoSuchMethodError-class failure is
  imminent on a specific transition. REQ-22 emits this as a
  high-confidence Finding(HIGH, RUNTIME_RISK) and SARIF rule
  TS-ABI-RUNTIME-RISK.
Implementation: existing Finding pipeline.
Tests: tests/integration/test_req22_compliance_signal.py.
```

---

## 18. REQ-23 Addendum (Phase 9f) — npm Overrides / Resolutions Pinning

### 18.1 Executive context

REQ-23 mirrors REQ-21's semantics into npm / yarn / pnpm. Three
mechanisms force a package to a specific version regardless of
transitive declarations: `overrides` (npm 8+), `resolutions` (yarn,
also read by pnpm), and `pnpm.overrides`. Each maps onto the same
`pin_override` flag introduced by REQ-21 with a mechanism-specific
`pin_override_kind`. Targeted overrides (`overrides.parent.child`,
`pnpm.overrides "parent>child"`) are handled with one level of
nesting; deeper nesting capped by SEC-NEW-45.

### 18.2 New abuse cases

```
SAC-51: Adversarial overrides tree triggers parser explosion
Linked threat: T-34
Attacker type: External.
Mitigated by: SEC-NEW-45 (_NPM_OVERRIDES_MAX_ENTRIES=2048,
  _NPM_OVERRIDES_MAX_NESTING=8).
OWASP: A05:2021.

SAC-52: Misleading override target name (homoglyph / shadowing)
Linked threat: T-35
Attacker type: External.
Goal: Cause REQ-23 to attribute a pin to the wrong dep, hiding a
  real removable dep.
Mitigated by: SUC-54 — exact-match-only logic + reuse of npm-name
  validator (SEC-NEW-34).
OWASP: A04:2021.
```

### 18.3 New countermeasures

```
SUC-54: Exact-match override target validation
Mitigates: SAC-52
Control: NpmOverride.target_name passes through _is_valid_npm_name
  before being used as a match key. Match logic is exact equality
  (after path-glob prefix strip for yarn resolutions); no fuzzy match.
Implementation: analysers/javascript/dep_file_parser.py.
OWASP ASVS: §5.1.4.

SUC-55: SEC-NEW-45 caps
Mitigates: SAC-51
Control: Per SEC-NEW-45.
Implementation: analysers/javascript/dep_file_parser.py.
OWASP ASVS: §11.1.4.

SUC-56: Defer to REQ-20 classifier (npm variant)
Mitigates: SAC-44 npm variant (silent vulnerability reintroduction)
Control: REQ-20's SUC-42 already defers to pin_override flags. REQ-23
  populates the same flag.
Implementation: src/scarno/core/detector.py.
```

### 18.4 Functional requirements (FR-240 .. FR-246)

| ID | Description | Test |
|---|---|---|
| FR-240 | NpmOverride dataclass + extraction from `overrides` | `test_req23_overrides.py` |
| FR-241 | Extraction from `resolutions` (yarn) | `test_req23_resolutions.py` |
| FR-242 | Extraction from `pnpm.overrides` | `test_req23_pnpm.py` |
| FR-243 | Targeted overrides nesting (one level) | `test_req23_targeted.py` |
| FR-244 | Pin-override flagging on direct dep matches | `test_req23_match.py` |
| FR-245 | REQ-20 classifier defers to npm pin flags | `test_req23_classifier_integration.py` |
| FR-246 | Markdown / JSON / SARIF reporter integration | `test_req23_reporters.py` |

### 18.5 Privacy

No new data category; all override target names inherit existing
sanitise() coverage.

---

## 19. Phase-9 Cross-Cutting Rollup (REQ-19 .. REQ-23)

### 19.1 Executive summary

Six new requirement specs (REQ-19, REQ-20, REQ-21, REQ-21b, REQ-22,
REQ-23) collectively re-key the dependency graph by version, give
each declared version an independent classification, detect when a
direct dep is a load-bearing pin (Maven, Gradle, npm), and add a
gated cross-version ABI-diff that catches `NoSuchMethodError`-class
runtime failures before they ship. The motivation is twofold:

1. **Reduce SBOM noise** — one resolved version per coord on the
   classpath, with declared versions classified for removability.
   CVE feeds get cleaner inputs; vulnerability triage time drops.
2. **Prevent silent vulnerability reintroduction** — pinning
   detection (REQ-21 / 21b / 23) ensures Scarno never recommends
   removing a direct dep that is, in fact, substituting for an
   excluded transitive.

The single highest-impact safety property across all six is
`SUC-42`: REQ-20's classifier defers to pinning flags before any
SAFE classification. Every other countermeasure flows through it.

The six new REQs add **48 functional requirements** (FR-190..195,
FR-200..207, FR-210..215, FR-220..225, FR-230..236, FR-240..246),
**16 abuse cases** (SAC-40..52), **17 countermeasures**
(SUC-40..56), **9 threat-model entries** (T-27..35), **9 SEC-NEW
controls** (SEC-NEW-37..45), **3 privacy threats** (PT-11..13),
**3 privacy controls** (PUC-10..12), **7 performance budgets**
(PERF-010..016), and **1 compliance requirement** (COMP-004).

### 19.2 STRIDE rollup (Phase 9)

| STRIDE | Threats | Notes |
|---|---|---|
| **S**poofing | none new | no new authentication surface |
| **T**ampering | T-27 (version strings), T-29 (gradle/mvn output), T-32 (crafted JAR), T-33 (m2 traversal) | all mitigated by sanitise + confine + cap pattern |
| **R**epudiation | none new | tool-output, no user actions to repudiate |
| **I**nformation Disclosure | T-34 (~/.m2 cache enumeration) | mitigated by SUC-52 coord-restricted reads |
| **D**enial of Service | T-27, T-28, T-30, T-31, T-32, T-34 (all DoS variants) | size + count + nesting caps + subprocess timeouts |
| **E**levation of Privilege | none new | no privilege boundary crossed |

### 19.3 LINDDUN rollup (Phase 9)

| LINDDUN | Threats | Notes |
|---|---|---|
| **L**inkability | none new | no expansion of data categories |
| **I**dentifiability | none new | no PII handling |
| **N**on-repudiation | none new | n/a |
| **D**etectability | PT-13 (cache shape leak via errors) | mitigated by PUC-12 sanitised error paths |
| **D**isclosure | PT-11 (edge dump), PT-12 (per-version coord dump), PT-13 | all within existing exposure scope; sanitisation reused |
| **U**nawareness | none new | tool documents its outputs |
| **N**on-compliance | none new | COMP-004 is a positive compliance signal |

### 19.4 Regulatory check (Phase 9)

| Regulation | Applicability to Scarno | Phase-9 impact |
|---|---|---|
| **EU CRA** | Scarno is a developer tool, not a consumer product placed on the EU market — CRA does NOT apply to Scarno itself. However, Scarno's **outputs** materially help downstream products meet CRA Annex II SBOM and vulnerability-handling obligations. | COMP-004 explicitly captures the runtime-risk surfacing as a CRA-relevant compliance signal. REQ-19/20 reduce SBOM noise so CVE feeds against the SBOM are more accurate. |
| **NIS2** | n/a — Scarno is not an essential / important entity. | n/a |
| **UK PSTI** | n/a — not a consumer connectable product. | n/a |
| **GDPR** | Scarno handles project metadata only (dep names + versions + manifest content). No personal data; no DPIA trigger. | All Phase-9 outputs continue to be project metadata only. PT-11..13 are corporate-confidentiality concerns, not GDPR. |
| **HIPAA / PCI-DSS / SOC 2** | n/a — no health, payment, or service-availability data. | n/a |

CRA scope was assessed and **Scarno itself is out of scope**;
the COMP-004 compliance line is for the *downstream consumer* of
Scarno output.

### 19.5 SEC-NEW controls index (Phase 9)

| ID | REQ | Purpose | Hard cap |
|---|---|---|---|
| SEC-NEW-37 | REQ-19 | Lockfile size + edge count cap | 8 MiB / 50 000 edges |
| SEC-NEW-38 | REQ-19 | Declared-version sanitiser | 64 chars + control-strip |
| SEC-NEW-39 | REQ-20 | Per-coordinate version cap | 64 versions |
| SEC-NEW-40 | REQ-21 | Maven exclusions + DM cap | 128 / 2048 |
| SEC-NEW-41 | REQ-21b | Gradle parser caps + timeout | 256 / 256 / 8s |
| SEC-NEW-42 | REQ-22 | javap per-jar timeout | 30s |
| SEC-NEW-43 | REQ-22 | javap per-run cap | 128 jars |
| SEC-NEW-44 | REQ-22 | resolve_and_confine + _validate_gav re-asserted | n/a |
| SEC-NEW-45 | REQ-23 | npm overrides cap + nesting cap | 2048 / 8 |

### 19.6 SRTM index (Phase 9)

| Range | REQ | Test home |
|---|---|---|
| FR-190 .. FR-195 | REQ-19 | tests/unit/test_req19_*.py |
| FR-200 .. FR-207 | REQ-20 | tests/unit/test_req20_*.py |
| FR-210 .. FR-215 | REQ-21 | tests/unit/test_req21_*.py |
| FR-220 .. FR-225 | REQ-21b | tests/unit/test_req21b_*.py |
| FR-230 .. FR-236 | REQ-22 | tests/unit/test_req22_*.py + tests/integration/test_req22_compliance_signal.py |
| FR-240 .. FR-246 | REQ-23 | tests/unit/test_req23_*.py |

Combined with the SEC-NEW / PERF / COMP entries listed per-REQ, this
brings the SRTM baseline from **195/195** to a projected **243/243**
once Phase 9 lands across all six PRs.

### 19.7 Refined requirements (carry-over additions)

The complete refined set — REQ-1 through REQ-18 plus REQ-19 through
REQ-23 — is the authoritative requirement list. No prior REQ
requirements are dropped. Backward compatibility is preserved in
two specific places:

- `AnalysisResult.dep_graph` (canonical-only, REQ-17) remains
  populated. REQ-19's `dep_edges` is additive; reporters fall back
  to `dep_graph` when `dep_edges` is empty.
- `Dependency.status` (canonical-rolled-up, all prior REQs) remains
  populated by the any-version-IN_USE rollup of REQ-20's
  `versioned_nodes`.

### 19.8 Penetration testing scenarios (Phase 9)

```
PEN-19: Adversarial lockfile fuzz (REQ-19 / REQ-20)
Scope: lockfile parsers + edge emitter
Objectives: Fuzz package-lock.json / yarn.lock / pnpm-lock.yaml with
  Atheris and similar tools; expect either bounded errors or partial
  result — never a crash or runaway.
Key abuse cases: SAC-40, SAC-41, SAC-43.

PEN-22a: Adversarial m2 cache fuzz (REQ-22, --deep-inspection on)
Scope: abi_diff module, m2 path construction, javap invocation
Objectives: Construct hostile JARs (deeply nested constant pools,
  oversized class lists) under a temp m2 root; expect timeout,
  truncation, or sanitised error — never a hang.
Key abuse cases: SAC-48, SAC-49, SAC-50.

PEN-22b: Coord-restricted read enforcement (REQ-22)
Scope: abi_diff cache enumeration
Objectives: Manual inspection that NO code path enumerates ~/.m2
  beyond the dep_edges coordinates. Atheris fuzz of error-path
  output to confirm sanitise() coverage.
Key abuse cases: SAC-50.
```

---

## 20. Phase-9 Architecture-Derived Requirements (NEW-ARCH-006..011)

### 20.1 Context

Phase-2 (security-architect) ran against REQ-19..REQ-23 and surfaced
six requirements that are architectural invariants rather than
user-visible features. Each one closes a class of regression that
would otherwise allow SUC-42 (the load-bearing pin-deferral safety
property) to be silently bypassed, or break the Phase-9
backwards-compatibility contract documented in
`docs/scarno-security-architecture.md` §11.7.

These six are captured in full at
`docs/requirements/REQ-19a.md`. This section is the index entry,
SRTM rollup, and a record of the two reference corrections applied
to existing REQ files during the same Phase-1 follow-up pass.

### 20.2 The six requirements

| ID | Statement (one line) | Type | Allocations |
|---|---|---|---|
| NEW-ARCH-006 | `core/classifier.py` is the single shared classifier; analysers MUST invoke it. | SEC + FR | SEC-NEW-46, FR-250 |
| NEW-ARCH-007 | `Dependency.__post_init__` rejects `pin_override=True AND manifest_redundant=True`. | SEC + FR | SEC-NEW-47, FR-251 |
| NEW-ARCH-008 | `PinOverrideKind` is a closed enum; new mechanisms require enum + safety-function update in the same PR. | SEC + FR | SEC-NEW-48, FR-252 |
| NEW-ARCH-009 | Frozen pre-Phase-9 fixtures + regression suite assert wire-format equivalence under all reporters. | SEC + FR | SEC-NEW-49, FR-253 |
| NEW-ARCH-010 | REQ-22 thread-pool capped at `min(8, cpu_count)`; cap counter incremented under `threading.Lock`. | SEC + PERF | SEC-NEW-50, PERF-017 |
| NEW-ARCH-011 | `analysers/java/abi_diff.py` MUST NOT import `subprocess`; `CrossVersionAbiDiffer` receives `_invoke_javap_safe` via dependency injection. | SEC | SEC-NEW-51 |

Threats added: T-36 (refactor-induced regressions class) and T-37
(adversarial multi-coordinate input → process flood).

### 20.3 Updated SRTM index

| Range | REQ | Lands with PR |
|---|---|---|
| FR-250..253, SEC-NEW-46..51, PERF-017 | REQ-19a (NEW-ARCH-006..011) | distributed across PR-1..PR-6 per `docs/requirements/REQ-19a.md` § "Overview" table |

§19.6 projected the SRTM marker count from **195/195** to **243/243**
once Phase 9 lands. REQ-19a adds **6 new markers** (one per
NEW-ARCH-NNN), bringing the projected baseline to **195/195 → 249/249**.

The eleven SRTM allocations (FR-250..253, SEC-NEW-46..51, PERF-017)
are subsumed under those six markers in the test layout — the
`@pytest.mark.NEW-ARCH-NNN` marker covers each requirement's full
test set rather than spreading one marker per FR/SEC/PERF row. This
matches the established pattern (see e.g. `pytest.mark.REQ_17` in
the existing suite covering FR-150..157 with one marker).

### 20.4 Reference corrections applied

Two implementation references in the prior Phase-1 output were
corrected during this follow-up pass (no semantic change to the
controls, only to where they live in the codebase):

- **`docs/requirements/REQ-20.md` SUC-42 + SUC-43** — corrected
  from `src/scarno/core/detector.py` to
  `src/scarno/core/classifier.py (NEW module — see architecture
  §11.4 / ADR-006)`. The original reference confused
  `core/detector.py` (project-type detector) with the new shared
  classifier extracted in Phase 2.
- **`docs/requirements/REQ-22.md` SUC-50** — corrected from
  `src/scarno/security.py:_invoke_javap_safe` to
  `src/scarno/analysers/java/source_analyser.py:JvmSourceAnalyser._invoke_javap_safe`,
  with a note pointing to architecture ADR-008 explaining why the
  helper stays a method of `JvmSourceAnalyser` rather than moving
  to the generic security module. NEW-ARCH-011 is the invariant
  that prevents the differ from re-spawning `subprocess` under
  this design.

Neither correction changes the security control itself — only the
file path where the control is implemented. The threat-modeling
phase (Phase 3) inherits the corrected references.

### 20.5 Privacy

No new data category. Architecture-derived requirements operate on
internal program state (Dependency objects, classifier output,
subprocess invocation) rather than personal data.

### 20.6 Compliance

No new compliance requirement. NEW-ARCH-009's back-compat
regression suite indirectly supports the CRA SBOM-stability
expectation (downstream consumers reading the JSON / SARIF output
keep working across versions), but the requirement itself is
captured under SEC + FR rather than COMP.

### 20.7 Workflow position

This addendum closes Phase 1's feedback loop from Phase 2. Phase 3
(threat-modeling) runs next against the corrected references and
the expanded SRTM. If Phase 3 surfaces any new architectural
findings, this addendum is extended (not re-run wholesale).

---

## 21. Phase-9 Threat-Model Feedback (Post-Architecture-Revision)

### 21.1 Context

Phase 3 (`docs/THREAT-MODEL.md` §9) ran against the Phase-9 design
and surfaced 5 new SEC-NEW requirements (52..56), 1 ID-collision
correction, 4 architecture-revision asks (§9.7), and 6 process /
clarification items. Phase 2 then revised the architecture
(`docs/scarno-security-architecture.md` §11.15) addressing
every §9.7 item plus the §9.8 SEC-NEW-55 requirement, and also
surfaced 2 additional architectural invariants (NEW-ARCH-012,
NEW-ARCH-013). The architecture re-validation closure is recorded
in `docs/THREAT-MODEL.md` §9.11.

This section closes Phase 1's outstanding loop:

1. Classifies the five Phase-3 SEC-NEW IDs (52..56).
2. Captures the two new NEW-ARCH-012 / NEW-ARCH-013 IDs (full
   per-requirement detail lives in `docs/requirements/REQ-19a.md`).
3. Records the T-34 ID-collision re-allocation.
4. Updates the SRTM rollup (195 → 256).
5. Provides the cross-reference table SRTM auditors need to trace
   each marker back to its threat / control / architecture
   revision.

### 21.2 SEC-NEW-52..56 classifications

All five originated in Phase 3 §9.8. Architecture closure is recorded
in `docs/scarno-security-architecture.md` §11.15 and the residual
risk is recorded in THREAT-MODEL §9.11.1.

#### SEC-NEW-52 — `MAVEN_HOME` / `GRADLE_HOME` mandatory verification

**Type:** SEC. **Origin:** Phase-3 S-Phase9-01 (PATH hijack of
`mvn` / `gradle` binary). **Closure:** architecture §11.15.5
(`_resolve_gradle_binary` mirrors `_resolve_mvn_binary`'s
SEC-NEW-28 pattern; PATH fallback emits a verbose-mode warning via
`_warn_path_fallback_once`). **Test home:**
`tests/security/test_mvn_gradle_binary_pinning.py`. **Priority:**
Medium (Low-residual after fix).

#### SEC-NEW-53 — `gradle.lockfile` vs `gradle dependencies` cross-check

**Type:** SEC. **Origin:** Phase-3 T-Phase9-01 (lockfile-strict-subset
silent edge suppression). **Closure:** architecture §11.15.5 covers
the binary-invocation hardening; the cross-check itself is a small
addition to PR-1's Gradle edge emitter. When both sources are
present the parser computes the symmetric set difference of
coordinate-only sets; a strict-subset relation triggers a
`result.errors[]` warning. **Test home:**
`tests/unit/test_req19_gradle_lockfile_crosscheck.py`. **Priority:**
Medium (Low-residual after fix).

#### SEC-NEW-54 — Per-destination escape coverage (clarification of SEC-NEW-38)

**Editorial decision: SEC-NEW-54 is recorded as a CLARIFICATION
EXTENSION to SEC-NEW-38 rather than a wholly new ID.** SEC-NEW-38
defined `sanitise_declared_version` with control + Mermaid-active
char stripping + 64-char cap. SEC-NEW-54 extends this with
explicit per-destination requirements:

- The sanitiser MUST also strip `|`, backtick, and ensure the
  resulting string is JSON-encodeable without further escaping
  (covers Markdown table rows, JSON output, SARIF emission).
- Test coverage MUST include adversarial version strings round-tripped
  through all three reporters (markdown / json / sarif), not just
  the Mermaid block.

The SRTM marker remains `SEC-NEW-38` (no new pytest marker is
added); the clarification widens the test scope. SRTM auditors
should treat SEC-NEW-38 and SEC-NEW-54 as a single requirement
with two phase-derived sub-requirements. **Origin:** Phase-3
T-Phase9-03. **Closure:** REQ-19 §SEC-NEW-38 acceptance criteria
extended; no architecture change needed. **Test home:**
`tests/security/test_req19_version_sanitise.py` extended with
per-destination cases. **Priority:** Medium.

(The 195 → 256 marker count below treats SEC-NEW-54 as a single
extension, NOT a separate +1.)

#### SEC-NEW-55 — `mvn` / `gradle` argv allowlist (REQ-20 fixed-argv contract)

**Type:** SEC. **Origin:** Phase-3 T-Phase9-04 (HIGH severity
escalation). **Closure:** architecture ADR-013 (§11.15.5–§11.15.7)
— generic `safe_subprocess_run` primitive in `security.py`,
per-binary `_invoke_mvn_safe` / `_invoke_gradle_safe` wrappers,
REQ-20 resolved-version invocation uses fixed argv only (no `-P`
profiles, no `-D` system properties from project config). **Test
home:** `tests/security/test_req20_argv_allowlist.py`. **Priority:**
**High** (Medium-residual until tests land in PR-2; Low-residual
after).

#### SEC-NEW-56 — `--deep-inspection` argv-only enable

**Type:** SEC. **Origin:** Phase-3 E-Phase9-01 (accidental enable
via env / config / preset). **Closure:** REQ-22's
`_RunOptions.deep_inspection` populated only from the
`--deep-inspection` argv flag — no env-var fallback, no config
file, no preset. Verified by an AST scan of `cli.py` that asserts
the field's only assignment site is the argparse handler.
**Test home:** `tests/security/test_req22_deep_inspection_argv_only.py`.
**Priority:** Medium.

### 21.3 NEW-ARCH-012 + NEW-ARCH-013 (architecture-derived)

Full per-requirement detail (statement / context / use case /
abuse case / countermeasure / SRTM rows) is appended to
`docs/requirements/REQ-19a.md`. Headline summary:

| ID | Statement (one line) | Type | Allocations |
|---|---|---|---|
| NEW-ARCH-012 | Pin-detector registry contract: every ecosystem analyser MUST register exactly once via `register_pin_detector` or `register_no_pin_mechanism`. | SEC + FR | SEC-NEW-57, FR-254 |
| NEW-ARCH-013 | `safe_subprocess_run` is the only sanctioned subprocess call site (one grandfathered exception: legacy `_invoke_javap_safe`). AST-scan test rejects new `subprocess.run` / `Popen` / `os.exec*` / `os.spawn*` / `os.popen` / `asyncio.subprocess.*` calls. | SEC + FR | SEC-NEW-58, FR-255 |

Both originate from Phase-2 architecture §11.15.10 and feed back
into the existing T-36 (refactor-induced regression class) — they
extend the threat's mitigation list with SUC-63 + SUC-64 rather
than introducing new threats.

### 21.4 T-34 ID-collision re-allocation

Phase-3 §9.3 identified that the prior Phase-1 work used **T-34**
for two unrelated threats:

- **T-34 (REQ-22)**: m2 cache-enumeration disclosure (kept).
- **T-34 (REQ-23)**: npm overrides parser DoS — **re-allocated to
  T-38** in the canonical record.

This pass records the re-allocation in the analysis doc only;
**REQ-23.md itself is not edited at this stage** (the §20 / §21
record is sufficient — the next REQ-23 author should rename in
place when next touching that file). SRTM auditors treating these
as two distinct threats should reference T-34 → REQ-22 and T-38
→ REQ-23.

T-38's mitigation remains SEC-NEW-45 (npm overrides cap +
nesting cap) per the original REQ-23 enumeration.

### 21.5 Updated SRTM rollup

| Pass | Cumulative marker total | Net additions |
|---|---|---|
| Pre-Phase-9 baseline | 195 | — |
| Phase-1 initial (REQ-19..23) | 243 | +48 (FR-190..195, 200..207, 210..215, 220..225, 230..236, 240..246) |
| Phase-1 follow-up (REQ-19a NEW-ARCH-006..011) | 249 | +6 |
| **Phase-1 follow-up #2 (this section)** | **256** | **+7** (SEC-NEW-52, 53, 55, 56 + NEW-ARCH-012, NEW-ARCH-013, with SEC-NEW-54 absorbed into SEC-NEW-38) |

§19.6 projected 195 → 243. §20 bumped to 195 → 249. **This section
finalises the projected baseline at 195 → 256** once Phase 9 lands
across all six PRs.

### 21.6 SRTM cross-reference (auditor view)

Trace each Phase-9 marker back to its threat → architecture
control → REQ document. Used by SRTM auditors and by Phase 4 test
engineers selecting test scope.

| Marker | Origin threat | Architecture closure | Authoritative REQ doc |
|---|---|---|---|
| SEC-NEW-52 | Phase-3 S-Phase9-01 | §11.15.5 (`_resolve_gradle_binary` + PATH-fallback warning) | This file §21.2 + threat-model §9.11.1 |
| SEC-NEW-53 | Phase-3 T-Phase9-01 | §11.15.5 (gradle.lockfile cross-check) | This file §21.2 + threat-model §9.11.1 |
| SEC-NEW-54 | Phase-3 T-Phase9-03 | extends SEC-NEW-38 acceptance | REQ-19.md SEC-NEW-38 + this file §21.2 |
| SEC-NEW-55 | Phase-3 T-Phase9-04 (HIGH) | ADR-013 (§11.15.5–§11.15.7) | This file §21.2 + arch §11.15.7 + threat-model §9.11.1 |
| SEC-NEW-56 | Phase-3 E-Phase9-01 | REQ-22 `_RunOptions.deep_inspection` argv-only | REQ-22.md + this file §21.2 |
| SEC-NEW-57 | Architecture §11.15.10 NEW-ARCH-012 | ADR-012 (§11.15.6) — pin-detector registry | REQ-19a.md NEW-ARCH-012 |
| SEC-NEW-58 | Architecture §11.15.10 NEW-ARCH-013 | ADR-013 (§11.15.7) — `safe_subprocess_run` primitive | REQ-19a.md NEW-ARCH-013 |
| FR-254 | Architecture §11.15.10 NEW-ARCH-012 | ADR-012 — registry API | REQ-19a.md NEW-ARCH-012 |
| FR-255 | Architecture §11.15.10 NEW-ARCH-013 | ADR-013 — `safe_subprocess_run` API | REQ-19a.md NEW-ARCH-013 |

### 21.7 Privacy & compliance

No new data category, no new privacy threat. NEW-ARCH-012 / 013
operate on internal program state (registry membership, AST
scans). The five SEC-NEW additions are all subprocess / argv
hardening — no PII expansion.

CRA / NIS2 / GDPR scope assessment is unchanged from §19.4: CRA
itself remains out-of-scope for Scarno (downstream-consumer
benefit captured via COMP-004); other regulations not applicable.

### 21.8 Phase 4 unblocking

With this section landed, **Phase 4 (software-test-engineer) is
unblocked** to plan the test suite. Phase 4 inherits:

- Threat-model §9.9 (the original 25-row hand-off table).
- Architecture §11.15.4 (cpu_count enumeration bullets).
- This section's SEC-NEW-52..58 + FR-254 + FR-255 marker rows.

The single highest-priority Phase 4 deliverable is the SEC-NEW-55
fixed-argv test (closes T-Phase9-04 from "Open / Escalated" to
"Closed").

### 21.9 Workflow position

This pass closes the Phase-1 ↔ Phase-2 ↔ Phase-3 feedback loop for
the Phase-9 design. The risk register is now:

- Zero Critical / High findings remain Open against the design.
- Two findings (D-Phase9-02, R-Phase9-01) await Phase-4 stress /
  determinism tests for status-flip to Closed.
- All other Phase-9 findings are Closed by design and pending
  Phase-4 test coverage.

Phase 4 begins next.

---

## 22. Phase-9 Test Plan Index

### 22.1 Authoritative document

The complete Phase-9 test plan lives at
**`docs/scarno-test-plan-phase9.md`**. This section is an index
+ summary; full per-test detail (TA-XXX rows with file path, marker,
scenario, expected outcome) is in the test-plan file.

The pre-existing `docs/scarno-test-suite.md` (covering REQ-1..18)
is unchanged. The Phase-9 plan is a separate file because it lands
incrementally with the six PRs, making per-PR review easier.

### 22.2 TA distribution

**Total automated TAs:** ~106 (TA-200 through TA-324, with some
sub-IDs).
**Penetration scenarios:** 5 manual narratives (PEN-Phase9-01..05).

| PR | TA range | Count | Primary REQ |
|---|---|---|---|
| PR-1 | TA-200..227 | 28 | REQ-19 |
| PR-2 | TA-220a..245 (+ overlap into REQ-19a markers) | 38 | REQ-20 + parts of REQ-19a (NEW-ARCH-006/007/010/012/013) |
| PR-3 | TA-250..264 | 15 | REQ-21 (Maven pinning) |
| PR-4 | TA-265..291 | 27 | REQ-22 (ABI diff) |
| PR-5 | TA-295..307 | 13 | REQ-23 (npm pinning) |
| PR-6 | TA-310..324 | 15 | REQ-21b (Gradle pinning) |

(TA numbering reuses some letters for sibling tests within a single
SRTM row — TA-220a..d, TA-221a..d, etc. — matching the established
TA-152s / TA-153a..f convention from the pre-existing test suite.)

### 22.3 Distribution by category

| Category | Approx count |
|---|---|
| Functional security (positive) | ~55 |
| Security attack (negative) | ~25 |
| Architecture-invariant (AST scans, registry contracts) | ~10 |
| Concurrency / determinism | ~5 |
| Performance | ~7 |
| Regression / back-compat | ~4 |
| Penetration (manual) | 5 |

### 22.4 SRTM marker coverage confirmation

The test plan's coverage map (test-plan §"Test categories —
distribution") asserts that **every SRTM marker enumerated in §21.6
of this document has at least one covering TA**. Marker-by-marker
trace lives in the test plan; the rollup:

- **FR markers** (FR-190..255): all covered. 48 from initial Phase-1
  + 6 from REQ-19a + 4 from this pass = 58 FR rows; ~85 TAs cover
  them (multiple TAs per FR is the norm).
- **SEC-NEW markers** (SEC-NEW-37..58 plus extension to SEC-NEW-38):
  all covered. ~25 TAs.
- **PERF markers** (PERF-010..017): all covered by 7 perf tests.
- **COMP-004**: covered by TA-270 (RUNTIME_RISK Finding emission).
- **NEW-ARCH-006..013**: each covered by ≥1 TA (NEW-ARCH-008 by 3,
  one per PR-3 / PR-5 / PR-6 — full enum coverage at PR-6 landing).

### 22.5 Highest-priority gating tests

The single highest-priority test in the plan is **TA-228** (PR-2,
`test_invoke_mvn_safe_uses_fixed_argv_no_project_flags`). It closes
Phase-3 finding **T-Phase9-04** (HIGH severity, Open / Escalated)
from "Open" to "Closed" by verifying that REQ-20's resolved-version
detection invokes `mvn` and `gradle` with fixed argv — no
project-derived flags reach the subprocess. Without TA-228, PR-2
cannot merge.

Other PR-gating tests are listed per-PR in the test plan's
"PR landing checklist" subsections.

### 22.6 SRTM marker rollforward

Once all six PRs land and the test suite passes, the SRTM marker
count is **195/195 → 256/256** per §21.5. The test plan does NOT
introduce new SRTM markers — it documents the tests that fulfil
the markers already allocated by §13..§21.

### 22.7 Workflow position

Phase 4 (software-test-engineer) is complete in plan form. Test
**implementation** is owned by the engineer landing each PR. The
test plan is the authoritative source for what each PR's test files
must contain. CI's existing `tests/srtm_plugin.py` will fail-fast
if any PR lands implementation without the corresponding markers.

This closes the Phase-1 → Phase-2 → Phase-3 → Phase-4 workflow
for Phase 9. Implementation work begins with PR-1 (REQ-19).

---

## 23. Phase: Remote Index Fetch (REQ-24)

### 23.1 Workflow provenance

This phase emerged from a feedback-direction pass through the
three-skill workflow: **security-architect → threat-modeling →
secure-privacy-by-design (this document) → threat-modeling
(closing validation)**. The trigger was an operator report that
`--deep-inspection` (REQ-22) silently skipped coordinates whose
JARs weren't in `~/.m2/repository`, leaving the user with no
ABI verdict for exactly the conflicts they ran the flag to
investigate.

The full requirement specification lives at
**`docs/requirements/REQ-24.md`**. This section is the SPbD
classification + SRTM rollforward + compliance assessment. It is
authoritative for the requirement IDs added to `tests/srtm.py`.

### 23.2 What the architect + threat-model loop produced

- **Initial design** (security-architect): `IndexConfigResolver`
  merging trusted CLI/env/user-config sources; `--allow-remote-fetch`
  argv-only capability; `RemoteArtifactFetcher` over HTTPS with
  SSRF guard, checksum verification, quarantined cache. Repo-local
  config files explicitly ignored as an index source.
- **First threat-model pass** (STRIDE): identified **9 design-level
  flaws**, including one Critical (E1: config-discovery anchoring).
- **Revised design**: introduced `security.resolve_user_config_path()`
  helper, `ValidatedCoordinate` opaque type, `SafeHttpsClient` with
  pin-resolved-IP, no-fallthrough-on-4xx, ≤2-hop redirects with
  full re-validation, cache size/TTL/perm controls, minimisation
  to multi-version-conflict subset, `Finding.provenance` tagging,
  and `--integrity-cross-check` opt-in.
- **Closing threat-model pass** (this loop's last analysis):
  zero design flaws remain; surfaced 1 new Medium threat (T-44,
  manifest probe oracle) and 12 implementation guardrails (N-1..N-12,
  enumerated in `THREAT-MODEL.md` §9.12).

### 23.3 Requirements added by REQ-24

Counts: **1** ARCH-SEC, **16** SEC-NEW, **12** FR, **3** PRV,
**6** T (T-39..T-44), **1 (each)** COMP-005, COMP-006.

#### Architecture-security

| ID | Brief |
|---|---|
| ARCH-SEC-005 | `security.resolve_user_config_path()` is the sole user-config locator; home-anchored; XDG-confined; never CWD/project-relative. |

#### Security non-functional (SEC-NEW)

| ID | Brief |
|---|---|
| SEC-NEW-59 | `ValidatedCoordinate` opaque type; per-ecosystem `CoordinateValidator`; structural non-bypassability. |
| SEC-NEW-60 | `SafeHttpsClient` is sole outbound-HTTPS path; pin-resolved-IP; mandatory cert verification; IPv4 + IPv6 + IPv4-mapped deny-list; HTTP/2 pool-coalescing disabled. |
| SEC-NEW-61 | HTTP 4xx is authoritative — no cross-index fallthrough. |
| SEC-NEW-62 | When `--allow-remote-fetch` is set, env-sourced indexes are dropped + warning. |
| SEC-NEW-63 | Redirect policy ≤2 hops, full SafeHttpsClient re-validation per hop, headers dropped on cross-host. |
| SEC-NEW-64 | Cache root mode 0700. |
| SEC-NEW-65 | Every cache write through `resolve_and_confine`. |
| SEC-NEW-66 | Total cache size cap (1 GiB default) with LRU eviction. |
| SEC-NEW-67 | Per-artefact TTL (30d default). |
| SEC-NEW-68 | Per-artefact fetch-time size cap (64 MiB default). |
| SEC-NEW-69 | Per-run fetch count/time caps; lock-counted. |
| SEC-NEW-70 | `IndexEndpoint.coordinate_prefix` reserved (no v1 surface). |
| SEC-NEW-71 | New finding rule `TS-INTEGRITY-MISMATCH` (HIGH). |
| SEC-NEW-72 | `--allow-remote-fetch` argv-only setter; mirror SEC-NEW-56 pattern. |
| SEC-NEW-73 | Decompression-bomb caps when reading fetched JARs. |
| SEC-NEW-74 | `--integrity-cross-check` retries once after jittered backoff before declaring mismatch. |

#### Functional (FR)

| ID | Brief |
|---|---|
| FR-256 | `--index ECOSYSTEM=URL` repeatable, order = priority. |
| FR-257 | `SCARNO_INDEX_<ECO>` env vars. |
| FR-258 | User-config `[indexes]` table. |
| FR-259 | Per-ecosystem override precedence (CLI > user-config > env). |
| FR-260 | `--allow-remote-fetch` requires `--deep-inspection`. |
| FR-261 | `--integrity-cross-check` argv-only. |
| FR-262 | Minimise to multi-version-conflict coords. |
| FR-263 | Pre-fetch disclosure line into `result.errors`. |
| FR-264 | Per-attempt structured audit line. |
| FR-265 | `Finding.provenance` field; conservative remote-tagging. |
| FR-266 | Top-of-report banner when fetches occurred. |
| FR-267 | `provenance="remote"` not escalated by `--fail-on-severity` by default; `--fail-on-remote-severity` opt-in. |

#### Privacy (PRV)

| ID | Brief |
|---|---|
| PRV-005 | Off-machine disclosure minimised to multi-version-conflict coords. |
| PRV-006 | Disclosure line names IP exposure explicitly. |
| PRV-007 | Operator-facing docs explain project-fingerprinting risk. |

#### Threats (T) — registered in THREAT-MODEL.md §9.12

| ID | Brief |
|---|---|
| T-39 | DNS rebinding TOCTOU between hostname check and connect. |
| T-40 | Compromised / MITM'd index serves coordinated artefact + checksum. |
| T-41 | Coordinate typosquat in untrusted manifest. |
| T-42 | Cache TOCTOU between fetch-write and javap-read. |
| T-43 | `--integrity-cross-check` false positives from CDN replica drift. |
| T-44 | Malicious manifest as probe oracle against operator's index. |

#### Compliance (COMP)

| ID | Brief |
|---|---|
| COMP-005 | GDPR — operator IP is disclosed to index hosts when fetch is enabled; lawful basis is informed consent via `--allow-remote-fetch` + PUC-006/008 disclosure. |
| COMP-006 | EU CRA — out of scope for scarno as open-source v1; flagged for downstream commercial packagers. |

### 23.4 Counter-use cases

Twelve new SUCs (SUC-65..SUC-76) and four PUCs (PUC-005..PUC-008)
defined in `docs/requirements/REQ-24.md`. Highlights:

- **SUC-72** (the keystone) — `security.resolve_user_config_path()`
  is the SOLE user-config locator, anchored to
  `Path.home()` / `$XDG_CONFIG_HOME` only, with XDG paths under
  `Path.cwd()` or the analysed project root falling back to
  `~/.config`. Mitigates E1 (Critical) + E2 from the threat model.
- **SUC-65** — `SafeHttpsClient` pin-resolved-IP semantics,
  defeating DNS-rebinding TOCTOU. Closes T-39.
- **SUC-66 / SUC-67** — TLS as the adversarial-integrity control;
  optional `--integrity-cross-check` cross-index byte comparison
  for the case where one index is compromised.
- **SUC-73** — `ValidatedCoordinate` opaque type makes coordinate
  validation **structurally** non-bypassable (URL/path construction
  cannot consume raw `str`).
- **PUC-005** — minimisation to multi-version-conflict coordinates
  (off-machine disclosure is a strict subset of `dep_edges`).
- **PUC-006/008** — pre-fetch disclosure into `result.errors` (the
  persistent report channel) explicitly names the host(s) and the
  IP-disclosure side-effect.

### 23.5 Conflations split

Three of the SPbD-pass-1 requirements were umbrella controls;
each split for clean SRTM traceability:

1. **Pre-fetch disclosure + per-attempt audit** → FR-263 + FR-264.
2. **Cache hardening** (1 GiB cap + LRU + 30d TTL + 0700 + confined writes)
   → SEC-NEW-64 + SEC-NEW-65 + SEC-NEW-66 + SEC-NEW-67 + SEC-NEW-68.
3. **`SafeHttpsClient` invariants** stayed as one control
   (SEC-NEW-60) but with five test artefacts (TA-339..TA-343)
   each pinning one property.

### 23.6 SRTM marker rollforward

REQ-24 adds **38 new IDs** to `tests/srtm.py`:

| Category | New IDs | Cumulative count |
|---|---|---|
| `SECURITY_REQUIREMENTS` | SEC-NEW-59..74 (16) | was 47, now 63 |
| `FUNCTIONAL_REQUIREMENTS` | FR-256..267 (12) | grew by 12 |
| `PRIVACY_REQUIREMENTS` | PRV-005..007 (3) | was 3, now 6 |
| `ARCHITECTURE_REQUIREMENTS` | ARCH-SEC-005 (1) | was 4, now 5 |
| `THREAT_REQUIREMENTS` | T-39..T-44 (6) | grew by 6 |
| **Total** | | **+38 IDs** |

The `tests/srtm_plugin.py` coverage report will surface all 38
as **uncovered** until the corresponding TA-XXX implementations
land (TA-325..TA-356, mapped in REQ-24.md §SRTM). This is
deliberate: the SRTM gap is the visible work-remaining signal.
The current FR-250 single-row gap remains separate.

### 23.7 Compliance assessment — explicit

| Framework | Status | Rationale |
|---|---|---|
| **GDPR** | **Marginally in scope (COMP-005)** | Feature transmits the operator's machine IP to configured indexes — personal data when an individual operator runs scarno. Lawful basis is consent — `--allow-remote-fetch` is the consent point, made informed by PUC-006/008. |
| **EU CRA** | **Out of scope for v1 (COMP-006)** | scarno is open-source Apache-2.0, distributed free; under CRA's open-source carve-out, currently outside *product* obligations. Flagged for downstream commercial packagers. |
| **NIS2** | **Out of scope for the tool; relevant for users** | scarno is not an essential/important entity. Users who *are* NIS2-regulated may use scarno for supply-chain risk-management obligations — the fetch feature's coordinate-disclosure (PRV-005..007) is a consideration in their own NIS2 risk assessments. |
| **UK PSTI** | **Out of scope** | Not a consumer connectable product. |

### 23.8 Open items resolved

The architect deferred two decisions to this pass; both are now
recommended:

- **(a) v2 syntax for `coordinate_prefix`** — TOML config table
  form (`[[indexes]] ecosystem="maven" url="…" prefix="com.corp."`).
  No CLI surface in v1 (CLI form `--index maven=URL:prefix` would
  collide with URL parsing). Defer CLI surface to v2.
- **(b) Severity capping for `provenance="remote"` findings** —
  no severity cap, but **excluded from `--fail-on-severity` by
  default** with `--fail-on-remote-severity` argv opt-in. Captured
  as **FR-267**. Rationale: when an attacker controls the fetched
  bytes, they can fabricate any verdict; visibility is the
  protection, not gating. Operators who require strict CI gating
  can opt in.

### 23.9 New requirements surfaced by THIS pass

This SPbD pass surfaced two requirements beyond the architect +
threat-model output:

- **SEC-NEW-74** — `--integrity-cross-check` retry-once on mismatch
  (mitigates T-43 CDN-replica-drift false positives).
- **FR-267** — fail-on-severity treatment of remote-provenance
  findings (resolves open item (b)).

Plus three privacy threats (PT-005/006/007) and three privacy
controls (PUC-005/006/007/008) — LINDDUN coverage the prior
STRIDE-only pass did not produce.

### 23.10 Workflow position

The architect → threat-model → SPbD → closing-threat-model loop
for REQ-24 is **closed**. Status:

- **Zero Critical / High design flaws remain Open.**
- All 9 original design flaws are closed by the revised design.
- T-44 (NEW Medium) is **Open — accepted** with documented
  partial mitigation (audit visibility + v2 prefix scoping).
- Twelve implementation guardrails (N-1..N-12 in THREAT-MODEL.md
  §9.12) are **Open — implementation invariants** on the
  decided controls.

Implementation is gated only on engineering capacity — the design
is ready. The first PR should land:

1. `security.resolve_user_config_path` + the security test (TA-325)
   — closes the Critical (E1) before any other code lands.
2. `IndexConfigResolver` + the precedence + env-drop tests
   (TA-326..329, TA-327 covers SEC-NEW-62).
3. The argv-only flag wiring + TA-330 (mirrors SEC-NEW-56's
   `test_req22_deep_inspection_argv_only.py`).

`SafeHttpsClient`, `ValidatedCoordinate`, `RemoteArtifactFetcher`,
and the cross-check retry follow in subsequent PRs in any order.
The cache hardening (SUC-69a..e) lands with the fetcher.

### 23.11 Option 2 amendment — POM + JAR fetching, minimisation relaxed

After REQ-24 v1 shipped, operator feedback exposed a design
mismatch: passing `--allow-remote-fetch` with a configured Maven
index did not, in fact, cause Scarno to fetch every
cache-missing artefact. The v1 design intentionally restricted the
fetcher to the **multi-version-conflict subset** of coordinates
(FR-262 / PRV-005) and to JARs only — POMs missing from the local
`~/.m2` simply meant the transitive walker stopped at that node.

Both restrictions were design-time privacy controls (minimise
off-machine disclosure to the strictly-necessary subset). In
practice they produced "I configured an index — why isn't this
being fetched?" surprise from operators who expected the simpler
"fetch any cache-miss" mental model.

The **Option 2 amendment** (landed 2026-05-17) reconciles the two:

**Behavioural changes:**

- POMs are now fetchable. `MavenPomResolver._locate_or_fetch_pom`
  walks `~/.m2` → REQ-24 fetcher → legacy `mvn dependency:get` CLI
  in that order. Transitives that were previously invisible (no
  local POM) are now discovered.
- JAR fetching is lazy and unminimised. `CrossVersionAbiDiffer`'s
  injected `find_jar` is a thin lambda that calls
  `fetcher.fetch(coord, version, endpoints)` on demand — for any
  coord the differ asks about, not just multi-version-conflict
  ones.
- Cache-first is preserved and strengthened.
  `_resolve_jar` now tries `~/.m2` first (H4); only on miss does
  `find_jar` fire. Artefacts already in the operator's pre-trusted
  cache never trigger network calls.

**Status of v1 requirements:**

| ID | v1 status | Post-Option-2 status |
|---|---|---|
| FR-262 (minimise to conflict coords) | Implemented | **Superseded** — lazy `find_jar` fetches any cache-miss coord. Cache-first ordering replaces the filter. |
| PRV-005 (off-machine disclosure minimised) | Implemented | **Superseded** — full transitive closure may be disclosed when fetch is enabled. The privacy story is now "operator-controlled visibility" (audit lines + pre-fetch disclosure) rather than "automatic minimisation". |
| PUC-005 (fetcher input = conflict subset) | Implemented | **Superseded** — fetcher input is whatever the orchestrator or differ asks for. |
| FR-263, FR-264 (pre-fetch disclosure + per-attempt audit) | Implemented | **Preserved** — pre-fetch disclosure wording updated to reflect the broader surface ("Both POMs and JARs will be fetched on cache-miss; the project's transitive dependency closure will be queried as needed"). |
| FR-265, FR-266, FR-267 (provenance + banner + fail-on-remote-severity) | Implemented | **Preserved** — work identically over the wider surface. |
| ARCH-SEC-005, SEC-NEW-59..74 (config/network/cache security) | Implemented | **Preserved** — every cache, SSRF, validation, and audit invariant applies identically to POM fetches. |

**Privacy trade-off documented in:** `docs/LIMITATIONS.md` PRV-007
section, updated to flag that the disclosure surface widened.
Operators of confidential codebases should re-read that section
before enabling fetch on a sensitive scan.

**Tests reflecting the new contract:**
- `tests/integration/test_req24_slice_e_wiring.py::TestLazyFindJarFetchesAnyCoord`
  (replaces the v1 `TestMinimisationToConflictCoords`).
- `tests/integration/test_req24_option2_pom_and_jar_fetch.py`
  (new file: POM-fetch wiring, m2-first ordering, three-tier POM
  resolver fallback).

**Threat-model impact:** documented in `docs/THREAT-MODEL.md`
§9.12.3 (closure-row I1/P1 amended to note the Option 2
relaxation; cache-first becomes the load-bearing
disclosure-reducer in this code path).

**Workflow position.** This amendment was driven by a
post-deployment operator-feedback loop rather than a fresh
secure-privacy-by-design pass. It is *deliberately* a relaxation
of a v1 privacy control; the threat-model loop was re-run mentally
during the design discussion (the operator option-list in the
conversation that triggered this change considered the four
candidate scopes explicitly) but a full STRIPED/LINDDUN re-walk
is a recommended follow-up if/when REQ-24 is re-certified for a
new regulatory context.

