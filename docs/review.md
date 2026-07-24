# Scarno Code Review

**Date:** 2026-04-16
**Reviewer:** Claude Opus 4.6 (automated)
**Scope:** All 40 Python source files under `src/scarno/` (~10,600 lines), `pyproject.toml`, `action.yml`, representative test files
**Codebase version:** 1.0.0

---

## Executive Summary

| Area | Score (1-10) | Notes |
|------|:---:|-------|
| Security | **9** | Excellent security posture; DOCTYPE rejection, path confinement, ANSI sanitisation, no eval/exec. One medium-risk operator-precedence bug found. |
| Software Composition | **8** | Lean dependency tree; tree-sitter wheels are the main risk. No known CVEs at review time. |
| Maintainability | **7** | Good modular design; some code duplication across analysers. Docstrings are thorough. |
| Best Practices | **8** | Modern Python 3.12+, consistent patterns, good error handling. Minor linting nits. |
| Architecture | **9** | Clean registry pattern, uniform analyser interface, well-separated concerns. |
| Performance | **7** | Some redundant file I/O in polyglot mode; tree-sitter parsers are properly module-scoped singletons. |
| Cognitive Complexity | **8** | Most functions are short and focused; a few long coordinators could benefit from extraction. |

**Overall assessment:** This is a well-engineered codebase with strong security foundations, clear architecture, and thorough test coverage. The security controls (path confinement, sanitisation, DOCTYPE rejection, file-size caps) are consistently applied across all language analysers. The main areas for improvement are reducing cross-analyser code duplication and addressing a few subtle logic bugs in the findings engine.

---

## 1. Security (Code Vulnerabilities)

### Finding 1.1 — Operator precedence bug in findings engine

- **File:** `src/scarno/findings/engine.py`, line 299
- **Severity:** MEDIUM
- **Description:** The condition `if full in {"exec", "eval"} or root in {"exec", "eval"} and not full:` is parsed as `(full in {"exec", "eval"}) or ((root in {"exec", "eval"}) and (not full))` due to Python operator precedence (`and` binds tighter than `or`). This means when `full` is `"exec"` or `"eval"`, the `and not full` guard is NOT applied. The intended logic likely wants `(full in {...} or root in {...}) and not full` or separate branches. In practice the `full in {"exec", "eval"}` branch still requires taint on `call.args[0]`, so exploitability is low, but the logic doesn't match apparent intent.
- **Recommended fix:** Parenthesise explicitly: `if (full in {"exec", "eval"} or (root in {"exec", "eval"} and not full)):` or restructure into two `if` branches.

### Finding 1.2 — Potential duplicate findings for `__import__` taint

- **File:** `src/scarno/findings/engine.py`, lines 309-316
- **Severity:** LOW
- **Description:** The TS-CE-004 detection has two separate code paths that can both match `__import__()` with tainted args. Line 310 checks `root == "__import__" and not full.startswith("__")`, and line 314 checks `full == "__import__"` or `call.func.id == "__import__"`. When `full == "__import__"`, the first condition evaluates `root == "__import__" and not "__import__".startswith("__")` which is `True and False = False`, so no double-fire. But when `call.func` is a bare `Name` node with `id == "__import__"`, both `full == "__import__"` (line 314) and `isinstance(call.func, ast.Name) and call.func.id == "__import__"` (line 314) match in the same `if`, so only one finding is emitted. However, the overlapping conditions are confusing and fragile.
- **Recommended fix:** Consolidate the two `__import__` checks into a single clear branch.

### Finding 1.3 — `xml.etree.ElementTree` used without `defusedxml`

- **File:** `src/scarno/analysers/java/maven.py`, line 134; `src/scarno/analysers/csharp/dep_file_parser.py`, line 163
- **Severity:** INFO
- **Description:** Both files use `ET.fromstring()` from the stdlib `xml.etree.ElementTree`. This is mitigated by the pre-parse DOCTYPE rejection (lines 122-128 in maven.py and bytes-level DOCTYPE check in csharp dep_file_parser.py), which blocks XXE and billion-laughs before the parser runs. The mitigation is sound and well-documented in comments (nosec B314). This is an acknowledged design choice to avoid adding `defusedxml` as a dependency.
- **Recommended fix:** None needed. The existing mitigation is correct. Consider adding a brief note in SECURITY.md documenting this choice.

### Finding 1.4 — `subprocess` usage is properly guarded

- **File:** `src/scarno/analysers/java/source_analyser.py`, lines 294-306
- **Severity:** INFO (positive finding)
- **Description:** The `_invoke_javap_safe` method is the only subprocess call in the codebase. It enforces `shell=False`, validates class names against a strict regex (`_JAVA_IDENT_RE`), uses a 10-second timeout, and confines `javap` binary resolution to `$JAVA_HOME`. This is exemplary subprocess handling.
- **Recommended fix:** None.

### Finding 1.5 — YAML always uses `safe_load`

- **Files:** `src/scarno/analysers/python/dep_file_parser.py` line 662, `container_ci_parser.py` lines 362/410, `javascript/dep_file_parser.py` lines 389/492
- **Severity:** INFO (positive finding)
- **Description:** Every YAML parse site uses `yaml.safe_load()` exclusively. No `yaml.load()` or `yaml.unsafe_load()` calls exist anywhere in the codebase.
- **Recommended fix:** None.

### Finding 1.6 — No hardcoded secrets or credentials

- **Files:** All source files
- **Severity:** INFO (positive finding)
- **Description:** No API keys, tokens, passwords, or credentials appear anywhere in the source. The `action.yml` uses `${{ github.token }}` which is the standard GitHub-provided token.
- **Recommended fix:** None.

### Finding 1.7 — Path confinement consistently applied

- **Files:** All analyser modules
- **Severity:** INFO (positive finding)
- **Description:** Every file-reading path in every analyser calls `resolve_and_confine()` from `security.py` before accessing files. Symlink escapes, `..` traversal, and file-size limits are uniformly enforced. The Maven POM parent chain uses a sandbox confined to `project_root.parent` for legitimate sibling-POM layouts, which is a reasonable widening.
- **Recommended fix:** None.

### Finding 1.8 — TOCTOU in file-size checks

- **File:** `src/scarno/security.py`, lines 113-117; replicated across all analysers
- **Severity:** LOW
- **Description:** `check_file_size()` calls `stat()` then later the file is `read_text()`. Between the stat and the read, the file could theoretically grow. However, this is a static analysis tool running on a local checkout, and the attacker model (malicious project content, not concurrent modification) makes this unexploitable in practice.
- **Recommended fix:** None needed for v1. If defense-in-depth is desired, read into a bounded buffer using `Path.read_bytes()` with a size cap on the returned bytes.

### Finding 1.9 — No network access

- **Files:** All source files
- **Severity:** INFO (positive finding)
- **Description:** Grep confirms zero use of `urllib`, `requests`, `httpx`, `socket`, or any network library in production code. The tool is fully offline as designed.
- **Recommended fix:** None.

### Finding 1.10 — Regex patterns are bounded

- **Files:** `gradle.py`, `container_ci_parser.py`, `maven.py`, `css/__init__.py`
- **Severity:** INFO (positive finding)
- **Description:** All regex patterns use anchored starts or bounded character classes. Line-length caps (`_MAX_LINE_BYTES = 64KB`) are enforced before regex matching in Gradle and container/CI parsers. The HTML scanner regexes use `[^"']+` (bounded by quote delimiters) and `.*?` (non-greedy with DOTALL), which are safe against catastrophic backtracking because the terminator characters are unambiguous.
- **Recommended fix:** None.

---

## 2. Software Composition Analysis

### Finding 2.1 — Runtime dependency inventory

| Package | Version | Risk | License | Notes |
|---------|---------|------|---------|-------|
| `typer` | >=0.12 | LOW | MIT | CLI framework; pure Python, well-maintained |
| `rich` | >=13.7 | LOW | MIT | Transitive via typer; pure Python |
| `pyyaml` | >=6.0 | LOW | MIT | Widely used; C extension for speed |
| `packaging` | >=23.0 | LOW | BSD/Apache | PEP 508 requirement parsing |
| `pathspec` | >=0.12 | LOW | MPL-2.0 | Gitignore-style matching |
| `tree-sitter` | ==0.25.2 | MEDIUM | MIT | **Contains native code (C)**; pinned to exact version |
| `tree-sitter-java` | ==0.23.5 | MEDIUM | MIT | **Native grammar wheel** |
| `tree-sitter-kotlin` | ==1.1.0 | MEDIUM | MIT | **Native grammar wheel** |
| `tree-sitter-javascript` | ==0.25.0 | MEDIUM | MIT | **Native grammar wheel** |
| `tree-sitter-typescript` | ==0.23.2 | MEDIUM | MIT | **Native grammar wheel** |
| `tree-sitter-css` | ==0.25.0 | MEDIUM | MIT | **Native grammar wheel** |
| `tree-sitter-go` | ==0.25.0 | MEDIUM | MIT | **Native grammar wheel** |
| `tree-sitter-c-sharp` | ==0.23.5 | MEDIUM | MIT | **Native grammar wheel** |

- **Severity:** MEDIUM (for tree-sitter wheels collectively)
- **Description:** The tree-sitter ecosystem (8 packages) dominates the dependency surface. Each grammar wheel contains compiled C code generated from a tree-sitter grammar. The core `tree-sitter` library is the binding to the C runtime. These are all pinned to exact versions, which is good for reproducibility but requires active maintenance to pick up security patches. The tree-sitter project is actively maintained by GitHub/Microsoft. All are MIT licensed.
- **Recommended fix:** Set up automated dependency update tooling (Dependabot/Renovate) to track tree-sitter security advisories. Consider whether `pathspec` (MPL-2.0) needs license review for your distribution model.

### Finding 2.2 — No unnecessary dependencies

- **Severity:** INFO (positive finding)
- **Description:** Every runtime dependency is actively used. `typer` for CLI, `rich` for terminal formatting (via typer), `pyyaml` for YAML parsing, `packaging` for PEP 508, `pathspec` for gitignore patterns, and tree-sitter for AST parsing. The action.yml correctly installs from PyPI rather than curl-piping a script.

### Finding 2.3 — Dev dependencies are appropriate

- **Severity:** INFO
- **Description:** `pytest`, `pytest-cov`, `mypy`, `bandit`, `pip-audit`, and type stubs are all standard Python dev tooling. `bandit` and `pip-audit` show proactive security posture.

---

## 3. Maintainability

### Finding 3.1 — Duplicated `_normalise()` function

- **Files:** `dep_file_parser.py:80`, `source_analyser.py:67`, `container_ci_parser.py:54`
- **Severity:** LOW
- **Description:** The PEP 503 name normalisation function `_normalise(name)` (`re.sub(r"[-_.]+", "-", name).strip().lower()`) is defined identically in three separate modules within the Python analyser alone. It should be extracted to a shared utility.
- **Recommended fix:** Move to `scarno/core/normalize.py` or add to `security.py` / `models.py` and import from there.

### Finding 3.2 — Duplicated deduplication logic

- **Files:** `python/dep_file_parser.py:726-783`, `javascript/dep_file_parser.py:742-797`
- **Severity:** LOW
- **Description:** The `_deduplicate()` function with source-priority logic is structurally identical between the Python and JavaScript dep file parsers. The precedence tables differ (as expected), but the algorithm is the same. A shared base with configurable precedence tables would reduce maintenance burden.
- **Recommended fix:** Extract a generic `deduplicate_deps(raw_deps, precedence_table)` function into `scarno/core/`.

### Finding 3.3 — Duplicated `_strip_json_comments` implementation

- **Files:** `javascript/dep_file_parser.py:178-225`, `javascript/source_analyser.py:388-427`
- **Severity:** LOW
- **Description:** JSONC comment stripping is implemented twice with slightly different interfaces. The `dep_file_parser` version handles both single and double quotes; the `source_analyser` version only handles double quotes. The source_analyser version has a comment acknowledging this: "avoid importing to keep this module standalone."
- **Recommended fix:** The standalone concern is legitimate for import-cycle avoidance, but the duplication could be resolved by extracting to a small `scarno/core/jsonc.py` utility.

### Finding 3.4 — Duplicated `_read_bounded` / `_read_xml` / `_read_text` patterns

- **Files:** `gradle.py:266-290`, `csharp/dep_file_parser.py:135-183`, `go/dep_file_parser.py:75-92`
- **Severity:** LOW
- **Description:** Each analyser implements its own "read file with size cap and error accumulation" helper. These differ slightly (XML adds DOCTYPE rejection, Go returns lines) but share the same skeleton.
- **Recommended fix:** A shared `read_bounded_text(path, errors, max_bytes)` in `security.py` could reduce this to ~5 lines per call site.

### Finding 3.5 — Finding construction boilerplate

- **Files:** `css/__init__.py:256-288`, `go/dep_file_parser.py:213-225`, `javascript/dep_file_parser.py:261-276`, `csharp/dep_file_parser.py:296-329`
- **Severity:** LOW
- **Description:** Creating `Finding` objects requires ~12 lines of boilerplate each time (look up rule, construct Finding with all fields). The findings engine has `_make_finding()` but it's private to the engine module and requires an `_RuleContext`. Other modules that emit findings repeat the construction pattern.
- **Recommended fix:** Expose a public `make_finding(rule_id, file_path, line, snippet, package_hint=None)` in `scarno/findings/` that looks up the rule and constructs the Finding.

### Finding 3.6 — Docstrings are consistently present

- **Files:** All source files
- **Severity:** INFO (positive finding)
- **Description:** Every module, class, and public function has a docstring. Module docstrings include safety guarantees, which is excellent for a security-focused tool. The docstrings reference requirement IDs (REQ-2, SEC-002, etc.) for traceability.

### Finding 3.7 — Error handling is consistent and never raises

- **Files:** All analyser `__init__.py` and coordinator functions
- **Severity:** INFO (positive finding)
- **Description:** Every analyser follows the "never raise, always accumulate errors" contract. Parse failures, file-read errors, and unexpected exceptions are all caught and appended to the errors list. This is documented in docstrings and enforced in the `BaseAnalyser` contract.

### Finding 3.8 — Type annotations are comprehensive

- **Files:** All source files
- **Severity:** INFO (positive finding)
- **Description:** `mypy --strict` is configured in `pyproject.toml` and covers all source files. The few `type: ignore` comments are annotated with specific error codes. Tree-sitter node types use string annotations (`"_ts.Node"`) for the optional-import path. The `# type: ignore[no-untyped-def]` annotations in the JS/Go/C# source analysers are appropriate since tree-sitter node types aren't typed.

---

## 4. Best Practices

### Finding 4.1 — `l` used as variable name (ambiguous)

- **File:** `src/scarno/cli.py`, line 407
- **Severity:** LOW
- **Description:** `normalised = tuple(l.lower() for l in language)` uses `l` as a loop variable, which is visually ambiguous with `1` in many fonts. PEP 8 discourages single-letter `l` for this reason.
- **Recommended fix:** Rename to `lang` or `eco`: `normalised = tuple(lang.lower() for lang in language)`.

### Finding 4.2 — Redundant duplicate check in deduplication

- **File:** `src/scarno/analysers/python/dep_file_parser.py`, lines 750-753
- **Severity:** INFO
- **Description:** The condition `current.version != dep.version and current.version != dep.version` has a redundant duplicate `and` clause with an inline comment "explicit -- placeholder for normalisation". This looks like a leftover from development.
- **Recommended fix:** Remove the duplicate condition.

### Finding 4.3 — Import organization is consistent

- **Files:** All source files
- **Severity:** INFO (positive finding)
- **Description:** All files use `from __future__ import annotations` for PEP 604 union syntax. Imports follow the standard stdlib / third-party / local ordering. The `noqa: F401` comments on CLI registration imports are correctly justified.

### Finding 4.4 — No print statements in library code

- **Files:** All source files except `security.py:132` and `detector.py:163-170`
- **Severity:** LOW
- **Description:** Two locations use `print()` to stderr: `check_root_privilege()` in security.py and `detect_project_type()` in detector.py. The security.py usage is justified (fixed warning string, documented in docstring). The detector.py usage is in a legacy compatibility function. All other output goes through the reporter abstraction.
- **Recommended fix:** Consider converting the detector.py warnings to use Python `logging.warning()` or accept the current approach since `detect_project_type()` is explicitly marked as a legacy API.

### Finding 4.5 — `__version__` mismatch

- **File:** `src/scarno/__init__.py`, line 3
- **Severity:** LOW
- **Description:** `__version__ = "0.0.0"` while `pyproject.toml` declares `version = "1.0.0"`. This means `scarno.__version__` reports `0.0.0` at runtime, and SARIF/JSON reports will include the wrong version. The SARIF reporter's `_INFORMATION_URI` also points to `https://github.com/anthropics/scarno` rather than `https://github.com/brettcrawley/scarno`.
- **Recommended fix:** Either use `importlib.metadata.version("scarno")` for dynamic version resolution, or sync the `__init__.py` version with `pyproject.toml`. Fix the SARIF `_INFORMATION_URI` to match the actual repository URL.

### Finding 4.6 — Resource cleanup is handled via context managers

- **Files:** All file-reading code
- **Severity:** INFO (positive finding)
- **Description:** TOML and ZIP file reads use `with` statements. Text file reads use `Path.read_text()` which handles cleanup automatically. The subprocess call uses `capture_output=True` with timeout. No resource leaks observed.

---

## 5. Architecture

### Finding 5.1 — Registry pattern is well implemented

- **File:** `src/scarno/core/registry.py`
- **Severity:** INFO (positive finding)
- **Description:** The registry is a simple dict-based lookup with `register()`, `get_analyser()`, `analysers_for()`, and `clear()` (test-only). Analysers self-register at import time via `registry.register("python", PythonAnalyser)` at the bottom of their `__init__.py`. The CLI forces these imports with explicit `# noqa: F401` imports. This is clean and extensible.

### Finding 5.2 — Adding a new language is straightforward

- **Severity:** INFO (positive finding)
- **Description:** Adding a new language requires: (1) create `analysers/<lang>/__init__.py` with a `BaseAnalyser` subclass, (2) add `dep_file_parser.py` and `source_analyser.py`, (3) register in the `__init__.py`, (4) add indicator files to `detector.py`, (5) import in `cli.py`. This pattern is demonstrated 6 times across Java, Python, JS, Go, C#, and CSS. The consistency makes the pattern easy to follow.

### Finding 5.3 — HTML scanner is a cross-cutting concern handled well

- **File:** `src/scarno/analysers/html_scanner.py`
- **Severity:** INFO (positive finding)
- **Description:** The HTML template scanner runs independently of any specific language analyser and is invoked by both the JS analyser, the CSS analyser, and the polyglot orchestrator in CLI. It returns a structured `HtmlScanResult` that callers merge. This avoids the scanner needing to know about the caller's dep list.

### Finding 5.4 — Reporter abstraction lacks a formal interface

- **File:** `src/scarno/reporters/`
- **Severity:** LOW
- **Description:** All four reporters (Text, JSON, Markdown, SARIF) have a `render(result: AnalysisResult) -> str` method, but there's no `BaseReporter` abstract class defining this contract. The contract is enforced only by the `_render()` function in `cli.py` which calls `.render()` on each.
- **Recommended fix:** Add a `BaseReporter(ABC)` with an abstract `render()` method in `reporters/__init__.py`. This would catch signature mismatches at type-check time.

### Finding 5.5 — Data flow is clear and linear

- **Severity:** INFO (positive finding)
- **Description:** The pipeline is: CLI parses args -> detector identifies languages -> registry provides analysers -> each analyser runs dep_file_parser then source_analyser -> results merge in CLI -> reporter renders output. Each stage has a clear interface (`AnalysisResult`, `Dependency`, `Finding`). The `AnalysisResult` dataclass is the universal exchange type. No global mutable state is used outside the registry (which is write-once-at-import-time).

### Finding 5.6 — Double HTML scan in polyglot mode

- **File:** `src/scarno/cli.py`, lines 289-312; `src/scarno/analysers/javascript/__init__.py`, lines 53-54
- **Severity:** MEDIUM
- **Description:** When a JS project is analysed, the `JavascriptAnalyser.analyse()` method calls `scan_html_templates()`. Then the CLI's `_run()` method calls `scan_html_templates()` again at lines 290-311 as a "cross-cutting pass". This means HTML templates are scanned twice in any run that includes JavaScript. The results are deduplicated by `declared_names` set, so no duplicate deps appear, but the I/O and parsing work is doubled.
- **Recommended fix:** Either (a) remove the HTML scan from `JavascriptAnalyser.analyse()` and rely solely on the CLI-level pass, or (b) skip the CLI-level HTML scan when JavaScript is among the runnable types.

---

## 6. Performance

### Finding 6.1 — Tree-sitter parsers are module-scoped singletons

- **Files:** `ast_extractor.py`, `javascript/source_analyser.py`, `go/source_analyser.py`, `csharp/source_analyser.py`
- **Severity:** INFO (positive finding)
- **Description:** All tree-sitter `Parser` instances are created once at module import time and reused for every file. This is the correct pattern -- creating a parser per file would be significantly slower.

### Finding 6.2 — Files are read once per analyser

- **Severity:** INFO (positive finding)
- **Description:** Within each analyser, files are discovered once via `rglob()` and read once. The text/bytes are passed through to the AST parser without re-reading. The one exception is Finding 5.6 (double HTML scan).

### Finding 6.3 — `rglob()` called multiple times for the same patterns

- **File:** `src/scarno/analysers/javascript/source_analyser.py`, lines 179-181
- **Severity:** LOW
- **Description:** The JS source analyser calls `root.rglob(pattern)` 8 times (once per extension: `*.js`, `*.mjs`, `*.cjs`, `*.jsx`, `*.ts`, `*.tsx`, `*.mts`, `*.cts`). Each `rglob` call walks the entire directory tree. A single `rglob("*")` with suffix filtering, or a `pathlib` walk, would reduce this to one traversal.
- **Recommended fix:** Use `root.rglob("*")` with `if raw_path.suffix in {".js", ".mjs", ...}:` filtering. Same applies to the CSS analyser (5 patterns) and C# analyser (multiple patterns).

### Finding 6.4 — `importlib.metadata.packages_distributions()` called per-import

- **File:** `src/scarno/analysers/python/source_analyser.py`, line 412
- **Severity:** LOW
- **Description:** `_resolve_import_to_distribution()` calls `importlib.metadata.packages_distributions()` each time it's invoked. This function enumerates all installed packages and builds a dict, which is O(n) in the number of installed packages. It's called once per unmatched import, so on a project with many phantom imports this could be slow.
- **Recommended fix:** Cache the result of `packages_distributions()` at the coordinator level and pass it into the function.

### Finding 6.5 — Regex patterns are compiled at module scope

- **Files:** All modules using regex
- **Severity:** INFO (positive finding)
- **Description:** All regex patterns are compiled to `re.compile()` constants at module scope (e.g., `_IMPORT_JAVA_RE`, `_CURL_PIPE_SHELL_RE`, `_LITERAL_DEP_RE`). No per-call `re.match()` or `re.search()` with raw pattern strings.

### Finding 6.6 — Entire files loaded into memory

- **Files:** All file-reading code
- **Severity:** INFO
- **Description:** Every file is read entirely into memory via `read_text()` or `read_bytes()`. This is bounded by `MAX_FILE_BYTES = 10 MB`, so memory usage per file is capped. For a typical project with hundreds of source files, peak memory would be dominated by the accumulated `Dependency` and `Finding` lists, not individual file reads. Acceptable for v1.

---

## 7. Cognitive Complexity

### Finding 7.1 — `_parse_build_file` in `gradle.py` is complex but manageable

- **File:** `src/scarno/analysers/java/gradle.py`, lines 293-377
- **Severity:** INFO
- **Description:** At ~85 lines with 3 regex-match loops, this is the longest single parsing function. Each loop handles one dependency declaration style (literal, interpolated, catalog). The complexity is inherent to the Gradle DSL's multiple dependency-declaration syntaxes. The function is well-commented.

### Finding 7.2 — `_run()` in `cli.py` is the longest function

- **File:** `src/scarno/cli.py`, lines 222-353
- **Severity:** MEDIUM
- **Description:** At ~130 lines, `_run()` is the main orchestration function. It handles path resolution, project detection, language filtering, analyser dispatch, HTML scanning, result merging, suppression, rendering, and output. While each step is clearly commented, the function does too many things.
- **Recommended fix:** Extract sub-functions: `_detect_and_filter_types()`, `_run_analysers()`, `_apply_html_scan()`, `_write_output()`. This would reduce `_run()` to ~30 lines of orchestration calls.

### Finding 7.3 — `analyse_source_files_with_findings` is long but linear

- **File:** `src/scarno/analysers/python/source_analyser.py`, lines 448-594
- **Severity:** LOW
- **Description:** At ~145 lines, this is a linear pipeline (discover files, parse each, collect imports, run rule engine, apply suppressions, classify deps, detect phantoms). The flow is sequential with no deep nesting. Could benefit from extracting the suppression-application block (lines 512-535) into a helper.

### Finding 7.4 — No files exceed 500 lines needing splitting

- **Severity:** INFO (positive finding)
- **Description:** The largest files are: `python/dep_file_parser.py` (~923 lines), `python/source_analyser.py` (~716 lines), `javascript/dep_file_parser.py` (~805 lines), `javascript/source_analyser.py` (~531 lines). The dep_file_parser modules are long because they handle many file formats, but each format's parser is a self-contained function. The structure within these files is clear with section comments.

### Finding 7.5 — Nesting depth is well controlled

- **Severity:** INFO (positive finding)
- **Description:** The deepest nesting I found is 4 levels (function -> for loop -> if -> if) in a few parsers. Most functions have 2-3 levels of nesting. No deeply nested conditional chains.

### Finding 7.6 — Parameter counts are reasonable

- **Severity:** INFO (positive finding)
- **Description:** The functions with the most parameters are the `_resolve_module` method in maven.py (7 keyword-only params) and `_resolve_group` in dep_file_parser.py (5 params). Both use keyword-only syntax for clarity. Most functions have 2-4 parameters.

---

## Summary Statistics

| Severity | Count |
|----------|:-----:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 3 |
| LOW | 12 |
| INFO (positive) | 17 |
| INFO (neutral) | 3 |
| **Total findings** | **35** |

---

## Top 10 Priority Items

1. **[MEDIUM] Fix operator precedence bug in findings engine** (1.1) -- `engine.py:299` -- Could cause missed detection or false positives in `exec`/`eval` taint analysis.

2. **[MEDIUM] Eliminate double HTML scan in polyglot mode** (5.6) -- `cli.py` + `javascript/__init__.py` -- Causes unnecessary I/O; fix is straightforward.

3. **[MEDIUM] Extract `_run()` sub-functions in CLI** (7.2) -- `cli.py:222-353` -- 130-line orchestrator is the main complexity hotspot; splitting improves readability and testability.

4. **[LOW] Fix `__version__` and SARIF `_INFORMATION_URI`** (4.5) -- `__init__.py` + `sarif_reporter.py` -- Version `0.0.0` appears in all JSON/SARIF output; wrong repo URL in SARIF.

5. **[LOW] Extract shared `_normalise()` function** (3.1) -- 3 identical copies across Python analyser modules.

6. **[LOW] Extract shared Finding construction helper** (3.5) -- Reduces ~12 lines of boilerplate per finding emission site across 4+ modules.

7. **[LOW] Extract shared `_deduplicate()` logic** (3.2) -- Same algorithm in Python and JS dep file parsers.

8. **[LOW] Cache `packages_distributions()` call** (6.4) -- Currently O(n * installed_packages) for n phantom imports.

9. **[LOW] Reduce `rglob()` calls in JS source analyser** (6.3) -- 8 separate directory traversals could be 1.

10. **[LOW] Add `BaseReporter` abstract class** (5.4) -- Formalises the implicit `render()` contract.

---

## Acknowledgements

The following aspects of the codebase are notably well done:

- **Security-first design**: Path confinement, DOCTYPE rejection, ANSI sanitisation, file-size caps, and `shell=False` subprocess handling are consistently applied across all 6 language analysers. The `security.py` module is a single source of truth.
- **Traceability**: Requirement IDs (REQ-2, SEC-002, etc.) are referenced in docstrings, comments, and test markers throughout the codebase, making it easy to audit which requirement each piece of code implements.
- **Graceful degradation**: Tree-sitter grammars are optional everywhere. When unavailable, analysers fall back to regex extraction or return empty results. No crash paths.
- **Never-raise contract**: Every analyser accumulates errors rather than raising exceptions. This means a parse error in one file never blocks analysis of the remaining project.
- **Test infrastructure**: `pyproject.toml` configures 85% coverage floor, strict markers, and both bandit and pip-audit in the dev dependency group. The test file names follow the requirement IDs they verify.

---

## 8. License and Copyleft Analysis

**Date:** 2026-04-19

All runtime dependencies were audited for copyleft license obligations. Scarno is Apache-2.0-licensed; any copyleft dependency would impose distribution restrictions.

### Runtime Dependencies

| Package | Version | License | Copyleft? |
|---------|---------|---------|-----------|
| typer | 0.24.1 | MIT | OK |
| rich | 15.0.0 | MIT | OK |
| pyyaml | 6.0.3 | MIT | OK |
| packaging | 26.1 | Apache-2.0 OR BSD-2-Clause | OK |
| **pathspec** | **1.0.4** | **MPL-2.0** | **WEAK COPYLEFT** |
| tree-sitter | 0.25.2 | MIT | OK |
| tree-sitter-java | 0.23.5 | MIT | OK |
| tree-sitter-kotlin | 1.1.0 | MIT | OK |
| tree-sitter-javascript | 0.25.0 | MIT | OK |
| tree-sitter-typescript | 0.23.2 | MIT | OK |
| tree-sitter-css | 0.25.0 | MIT | OK |
| tree-sitter-go | 0.25.0 | MIT | OK |
| tree-sitter-c-sharp | 0.23.5 | MIT | OK |

### Key Transitive Dependencies

| Package | Version | License | Copyleft? |
|---------|---------|---------|-----------|
| click | 8.3.2 | BSD-3-Clause | OK |
| shellingham | 1.5.4 | ISC | OK |
| typing_extensions | 4.15.0 | PSF-2.0 | OK |
| markdown-it-py | 4.0.0 | MIT | OK |
| mdurl | 0.1.2 | MIT | OK |
| pygments | 2.20.0 | BSD-2-Clause | OK |

### Findings

#### Finding 8.1 — `pathspec` is MPL-2.0 (weak copyleft)

- **Severity:** LOW
- **Package:** `pathspec==1.0.4`
- **License:** Mozilla Public License 2.0 (MPL-2.0)
- **Description:** MPL-2.0 is a "weak copyleft" license. Unlike GPL, it requires only that modifications to MPL-covered **files** (not the whole project) remain under MPL. Since Scarno imports `pathspec` but does not modify its source files, no copyleft obligation is triggered for Scarno's own Apache-2.0-licensed code. MPL-2.0 is explicitly compatible with Apache-2.0 distribution.
- **Risk:** Negligible for this use case. The FSF and OSI both consider MPL-2.0 compatible with proprietary and permissive-licensed projects when the MPL-covered files are not modified.
- **Recommended action:** No action required. Document in LICENSE or NOTICE file that `pathspec` is MPL-2.0 licensed. If a future contributor modifies `pathspec` source directly (e.g. vendoring), that modified file must remain MPL-2.0.

#### Finding 8.2 — No GPL, AGPL, LGPL, SSPL, or EUPL dependencies

- **Severity:** INFO (positive finding)
- **Description:** No strong copyleft licenses were found in any runtime or transitive dependency. The entire dependency tree is MIT/BSD/Apache/ISC/PSF/MPL-2.0, all of which are compatible with Apache-2.0 distribution.

#### Finding 8.3 — tree-sitter grammars contain native code (C/C++)

- **Severity:** INFO
- **Description:** All 7 tree-sitter grammar packages distribute pre-compiled native shared libraries (`.so` / `.dylib` / `.dll`) built from C source code. The grammars themselves are MIT-licensed, but the compiled binaries link against the C standard library of the build platform. No additional license obligations arise from this linkage on standard platforms (glibc on Linux is LGPL, but dynamic linking to LGPL does not impose copyleft on the calling application).
- **Recommended action:** None. Standard dynamic linkage to system libraries does not trigger copyleft.

### Summary

| Category | Count |
|----------|:-----:|
| Strong copyleft (GPL/AGPL/SSPL) | **0** |
| Weak copyleft (MPL-2.0) | **1** (pathspec — no obligation triggered) |
| Permissive (MIT/BSD/Apache/ISC/PSF) | **18** |
| **Total runtime + key transitive** | **19** |

**Conclusion:** Scarno's dependency tree is fully compatible with Apache-2.0 distribution. No copyleft obligations are triggered by the current usage patterns.
