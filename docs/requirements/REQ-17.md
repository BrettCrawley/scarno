# REQ-17 — Test Exclusion, Symbol Tally, Direct-Use Transitives, and Mermaid Graph

## Overview

Five connected enhancements that tighten the signal in Scarno output:

1. **Symbol-usage tally** — every `IN_USE` dependency must list the classes / methods / functions actually called from project source, with a per-symbol *usage_count* (how many call sites referenced it). Renders in `text`, `json`, `markdown`, and `sarif` reporters.
2. **Direct-use transitive flag** — a transitive dependency that is imported directly by project source code is distinguished from transitives that are only required indirectly. Surfaces as `Dependency.imported_directly = True` and is reported separately so the engineer can promote it to a first-class declared dep.
3. **Mermaid dependency-hierarchy diagram** in markdown output — colour-coded: black = used, red = unused (`SAFE`), orange = uncertain. Transitive nodes that are imported directly by source are coloured **black** (regardless of their parent's status) so promotion-needed nodes stand out.
4. **`--exclude-tests`** CLI flag — drops test-scoped declared dependencies *and* skips test source files during discovery, across every supported ecosystem.
5. **`--test-paths PATTERN`** (repeatable) — operator-supplied glob list that overrides the heuristic test-path matcher for non-standard layouts (e.g. `it/`, `e2e/`, `src-tests/`). Patterns are confined to the project root.

A sixth, narrowly-scoped flag is included:

6. **`--exclude-dev`** — npm-only opt-out for `devDependencies` (linters, bundlers, formatters). **Off by default** — the user's convention is that dev tooling is treated as runtime-relevant unless explicitly suppressed.

This requirement also tightens the data model so all three of the above pieces of information have a stable wire-format.

---

## Problem Statement

Three observable gaps in the current output:

- **`entry_points` already lists symbols, but does not count them.** A user reading the report cannot tell whether `requests.get` is called once in a fixture or 412 times across the codebase. Counting matters when deciding whether to inline a single-use API or to keep the dep.
- **Transitive deps that are imported directly by project source are silently treated as transitive.** If the project does `import lodash` but `lodash` is pulled in only by an unused declared dep, then removing the parent will break the build. Today the user sees the parent flagged `SAFE` and the transitive flagged "required by parent" — neither row says "your code is calling this".
- **No dependency-graph view.** Markdown output is a flat checklist; reviewers cannot visually trace which removals would orphan which subtrees.

Two ergonomic gaps in the CLI:

- **No way to scope analysis to production code.** A project with a deep `tests/` tree often has test-only deps (`pytest`, `mockito`, `vitest`) that pollute the `IN_USE` list and hide the real production picture.
- **No way to override test-path heuristics.** Projects with `it/`, `e2e/`, `src-tests/`, co-located test conventions cannot benefit from `--exclude-tests` without help.

---

## Solution

### 1. Data-model changes (`src/scarno/models.py`)

```python
@dataclass
class EntryPoint:
    name: str
    kind: str
    used: bool
    usage_count: int = 0   # new — number of source-level call/reference sites


@dataclass
class Dependency:
    ...
    is_transitive: bool = False
    imported_directly: bool = False   # new — True when project source imports
                                      # this dep regardless of how it was declared
```

`imported_directly` is set on transitives only when source code imports them; for direct (non-transitive) deps it is left at the default `False` to avoid duplicating information already encoded in `is_transitive=False`.

### 2. CLI surface (`src/scarno/cli.py`)

```text
--exclude-tests              Drop test-scoped deps and skip test source files.
--test-paths PATTERN         Repeatable glob (relative to project root) added
                              to the test-path matcher when --exclude-tests
                              is on. Has no effect without --exclude-tests.
--exclude-dev                npm-only: drop devDependencies during parsing.
                              Off by default. Independent of --exclude-tests.
```

`_RunOptions` gains:

```python
exclude_tests: bool = False
test_paths: tuple[str, ...] = ()
exclude_dev: bool = False
```

Validation rules (CLI layer, before analysis runs):
- `--test-paths` patterns are stripped of leading `/`; `..` segments cause a sanitised `_CliError` ("test-path patterns must stay inside the project root").
- A hard cap of **64 patterns** is enforced (`SEC-NEW-31`) to prevent O(N×M) blow-up.
- Each pattern is bounded to **256 bytes** before glob compilation.
- `--exclude-dev` without any npm project produces a warning, never a fatal error.

### 3. BaseAnalyser scope plumbing

```python
class BaseAnalyser(ABC):
    use_gitignore: bool = True
    exclude_tests: bool = False
    test_paths: tuple[str, ...] = ()
    exclude_dev: bool = False
```

The orchestrator sets these three attributes on every analyser instance after `analysers_for(...)` returns and before calling `analyse(...)`.

### 4. Per-ecosystem test-scope rules

| Ecosystem | Test-scoped deps to drop when `--exclude-tests` is on | Test source files to skip |
|---|---|---|
| **Python (pypi)** | `[project.optional-dependencies]` groups whose name (case-insensitive) ∈ {`test`, `tests`, `dev`}; `[dependency-groups]` test/dev groups; `[tool.poetry.group.<name>.dependencies]` where `<name>` ∈ {`test`, `dev`}; `tests-require` / `extras_require={"test": ...}` from setup.cfg / setup.py; `requirements-test.txt`, `requirements-dev.txt`, `test-requirements.txt`, `dev-requirements.txt` whole files | `tests/`, `test/`, `__tests__/`, `**/test_*.py`, `**/*_test.py`, `conftest.py`, `noxfile.py`, `tox.ini` (parsing only — file is still read for non-test deps in CI mode) |
| **Maven** | `<dependency>` elements with `<scope>test</scope>` | `src/test/java/**/*.java`, `src/test/kotlin/**/*.kt`, `**/*Test.java`, `**/*Tests.java`, `**/*IT.java` |
| **Gradle** | configurations matching prefixes `test`, `androidTest` (`testImplementation`, `testRuntimeOnly`, `testCompileOnly`, `androidTestImplementation`, etc.) | same as Maven |
| **JavaScript / TypeScript (npm)** | nothing by default. **`devDependencies` only when `--exclude-dev` is also on.** Always drop `optionalDependencies` flagged with `"devOnly"` semantics if seen. | `**/__tests__/**`, `**/*.test.{js,jsx,ts,tsx}`, `**/*.spec.{js,jsx,ts,tsx}`, `tests/`, `test/`, `cypress/`, `playwright/`, `e2e/` |
| **Go** | dependencies that appear *only* in `_test.go` import sets and are not in `go.mod` `require` (we drop the test-only resolved set) | `**/*_test.go` |
| **C# / .NET** | projects whose `*.csproj` filename ends in `.Tests.csproj` / `.Test.csproj` / `Tests.fsproj` / `.Tests.vbproj`, *and* projects with `<IsTestProject>true</IsTestProject>` or referencing `Microsoft.NET.Test.Sdk` | the source files under those projects |
| **CSS** | none — CSS has no test scope | none |
| **HTML scanner** | none — HTML scope is not test-aware | none |

Test-path patterns supplied via `--test-paths` are appended to the per-ecosystem default list. They are interpreted as `fnmatch.fnmatchcase(relative_path, pattern)` after path-confinement.

### 5. Symbol-usage tally

The Python source analyser already collects `used_symbols: dict[str, set[str]]`. Replace `set[str]` with `dict[str, int]` (symbol → call-site count). Each `_ImportVisitor` increments the count on every `ast.Attribute` access or bare-name reference resolved to that symbol. Notebook / Dockerfile passes contribute to the same counter.

For ecosystems where entry-point enumeration is shallow (Java, JS/TS, Go, C#) populate `usage_count` from the same source-side counter. Where the ecosystem's source analyser is reference-based (e.g. tree-sitter), each tree-sitter capture node is one call-site.

Reporter output (text):

```
flask==3.0.0 — IN_USE — imported as 'flask' in project source
  entry points: 14 / 87 used
    flask.Flask              (class)     used 23×
    flask.Blueprint          (class)     used  4×
    flask.jsonify            (function)  used 11×
    ...
```

Reporter output (json):

```json
{
  "name": "flask",
  "entry_points": [
    {"name": "flask.Flask", "kind": "class", "used": true, "usage_count": 23},
    ...
  ]
}
```

Reporter output (markdown): same shape as text, inside the "In use" section.

Reporter output (sarif): `usage_count` is added to the `properties` object of the `TS-DEP-INUSE` result for each used symbol so SARIF consumers can sort/group by call frequency.

### 5b. Transitive status propagation

`_resolve_transitive_statuses` propagates the strongest direct-parent
status down the dep graph:

| Parent state across all direct deps that pull in transitive `T` | `T` final status |
|---|---|
| Any IN_USE parent | **IN_USE** — transitively required |
| Only UNCERTAIN parents (dynamic / non-literal) | UNCERTAIN |
| All parents SAFE | SAFE — orphaned |
| No parents in graph at all | SAFE — unreachable |
| `imported_directly=True` (REQ-17) | IN_USE — never demoted; user should promote to a direct dep |

The reason text names which direct dep(s) keep the transitive alive
(e.g. `"transitively required by: alpha, gamma"`).

### 6. Directly-used transitive surfacing

After the Python source analyser builds `direct_all` (set of top-level imports), we cross-reference against the dependency list. For every dep where `is_transitive=True` and a matching import is present in `direct_all`, set `imported_directly=True`.

The orphan-resolution pass (`_resolve_transitive_statuses`) is updated:

- A transitive dep with `imported_directly=True` is **never** marked `SAFE` purely on parent-orphan grounds. Its reason becomes:
  > `"transitive dep used directly by project source — promote to a declared dependency in <manifest>"`
- The reporter sorts this category to the top of the markdown checklist with a header **"Transitive — imported directly (promote to first-class)"** so engineers act on it before processing orphans.

For Java, JS/TS, Go, C# the equivalent cross-reference is performed against each ecosystem's symbol set — Java fully-qualified imports, JS bare-specifier `import "lodash"`, Go module path, C# `using`.

### 7. ASCII dependency tree in markdown

Markdown reporter emits a fenced ```diff block immediately after the
project-summary header and before the checklists. Vertical Unix-style
tree: project at the root, direct deps below, transitives nested.
Status colour is carried by the line's diff prefix — GitHub, GitLab,
and most IDE markdown viewers honour it.

```
  <project-path>
  ├── alpha@1               (no marker → in use, neutral colour)
! │   ├── beta@2  (uncertain)
! │   │   └── delta@4  (uncertain)
! │   └── gamma@3  (uncertain)
- ├── boto3@1  (unused)
- └── unused-lib@1  (unused)
-     └── orphan@1  (unused)

  Legend:  (no marker) in use      - unused      ! uncertain / undeclared
```

Diff-prefix colour map:

| Status | Prefix | Renders as |
|---|---|---|
| `IN_USE` | `  ` (two spaces) | neutral / black |
| `SAFE` | `- ` | red |
| `UNCERTAIN` | `! ` | orange (in viewers that color `!`); otherwise plain with the explicit text suffix |
| `UNDECLARED` | `! ` | same as UNCERTAIN |
| `is_transitive=True` AND `imported_directly=True` | `  ` (neutral) plus a `(promote — imported directly)` text suffix |

History: an earlier iteration used Mermaid (`graph TD` → `flowchart
LR`). On real multi-hundred-dep projects Mermaid produced unreadable
spaghetti; the ASCII tree stays legible at any size and doesn't
depend on the viewer having a Mermaid renderer. The Mermaid label
sanitiser (`_mermaid_label`) is retained as a defensive utility for
any future renderer that might surface dep names inside a Mermaid
fence.

Node-id rule: `n_<index>` where `<index>` is the dep's position in the *deduplicated, sorted-by-name* dep list. **Names are never inlined into ids** — only into the label, which is bracket-escaped (see "security" below).

Edge rule: build edges from `dep_graph: dict[str, set[str]]` already produced by REQ-2 and REQ-4. If `dep_graph` is empty (single-language projects without lock-file graph data), emit only the node list and an info comment `%% no edge data available` — never a half-graph.

Class assignment rule per dep:

| Dependency state | classDef |
|---|---|
| `IN_USE` (direct or transitive) | `status_used` (black) |
| `is_transitive=True` AND `imported_directly=True` | `status_used` (black, regardless of parent) |
| `UNCERTAIN` | `status_uncertain` (orange) |
| `SAFE` | `status_unused` (red) |
| `UNDECLARED` | `status_used` (black) — they *are* in use, just undeclared |

Hard limits (`SEC-NEW-32`):
- Maximum **1000 nodes** per diagram. Above this, emit `%% diagram truncated — N additional nodes elided` and render only the first 1000 deps sorted by `(status_priority, name)` where priority puts SAFE/UNCERTAIN/UNDECLARED first.
- Maximum **2000 edges**.
- Label maximum **80 characters**; truncate with ellipsis.

### 8. Mermaid-label injection defence (`SEC-NEW-32`)

Mermaid label syntax permits arbitrary text inside `["..."]` *but breaks* on `"`, `]`, newline, and a handful of reserved tokens (`---`, `;;`). It also supports `click n_3 "javascript:..."` events when rendered by some viewers. The label sanitiser:

```python
def _mermaid_label(name: str) -> str:
    text = sanitise(name)                           # strip ANSI / control chars
    text = text.replace("\\", "\\\\")
    text = text.replace('"', "&quot;")
    text = text.replace("]", "&#93;")
    text = text.replace("[", "&#91;")
    text = text.replace("\n", " ").replace("\r", " ")
    return text[:80]                                # cap label length
```

The reporter MUST NOT emit any `click` directive — ever — and MUST NOT pass through mermaid-active tokens (`---`, `===`, `subgraph`, `end`, `classDef`, `linkStyle`, `style`) verbatim from a dep name. A dep name that exactly matches one of those tokens after sanitisation is rendered as `&lt;reserved&gt;` (still legal label text).

### 9. `--test-paths` confinement (`SEC-NEW-33`)

Patterns supplied via `--test-paths` undergo:

1. Length cap of 256 bytes per pattern; oversized → `_CliError`.
2. Total-pattern cap of 64; oversized → `_CliError`.
3. Reject any pattern containing `..` segment (after splitting on `/`).
4. Reject any pattern starting with `/` (absolute) — convert by stripping leading `/` and warn.
5. Reject any pattern matching the regex `\\\\` (Windows-style backslash) — patterns are POSIX globs only.

Match step uses `fnmatch.fnmatchcase` against the *relative* path computed by `Path.relative_to(project_root)`. We never `glob` from arbitrary roots — the project tree walk produces paths and the patterns gate them.

### 10. Behavioural defaults table

| Flag | Default | Rationale |
|---|---|---|
| `--exclude-tests` | **off** | Backwards-compatible — existing reports keep the same dep set. |
| `--test-paths` | empty | Heuristic list above already covers ~95% of layouts. |
| `--exclude-dev` | **off** | Dev tooling commonly contains runtime-relevant packages (e.g. `vite` runs builds in CI); user explicitly requested off-by-default. |

---

## Out of Scope (REQ-17)

- **Auto-promotion of directly-used transitives.** REQ-17 surfaces them; the human decides what to write to the manifest.
- **Per-language `--exclude-dev` semantics.** Only npm distinguishes "dev" from "test"; we don't extend this to `tool.poetry.group.dev` (covered already by `--exclude-tests` because Python `dev` groups are usually test-adjacent).
- **Mermaid diagrams in any output other than markdown.** Text/json/sarif are unchanged. Sarif consumers can parse the dep graph from `properties.dep_graph`.
- **Cycle annotation in the Mermaid graph.** Cycles in `dep_graph` are rendered as plain back-edges; a future enhancement could highlight them.

---

## File Layout

```
src/scarno/
├── cli.py                                     # +3 flags, +validation
├── models.py                                  # +EntryPoint.usage_count, +Dependency.imported_directly
├── core/base_analyser.py                      # +exclude_tests, +test_paths, +exclude_dev
├── core/test_scope.py                         # NEW — TestScopeMatcher + sanitise_test_paths
├── reporters/markdown_reporter.py             # +mermaid section, +promote-direct subsection
├── reporters/text_reporter.py                 # +usage_count rendering
├── reporters/json_reporter.py                 # carries new fields automatically via dataclass dump
├── reporters/sarif_reporter.py                # +usage_count in result.properties
├── analysers/python/dep_file_parser.py        # +exclude_tests filter on optional groups + requirements-*.txt
├── analysers/python/source_analyser.py        # +usage_count counter, +imported_directly cross-ref,
│                                              #  +test-path skip in _discover_py_files
├── analysers/java/maven.py                    # +scope=test filter
├── analysers/java/gradle.py                   # +configuration-prefix filter (test*, androidTest*)
├── analysers/java/source_analyser.py          # +test-path skip
├── analysers/javascript/dep_file_parser.py    # +exclude_dev filter
├── analysers/javascript/source_analyser.py    # +test-path skip
├── analysers/go/source_analyser.py            # +_test.go test-only set + test-path skip
├── analysers/csharp/dep_file_parser.py        # +.Tests.csproj / IsTestProject filter
└── analysers/csharp/source_analyser.py        # +test-path skip

tests/
├── unit/test_req17_test_scope.py              # NEW — sanitise_test_paths, matcher
├── unit/test_req17_symbol_tally.py            # NEW — usage_count tally across ecosystems
├── unit/test_req17_imported_directly.py       # NEW — transitive direct-use detection
├── unit/test_req17_mermaid.py                 # NEW — markdown mermaid block content + injection
├── unit/test_req17_cli.py                     # NEW — flag plumbing + validation
├── security/test_req17_adversarial.py         # NEW — Mermaid injection, glob ReDoS, traversal in --test-paths
└── fixtures/req17/                            # NEW fixture trees per ecosystem
```

---

## Public Interface

```python
# src/scarno/core/test_scope.py

DEFAULT_TEST_PATTERNS: dict[str, tuple[str, ...]] = {
    "python":     ("tests/*", "tests/**/*", "test/*", "test/**/*",
                   "**/test_*.py", "**/*_test.py", "conftest.py"),
    "java":       ("src/test/**/*.java", "src/test/**/*.kt",
                   "**/*Test.java", "**/*Tests.java", "**/*IT.java"),
    "javascript": ("**/__tests__/**/*", "**/*.test.js", "**/*.test.jsx",
                   "**/*.test.ts", "**/*.test.tsx",
                   "**/*.spec.js", "**/*.spec.jsx",
                   "**/*.spec.ts", "**/*.spec.tsx",
                   "tests/**/*", "test/**/*", "cypress/**/*",
                   "playwright/**/*", "e2e/**/*"),
    "go":         ("**/*_test.go",),
    "csharp":     ("**/*Tests/**/*", "**/*Test/**/*"),
}

MAX_USER_TEST_PATTERNS: int = 64
MAX_USER_TEST_PATTERN_BYTES: int = 256


def sanitise_test_paths(raw: tuple[str, ...]) -> tuple[str, ...]:
    """Validate operator-supplied --test-paths patterns.

    Raises ``ValueError`` (caller maps to ``_CliError``) when:
      * count > MAX_USER_TEST_PATTERNS
      * any pattern length > MAX_USER_TEST_PATTERN_BYTES
      * any pattern contains '..' segments
      * any pattern contains '\\' (Windows-style separator)

    Strips a single leading '/' from each pattern.
    """


class TestScopeMatcher:
    def __init__(
        self,
        language: str,
        *,
        exclude_tests: bool,
        user_patterns: tuple[str, ...] = (),
    ) -> None: ...

    def is_test_path(self, relative_path: str) -> bool:
        """True when path matches any default OR user pattern, else False.
        Always False when exclude_tests=False."""
```

```python
# src/scarno/reporters/markdown_reporter.py

def _render_mermaid(
    deps: list[Dependency],
    dep_graph: dict[str, set[str]],
) -> list[str]:
    """Return the Mermaid block lines for the deduplicated dep set."""
```

---

## Acceptance Criteria

### Symbol-usage tally
- [ ] Given Python source with 23 calls to `flask.Flask`, when source analysis completes, then the `requests` `Dependency.entry_points` element for `flask.Flask` has `used=True` and `usage_count == 23`.
- [ ] Given an entry point that is imported but never called, when reporters render, then `usage_count == 0` and `used == False`.
- [ ] Given a JS/TS project that calls `lodash.debounce` 7 times, when source analysis completes, then `usage_count == 7` for that entry point.
- [ ] Given an `IN_USE` dep with `entry_points=[]` (e.g. dynamic-import only), when reporters render, then no per-symbol section is emitted but a one-line summary is still shown.
- [ ] Given the text reporter, when it renders an `IN_USE` dep with `usage_count` populated, then the line includes the `used N×` suffix.
- [ ] Given the SARIF reporter, when it emits a `TS-DEP-INUSE` rule result, then `result.properties.entry_points[i].usage_count` is present for every entry point.

### Directly-used transitives
- [ ] Given a Python project that does `import lodash_clone` where `lodash_clone` is a transitive of an unused declared dep, when analysis completes, then the dep has `is_transitive=True`, `imported_directly=True`, and the reason mentions "promote to a declared dependency".
- [ ] Given a directly-used transitive whose only declared parent is `SAFE`, when `_resolve_transitive_statuses` runs, then the transitive is **not** marked `SAFE` — it stays `IN_USE`.
- [ ] Given a transitive that is *not* imported directly, when analysis completes, then `imported_directly == False` and existing orphan-resolution behaviour is unchanged.
- [ ] Given the markdown reporter and at least one directly-used transitive, when render is called, then a `Transitive — imported directly (promote to first-class)` section appears above the regular `In use` section.

### Mermaid diagram (markdown)
- [ ] Given any dep set, when the markdown reporter renders, then the output contains exactly one ```mermaid fenced block placed before the first checklist heading.
- [ ] Given a project with `dep_graph={"a": {"b"}, "b": {"c"}}`, when rendered, then the diagram includes `n_<a> --> n_<b>` and `n_<b> --> n_<c>`.
- [ ] Given a `SAFE` dep, when rendered, then its node uses `:::status_unused` (red).
- [ ] Given an `UNCERTAIN` dep, when rendered, then its node uses `:::status_uncertain` (orange).
- [ ] Given a transitive dep with `imported_directly=True` whose declared parent is `SAFE`, when rendered, then its node uses `:::status_used` (black) — not red.
- [ ] Given a dep name containing `]`, `"`, newline, or ANSI escapes, when rendered, then those characters appear escaped in the label and never break the diagram syntax.
- [ ] Given a project with > 1000 deps, when rendered, then exactly 1000 nodes are emitted plus a `%% diagram truncated` comment.
- [ ] Given the markdown reporter, when it renders, then it never emits a `click` directive.
- [ ] Given an empty `dep_graph`, when rendered, then nodes are present but no edges, plus a `%% no edge data available` comment.

### `--exclude-tests` (Python)
- [ ] Given `pyproject.toml` with `[project.optional-dependencies]` `test=["pytest"]` and `--exclude-tests`, when CLI runs, then `pytest` is not in the dep list.
- [ ] Given `requirements-test.txt` containing `pytest` and `--exclude-tests`, when CLI runs, then `pytest` is not in the dep list.
- [ ] Given a project with `tests/test_things.py` importing `pytest`, with `--exclude-tests`, then no import statement from that file is collected and `pytest` (if undeclared) does not appear as an `UNDECLARED` finding.
- [ ] Given the same project without `--exclude-tests`, when CLI runs, then `pytest` is present in the output (default behaviour is unchanged).

### `--exclude-tests` (Java/Maven)
- [ ] Given `pom.xml` with `<dependency><scope>test</scope></dependency>` for `junit:junit` and `--exclude-tests`, then `junit` is not in the dep list.
- [ ] Given `src/test/java/com/example/FooTest.java` importing `org.mockito.Mockito` and `--exclude-tests`, then no import from that file is collected.

### `--exclude-tests` (Java/Gradle)
- [ ] Given `build.gradle.kts` declaring `testImplementation("org.mockito:mockito-core:5.0")` and `--exclude-tests`, then `mockito-core` is not in the dep list.
- [ ] Given `androidTestImplementation` and `--exclude-tests`, then the dep is dropped.

### `--exclude-tests` (JS/TS)
- [ ] Given `package.json` with `devDependencies={"vitest": "..."}` and `--exclude-tests` *only* (no `--exclude-dev`), then `vitest` remains in the dep list (because devDependencies are not test-scoped without `--exclude-dev`).
- [ ] Given `tests/foo.test.ts` and `--exclude-tests`, then no import from that file is collected.
- [ ] Given `src/foo.spec.ts` and `--exclude-tests`, then no import from that file is collected.

### `--exclude-tests` (Go)
- [ ] Given `*_test.go` containing `import "github.com/stretchr/testify/assert"` and `--exclude-tests`, then `testify` (if test-only) is dropped.
- [ ] Given a non-test `.go` file also importing `testify`, when `--exclude-tests` is on, then `testify` is retained (because it's required by production code).

### `--exclude-tests` (C#)
- [ ] Given a solution with `Foo.csproj` and `Foo.Tests.csproj`, with `--exclude-tests`, then `xunit` and `Microsoft.NET.Test.Sdk` (declared only in `Foo.Tests.csproj`) are not in the dep list.
- [ ] Given a `.csproj` containing `<IsTestProject>true</IsTestProject>` and `--exclude-tests`, then its deps are dropped.

### `--test-paths`
- [ ] Given `--test-paths "it/**/*"` and a file at `it/IntegrationTest.java` plus `--exclude-tests`, then that file is skipped during source discovery.
- [ ] Given `--test-paths` with no `--exclude-tests`, then the patterns have no effect (default behaviour preserved).
- [ ] Given `--test-paths "../etc/passwd"`, then the CLI exits with code 2 and a sanitised error mentioning the project root.
- [ ] Given `--test-paths "/abs/path"`, then the leading `/` is stripped and a stderr warning is emitted (verbose mode only).
- [ ] Given 65 `--test-paths` patterns, then the CLI exits with code 2 and a "too many patterns" error.
- [ ] Given a `--test-paths` pattern of 257 bytes, then the CLI exits with code 2.

### `--exclude-dev`
- [ ] Given npm `package.json` with `devDependencies` and `--exclude-dev` (without `--exclude-tests`), then those deps are not in the output.
- [ ] Given the same project without `--exclude-dev`, then devDependencies are present (default behaviour unchanged).
- [ ] Given a non-npm project and `--exclude-dev`, then a single warning line ("--exclude-dev has no effect outside npm projects") appears in `errors` and analysis continues.

### Output integrity
- [ ] Given any combination of flags, when JSON output is rendered, then it is valid JSON parseable by `json.loads`.
- [ ] Given any combination of flags, when SARIF output is rendered, then it validates against SARIF 2.1.0 schema.
- [ ] Given a dep name `"]<script>alert(1)</script>["`, when markdown reporter renders the Mermaid block, then the rendered Markdown does not contain `<script>` and the diagram remains syntactically valid (parseable by mermaid CLI).

### Security & robustness
- [ ] Given an adversarial `--test-paths` pattern designed for ReDoS (`((a+)+)+`), then the CLI rejects it because it contains the prohibited regex special characters under `fnmatch` semantics — actually `fnmatch` is not regex-based, but pattern length cap (256B) bounds runtime to O(N).
- [ ] Given an analysed project with a symlink at `tests/escape -> ../../../../etc`, when `--exclude-tests` is on, then the test-scope matcher does not follow the symlink (already covered by existing path confinement).
- [ ] Given the Mermaid block, when rendered, then no line contains the substring `click ` (case-insensitive) regardless of dep names.

---

## Performance Targets (`PERF-007`)

- 1000-dep project with full Mermaid render: < 200 ms additional vs the same project without Mermaid.
- 10 000-file project with `--exclude-tests` + 32 user `--test-paths`: discovery time < 2× the no-test-filter baseline.
- `usage_count` aggregation: O(call_sites), no quadratic behaviour relative to dep count.