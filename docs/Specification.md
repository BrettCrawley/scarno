# Scarno — Smart Dependency Pruner for Polyglot Projects

## One-liner
Safely identify unused dependencies in Python, Java/Kotlin, JavaScript/TypeScript, Go, C#/.NET, and CSS projects — without the false positives that break apps when you act on them.

## Value Proposition
Existing tools like `mvn dependency:analyze` and `pipreqs` regularly flag dependencies as "unused" when they're actually being consumed via Spring `@Autowired`, reflection, `Class.forName()`, or declarative config. Developers either ignore the output entirely (because they've been burned before) or spend hours manually verifying each recommendation. Scarno understands how modern frameworks actually use dependencies, so it only recommends removals it's genuinely confident about — reducing bloat, shrinking CVE surface area, and speeding up CI builds without the risk of breaking anything. It also surfaces the full entry point surface area of every direct dependency — showing which APIs your code actually calls — so engineers can make an informed call when a large library has been pulled in for just one or two methods, or when an entire dependency subtree is serving no real purpose.

## Who It's For
- **Java developers on Spring, Guice, or other DI frameworks**: Get dependency cleanup recommendations they can actually trust, without manually auditing every `@Autowired` and `@Bean` annotation
- **Python developers on medium-to-large projects**: Identify truly unused packages across the full ecosystem of config formats without chasing false positives
- **Platform and DevOps engineers**: Drop Scarno into CI pipelines and get structured output that flags real bloat before it accumulates

## Job to Be Done
When I want to clean up dependencies in a mature project, I need a tool that understands how my framework actually uses those dependencies — so I can remove what's safe to remove without spending hours second-guessing the output or accidentally breaking the build.

## Key Functionality
- **Static and bytecode analysis** for direct, reflective, and annotated usages — not just surface-level import scanning
- **DI-aware detection**: understands Spring `@Autowired`, `@Bean`, and `@Component`; Guice `@Inject`; and Python DI patterns so framework-wired dependencies aren't falsely flagged
- **Reflection heuristics**: usages via `Class.forName()`, `importlib`, and `__import__()` are flagged as "uncertain" rather than safe to remove
- **Maven POM hierarchy traversal**: follows parent/child POM relationships, BOM imports, and dependency management sections across multi-module projects
- **Gradle support**: analyzes `build.gradle` and `build.gradle.kts` files, including multi-module Gradle projects
- **Kotlin support**: processes `.kt` source files alongside `.java` files in mixed-language projects
- **Python config coverage**: reads `requirements.txt`, `pyproject.toml` (including `[project]`, `[tool.poetry]`, PEP 518 `[build-system].requires`, and PEP 735 `[dependency-groups]`), `setup.py`, `setup.cfg`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, and Conda `environment.yml`
- **Container & CI coverage**: extracts `pip install` declarations from `Dockerfile`, `.github/workflows/*.yml`, `.gitlab-ci.yml`, `tox.ini`, and `noxfile.py` so runtime/build-time deps aren't misclassified as unused (REQ-2c)
- **Phantom / undeclared import detection**: flags imports that resolve to installed packages but are not in any dependency file — and flags packages vendored in-repo under `vendor/`, `third_party/`, or `_vendor/` (REQ-3b)
- **Suspicious install & code-execution findings**: detects runtime `pip install` via `subprocess`/`os.system`, Jupyter `!pip install` magics, `exec`/`eval` of network responses, `curl … | sh` in container recipes, and other supply-chain-risky patterns — emitted as structured `Finding` objects with severity, rule ID, location, and remediation (REQ-3c). Defensive only: Scarno reports; it never executes project code.
- **Confidence-scored report**: every dependency is classified as Safe to Remove, Uncertain, In Use, or Undeclared — the tool never silently deletes anything

- **Entry point surface area report**: for each direct dependency, lists all public entry points (classes, functions, symbols) it exposes and marks which ones your code actually calls — making it easy to spot a 200-class library used for a single utility method, or an entire dependency subtree that can be removed together
- **CLI-first with CI integration**: runs from the command line, outputs four formats for pipeline consumption:
  - **`text`** — human-readable terminal output (default)
  - **`json`** — full structured schema for programmatic consumption
  - **`markdown`** — actionable-checklist format suitable for PR descriptions and issue bodies (unticked checkboxes on SAFE / UNDECLARED / UNCERTAIN deps and every Finding; confirmed IN_USE deps as a plain list)
  - **`sarif`** — SARIF 2.1.0 for GitHub Code Scanning, SonarQube, Azure DevOps, and GitLab Security Dashboard (rule catalogue includes every REQ-3c rule plus synthesised `TS-DEP-SAFE` / `TS-DEP-UNDECLARED` / `TS-DEP-UNCERTAIN` so dependency findings surface alongside security findings in any SARIF-aware viewer)
- Exit code 3 signals HIGH/CRITICAL findings so CI can gate on supply-chain risk independently of dependency cleanup

## Out of Scope (Not in v1)
- **Auto-removal and code rewriting**: Scarno reports findings; developers make the call — automated changes come later once trust is established
- **IDE plugin**: CLI covers the core workflow; an IDE integration can follow once the analysis engine is proven
- **CVE enrichment**: flagging vulnerable dependencies is a natural extension, but the focus for v1 is accurate usage detection first
- **Typosquat / name-similarity database**: REQ-3c flags suspicious install patterns but does not compare package names against PyPI or OSV (Phase 4)
- **Inter-procedural taint analysis**: REQ-3c's taint pass is intra-procedural by design — it will miss payloads that flow through helper functions and class fields, biased towards no-false-positives
- **`pipx`, `uv tool install`, system package manager installs**: user-global installs are outside the project boundary and not treated as project dependencies
- **SBOM export formats** (CycloneDX, SPDX): not in v1 — Markdown and SARIF are delivered; SBOM joins Phase 4
- **Groovy DSL Gradle beyond the Kotlin-DSL v1 scope**: covered in Phase 4

Phase 4 items now explicitly **in scope** (see `requirements/REQ-6b.md` and `requirements/REQ-8.md`) — **all now complete**:

- **Robust Java / Kotlin AST parsing via tree-sitter** (REQ-6b) — replaces the regex-based scanner in REQ-6 so annotations / imports / reflection literals are matched only against genuine source constructs, never text inside comments, Javadoc, or string literals. This is a known fragility of the Phase 2 implementation; see the warning in `src/scarno/analysers/java/source_analyser.py`.
- **GitHub Action packaging** (REQ-8) — ship `scarno/scarno-action@v1` as a composite action with SARIF auto-upload, sticky PR comments, workflow annotations, and job-summary rendering.

Phase 2.5 / Phase 5 / Phase 6 / Phase 7 — **all complete** (see `requirements/REQ-9` through `requirements/REQ-16`):

- **Polyglot foundations** (REQ-9, Phase 2.5) — `Dependency.ecosystem` field, analyser registry, multi-language orchestrator, per-ecosystem grouping in all four reporters, `--language` CLI filter. Lands before Phase 3 so Gradle is born polyglot-aware.
- **JavaScript / TypeScript / CSS / Node.js** (REQ-10 + REQ-11 + REQ-12, Phase 5) — npm / yarn / pnpm / bun / Deno manifest + lock parsing (incl. npm workspaces, yarn PnP, `bin` / `engines` fields); tree-sitter-based ESM + CJS + TS reference scanning with Node core-module exclusion; CSS `@import` / `url()` extraction; Finding rules for `postinstall` hooks, `.npmrc` registry overrides, `new Function(taint)`, `child_process.exec(taint)`, remote CSS `@import`. **Server-side Node.js is explicitly in scope** — there is no separate Node phase.
- **Go** (REQ-13 + REQ-14, Phase 6) — `go.mod` + `go.sum` + `vendor/modules.txt` with `replace` / `exclude` / `retract` honoured; tree-sitter-go source analyser respecting blank / dot imports, `_test.go` test-scope, `vendor/`, and build tags; Finding rules for `unsafe.Pointer`, `cgo`, `exec.Command(taint)`.
- **C# / F# / VB.NET** (REQ-15 + REQ-16, Phase 7) — MSBuild `*.csproj`/`*.fsproj`/`*.vbproj` XML parser (stdlib XML + DOCTYPE rejection), Central Package Management via `Directory.Packages.props`, legacy `packages.config`, `*.sln` multi-project discovery, `packages.lock.json` version resolution, `nuget.config` registry inspection; tree-sitter-c-sharp source analyser with `using` (regular / static / alias / global), Razor `@using`/`@inject` directives, `Microsoft.AspNetCore.App` + `Microsoft.NETCore.App` shared-framework alias table; Finding rules for `Assembly.Load(taint)`, `Process.Start(taint)`, `[DllImport]`, MSBuild `<Exec>` and `<UsingTask>` elements.

Phase 8 — **in scope** (see `requirements/REQ-17.md`):

- **Test-scope exclusion, symbol tally, direct-use transitives, and Mermaid graph** (REQ-17) — adds:
  - `--exclude-tests` CLI flag that drops test-scoped declared deps and skips test source files across every ecosystem (Maven `<scope>test</scope>`, Gradle `test*Implementation`/`androidTest*`, Python `[project.optional-dependencies]` test/dev groups + `requirements-{test,dev}.txt`, Go `_test.go`-only deps, `*.Tests.csproj`/`<IsTestProject>true</IsTestProject>`, plus `tests/`/`test/`/`__tests__/` source globs).
  - `--test-paths PATTERN` (repeatable, max 64 patterns × 256 bytes) — operator override for non-standard layouts (`it/`, `e2e/`, `src-tests/`); confined to project root, no `..`, no Windows separators.
  - `--exclude-dev` (npm-only, off-by-default) — opt-in `devDependencies` exclusion for projects that want to strip linters/bundlers/formatters from the report.
  - **Symbol-usage tally** — `EntryPoint.usage_count` is populated for every used symbol so reports show `requests.get used 23×` instead of merely `used`. Renders in text, JSON, markdown, and SARIF.
  - **Direct-use transitives** — `Dependency.imported_directly` flags transitive deps that project source imports directly (regardless of which declared dep pulled them in). The reporter sorts these to a dedicated *"promote to first-class"* section so the engineer doesn't lose them when the parent is removed.
  - **ASCII dependency tree** in markdown output (originally Mermaid, replaced because Mermaid became illegible spaghetti at 100+ deps) — vertical Unix-style tree wrapped in a ```diff fenced block. Status colour is carried by the line's diff prefix: ` ` neutral for IN_USE (black), `-` for SAFE (red), `!` for UNCERTAIN/UNDECLARED (orange in viewers that color `!`). Hard limits: 1000 nodes, 200-char labels. Backticks, `<`/`>`, ANSI / control chars, and newlines are all neutralised so an attacker-controlled dep name cannot break the fence (label injection defence; SEC-NEW-32).

Phase 8b — **in scope** (see `requirements/REQ-17b.md`):

- **Per-language entry-point taxonomy** (REQ-17b) — across Java/Kotlin, Python, JavaScript/TypeScript, C#/.NET, and Go, every IN_USE dep now surfaces:
  - **`class`** — concrete imports.
  - **`method`** — `<receiver>.<method>(…)` call sites, with instance-method attribution via per-language variable-type binding (Java `local_variable_declaration` / `field_declaration` / `formal_parameter`; Python `Assign` + `AnnAssign` + function-parameter annotations; JS/TS `lexical_declaration` + TS type annotations + parameter types; C# `local_declaration_statement` + `parameter`; Go `var_spec` + `short_var_declaration` with `New<Type>` heuristic + `parameter_declaration`).
  - **`constructor`** — `new ClassName(…)` (Java, JS, C#), `ClassName(…)` (Python via `kind="class"`), composite literal `pkg.Type{…}` / `&pkg.Type{…}` (Go).
  - **`wildcard`** (Java / Python) — `import x.*;` / `from x import *` rows; member attribution via JAR class lists (Java) or `unqualified_name_refs` cross-reference (Python).
  - **`annotation` / `reflective`** (Java) — synthetic activation entry points when DI annotation or `Class.forName(…)` is the only signal; resolves the `IN_USE — 0/N entry points used` confusion.
  - **`function` / `package` / `namespace` / `export`** — per-symbol attribution where the language exposes them at AST level (JS named imports, Go selectors, C# `using` directives, npm `package.json` `exports`).
- **Multi-wildcard signature disambiguation** (Java) — when two wildcard'd deps' JARs both contain a class with the same simple name, `_invoke_javap_safe` reads each candidate's class file and the dep whose JAR exposes the called method wins exclusively.
- **Maven transitive `dep_graph`** — `MavenPomResolver._build_transitive_graph` walks each direct dep's POM in `~/.m2/repository` and records its `<dependencies>` as graph children. `test`, `provided`, and `system` scopes excluded so the graph reflects the runtime closure that would actually be freed by removing a parent. Bounded to 1000 nodes per call.
- **Maven `${project.version}` resolution fix** — `project.version` / `project.groupId` / `project.artifactId` resolve to the leaf POM (analysis target), not the deepest ancestor. Re-asserted after user-property merge so reserved keys cannot be silently shadowed.
- **Path-traversal hardening** (SEC-NEW-34, SEC-NEW-35) — npm dep names validated against the npm spec before being interpolated into `node_modules/<name>/package.json` paths; C# `.sln` `Project` references confined via `resolve_and_confine` to the project root.

**Open-source consumer guidance**: known limitations are documented prominently in `docs/requirements/REQ-17b.md` under "Aggregate limitations summary".

Phase 8c — **in scope** (see `requirements/REQ-18.md`):

- **TypeScript first-class support** (REQ-18) — closes the four TS-specific gaps left after REQ-17b:
  - **`@types/X` runtime-pair detection** (FR-180) — DefinitelyTyped stubs are paired with their runtime package. `@types/lodash` declared alongside `lodash` shows as IN_USE with `is_type_stub=True` and a reason naming the runtime; orphaned stubs surface a clear "runtime not declared" reason. Scoped pairs (`@types/scope__pkg` ↔ `@scope/pkg`) follow the DefinitelyTyped convention (FR-184).
  - **`import type` distinction** (FR-181) — TypeScript type-only imports surface as `kind="type-only"` entry points, distinct from runtime calls. Per-specifier `import { type A, b }` is split correctly.
  - **`.d.ts` ambient declarations** (FR-182) — `declare module "x"` blocks in project `.d.ts` files mark `x` as type-used so the dep doesn't show falsely SAFE.
  - **TypeScript decorators** (FR-183) — `@Component`, `@Injectable`, `@Get` etc. surface as `kind="decorator"` rows with usage counts.
- **Path-traversal hardening** (SEC-NEW-36) — `_runtime_target_for_types_stub` re-validates the derived runtime name against `_is_valid_npm_name`, defence-in-depth against any future code path that might bypass the upstream npm-name validator.
