# REQ-17b — Per-Language Entry-Point Taxonomy, Maven Transitives, and Property Resolution

This document extends [REQ-17](REQ-17.md) with the work that brought
each ecosystem's entry-point detail up to a uniform standard. REQ-17
introduced `EntryPoint.usage_count`, `Dependency.imported_directly`,
`AnalysisResult.dep_graph`, and the Mermaid hierarchy view; REQ-17b
fills in the *what was actually called* dimension across all five
analysed ecosystems.

## Overview

Per-language entry-point kinds, what now triggers them, and the
*Limitations* a downstream user should be aware of when consuming
Scarno output (or running it in CI).

```
class      — concrete `import com.x.Y;` (Java) / `from x import Y` (Py)
              / `import { Y } from "x"` (JS) / `using x.Y` reference (C#)
method     — <receiver>.<method>(...) call site
constructor — `new ClassName(...)` (Java/JS), `ClassName(...)` (Py),
              `new ClassName(...)` (C#), `pkg.Type{...}` / `&pkg.Type{...}` (Go)
wildcard   — `import x.*;` (Java), `from x import *` (Py),
              `using namespace;` (C#)
namespace  — C# `using` directive
package    — Go imported package path
function   — JS / Go per-symbol selector counts
import     — fallback when no JAR / `node_modules` / language-specific
              package metadata is available — surfaces the literal
              import the project wrote
annotation — Java DI activation entry point (`@Autowired (DI activation)`)
reflective — Java `Class.forName("…")` activation
export     — npm `package.json` `exports` field entry
```

## Per-language behaviour

### Java / Kotlin

- **Concrete imports** → `kind="class"`, one per imported FQCN.
  `usage_count` = 1 per `import` statement + 1 per simple-name
  word-boundary occurrence in source. JAR-derived class entries are
  used when `~/.m2/repository` has the artefact.
- **Wildcard imports** → `kind="wildcard"`. JAR-aware path uses the
  JAR's class list to enumerate which simple names the package owns;
  JAR-less heuristic attributes any unqualified call/ctor receiver
  not already claimed by another dep's concrete import.
- **Method invocations** → `kind="method"`. Captured by walking
  tree-sitter `method_invocation` nodes. Receiver names that resolve
  to a known class (concrete import OR wildcard-owned simple name)
  produce `<Class>.<method>` entries with usage counts. Instance
  receivers (`s` after `Splitter s = …`) are resolved through
  per-file `variable_types` bindings populated by
  `local_variable_declaration`, `field_declaration`, and
  `formal_parameter` walkers.
- **Constructors** → `kind="constructor"`. Tree-sitter
  `object_creation_expression` produces `new <Type>()` entries.
- **DI / reflective activation** → `kind="annotation"` or
  `kind="reflective"`. When a dep is classified IN_USE via
  `@Autowired`-style annotation or `Class.forName("…")` literal but
  no concrete import resolves to it, a synthetic activation entry
  point is prepended so the user sees a meaningful "why" instead of
  `IN_USE — 0 / N entry points used`.
- **Multi-wildcard signature disambiguation** → when two wildcard'd
  deps' JARs both contain a class with the same simple name and the
  source calls `<Simple>.<method>(…)`, `_invoke_javap_safe` is run on
  each candidate's `<package>/<Simple>.class` and the dep whose JAR
  exposes `<method>` wins exclusively.

#### Maven property resolution

- `${project.version}` / `${project.groupId}` /
  `${project.artifactId}` resolve to the **leaf** POM (the analysis
  target), not whichever ancestor `setdefault` happened to see first.
- Parent POM `<properties>` are merged in ancestor-first order so
  child overrides win.
- Reserved `project.*` keys are re-asserted after the user-property
  merge so a user property cannot shadow a Maven-reserved name.

#### Maven transitive `dep_graph`

`MavenPomResolver._build_transitive_graph` walks each direct dep's
POM in `~/.m2/repository` (using the existing tier-1 cache helper)
and records its `<dependencies>` as graph children. `test`,
`provided`, and `system`-scoped transitives are excluded so the graph
reflects the runtime closure that would actually be freed by removing
a parent. Bounded to 1000 nodes per call.

#### Limitations (Java)

- **`var` declarations** (Java 10+): `var sp = Splitter.on(',')` binds
  `sp` to the literal token `var`, not the inferred return type. Use
  explicit types to get instance-method attribution.
- **Generic type parameters** (`<String>`) are stripped at binding
  time. Methods on the type parameter itself (`T.foo()`) are not
  attributed.
- **Re-assignment shadows the prior type**: `Splitter sp = …; sp =
  somethingElse.create();` — only the latest binding is recorded.
- **Chained-call return types** (`Splitter.on(',').split(s)`) — the
  intermediate type is not tracked; only the call sites we observe
  are counted.
- **Disambiguator requires `javap` on PATH.** Without a working JDK
  the wildcard signature disambiguator falls back to over-attribution.
- **Inner-class methods** are surfaced as part of the outer class
  (we treat `Foo$Bar` and `Foo` as a single simple name for
  attribution).
- **Bytecode-only symbols** (synthetic methods, lambda generated
  classes) are reflected only via JAR class entries; they don't get
  per-symbol counts.

### Python

- **Concrete imports** → `kind` per `inspect` (`class` / `function` /
  `method` / `constant` / `unknown`). One entry per public symbol.
- **Wildcard imports** (`from x import *`) → `kind="wildcard"` row.
  Bare-name LOAD references (everything that isn't a known import,
  not a builtin like `True`/`False`/`None`, doesn't start with `_`,
  and isn't `self`/`cls`) are recorded as `unqualified_name_refs`.
  At entry-point time, when a dep was wildcard-imported AND a symbol
  in its `__all__`/`dir()` matches a tracked unqualified ref, that
  symbol is marked `used=True` with the bare-name count.
- **Method invocations** → `kind="method"`. `instance.method()` is
  resolved through `_variable_class` bindings populated by
  `visit_Assign` (`x = ClassName(args)`), `visit_AnnAssign` (`x:
  ClassName = …`), and `visit_FunctionDef` parameter annotations.
  Records `<top>.<class>.<method>` triples and bumps the class
  symbol's own usage count.
- **Constructors** Python doesn't syntactically distinguish
  constructors from regular calls. A class's usage count is bumped
  by both the import site, every reference, and every call (because
  `Foo()` is just a call). The `kind="class"` already conveys that
  the symbol is a class.
- **Decorators** (`@app.route`, `@dataclass`) are tracked through the
  regular attribute walker — no special handling needed.

#### Limitations (Python)

- **Multi-target assignment** (`a, b = SomeClass(), Other()`) is
  deliberately not handled — we'd risk wrong bindings.
- **Walrus expressions** (`if (x := SomeClass()):`) are not bound.
  One-line `visit_NamedExpr` extension would add this if needed.
- **Generic peeling depth = 1**: `list[Foo]` is peeled but
  `list[Optional[Foo]]` is not.
- **`kind="unknown"`** appears for symbols whose `inspect` classifier
  doesn't map to function/class/method/constant — this is a
  pre-existing quirk of the standard library, not new to REQ-17b.
- **Entry-point enumeration requires the package to be installed**
  in Scarno's own Python environment OR for the project's `.venv`
  to populate `top_level.txt` (FR-135). Otherwise we can mark the
  dep IN_USE but cannot list its public surface.
- **Re-binding shadows**: `x = Foo(); x = Other(); x.bar()` attributes
  to `Other`.
- **Module-level `__getattr__` (PEP 562) lazy loading** (FR-271): lazy
  symbols are enumerated when listed in `__all__`, surfaced via a
  module-level `__dir__`, or actually used by the project. The residual
  gap is a dependency's **unused** lazy surface when it relies on
  `__getattr__` with neither `__all__` nor `__dir__` — those names are
  not statically enumerable and emit an `entry_point_enumerator` advisory.

### JavaScript / TypeScript

- **Named, default, and namespace imports** are tracked per local
  binding via `name_to_package` / `name_to_symbol` /
  `namespace_locals`. `import { foo as bar }` correctly attributes
  bare-name `bar()` calls to `foo`.
- **Per-symbol calls** → `kind="function"`. Bumped by bare-name LOAD
  references that resolve through `name_to_symbol`, plus
  `member_expression` access through default-import / namespace-import
  receivers (e.g. `_.debounce()` after `import * as _ from "lodash"`).
- **Constructors** → `kind="constructor"`. `new_expression` walker
  records `new Foo(...)` and `new ns.Foo(...)`.
- **Method invocations** → `kind="method"`. Bound via
  `variable_class` from `const x = new Foo()` and TS `const x: Foo =
  …` and TS function-parameter annotations. Resolves `x.method()`
  back to `Foo.method`.
- **Type-only imports** in TS (`import type { Foo } from "x"`) are
  treated identically — they still count as a use site.

#### Limitations (JavaScript / TypeScript)

- **Object / array destructuring outside an import** (`const { foo }
  = x`) does not bind `foo` to a type.
- **TS inferred return types** (`const x = make()` where `make`
  returns `Promise<Redis>`) — we don't peel promises or other generic
  containers. Direct types only.
- **Arrow-function parameters in plain JS** have no type annotation,
  so no instance binding (same trade-off as Python without
  annotations).
- **CommonJS destructured require** (`const { Foo } = require("y")`)
  is partially tracked — the `require("y")` site counts but the
  destructured `Foo` doesn't get a per-symbol entry. Use ESM
  `import` syntax for full attribution.
- **Decorator-style attribution** (TS `@Component`, NestJS) is
  tracked as a regular member call, not a dedicated `annotation`
  kind (Java is the only ecosystem with that).
- **Re-exports** (`export { Foo } from "x"`) don't propagate to a
  consuming package's report.

### C# / .NET

- **Concrete classes** referenced through `using` directives →
  `kind="namespace"`. Each `using` directive contributes one row.
  Bumped by 1 per `using` site + 1 per word-boundary reference to
  the namespace's last segment.
- **Constructors** → `kind="constructor"`. `object_creation_expression`
  records `new ClassName(...)` and `new ClassName<T>{ ... }`.
- **Static and instance method calls** → `kind="method"`.
  `invocation_expression` containing a `member_access_expression`
  records `<receiver>.<method>` calls. Receivers that look like a
  class (Pascal-Case) are taken as static; lowercase receivers are
  resolved through `variable_class` bindings populated by
  `local_declaration_statement` / `field_declaration` / `parameter`
  walkers handling both explicit (`Foo x = new Foo()`) and `var`
  (`var x = new Foo()`) declarations.

#### Limitations (C# / .NET)

- **No DLL inspection.** Without reading the actual NuGet package's
  DLL (which would require a Roslyn-style metadata reader), we can't
  enumerate the actual type list of a namespace. Method/constructor
  attribution falls back to a "this package's namespaces are in
  scope, attribute" heuristic.
- **Multi-namespace ambiguity**: when two `using` directives both
  bring a namespace into scope and the source uses a class with a
  simple name, we cannot definitively tell which namespace owns it
  without DLL metadata. We accept over-attribution rather than
  silently dropping the call.
- **Generic type peeling**: `Foo<T>` is peeled at binding time. Type
  parameters (`T.method()`) are not attributed.
- **`var`** is followed only when the RHS is a direct
  `object_creation_expression`. Method-call return types are not
  inferred.
- **Property access vs method call** is not distinguished (both go
  through `member_access_expression`).
- **Razor `.cshtml`** scanning uses a regex pre-pass for `@using`
  directives only — no method/constructor walking inside the Razor
  body.
- **Predefined types** (`int`, `string`, `bool`, `void`) are
  explicitly *not* bound to anything; they can never be a class
  binding.

### Go

- **Per-symbol selectors** → `kind="function"`. `selector_expression`
  with receiver matching an imported package's last segment records
  `<pkg>.<member>` counts. Distinguishes `errors.New` from
  `errors.Wrap`.
- **Composite-literal "construction"** → `kind="constructor"`.
  `composite_literal` with a `qualified_type` head produces
  `<pkg>.<Type>{}` entries. Both `pkg.Type{...}` and
  `&pkg.Type{...}` (pointer form) are captured.
- **Instance methods** → `kind="method"`. Bound via `variable_type`
  populated by:
  - `var c *pkg.Type = …` and `var c pkg.Type` (explicit qualified
    type via `pointer_type` / `qualified_type`).
  - `c := pkg.NewType(...)` (Go convention: function name starts
    with `New<Type>` → bind `c` to `pkg.Type`).
  - `func f(c *pkg.Type)` parameter annotations.
- **Blank (`_`) and dot (`.`) imports** continue to be marked
  unconditionally IN_USE per FR-119; the `package` entry-point row
  reflects this.

#### Limitations (Go)

- **`c := pkg.Foo()` with no `New` prefix** is not bound. Go has no
  general-purpose return-type inference in this analyser; the `New`
  convention is the only heuristic we apply.
- **Embedded fields** — when a struct embeds another type and the
  embedded type's method is called via outer receiver, we attribute
  to the outer type's package, not the embedded one.
- **Generic types** (Go 1.18+) — type parameters are not tracked.
- **`make()` / built-in `new()`** don't surface as constructor entries
  (they're for built-in types, not deps).
- **Test-only symbols** are tracked only when `--exclude-tests` is
  off; otherwise `_test.go` files are skipped wholesale.

## CSS / HTML

CSS and HTML scanners surface CDN-loaded scripts and stylesheet links
as `IN_USE` deps with `kind="unknown"` entry points and no per-symbol
attribution. These ecosystems don't have a method/constructor model
that maps to source analysis. **No changes in REQ-17b.**

## Security additions

| ID | Description |
|---|---|
| SEC-NEW-34 | npm dep-name validator (`_NPM_NAME_RE` + `_is_valid_npm_name`) rejects names with `..`, `\`, leading `.`/`_`, or invalid characters before they reach `node_modules/<name>/package.json` resolution. Defense-in-depth complement to `resolve_and_confine`. |
| SEC-NEW-35 | C# `.sln` `Project("...") = "Foo", "<rel>"` paths are resolved through `resolve_and_confine` against the project root. Out-of-tree references emit a sanitised "escapes project root" error and are skipped. |

## Threat model additions

| ID | Threat | Mitigation |
|---|---|---|
| T-21 | Maven transitive walker reads attacker-controlled GAVs from cached POMs | `_validate_gav` strict pre-check + `resolve_and_confine` to `~/.m2/repository` + DOCTYPE pre-rejection in `_parse_pom_file` + 1000-node cap |
| T-22 | `_invoke_javap_safe` reachable from disambiguator path | shell=False, validated argv, 10s timeout, JAVA_HOME-pinned binary (existing controls) |
| T-23 | npm `node_modules/<dep>/package.json` traversal via crafted dep name | `_NPM_NAME_RE` validator at parse time + `resolve_and_confine` defense-in-depth at read |
| T-24 | C# `.sln` reference path traversal | `resolve_and_confine` + sanitised error |

## SRTM additions

| Req ID | Description | Test File |
|---|---|---|
| FR-160 | Java method-invocation entry points | `test_java_reporting_gaps.py` |
| FR-161 | Java constructor entry points | `test_java_reporting_gaps.py` |
| FR-162 | Java instance-method attribution via variable_types | `test_java_reporting_gaps.py` |
| FR-163 | Java multi-wildcard signature disambiguation | `test_java_reporting_gaps.py` |
| FR-164 | Java DI / reflective activation entry points | `test_java_reporting_gaps.py` |
| FR-165 | Maven transitive dep_graph from `~/.m2/repository` | `test_entry_points_and_graph_e2e.py` |
| FR-166 | Maven `${project.version}` resolves to leaf POM | `test_java_reporting_gaps.py` |
| FR-167 | Python wildcard import + unqualified-name attribution | `test_python_reporting_gaps.py` |
| FR-168 | Python instance-method via assignment / annotation binding | `test_python_reporting_gaps.py` |
| FR-169 | JS named/default/namespace per-symbol tracking | `test_javascript_reporting_gaps.py` |
| FR-170 | JS constructor + instance-method attribution | `test_javascript_reporting_gaps.py` |
| FR-171 | C# constructor + method + type-binding | `test_csharp_reporting_gaps.py` |
| FR-172 | Go selector / composite literal / type-binding | `test_go_reporting_gaps.py` |
| FR-271 | Python PEP 562 `__getattr__`: used-lazy-symbol surfacing + unenumerable-surface advisory | `test_source_analyser.py` |
| SEC-NEW-34 | npm dep-name validator | `test_path_traversal_via_dep_inputs.py` |
| SEC-NEW-35 | C# `.sln` confinement | `test_path_traversal_via_dep_inputs.py` |

## Aggregate limitations summary (open-source onboarding)

For users encountering Scarno for the first time, these are the
honest gaps:

1. **Type inference is shallow.** Across every language we bind via
   the most direct annotation/declaration available. Promises,
   generics-with-type-parameters, chained-call return types, and
   custom decorators that change types are not followed.
2. **Last-write-wins for variable bindings.** Re-assigning a
   variable to a different type within the same scope shadows the
   prior type. Common idioms (`x = make_a(); x = make_b();
   x.method()`) attribute to `make_b`'s type.
3. **Heuristic attribution under ambiguity.** When two deps could
   own a class with the same simple name and we have no JAR/DLL
   metadata to disambiguate, we accept over-attribution rather than
   silently dropping the call. Users who want precise attribution
   should run with the relevant package cache populated
   (`~/.m2/repository` for Java, `node_modules` for npm).
4. **No DLL inspection for C#.** All C# attribution is heuristic.
5. **Wildcard imports** are surfaced as a distinct row but
   member-level attribution requires either a JAR/package-metadata
   index (Java/npm) or the heuristic that other deps don't claim the
   simple name (Java).
6. **Test-source code is skipped wholesale** under `--exclude-tests`
   — no per-file fine-grained scoping. Use `--test-paths` to extend
   the test heuristic for non-standard layouts.
7. **CDN-loaded HTML / CSS deps** surface only as IN_USE / SAFE; no
   per-symbol attribution for client-side libraries pulled via
   `<script src=...>`.
8. **Reflective / dynamic invocation** in any language flags the
   call site as `UNCERTAIN` rather than guessing — by design.
