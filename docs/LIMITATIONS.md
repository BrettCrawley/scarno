# Scarno — Known Limitations

Honest list of what Scarno **doesn't** handle, so you can decide
whether the gaps matter for your project before relying on the output
in production.

For the full design rationale, see
[`docs/requirements/REQ-17b.md`](requirements/REQ-17b.md).

---

## Cross-cutting

- **Type inference is shallow.** Across every language we resolve
  `instance.method()` calls by reading the most direct annotation or
  declaration available — `Foo x = …`, `x: Foo`, `(x: Foo) => …`,
  `var x = new Foo()`, `c := pkg.NewType(...)`. We do **not** follow:
  - Promise / async return types (`const x = await fetch()`).
  - Chained-call return types (`builder.build().method()`).
  - Generic type parameters (`<T>` is stripped at binding time).
  - Custom decorators that change a value's type.

- **Last-write-wins for variable bindings.** Re-assigning a variable
  to a different type within the same scope shadows the prior type.
  `x = make_a(); x = make_b(); x.method()` attributes to `make_b`'s
  type, not `make_a`'s.

- **Heuristic attribution under ambiguity.** When multiple deps could
  own a class with the same simple name and Scarno has no
  package-cache metadata to disambiguate, we accept over-attribution
  rather than silently dropping the call. Populating the relevant
  package cache (`~/.m2/repository` for Java, `node_modules` for
  npm) gives the analyser more information to work with.

- **Reflective / dynamic invocation** in any language flags as
  `UNCERTAIN` rather than guessing — by design.

- **CDN-loaded HTML / CSS deps** surface only as `IN_USE` / `SAFE`
  with no per-symbol attribution. Client-side libraries pulled via
  `<script src="…">` don't have a method-call model to analyse.

- **Test-source code is skipped wholesale** under `--exclude-tests`
  — no per-file fine-grained scoping. Use `--test-paths` to extend
  the heuristic for non-standard layouts.

---

## Java / Kotlin

- **`var` declarations** (Java 10+) bind the variable to the literal
  token `var` rather than the inferred return type. Use explicit
  types for instance-method attribution.
- **Generic type parameters** (`<String>`) are stripped. Methods on
  the parameter itself (`T.foo()`) are not attributed.
- **Chained-call return types** (`Splitter.on(',').split(s)`) — the
  intermediate type is not tracked; we only count the call sites we
  observe directly.
- **Wildcard signature disambiguation requires `javap`** on PATH.
  Without a working JDK, two wildcard'd deps that both contain a
  class with the same simple name fall back to over-attribution.
- **Inner-class methods** are surfaced as part of the outer class
  (`Foo$Bar` and `Foo` are treated as one simple name).
- **Bytecode-only synthetic methods** (lambda generated classes,
  compiler-emitted bridges) appear in JAR class entries but don't get
  per-symbol counts.
- **Maven transitive `dep_graph`** is best-effort: requires
  `~/.m2/repository` to be populated, and excludes `test`,
  `provided`, and `system`-scoped transitives by design (so the
  graph reflects the runtime closure).

## Python

- **Multi-target assignment** (`a, b = SomeClass(), Other()`) is
  deliberately not bound to a type — risk of wrong attribution.
- **Walrus expressions** (`if (x := SomeClass()):`) don't bind.
- **Generic peeling depth = 1**: `list[Foo]` works; nested
  `list[Optional[Foo]]` does not.
- **Entry-point enumeration requires the package to be installed**
  in Scarno's Python environment OR for the project's `.venv`
  to expose `top_level.txt` in dist-info metadata. Otherwise the
  dep is classified IN_USE but its public surface can't be listed.
- **`kind="unknown"`** appears for symbols whose `inspect`
  classifier doesn't map cleanly to function/class/method/constant
  (e.g. some `pytest` callables). Pre-existing behaviour, not
  introduced by REQ-17. A symbol the project demonstrably *used* but
  whose access raised during enumeration is also surfaced as
  `kind="unknown"` (still `used=True`) rather than being dropped (FR-271).
- **Module-level `__getattr__` (PEP 562) lazy loading** (FR-271): symbols a
  dependency exposes lazily are handled as follows — names listed in
  `__all__`, surfaced via a module-level `__dir__`, **or** actually
  imported/used by the project are enumerated correctly. The residual gap
  is a dependency's **unused** lazy surface when it relies on `__getattr__`
  with *neither* `__all__` nor `__dir__`: those names are not statically
  enumerable, so the unused public surface may be under-reported. Such
  dependencies emit an `entry_point_enumerator` diagnostic noting the
  possible under-enumeration.

## JavaScript / TypeScript

- **Object / array destructuring outside an import** (`const { foo }
  = x`) does not bind `foo` to a type.
- **CommonJS destructured require** (`const { Foo } = require("y")`)
  is partially tracked — the `require("y")` site counts but the
  destructured `Foo` doesn't get a per-symbol entry. Use ESM
  `import` syntax for full attribution.
- **TS inferred return types** (`const x = make()` where `make`
  returns `Promise<Redis>`) are not peeled. Direct types only.
- **Arrow-function parameters in plain JS** (without TS type
  annotations) have no instance binding.
- **Re-exports** (`export { Foo } from "x"`) don't propagate to a
  consuming package's report.

### TypeScript-specific (REQ-18)

- **`@types/X` runtime-pair detection** is regex-based on the
  `@types/...` prefix and DefinitelyTyped's `__` scope-separator
  convention. Custom type-stub packaging conventions outside
  DefinitelyTyped are not recognised.
- **`import type` distinction**: per-specifier `type` keywords inside
  `import { type A, b }` are recognised; whole-import `import type
  { … }` is recognised; `export type` is not separately tracked
  (re-export semantics out of scope, see general "Re-exports" above).
- **`.d.ts` ambient declarations**: `declare module "x"` blocks
  surface `x` as ambient-used. `declare global` blocks are ignored
  (they don't link to a specific dep). `.d.ts` files inside
  `node_modules/typescript/lib/` are skipped via the existing
  `node_modules` exclusion.
- **TypeScript decorators**: emit as `kind="decorator"` when the
  decorator name resolves to an imported binding. Decorators that
  reference non-imported helpers (`@local.helper`) are not surfaced.
- **TS-specific syntax** (mapped types, conditional types, template
  literal types) is not interpreted; we only walk identifier
  references.
- **TS path mappings beyond simple alias** (`tsconfig.json` `paths`
  with multiple targets) are partially handled: any alias whose
  target matches drops the import, but only the leftmost target is
  checked.

## C# / .NET

- **No DLL inspection.** Without a Roslyn-style metadata reader, we
  can't enumerate the actual type list of a NuGet package's
  namespace. Method/constructor attribution is heuristic: when this
  package's namespaces are in scope (via `using` directives), we
  attribute matching calls.
- **Multi-namespace ambiguity**: when two `using` directives bring
  namespaces into scope and source uses a class with a simple name
  found in both, we cannot definitively tell which package owns it.
  Over-attribution is preferred.
- **Generic type peeling**: `Foo<T>` is peeled at binding time;
  type parameters (`T.method()`) aren't attributed.
- **`var`** is followed only when the RHS is a direct
  `object_creation_expression`. Method-call return types aren't
  inferred.
- **Property access vs method call** is not distinguished — both
  flow through `member_access_expression` and surface as
  `kind="method"`.
- **Razor `.cshtml`** scanning uses a regex pre-pass for `@using`
  directives only — no method/constructor walking inside the Razor
  body.

## Go

- **`c := pkg.Foo()` with no `New` prefix** is not bound. Only the
  Go `New<Type>` factory convention is heuristically followed.
- **Embedded fields** — when a struct embeds another type and the
  embedded type's method is called via the outer receiver, we
  attribute to the outer type's package, not the embedded one.
- **Generic types** (Go 1.18+) — type parameters are not tracked.
- **`make()` / built-in `new()`** don't surface as constructor
  entries (they're for built-in types, not deps).
- **Test-only symbols** are tracked only when `--exclude-tests` is
  off; otherwise `_test.go` files are skipped wholesale.

## CDN / HTML / CSS

- **CSS `@import` URLs** are surfaced as `IN_USE` deps but with no
  per-rule attribution.
- **HTML `<script src=…>`** and `<link rel="stylesheet">` references
  are recognised as deps but don't have a method-call analysis
  model.
- **Inline `<script>` blocks** are not parsed for their JS contents.

## Detection scope

- **CVE / vulnerability enrichment** is out of scope (Phase 4).
- **Typosquat / package-similarity database** comparisons are not
  performed; REQ-3c flags suspicious install patterns by AST shape.
- **Inter-procedural taint analysis** is intra-procedural only.
- **`pipx`, `uv tool install`, system package manager installs** are
  outside the project boundary — Scarno only analyses what's
  declared in your project's manifest files.

## CLI / output

- **Exit code 3** signals HIGH/CRITICAL findings. Use
  `--fail-on-severity` to lower the bar.
- **ASCII dependency tree** in markdown output is capped at 500
  nodes; larger projects render with a `… tree truncated` notice.
  Branch glyphs are unicode (`├──`, `│`, `└──`) — your viewer must
  render them with a monospace font or the alignment will look
  ragged.
- **Diff-block colouring** for the dependency tree depends on the
  markdown viewer honouring fenced ` ```diff ` syntax. GitHub, GitLab,
  and most IDE viewers do; some plain-markdown renderers won't
  colour the lines but the textual `-`/`!` markers remain readable
  regardless.
- **Markdown reporter** escapes adversarial dep names: backticks,
  `<`/`>`, ANSI / control bytes, and newlines are all neutralised so
  no dep name can close the fence or inject HTML.

## REQ-24 Remote Index Fetch — operator awareness (PRV-007)

When you pass `--allow-remote-fetch` (with `--deep-inspection`),
Scarno reaches out to the configured package indexes for any
artefact missing from your local cache — both POMs (during the
transitive walk) and JARs (during the cross-version ABI diff).
Be aware of these properties before enabling it on confidential
codebases or in CI:

- **Project fingerprinting at the index host (PT-005).** The set of
  coordinates Scarno fetches against the configured indexes is
  a project-distinguishing fingerprint. Even a fully-trusted index
  host (or a passive observer at it) can build a profile of the
  project over repeated runs.

  > **Option 2 amendment (current behaviour).** REQ-24 v1 originally
  > minimised disclosure to the multi-version-conflict subset only
  > (FR-262 / PRV-005). That gate was removed in the Option 2 update
  > so the operator's "I gave you an index, use it for misses"
  > mental model is honoured. The current behaviour fetches **any**
  > artefact missing from `~/.m2` against the configured indexes —
  > POMs during the transitive walk AND JARs during the ABI diff.
  > Cache-first ordering means artefacts already in `~/.m2` never
  > trigger network calls; only true misses go to the index. The
  > pre-fetch disclosure line (`req24-fetch: REMOTE FETCH ENABLED`)
  > and the per-attempt audit lines (`req24-fetch: fetched ...@...`)
  > are the operator's full visibility into what was disclosed and
  > where. Operators of confidential codebases should weigh whether
  > the value of remote-provenance ABI findings outweighs disclosing
  > the project's transitive closure to the index host.

- **Your machine's IP is logged at the index host (PT-007 / PRV-006).**
  Each fetch sends your IP to the host. The pre-fetch disclosure
  line in `result.errors` names the host(s) and explicitly states
  the IP visibility — see the persistent report channel for the
  exact wording.

- **Remote-provenance findings are advisory by default (FR-267).**
  An ABI finding whose comparison depended on a fetched artefact
  carries `provenance="remote"`. By default, those findings are
  visible (with a top-of-report banner) but do NOT escalate exit
  code 3 via `--fail-on-severity`. The reasoning: if the bytes
  Scarno analysed were attacker-controlled (T-40 compromised
  index, T-41 coordinate typosquat in the analysed manifest, or
  the manifest itself is hostile), the resulting verdict is
  attacker-influenceable — gating CI on it by default would let
  the attacker fabricate passes or failures. Pass
  `--fail-on-remote-severity` to opt into strict gating once you
  have understood that trade-off.

- **Coordinate typosquatting in untrusted manifests (T-41) cannot
  be statically caught.** A near-name dep (`com.gooogle.guava:guava`)
  passes syntactic validation; Scarno fetches the typosquatted
  package. The control is visibility (`provenance="remote"` tag +
  banner). When scanning a repo you do not trust, treat
  remote-provenance findings as advisory and verify call sites by
  hand.

- **Manifest-as-probe-oracle against your internal indexes (T-44).**
  A widely-scanned malicious repo can declare arbitrary coordinates
  to learn whether they exist in your configured corporate Nexus
  (200 vs 404 over many operator runs). SEC-NEW-61 limits this to
  one probe per coord per session (no fall-through on 4xx); FR-264
  audits every probe; v2 will surface coordinate-prefix scoping on
  `IndexEndpoint` so internal coords can be pinned to internal
  indexes only. **The Option 2 amendment makes this surface wider**
  (POMs are also queried, and there's no minimisation gate) — review
  the per-attempt audit lines carefully when scanning untrusted
  repositories.

- **Cross-index integrity (`--integrity-cross-check`) catches a
  divergent index, not a conspiratorial one.** When you pass
  `--integrity-cross-check`, Scarno fetches each artefact from
  the top-2 priority indexes for an ecosystem, retries once on
  mismatch, and emits `TS-INTEGRITY-MISMATCH` (HIGH) on persistent
  disagreement. An attacker who controls **both** configured indexes
  defeats this — choose a primary you trust independently of the
  secondary.

- **Repo-local config files cannot influence indexes (ARCH-SEC-005).**
  By design, `pyproject.toml` / `.scarno.toml` inside the
  scanned repo are ignored as a source of `[indexes]` — only
  CLI flags, env vars, and `~/.config/scarno/config.toml`
  (or `$XDG_CONFIG_HOME/scarno/config.toml`, when not pointing
  inside the analysed tree) contribute. A malicious repo cannot
  inject a fetch target.
