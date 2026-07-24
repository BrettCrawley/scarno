# REQ-18 — TypeScript First-Class Support

## Overview

The JavaScript analyser already parses `*.ts` / `*.tsx` / `*.mts` / `*.cts`
files via `tree-sitter-typescript`. REQ-17b added type-annotation binding for
TypeScript instance-method attribution. This requirement closes the four
remaining TypeScript-specific gaps:

1. **`@types/foo` runtime-pair detection** — DefinitelyTyped packages
   are recognised as type stubs for the runtime package they describe.
   Analogous to Python's `is_type_stub` (REQ-2). Falsely-SAFE
   `@types/lodash` rows go away when `lodash` is in use.
2. **`import type { Foo } from "x"`** — TypeScript type-only imports
   are erased at runtime. They surface as `kind="type-only"` entries
   that count toward classification but are clearly distinguished from
   runtime use.
3. **`.d.ts` ambient declarations** — `declare module "x" { … }` and
   triple-slash references are recognised as a type surface for `x`,
   contributing to type-only attribution without counting as runtime
   use.
4. **TypeScript decorators** — `@Component`, `@Injectable`,
   `@Inject(...)` surface as `kind="decorator"` entries, distinct
   from regular method calls.

## Problem statement

A typical TypeScript project has `package.json` like:

```json
{
  "dependencies": { "lodash": "^4" },
  "devDependencies": { "@types/lodash": "^4", "typescript": "^5" }
}
```

with source like:

```ts
import _ from "lodash";          // runtime
import type { Cancelable } from "lodash";  // type-only
const fn: _.DebouncedFunc<...> = _.debounce(() => {}, 100);
```

Today Scarno:
- Classifies `@types/lodash` as `IN_USE` because TS auto-loads it (not because of any explicit import) — actually, more often as `SAFE` because no source file imports `@types/lodash` directly. **Wrong** either way; the correct semantic is "type stub paired with runtime `lodash`".
- Treats `import type { Cancelable } from "lodash"` identically to a runtime import, hiding runtime-unused deps that are only referenced from type positions.
- Doesn't recognise `.d.ts` `declare module "x"` blocks; an ambient module declaration providing a type surface for an external lib leaves the lib looking unused.
- Surfaces `@Component(...)` as `kind="method"` (the decorator function call) — accurate but uninformative; the user can't tell decorators from regular calls.

## Solution

Four targeted extensions to the existing JavaScript analyser:

### 1. `@types/foo` runtime-pair detection

Mirror Python's REQ-2 type-stub model:

- During npm dep parsing, identify any dep whose name matches
  `^@types/(.+)$` and record its target runtime name.
- After source classification, for each `@types/X` dep:
  - If runtime `X` is also declared: mark the type stub `IN_USE` with
    reason `"type stubs for 'X' which is declared as a dependency"`
    AND set `is_type_stub=True`.
  - Otherwise: keep the existing classification but populate
    `reason="type stub for 'X' but runtime package not declared"`.

Sub-paths matter: `@types/node-fetch` pairs with `node-fetch`. Scoped
runtimes (`@scope/pkg`) ship types as `@types/scope__pkg` per the
DefinitelyTyped convention — handle that mapping too.

### 2. `import type` distinction

Tree-sitter exposes the `type` keyword inside `import_clause`:

```ts
import type { Cancelable } from "lodash";          // whole-import type-only
import { type Cancelable, debounce } from "lodash"; // per-specifier type-only
```

The walker records type-only specifiers in
`_Facts.type_only_specifiers` separately from runtime specifiers.
Per-symbol entry points emit `kind="type-only"` for the type-only
ones and `kind="function"` / `kind="class"` (per existing logic) for
runtime symbols.

A package whose ONLY uses are type-only is classified `IN_USE` (with
`reason` mentioning type-only) and tagged `is_type_stub=False` (it's
not a stub, it's a real runtime package used only at compile time).
The user gets a clear signal that the dep can move from
`dependencies` to `devDependencies`.

### 3. `.d.ts` ambient declaration scanning

Walk every `*.d.ts` file:

- `declare module "x"` adds `x` to a new `_Facts.ambient_modules`
  set. Treated as a type-only declaration of `x`.
- `declare global { … }` and other constructs are ignored for our
  purposes (no dep linkage).
- Triple-slash `/// <reference types="x" />` already populates
  `reference_types`. Extend the matching so referenced types
  contribute to type-only classification too.

### 4. TypeScript decorators

Walk `decorator` AST nodes. The decorator's expression is recorded
as a separate kind:

- `@Component(...)` → `kind="decorator"` with `name="@Component"`.
- `@Injectable()` → same.
- `@Inject("x")` → same.

Decorator counts feed the existing usage_count machinery so the
report shows e.g. `@Component used 4×` for a NestJS project.

## File layout

```
src/scarno/analysers/javascript/
├── dep_file_parser.py      # +_TYPES_PACKAGE_RE, +_runtime_target_for_types_stub
├── source_analyser.py      # +_Facts.type_only_specifiers,
│                           #  +_Facts.ambient_modules,
│                           #  +_Facts.decorator_calls,
│                           #  +visit decorator / ambient_declaration nodes,
│                           #  +import_type distinction in _extract_import_clause

tests/integration/test_typescript_support.py  # E2E
```

## Public interface

```python
# javascript/dep_file_parser.py
_TYPES_PACKAGE_RE = re.compile(r"^@types/(?P<runtime>.+)$")

def _runtime_target_for_types_stub(name: str) -> str | None:
    """``@types/lodash`` → ``lodash``.
    ``@types/scope__pkg`` → ``@scope/pkg`` (DefinitelyTyped convention)."""
```

```python
# javascript/source_analyser.py — additions to _Facts
type_only_specifiers: set[str] = field(default_factory=set)
ambient_modules: set[str] = field(default_factory=set)
decorator_calls: dict[str, int] = field(default_factory=dict)
```

## Use cases

```
UC-18a: @types stub paired with runtime
Actor: TypeScript developer
Goal: See @types/lodash classified IN_USE only because lodash is used at runtime.
Preconditions: package.json declares both lodash and @types/lodash.
Main flow:
  1. Source has `import _ from "lodash"; _.debounce(...)`.
  2. Analyser pairs @types/lodash with lodash.
  3. Classifier marks @types/lodash IN_USE with "type stubs for 'lodash'" reason.
Postconditions: removing lodash would also remove @types/lodash; user can act on
  one row instead of two.

UC-18b: type-only import surfaced distinctly
Actor: TypeScript developer auditing devDependencies vs dependencies.
Goal: Identify packages whose only use is at compile time, eligible to move
  from `dependencies` to `devDependencies`.
Preconditions: source has `import type { … } from "x"` only.
Main flow:
  1. Analyser records type-only specifiers separately.
  2. Report distinguishes type-only entries from runtime calls.
Postconditions: reviewer sees runtime-only vs type-only at a glance.

UC-18c: .d.ts ambient module
Actor: Developer of a project with a custom .d.ts wrapping an external lib.
Goal: Have the wrapped lib classified as in use (type-only) so it doesn't
  show as SAFE.
Main flow:
  1. .d.ts contains `declare module "wrapped-lib" { … }`.
  2. Analyser records `wrapped-lib` in ambient_modules.
  3. Classifier links the declared dep `wrapped-lib` to the ambient module.

UC-18d: NestJS-style decorator surface
Actor: NestJS / Angular developer.
Goal: See @Component / @Injectable usage counts in the report.
Main flow:
  1. Source uses @Component(...) on a class.
  2. Walker records decorator name + count.
  3. Entry point emits with kind="decorator".
```

## Abuse cases

```
SAC-36: Path traversal via @types/.. dep name
Linked threat: T-25
Attacker: External (publishes a malicious @types-prefixed name to npm).
Goal: Reach `node_modules/@types/<traversal>/package.json` outside project root.
Mitigation: existing SEC-NEW-34 (`_is_valid_npm_name`) already validates the
  full name including the `@types/` prefix; the regex requires
  identifier-class characters per segment and rejects `..` substrings.
  The runtime-pair extractor MUST validate the runtime target too: a
  malicious `@types/../../etc` would resolve to a runtime target of
  `../../etc`, which would propagate the traversal if not validated
  on the runtime side.

SAC-37: Adversarial .d.ts CPU exhaustion
Linked threat: T-26
Attacker: External (commits a 10MB .d.ts with deeply nested generic types).
Goal: Stall analysis via tree-sitter parse.
Mitigation: existing PERF-006 (per-file tree-sitter parse timeout) +
  MAX_FILE_BYTES; .d.ts files are governed by the same controls.
```

## Security use cases

```
SUC-36: @types runtime-target validation
Mitigates: SAC-36
Control: After `_runtime_target_for_types_stub` extracts the runtime name,
  re-validate it via `_is_valid_npm_name`. If invalid, the pairing is
  silently dropped (the @types entry remains, just unpaired).
Implementation: ``analysers/javascript/dep_file_parser.py``.

SUC-37: .d.ts file-size + parse-timeout reuse
Mitigates: SAC-37
Control: .d.ts files are governed by the same MAX_FILE_BYTES and
  per-file tree-sitter parse timeout as `.ts` files. No new code path —
  documenting the implicit reuse.
```

## Privacy use cases

```
PUC-05: type-only imports remain non-PII
Privacy control: type-only specifiers and ambient module names pass
  through the same `sanitise()` as runtime imports before reaching any
  reporter. No new exposure surface.
PbD principle: Privacy embedded into design.
```

## Performance use cases

```
PERF-008: .d.ts scanning
- 1000-line `.d.ts` file parses < 200 ms (tree-sitter linear in file size).
- Bounded by MAX_FILE_BYTES (10 MB).
- TypeScript stdlib `.d.ts` files in `node_modules/typescript/lib/` are
  skipped via the existing `node_modules` exclusion at source-walk time.

PERF-009: decorator walker overhead
- Decorator walking is a tree-sitter node-type check (`decorator`) plus a
  shallow extraction. Constant per-decorator-site cost; no nested
  iteration. Negligible vs the existing call-expression walker.
```

## Threat model

| ID | Threat | Mitigation |
|---|---|---|
| T-25 | `@types/<traversal>` dep name → runtime-target traversal in pairing | `_is_valid_npm_name` on both stub and runtime-target; pairing dropped if either fails |
| T-26 | Adversarial `.d.ts` parse stall | MAX_FILE_BYTES + tree-sitter per-file timeout (existing controls) |

## SRTM

| Req ID | Description | Test File |
|---|---|---|
| FR-180 | `@types/X` runtime-pair detection | `test_typescript_support.py::test_at_types_runtime_pair` |
| FR-181 | `import type` distinguished from runtime | `test_typescript_support.py::test_import_type_distinct_kind` |
| FR-182 | `.d.ts` `declare module "x"` ambient scan | `test_typescript_support.py::test_dts_ambient_module_declaration` |
| FR-183 | TS decorator entry-point kind | `test_typescript_support.py::test_ts_decorator_kind` |
| FR-184 | Scoped `@types/scope__pkg` → `@scope/pkg` mapping | `test_typescript_support.py::test_scoped_at_types_pair` |
| SEC-NEW-36 | `@types` runtime-target re-validation | `test_typescript_support.py::test_at_types_traversal_rejected` |

## Acceptance criteria

- [ ] Given `package.json` declaring both `lodash` and `@types/lodash` and
  source `import _ from "lodash"`, when analysis completes,
  `@types/lodash` has `status=IN_USE` with reason mentioning type stubs
  for lodash.
- [ ] Given `package.json` declaring `@types/lodash` but NOT `lodash`,
  when analysis completes, `@types/lodash` reason mentions
  "runtime package not declared".
- [ ] Given `package.json` declaring `@types/node-fetch` and `node-fetch`,
  when analysis completes, the pair is recognised.
- [ ] Given `@types/scope__pkg` and `@scope/pkg`, when analysis completes,
  the scoped pair is recognised.
- [ ] Given source `import type { Foo } from "lodash"` (and no runtime
  import), when analysis completes, lodash has at least one entry point
  with `kind="type-only"`.
- [ ] Given a `.d.ts` containing `declare module "wrapped-lib" { … }` and
  a declared dep `wrapped-lib`, when analysis completes, `wrapped-lib`
  has at least one type-only attribution.
- [ ] Given source `@Component({ … }) class App {}`, when analysis
  completes, the dep owning `Component` has at least one entry point
  with `kind="decorator"`.
- [ ] Given an attacker name `@types/../../etc`, when the dep parser
  runs, the name is rejected by `_is_valid_npm_name` (SEC-NEW-34); no
  pairing attempt against the (potentially traversal-shaped) runtime
  target occurs.

## Limitations

- **No type-flow analysis.** A symbol used as a type via aliasing
  (`type X = SomeImport["foo"]`) may not be recognised. Direct
  `import type` and explicit annotations are tracked.
- **`declare global` blocks** are ignored — they don't link to a
  specific dep.
- **TypeScript-specific syntax** (mapped types, conditional types,
  template literal types) is not interpreted; we only walk identifier
  references.
- **`.d.ts` files inside `node_modules`** are skipped per the
  existing `_EXCLUDED_DIR_NAMES` rule. We don't try to scan
  `node_modules/typescript/lib/` etc.
- **TS path mappings beyond the simple alias case** (`tsconfig.json`
  `paths` with multiple targets) are partially handled: any alias
  whose target matches drops the import, but only the leftmost target
  is checked.
