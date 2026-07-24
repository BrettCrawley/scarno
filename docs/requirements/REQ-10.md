# JavaScript / TypeScript / Node.js Package Manifest & Lock File Parsers

## Overview
Parse declared JS / TS / **Node.js** dependencies from all major npm-compatible manifest and lock-file formats into a unified `list[Dependency]` with `ecosystem="npm"`. Covers npm, yarn (v1 and Berry), pnpm, bun, and Deno — and explicitly covers **server-side Node.js** projects, not just browser-side frontend bundles. Every dep carries `status=UNCERTAIN` as a placeholder for REQ-11 source analysis.

**Explicit Node.js coverage.** The npm ecosystem is Node's package manager. Every `package.json` — whether it's a React app, a Next.js full-stack project, an Express backend, a NestJS monorepo, a CLI tool, or a vanilla Node.js script — is parsed the same way. REQ-10 and REQ-11 together form Scarno's Node.js analyser; there is no separate "Node.js" REQ because the dep model is identical to browser-side JS.

## Problem Statement
The JS ecosystem has more dep-file formats than Python, with subtle differences in semantics:

| Format | Used by |
|---|---|
| `package.json` | all package managers |
| `package-lock.json` | npm |
| `yarn.lock` (v1 / v2+ Berry) | yarn |
| `pnpm-lock.yaml` | pnpm |
| `bun.lockb` (binary) | bun |
| `deno.json` / `deno.jsonc` / `deno.lock` | Deno |
| `npm-shrinkwrap.json` | npm legacy |

Misinterpreting any of these produces false-positive SAFE classifications that break CI builds. For example, yarn Berry uses a completely different lockfile format from yarn v1.

## Solution
Implement `parse_all_npm_dependency_files(project_path) -> (list[Dependency], list[str])` in `src/scarno/analysers/javascript/dep_file_parser.py`. Each per-format parser is small and isolated; the coordinator handles precedence and deduplication.

## Scope

### Formats supported

1. **`package.json`** (JSON) — `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundleDependencies`. Also extract `overrides` / `resolutions` as provenance but not as deps.
2. **`package-lock.json`** (JSON, npm v7+ lockfile v2/v3) — `packages` top-level key; resolve direct deps only (`"": {...}` root + any key starting with `node_modules/` at depth 1).
3. **`yarn.lock`** — yarn v1: custom indented text format (use a bespoke parser — **not** regex; state-machine style). yarn Berry v2+: YAML with header preserved.
4. **`pnpm-lock.yaml`** — YAML, `importers` top-level map; extract direct from `.` importer entry.
5. **`bun.lockb`** — binary format. Phase 5 out of scope to parse binary directly; instead detect and emit a warning referencing `bun.lock` (the text format Bun now also emits).
6. **`bun.lock`** — JSONC introduced by Bun 1.1+; parse with JSONC-tolerant reader.
7. **`deno.json(c)`** — JSONC; `imports` map maps specifier → URL-or-registry-spec. Extract the bare-name deps from `npm:` and `jsr:` specifiers.
8. **`deno.lock`** — JSON, `packages.specifiers` map.
9. **`npm-shrinkwrap.json`** — same format as package-lock.json; parse identically.

### Node.js-specific fields (REQ-10 additions)

| Field | Handling |
|---|---|
| `workspaces` (array of glob patterns) | Each matched directory is parsed as its own `package.json` and its deps merged into the top-level analysis with `source="<pkg>:workspaces.<path>"`. Cycles between workspaces detected by resolved path. |
| `bin` (string or object mapping exec-name → file) | Stored in metadata; not treated as a dep, but surfaced in the reporter as "exposes CLI tool <name>". Useful for users deciding whether a dep is a library or a tool. |
| `engines` (`node`, `npm`, `yarn`, `pnpm`) | Stored as metadata; a Finding `TS-SI-014` (MEDIUM) fires if the declared Node version is End-Of-Life per a bundled lookup table. |
| `exports` (conditional exports map) | Used by REQ-11 for entry-point enumeration. |
| `type` (`"module"` / `"commonjs"`) | Routed to REQ-11 to choose the right grammar variant when scanning `.js` files. |
| `private: true` | Stored as metadata; the top-level workspace root is typically private and doesn't need to publish — informational only. |
| `peerDependenciesMeta[*].optional` | Dep emitted with `optional=True` field (new `Dependency` flag). Optional peer deps aren't flagged SAFE when missing. |

### Yarn PnP (Plug'n'Play)

Yarn Berry's alternative to `node_modules/`. When `.pnp.cjs` / `.pnp.loader.mjs` is present:
- REQ-11's entry-point enumeration uses the PnP API instead of walking `node_modules/<pkg>/exports`.
- Parser treats the PnP manifest as authoritative for "installed versions" when the lockfile is absent.

### Dep name canonicalisation

npm names are case-sensitive but lowercase-by-convention. Scoped deps use `@scope/name`. Do **not** normalise case. Key form: `<name>` for unscoped, `@<scope>/<name>` for scoped.

### Version handling

- `package.json` ranges (`^1.2.3`, `~1.2`, `1.x`, `>=1.0 <2.0`) → store raw; don't resolve.
- Lockfile versions are resolved (`1.2.3`) → store as-is.
- Precedence when both exist: lockfile wins (same rule as Python).

### Precedence order (highest → lowest)

1. `bun.lock` (JSONC)
2. `pnpm-lock.yaml`
3. `yarn.lock` (v2+ first, fallback v1)
4. `package-lock.json` / `npm-shrinkwrap.json`
5. `deno.lock`
6. `package.json`
7. `deno.json(c)`

### Security

| Concern | Mitigation |
|---|---|
| Malicious `postinstall` script in `package.json` | Surfaced as REQ-3c-style `Finding` (new rule `TS-SI-007` — see REQ-11) |
| `.npmrc` pointing to a rogue registry | `Finding` rule `TS-SI-008` |
| YAML bombs in `pnpm-lock.yaml` / yarn Berry | `yaml.safe_load` + anchor cap (reuse REQ-2b defenses) |
| JSON bomb in `package-lock.json` (very deep) | Stream-parse; cap depth at 1000 |
| Binary `bun.lockb` — attempting to parse could deref arbitrary memory if naive | Explicitly refuse; only accept the text `bun.lock` form |

### `Dependency` emission

Every dep emitted by this parser:
- `ecosystem = "npm"`
- `status = UNCERTAIN`
- `reason = "declared — source analysis pending"`
- `source = "<file>:<section>"` (e.g., `"package.json:dependencies"`)

## Acceptance Criteria
- [] Given a Node.js project (`package.json` with `"type": "module"`, Express in `dependencies`), When parsed, Then Express is emitted with `ecosystem="npm"` and `source="package.json:dependencies"` — the parser treats browser-JS and Node.js identically
- [] Given a `package.json` with `workspaces: ["packages/*"]`, When parsed, Then each workspace's `package.json` is discovered and its deps merged with distinct `source` labels
- [] Given a `package.json` with `engines: { node: "14" }`, When parsed and 14 is EOL, Then Finding `TS-SI-014` (MEDIUM) is emitted
- [] Given a `package.json` with `bin: { "my-cli": "./bin/cli.js" }`, When parsed, Then the metadata records this as an exposed CLI (not a dep)
- [] Given yarn Berry PnP (`.pnp.cjs` present, no `node_modules/`), When parsed, Then analysis proceeds without requiring a node_modules tree
- [] Given `package.json` with `dependencies` + `devDependencies`, When parsed, Then both are returned with correct `source` provenance
- [] Given a scoped dep `@types/node` in `package.json`, When parsed, Then the name is preserved with the `@` prefix and the slash
- [] Given both `package.json` and `package-lock.json` with differing versions, When parsed, Then the lockfile version wins and a conflict warning appears in `errors`
- [] Given a `yarn.lock` v1 file, When parsed, Then direct deps resolve to exact versions
- [] Given a yarn Berry `yarn.lock` with its YAML header, When parsed, Then direct deps resolve correctly
- [] Given a `pnpm-lock.yaml` with multiple importers, When parsed, Then only the root importer's deps are emitted (sub-importers come with monorepo support in a follow-up)
- [] Given a `deno.json` with `imports: { "foo": "npm:lodash@^4" }`, When parsed, Then `lodash` is emitted with `ecosystem="npm"`
- [] Given a `bun.lockb` without a `bun.lock` companion, When parsed, Then a warning is emitted recommending `bun.lock` be committed
- [] Given an adversarial `pnpm-lock.yaml` YAML bomb, When parsed, Then parsing terminates within 5 seconds
- [] Given a `package.json` with `postinstall` script, When parsed, Then a `Finding` with `rule_id="TS-SI-007"` is emitted (delegated to REQ-11 but observed via this parser's output)

## SRTM

| ID | Description |
|---|---|
| FR-103 | `package.json` parsed (deps + devDeps + peerDeps + optionalDeps) |
| FR-104 | npm lock files parsed (`package-lock.json`, `npm-shrinkwrap.json`, yarn v1 + Berry, `pnpm-lock.yaml`, `bun.lock`) |
| FR-105 | Deno manifest + lock parsed (`deno.json(c)`, `deno.lock`) |
| FR-106 | Binary `bun.lockb` rejected with a clear warning — no native-binary parse |
| SF-016 | `postinstall` script in `package.json` emits Finding `TS-SI-007` |
| SF-017 | Non-default registry in `.npmrc` emits Finding `TS-SI-008` |
