# JavaScript / TypeScript / Node.js Source Analyser

## Overview
Scan `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts`, `.cts` files via **tree-sitter** AST traversal (same technology choice as REQ-6b for JVM — consistent, non-regex, comment- and string-safe). Update each `npm` dep's status to `IN_USE`, `UNCERTAIN`, or `SAFE`. Enumerate entry points for `IN_USE` deps from the installed `node_modules` tree (or the yarn PnP manifest when `.pnp.cjs` is present).

**Explicit Node.js coverage.** Applies equally to browser-side JS, server-side Node.js, hybrid full-stack projects (Next.js, Nuxt, Remix), monorepos (Nx, Turborepo, Lerna), and Node-only projects (Express / Fastify / NestJS backends, CLI tools, Electron apps). The analyser recognises Node-specific idioms — `require()`, `process.env`, `Buffer`, `__dirname` — without flagging them as undeclared.

## Problem Statement
JS / TS sources use more import mechanisms than Python or Java combined:

- ESM static: `import x from 'foo'` / `import { x } from 'foo'`
- ESM dynamic: `await import('foo')`
- CJS: `require('foo')` / `require.resolve('foo')`
- TS triple-slash: `/// <reference types="node" />` / `/// <reference path="..." />`
- TS `import type { ... } from 'foo'`
- `tsconfig.json` `paths` / `baseUrl` remapping
- Bundler-specific: Webpack `require.context`, Vite `import.meta.glob`

Regex won't cut it. Tree-sitter is.

## Solution
`analyse_source_files(project_path, dependencies) -> (list[Dependency], list[str], list[Finding])` in `src/scarno/analysers/javascript/source_analyser.py`. Uses `tree-sitter-javascript` + `tree-sitter-typescript` grammars.

## Scope

### Import discovery

AST node types to walk:

| Node type | Example | Extracted |
|---|---|---|
| `import_statement` | `import x from 'foo'` | `'foo'` |
| `import_clause` > `namespace_import` | `import * as x from 'foo'` | `'foo'` |
| `call_expression` with callee `require` | `require('foo')` | `'foo'` |
| `call_expression` with callee `require.resolve` | `require.resolve('foo')` | `'foo'` |
| `await_expression` wrapping `call_expression` of `import` | `await import('foo')` | `'foo'` |
| TS `ts_reference_directive` | `/// <reference types="node" />` | `'node'` |

Dynamic imports with non-literal arguments → `UNCERTAIN`.

### Path vs package discrimination

An import can be a relative path (`./foo`), absolute (`/foo` — rare), URL (`https://...` — Deno), a **Node.js core module** (`fs`, `path`, `http`, …), or a package name (`foo`, `@scope/foo`, `foo/nested/path`).

- Starts with `./` or `../` or `/` → local file, skip
- `protocol://...` → skip (Deno URL imports get their own handling)
- Node.js core module (see table below) → skip (like Python's stdlib exclusion)
- `node:fs`, `node:path`, etc. (explicit node-prefix form, Node 16+) → skip
- Otherwise → package import; extract the leading `@scope/name` or `name` before the first `/`

### Node.js core modules (excluded from phantom detection)

Bundled set, same role as Python's `sys.stdlib_module_names`:

```
assert, async_hooks, buffer, child_process, cluster, console, constants,
crypto, dgram, diagnostics_channel, dns, domain, events, fs, http, http2,
https, inspector, module, net, os, path, perf_hooks, process, punycode,
querystring, readline, repl, stream, string_decoder, sys, test, timers,
tls, trace_events, tty, url, util, v8, vm, wasi, worker_threads, zlib
```

Plus the `node:`-prefixed form of each (`node:fs`, `node:path`, …).

`import fs from 'fs'` in a Node project → **not** flagged as undeclared. Only real npm packages trigger UNDECLARED.

### TSConfig path resolution

Parse `tsconfig.json` (JSONC) `compilerOptions.paths` and treat mapped specifiers as local-file imports (skip). This mirrors how the TS compiler resolves them.

### Alias table

Most JS deps match by exact package name. No alias table needed for Phase 5 — unlike Java's `com.google.guava → com.google.common` mismatch, JS package-name-equals-import-name is near-universal. A few exceptions (monorepo package re-exports) handled case-by-case as findings rather than matches.

### Security findings (extends REQ-3c)

New rule catalogue entries (`src/scarno/findings/rules.py`):

| Rule ID | Kind | Severity |
|---|---|---|
| `TS-SI-007` | `PACKAGE_POSTINSTALL_HOOK` | HIGH |
| `TS-SI-008` | `NPM_RC_CUSTOM_REGISTRY` | MEDIUM |
| `TS-SI-009` | `EXEC_OF_CHILD_PROCESS_SHELL` | CRITICAL — `child_process.exec(untrustedString)` |
| `TS-SI-010` | `FUNCTION_CONSTRUCTOR_WITH_TAINT` | CRITICAL — `new Function(userInput)` |
| `TS-SI-011` | `NETWORK_FETCH_INTO_EVAL` | CRITICAL — `eval(await fetch(...).then(r => r.text()))` |

### Entry-point enumeration

When a dep is IN_USE and `node_modules/<name>/package.json` is readable:
- Parse `exports` / `main` / `module` / `types` fields
- Each key in `exports` is a public entry point
- Cross-reference against actual imports (same `used` flag pattern as REQ-3)

### ESM-only vs CJS-only detection

Read `package.json` `type` field:
- `"type": "module"` → ESM-first; treat `.js` as ESM
- absent / `"commonjs"` → CJS-first; treat `.js` as CJS

This affects which grammar variant to use (tree-sitter-javascript handles both but some heuristics differ).

### Safety

- Tree-sitter parse confined by 10-sec timeout + `MAX_FILE_BYTES` (same as REQ-6b).
- `tsconfig.json` JSONC parsed with strict depth cap.
- `.mts` / `.cts` / `.mjs` / `.cjs` treated identically to `.ts` / `.js` for grammar selection.

## SRTM

| ID | Description |
|---|---|
| FR-107 | ESM + CJS imports extracted via tree-sitter AST |
| FR-108 | TS triple-slash references extracted |
| FR-109 | `tsconfig.json` paths resolve to local files (not flagged as deps) |
| FR-110 | Entry points enumerated from `node_modules/<pkg>/exports` |
| SF-018 | Rule engine extended with TS-SI-007..011 |

## Acceptance Criteria
- [] Given `import x from 'lodash'`, When analysed, Then `lodash` → IN_USE
- [] Given a Node.js project with `import fs from 'fs'`, When analysed, Then `fs` is NOT emitted as UNDECLARED (core module)
- [] Given `import fs from 'node:fs/promises'`, When analysed, Then `node:fs/promises` is NOT emitted as UNDECLARED
- [] Given `require('http')`, When analysed, Then no phantom detection fires (core module)
- [] Given `require('express')` and `express` is declared, When analysed, Then `express` → IN_USE
- [] Given `await import(userSuppliedString)`, When analysed, Then the dynamic-import finding `TS-CE-004` fires
- [] Given a relative import `import x from './foo'`, When analysed, Then no npm dep is matched (local file)
- [] Given `tsconfig.json` with `paths: { "@/*": ["./src/*"] }`, When analysed, Then `import x from '@/utils'` does not fire a phantom-import detection
- [] Given `require('child_process').exec(req.body)`, When analysed, Then `TS-SI-009` fires at CRITICAL
- [] Given an `import` inside a multi-line template literal, When analysed, Then no false positive fires (tree-sitter handles it)
- [] Given `// import x from 'secret'`, When analysed, Then no import is registered (comment excluded by AST walk)
- [] Given a yarn-PnP project (no `node_modules/`), When analysed, Then entry-point enumeration reads from the PnP manifest
