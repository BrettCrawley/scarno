# Go Module Manifest Parser

## Overview
Parse Go's `go.mod` and `go.sum` into a unified `list[Dependency]` with `ecosystem="go"`. Honours `require`, `replace`, `exclude`, and `retract` directives.

## Problem Statement
Go modules have a custom text format (not JSON / TOML / XML). Tooling that assumes JSON breaks immediately. `replace` directives are particularly subtle: a dep declared in `require` can be redirected to a local path or a fork — removing the `require` without removing the `replace` leaves dead state.

## Solution
`parse_go_module_files(project_path) -> (list[Dependency], list[str])` in `src/scarno/analysers/golang/mod_parser.py`.

## Scope

### `go.mod`

Full grammar per [the official spec](https://go.dev/ref/mod#go-mod-file):

| Directive | Example | Handling |
|---|---|---|
| `module <path>` | `module github.com/foo/bar` | Project's own import path (used by REQ-14 to recognise internal imports) |
| `go <version>` | `go 1.22` | Stored in result metadata (not a dep) |
| `require <path> <version>` | `require github.com/stretchr/testify v1.9.0` | Dep — store name = `github.com/stretchr/testify`, version = `v1.9.0` |
| `require ( … )` block | `require ( foo v1 … bar v2 )` | Same as single form, one dep per line |
| `// indirect` comment | `require github.com/foo/bar v1.0.0 // indirect` | Mark dep as transitive (field `is_transitive: bool`) |
| `exclude <path> <version>` | `exclude github.com/bad v1.0.0` | Recorded as a warning in `errors` |
| `replace <path> => <newpath> <version>` | `replace github.com/foo => ../local-foo` | Update the matching `require` dep's source field to `"go.mod:replace"`. Emit warning if replace target is a local path |
| `retract [<version-or-range>]` | `retract v1.0.0` | No deps; record for metadata |

### `go.sum`

Integrity database; two lines per dep (one for archive, one for `go.mod`). Use only to fill in resolved versions when `go.mod` used a range or `latest` pseudo-version.

### `vendor/modules.txt`

Vendored builds. Parse for module → version mapping when `vendor/` is present. Cross-check against `go.mod`; deps in `vendor/` but not in `go.mod` → warning.

### Dep name canonicalisation

Go module paths are case-sensitive and include the host (`github.com/...`, `golang.org/x/...`). Do **not** lowercase. Key form: the full module path.

### Precedence order

1. `go.sum` (for version resolution only — not a dep list)
2. `vendor/modules.txt` (when present)
3. `go.mod` `require` (authoritative)

### Security

| Concern | Mitigation |
|---|---|
| `replace` directive pointing to remote URL | Warning — possible dep hijack |
| `replace` to local path outside project | Warning — possible path-traversal in a monorepo |
| `go.mod` with unusually deep grouping or millions of lines | Size cap (`MAX_FILE_BYTES`) |
| `+build` style comment smuggling | Line-by-line parser ignores comments; no AST involved |

## SRTM

| ID | Description |
|---|---|
| FR-114 | `go.mod` `require` directive parsed |
| FR-115 | `go.mod` `replace` / `exclude` / `retract` honoured with warnings |
| FR-116 | `go.sum` version resolution cross-references `go.mod` ranges |
| FR-117 | `vendor/modules.txt` cross-checked against `go.mod` |
| SF-021 | `replace` pointing to remote URL emits Finding `TS-DS-002` (MEDIUM) |

## Acceptance Criteria
- [] Given a `go.mod` with three `require` entries, When parsed, Then three deps emitted with `ecosystem="go"` and exact versions
- [] Given `require github.com/foo v1.2.3 // indirect`, When parsed, Then the dep has `is_transitive=True`
- [] Given `replace github.com/foo => ../local`, When parsed, Then the dep's source is `"go.mod:replace"` and a warning mentions the local redirect
- [] Given a `go.sum` with two lines per module, When parsed, Then versions resolve correctly
- [] Given `vendor/modules.txt` listing a module not in `go.mod`, When parsed, Then a warning is appended
- [] Given an `exclude` directive, When parsed, Then an informational warning lists the excluded versions
