# Go Source Analyser

## Overview
Scan `.go` files via **tree-sitter-go** AST traversal and classify each Go dep from REQ-13 as `IN_USE`, `UNCERTAIN`, or `SAFE`. Honours build tags, `vendor/`, and Go's test-file conventions.

## Problem Statement
Go imports look simple (`import "github.com/foo/bar"`) but the language has several features that trip up naive parsers:

- Multiple import blocks: `import ( … )`
- Build-tagged files: `//go:build linux` — imports only active on specific platforms
- `_test.go` files — separate import set; `require` deps in test files don't justify keeping them in production `go.mod` `require`
- `vendor/` directory — if present, imports resolve to vendored copies, and the real module graph is in `vendor/modules.txt`
- Dot imports: `import . "github.com/foo/bar"` — unusual but legal
- Blank imports: `import _ "github.com/foo/driver"` — side-effect registration; must NOT be flagged as SAFE

## Solution
`analyse_source_files(project_path, dependencies) -> (list[Dependency], list[str], list[Finding])` in `src/scarno/analysers/golang/source_analyser.py`. Uses `tree-sitter-go`.

## Scope

### Import discovery

Walk AST node type `import_declaration`. Each child `import_spec`:
- `path` child (quoted string) → `github.com/foo/bar`
- Optional `name` child: `.` (dot import), `_` (blank), or an alias identifier

### Matching imports to deps

Go is simple: the `require` path in `go.mod` matches the full import path prefix.

For an import `github.com/stretchr/testify/assert`:
- Dep `github.com/stretchr/testify` → prefix match → IN_USE

For `golang.org/x/sync/errgroup`:
- Dep `golang.org/x/sync` → prefix match → IN_USE

No alias table needed (unlike Java) — Go module paths ARE the import paths.

### Blank imports (`import _`)

Always IN_USE with reason `"side-effect import ('_') — driver / init() registration"`. Never downgrade to SAFE.

### Dot imports (`import .`)

IN_USE with reason `"dot import — names injected into current namespace"`.

### Build tags

Respect `//go:build <constraint>` at the top of a file. Phase 6 targets **all** build tags treated as active (conservative) — a file with `//go:build linux,arm64` still contributes its imports to the analysis. This over-estimates IN_USE (safer than missing a dep) and matches `go mod tidy`'s behaviour.

Legacy `// +build` comments handled identically.

### Test files

Files with `_test.go` suffix contribute to a separate `test_imports` set. Deps imported only from tests are classified IN_USE but with a reason noting the dep is test-only. Users often want to see these separately; the reporter shows them under a `[test]` sub-section.

### Vendor directory

When `vendor/` is present and populated:
- Skip scanning `vendor/` itself (its imports are not the project's imports)
- Treat `vendor/modules.txt` as authoritative for the list of used modules (already done in REQ-13)

### Security findings

Go-specific additions to the rule catalogue:

| Rule ID | Kind | Severity |
|---|---|---|
| `TS-SI-012` | `UNSAFE_POINTER_USAGE` | MEDIUM — `import "unsafe"` plus `unsafe.Pointer` use; flag for review |
| `TS-SI-013` | `CGO_IMPORT` | MEDIUM — `import "C"` in source (cgo); surfaces supply-chain concern |
| `TS-CE-009` | `OS_EXEC_WITH_TAINT` | CRITICAL — `exec.Command(userInput)` or `/bin/sh -c <tainted>` |

### Safety

- Tree-sitter parse bounded by `MAX_FILE_BYTES` + 10 s timeout.
- `//go:generate` directives ignored (they're build-time scripts, not imports — but flagged in a future extension).
- `go:embed` directives: extract embedded file paths for path-confinement sanity but don't treat as deps.

## SRTM

| ID | Description |
|---|---|
| FR-118 | ESM-style `import` declarations extracted via tree-sitter |
| FR-119 | Blank (`_`) and dot (`.`) imports classified IN_USE unconditionally |
| FR-120 | `_test.go` files contribute to a separate test-scope import set |
| FR-121 | `vendor/` directory skipped during scan (its own imports not the project's) |
| FR-122 | Build-tagged files included (conservative — all tags treated active) |
| SF-022 | `unsafe` + `unsafe.Pointer` usage emits `TS-SI-012` |
| SF-023 | `cgo` imports emit `TS-SI-013` |
| SF-024 | `exec.Command` with tainted input emits `TS-CE-009` |

## Acceptance Criteria
- [] Given `import "github.com/stretchr/testify/assert"` and dep `github.com/stretchr/testify`, When analysed, Then the dep → IN_USE via prefix match
- [] Given `import _ "github.com/lib/pq"`, When analysed, Then the dep → IN_USE with reason referencing blank / side-effect import
- [] Given `import . "github.com/foo/bar"`, When analysed, Then the dep → IN_USE with reason referencing dot import
- [] Given a `//go:build linux` file, When analysed on macOS, Then its imports are still counted (build tags treated as active)
- [] Given a dep imported only from `_test.go` files, When analysed, Then the dep → IN_USE with reason noting test-only usage
- [] Given a project with `vendor/`, When analysed, Then `vendor/`'s own source is skipped and module membership comes from `vendor/modules.txt`
- [] Given `import "C"` in a `.go` file, When analysed, Then a `TS-SI-013` Finding is emitted
- [] Given `exec.Command(os.Getenv("X"))`, When analysed, Then `TS-CE-009` fires at CRITICAL
