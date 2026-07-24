# CSS Dependency Analyser

## Overview
Detect npm-backed CSS dependencies referenced via `@import` or `url(...)`. **Limited scope** — this is NOT a dead-selector analyser (that's a different tool class, e.g. PurgeCSS). Scarno's remit is "find unused packages"; this requirement extends the idea narrowly to CSS files that import from npm-published style packages.

## Problem Statement
Modern frontend projects `@import "~normalize.css"` or `@import "tailwindcss/base"` from CSS files. If a team moves away from a CSS framework, the JS source no longer references it — but a stale `@import` in a `.css` / `.scss` file keeps the npm dep "in use" from the JS side. Scarno without CSS scanning would mis-classify.

## Solution
Add a lightweight CSS scanner that extracts `@import "…"` / `@use "…"` / `url("…")` targets from `.css`, `.scss`, `.sass`, `.less`, `.styl` files, and routes matches through the **same npm ecosystem registry** used by REQ-11. Deps matched via CSS-only imports are emitted with `ecosystem="npm"` and a `source` label identifying the CSS file.

## Scope

### File types

- `.css`, `.scss`, `.sass`, `.less`, `.styl`

### Extracted patterns

| Pattern | Example | Matched if |
|---|---|---|
| `@import "<target>"` | `@import "normalize.css"` | target doesn't start with `./`, `../`, `/`, or `url(` |
| `@import url("<target>")` | `@import url("bootstrap/dist/bootstrap.css")` | target is a bare package specifier |
| `@use "<target>" as …` (SCSS) | `@use "sass-math"` | target is a bare package specifier |
| Webpack tilde-prefix | `@import "~normalize.css"` | strip `~` then match as bare specifier |
| `url(...)` in `src:` / `background:` etc. | `url("@fontsource/roboto/latin.woff2")` | bare package specifier only |

### Not extracted (out of scope)

- CSS selectors / rules / classes / variables
- `@font-face` references to local files
- Media queries / `@supports` / `@keyframes`
- PostCSS plugins declared in `postcss.config.js` (they're npm deps — handled by REQ-10)

### Package-name extraction

Same rules as REQ-11:
- `@scope/pkg/subpath` → `@scope/pkg`
- `pkg/subpath` → `pkg`
- Strip `~` Webpack prefix before matching

### Dependency emission

When no matching JS import exists but a CSS `@import` does, emit the dep as IN_USE with:
- `ecosystem = "npm"` (CSS doesn't have its own registry)
- `source = "<css_file>:@import"`
- `reason = "imported from CSS as '<target>' in <file>"`

### Security considerations

- Remote URL in `@import url(https://...)` → `Finding` `TS-CE-007` (MEDIUM) — loading stylesheets from external URLs at build time is a supply-chain vector.
- `url("file:///etc/passwd")` → blocked via path confinement; finding `TS-CE-008` (HIGH).

### Parser choice

`tree-sitter-css` exists and covers most cases. For SCSS/Sass/Less, parsing fidelity varies — fall back to regex **with** a comment-stripping pre-pass (small, well-bounded) if no grammar is available.

## SRTM

| ID | Description |
|---|---|
| FR-111 | `@import` / `@use` / `url()` targets extracted from CSS-family files |
| FR-112 | Webpack `~`-prefix handled |
| FR-113 | CSS-only deps emitted with `ecosystem="npm"` |
| SF-019 | Remote-URL `@import` → Finding `TS-CE-007` |
| SF-020 | `file://` URL in CSS `url()` → Finding `TS-CE-008` |

## Acceptance Criteria
- [] Given a CSS file with `@import "normalize.css"` and no JS import of normalize.css, When analysed, Then `normalize.css` → IN_USE with `ecosystem="npm"` and `source` references the CSS file
- [] Given `@import "~bootstrap/dist/css/bootstrap.css"`, When analysed, Then `bootstrap` → IN_USE (tilde prefix stripped, sub-path ignored)
- [] Given `@use "@fontsource/roboto"`, When analysed, Then `@fontsource/roboto` → IN_USE
- [] Given `@import "./local.css"`, When analysed, Then no npm dep is emitted (relative path)
- [] Given `@import url("https://fonts.googleapis.com/css2?family=Roboto")`, When analysed, Then Finding `TS-CE-007` fires at MEDIUM severity
- [] Given a `.scss` file with commented-out `@import` (`// @import "foo"`), When analysed, Then no dep is matched
- [] Given CSS and JS both `@import`/`import` the same package, When analysed, Then the dep appears once in the merged report with both `source` paths listed in the reason
