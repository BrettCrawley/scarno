# GitHub Action Packaging

## Overview
Package Scarno as a reusable GitHub Action so any repository can drop it into a workflow and get SARIF findings uploaded to Code Scanning, a PR-comment dependency checklist, and an annotated job summary — without installing Python or configuring uv.

## Problem Statement
Today a user wanting Scarno in CI has to:

```yaml
- run: pip install scarno
- run: scarno . --format sarif --output ts.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ts.sarif
- run: scarno . --format markdown --output ts.md
- name: Comment on PR
  uses: marocchino/sticky-pull-request-comment@v2
  with:
    path: ts.md
```

Five steps and a third-party PR-comment action. Each of those is a friction point that prevents adoption.

## Solution
Ship an official `scarno/scarno-action@v1` composite action that wraps the entire flow into one step:

```yaml
- uses: scarno/scarno-action@v1
  with:
    path: .
    fail-on-severity: HIGH
    upload-sarif: true
    comment-on-pr: true
```

## Repository Layout

A separate repository `scarno/scarno-action` (not this one) holding:

```
scarno-action/
├── action.yml                   # composite action manifest
├── scripts/
│   ├── run-analysis.sh          # install + invoke scarno
│   ├── post-pr-comment.sh       # gh api wrapper
│   └── write-job-summary.sh     # $GITHUB_STEP_SUMMARY writer
├── test-workflows/              # self-test workflows for the action itself
└── README.md
```

The main Scarno repo (this one) adds a pointer in `README.md` and an end-to-end test workflow under `.github/workflows/action-smoke.yml` that uses the published action against a fixture.

## action.yml Inputs

| Input | Type | Default | Purpose |
|-------|------|---------|---------|
| `path` | string | `.` | Project directory to analyse |
| `format` | string | `sarif` | `text` / `json` / `markdown` / `sarif`; used for the primary output |
| `output-file` | string | `scarno.sarif` | Where to write the primary report |
| `fail-on-severity` | string | `HIGH` | Passed to `scarno --fail-on-severity` |
| `show-suppressed` | bool | `false` | Passed to `scarno --show-suppressed` |
| `upload-sarif` | bool | `true` | When true **and** format is `sarif`, upload to GitHub Code Scanning via `github/codeql-action/upload-sarif` |
| `comment-on-pr` | bool | `true` | When true **and** the workflow runs on `pull_request`, post a sticky Markdown comment via `gh api` |
| `job-summary` | bool | `true` | Write a summary of findings to `$GITHUB_STEP_SUMMARY` |
| `annotate` | bool | `true` | Emit `::warning file=...,line=...::` / `::error file=...,line=...::` workflow commands so findings show inline in the PR "Files changed" view |
| `scarno-version` | string | `latest` | Pin the Scarno PyPI version |
| `python-version` | string | `3.12` | Python runtime version |

## action.yml Outputs

| Output | Description |
|--------|-------------|
| `safe-count` | Number of SAFE-to-remove dependencies |
| `uncertain-count` | Number of UNCERTAIN dependencies |
| `undeclared-count` | Number of UNDECLARED imports |
| `finding-count` | Total security findings (unsuppressed) |
| `highest-severity` | Highest severity seen (`NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) |
| `exit-code` | The Scarno CLI exit code (0 / 1 / 2 / 3) |
| `sarif-path` | Absolute path of the SARIF report |
| `markdown-path` | Absolute path of the Markdown report |

Downstream steps can gate on these:

```yaml
- uses: scarno/scarno-action@v1
  id: ts
- run: echo "Safe to remove: ${{ steps.ts.outputs.safe-count }}"
- if: steps.ts.outputs.highest-severity == 'CRITICAL'
  run: exit 1
```

## Behaviour Details

### SARIF upload
When `upload-sarif: true` and the action produces a SARIF file, the composite action invokes `github/codeql-action/upload-sarif@v3` internally. The SARIF's `category` defaults to `scarno` so findings appear under their own banner in the Security → Code Scanning tab.

### PR comment (sticky)
When `comment-on-pr: true` and `github.event_name == 'pull_request'`, the action:

1. Runs Scarno a second time with `--format markdown` (cheap; cached analysis).
2. Finds any existing comment authored by `github-actions[bot]` whose body starts with `<!-- scarno-report -->`.
3. Edits that comment in-place if present, otherwise creates a new one.

Sticky comments avoid notification spam on every push.

### Job summary
`$GITHUB_STEP_SUMMARY` gets the Markdown report verbatim. This renders on the run's detail page and is discoverable without scrolling the PR.

### Annotations
For each Finding, emit:

```
::warning file=<path>,line=<n>,title=<rule_id>::<message>
::error   file=<path>,line=<n>,title=<rule_id>::<message>
```

Severity mapping: `CRITICAL` / `HIGH` → `error`, `MEDIUM` → `warning`, `LOW` → `notice`. Same mapping as the SARIF reporter.

### Secrets and least privilege
The action requires:

- `contents: read` — to check out the project
- `security-events: write` — only when `upload-sarif: true`
- `pull-requests: write` — only when `comment-on-pr: true`

Document these in the README so users set `permissions:` on their job explicitly. Don't request write scopes the user hasn't opted into.

## Self-Tests

Add `.github/workflows/action-smoke.yml` in this repo that:

1. Checks out a fixture project (the existing `tests/fixtures/simple_python`).
2. Invokes the action via its repo-local path (`./`).
3. Asserts the action's outputs match expected values (e.g., `safe-count == 1` for simple_python).
4. Validates the SARIF output parses and contains at least one result when the fixture has findings.

The smoke workflow runs on every push.

## Marketplace Publication

Requirements for GitHub Marketplace listing:

- `action.yml` with `branding` metadata (icon + colour)
- Top-level README in the action repo describing inputs, outputs, and example usage
- Semantic versioning with major-version tags (`v1`, `v1.0.0`, etc.)
- A release workflow that tags the major version on every release
- License file (Apache-2.0 to match this repo)

## Security Considerations

- Composite actions run **in the user's runner context** with their secrets in scope. The action must never echo `GITHUB_TOKEN`, `GITHUB_ACTOR`, or any `secrets.*` value.
- Scarno's own invocation runs with the default user (non-root); the existing root-privilege warning (SEC-005) fires visibly in the runner log if someone overrides this.
- `gh api` calls for PR comments scope to the issue, never the repo admin endpoints.
- Don't download any asset at runtime — pin Scarno to a PyPI version and install via `pip install scarno==<ver>`. No `curl … | sh` (we'd be hypocrites otherwise: TS-CE-005).

## SRTM

| ID | Description |
|----|-------------|
| FR-090 | `action.yml` composite action with documented inputs and outputs |
| FR-091 | SARIF auto-upload via `github/codeql-action/upload-sarif` |
| FR-092 | Sticky PR comment via `gh api` (edit-in-place; not spam on every push) |
| FR-093 | `::error` / `::warning` / `::notice` annotations emitted per finding |
| FR-094 | `$GITHUB_STEP_SUMMARY` rendered with the Markdown report |
| FR-095 | Action-smoke CI workflow runs on every push against a fixture project |

## Acceptance Criteria
- [] Given a repo using `uses: scarno/scarno-action@v1`, When the action runs, Then Scarno is installed and analysis is produced in a single workflow step
- [] Given `upload-sarif: true`, When the action runs, Then SARIF appears in the repo's Security → Code Scanning view under the `scarno` category
- [] Given `comment-on-pr: true` and the event is `pull_request`, When the action runs twice on the same PR, Then only one sticky comment exists (the second run edits the first)
- [] Given findings with HIGH severity, When `annotate: true`, Then `::error` lines for each finding appear in the run log and show inline in the PR "Files changed" view
- [] Given `fail-on-severity: HIGH` and one HIGH finding, When the action runs, Then the job fails with the Scarno exit code `3`
- [] Given the action's outputs are consumed by a later step, When that step reads `steps.ts.outputs.safe-count`, Then the value is a non-negative integer
- [] Given the action is invoked without any input overrides, When the workflow has no `permissions:` block set, Then the action documents the required `security-events: write` and `pull-requests: write` scopes in its README
- [] Given the action repo publishes a tag `v1.0.0`, When Marketplace indexes it, Then the listing shows inputs, outputs, and an example workflow snippet

## Out of Scope
- GitLab CI component packaging — documented as a future extension
- Self-hosted runner optimisations (caching Scarno install)
- Custom SARIF report categorisation beyond the default `scarno` category
