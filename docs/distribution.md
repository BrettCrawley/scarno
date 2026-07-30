# Distribution Guide

How to package and distribute Scarno as a PyPI package and a GitHub Action.

> **The PyPI half of this document is background only.** Releasing is now done by
> [`.github/workflows/release.yml`](../.github/workflows/release.yml) on a `v*`
> tag — trusted publishing, no API token, SLSA Build L3 provenance. Follow
> [`releasing.md`](releasing.md); it is the procedure that is kept current. What
> stays authoritative here is the **GitHub Action Distribution** section below,
> which the release workflow does not cover.

## Prerequisites

Both distribution paths require:

- A real version number in `pyproject.toml` (replace `0.0.0`)
- The `LICENSE` file (Apache-2.0, already committed)
- A populated `README.md` (PyPI renders this as the project page)
- The repo pushed to GitHub

## PyPI Distribution

### 1. Update project metadata

In `pyproject.toml`, set a real version and add project URLs:

```toml
[project]
name = "scarno"
version = "1.0.0"

[project.urls]
Homepage = "https://github.com/yourorg/scarno"
Repository = "https://github.com/yourorg/scarno"
Documentation = "https://github.com/yourorg/scarno#readme"
Issues = "https://github.com/yourorg/scarno/issues"
```

### 2. Install build tools

```bash
uv add --dev build twine
```

### 3. Build the sdist + wheel

```bash
uv run python -m build
```

This produces files in `dist/`:
- `scarno-1.0.0.tar.gz` (source distribution)
- `scarno-1.0.0-py3-none-any.whl` (wheel)

### 4. Test on TestPyPI first

Create an account at https://test.pypi.org and generate an API token.

```bash
uv run twine upload --repository testpypi dist/*
```

Verify the package installs correctly:

```bash
pip install --index-url https://test.pypi.org/simple/ scarno
scarno --help
```

### 5. Publish to PyPI

Create an account at https://pypi.org and generate an API token.

```bash
uv run twine upload dist/*
```

### 6. Automated publishing via GitHub Actions — implemented

This is what [`release.yml`](../.github/workflows/release.yml) does, and it goes
further than the sketch this section used to carry: the build is separated from
the upload so the OIDC-privileged job never touches repository source, SLSA
provenance is generated in a builder the build steps cannot reach, and the upload
waits on a human approval through the `pypi` environment.

Procedure, one-time PyPI/GitHub setup, and verification:
[`releasing.md`](releasing.md). What the provenance claims: [`slsa.md`](slsa.md).

Steps 2–5 above (`build`, `twine`, manual `twine upload`) are the break-glass
path only — see the appendix of [`releasing.md`](releasing.md), which also notes
what a hand-built release loses.

---

## GitHub Action Distribution

Scarno ships as a **composite GitHub Action** that installs from PyPI
at runtime. No Docker image or JavaScript wrapper is needed.

### How it works

`action.yml` at the repo root defines the composite action. When a
consumer workflow calls `uses: brettcrawley/scarno@v1.0.4`, GitHub:

1. Checks out the action repo (just `action.yml`)
2. Runs the composite steps:
   - Sets up Python
   - `pip install scarno` from PyPI
   - Runs `scarno` with the configured options
   - Uploads SARIF, posts PR comments, writes job summary

### Publish order

**PyPI must be published before the action tag is created**, because the
action's install step does `pip install scarno`. If the package isn't
on PyPI yet, the action fails.

### 1. Tagging

The release tag is the action's version — one annotated `vX.Y.Z` tag per release,
created by the procedure in [`releasing.md`](releasing.md), which also publishes
to PyPI.

**No floating major tag.** The usual Actions convention is a mutable `v1` that
follows the latest `v1.x.x`, and this project deliberately does not have one: it
changes what consumers run without them asking, and the action is the part of
Scarno the SLSA provenance does not cover. The README pins exact version tags
instead, so they move only when someone edits the README.

### 2. Consumer usage

In any GitHub workflow:

```yaml
permissions:
  security-events: write  # for SARIF upload
  pull-requests: write    # for PR comments

steps:
  - uses: actions/checkout@v4

  - uses: brettcrawley/scarno@v1.0.4
    with:
      path: .
      format: sarif
      fail-on-severity: HIGH
```

All inputs are optional and documented in `action.yml`.

### 3. Updating the action

Nothing action-specific: the release tag *is* the action version, so
[`releasing.md`](releasing.md) covers it end to end. The one thing not to forget
is bumping the `uses:` examples in `README.md` to the tag being released — that
is what consumers copy, and there is no floating tag doing it for them.

### 4. GitHub Marketplace (optional)

To list in the Marketplace:

1. Go to the repo's **Releases** page
2. Create a new release from the `v1.0.0` tag
3. Check **Publish this action to the GitHub Marketplace** (the release itself
   is created by the `release` job — see [`releasing.md`](releasing.md))
4. Fill in the category (Security / Code quality) and description

Requirements: the repo must be **public**, and `action.yml` must have
`name`, `description`, `author`, and `branding` fields (already present).

---

## Checklist

| Step | PyPI | Action |
|------|:----:|:------:|
| Set version in `pyproject.toml` | Required | Required |
| `LICENSE` file committed | Required | Required |
| `README.md` populated | Required | Recommended |
| `[project.urls]` in `pyproject.toml` | Recommended | - |
| PyPI account + trusted publishing | Required | - |
| `pypi` GitHub environment (`v*` tags, required reviewer) | Required | - |
| Release workflow (`.github/workflows/release.yml`) | Done | - |
| Publish to PyPI | Required | **Prerequisite** |
| Create release tag (`vX.Y.Z`) | Required | Required |
| README `uses:` examples pinned to that tag | - | Required |
| Repo is public | - | Required (for external consumers) |
| Marketplace listing | - | Optional |

---

## Version management

The project uses a single source of truth for the version:
`pyproject.toml` → `[project].version`. The CLI reads this at runtime
via `importlib.metadata`.

To bump: edit `pyproject.toml`, commit, tag, push. The publish workflow
handles the rest.
