# Distribution Guide

How to package and distribute Scarno as a PyPI package and a GitHub Action.

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

### 6. Automated publishing via GitHub Actions (recommended)

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write  # trusted publishing (no API token needed)
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          python-version: "3.12"

      - name: Build
        run: uv run python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

To use trusted publishing (no API token), configure the PyPI project at
https://pypi.org/manage/project/scarno/settings/publishing/ to trust
your GitHub repository and workflow.

Then to release:

```bash
# Update version in pyproject.toml, commit, then:
git tag -a v1.0.0 -m "Scarno 1.0.0"
git push origin v1.0.0
```

The workflow builds and publishes automatically on tag push.

---

## GitHub Action Distribution

Scarno ships as a **composite GitHub Action** that installs from PyPI
at runtime. No Docker image or JavaScript wrapper is needed.

### How it works

`action.yml` at the repo root defines the composite action. When a
consumer workflow calls `uses: yourorg/scarno@v1`, GitHub:

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

### 1. Create the initial release

After publishing to PyPI:

```bash
# Create an annotated release tag
git tag -a v1.0.0 -m "Scarno 1.0.0"
git push origin v1.0.0

# Create the floating major-version tag (convention for Actions)
# Consumers use @v1 and get the latest v1.x.x automatically
git tag -fa v1 -m "Scarno v1 (floating)"
git push origin v1 --force
```

### 2. Consumer usage

In any GitHub workflow:

```yaml
permissions:
  security-events: write  # for SARIF upload
  pull-requests: write    # for PR comments

steps:
  - uses: actions/checkout@v4

  - uses: yourorg/scarno@v1
    with:
      path: .
      format: sarif
      fail-on-severity: HIGH
```

All inputs are optional and documented in `action.yml`.

### 3. Updating the action

For patch/minor releases:

```bash
# Update version in pyproject.toml, commit, push
# Publish to PyPI (via tag push or manually)
git tag -a v1.1.0 -m "Scarno 1.1.0"
git push origin v1.1.0

# Move the floating major tag
git tag -fa v1 -m "Scarno v1 (floating)"
git push origin v1 --force
```

For major releases (breaking changes):

```bash
git tag -a v2.0.0 -m "Scarno 2.0.0"
git push origin v2.0.0

# New floating tag
git tag -fa v2 -m "Scarno v2 (floating)"
git push origin v2 --force
```

### 4. GitHub Marketplace (optional)

To list in the Marketplace:

1. Go to the repo's **Releases** page
2. Create a new release from the `v1.0.0` tag
3. Check **Publish this action to the GitHub Marketplace**
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
| `build` + `twine` in dev deps | Required | - |
| Publish workflow (`.github/workflows/publish.yml`) | Recommended | - |
| Publish to PyPI | Required | **Prerequisite** |
| Create release tag (`v1.0.0`) | Recommended | Required |
| Create floating tag (`v1`) | - | Required |
| Repo is public | - | Required (for external consumers) |
| Marketplace listing | - | Optional |

---

## Version management

The project uses a single source of truth for the version:
`pyproject.toml` → `[project].version`. The CLI reads this at runtime
via `importlib.metadata`.

To bump: edit `pyproject.toml`, commit, tag, push. The publish workflow
handles the rest.
