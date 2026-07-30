# Releasing Scarno to PyPI

Pushing a `v*` tag publishes the release. The
[`Release` workflow](../.github/workflows/release.yml) builds from the tagged
tree, generates SLSA provenance in an isolated builder, uploads to PyPI over
**Trusted Publishing** (OIDC — no API token exists anywhere in this repository),
and attaches the same artefacts to the GitHub release. Your job is everything up
to the tag.

**The one rule that matters:** a version number on PyPI can never be reused.
Upload a version, notice a mistake, and your only options are to yank it and
release the next patch. The workflow refuses to publish if the tag and the
packaged version disagree, but it cannot check that the *contents* are right —
that is what step 3 is for.

Package: [`scarno`](https://pypi.org/project/scarno/) · built with `hatchling`,
driven by `uv`. What the provenance claims and how it is verified:
[`slsa.md`](slsa.md).

---

## 0. One-time setup

Do this once, before the first tag. It breaks silently if anyone renames things
afterwards.

**On PyPI** (<https://pypi.org/manage/project/scarno/settings/publishing/> →
*Add a new publisher* → GitHub):

| Field | Value |
|---|---|
| Owner | `BrettCrawley` |
| Repository name | `scarno` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

PyPI matches all four. Renaming the workflow file or the environment stops
publishing until the publisher entry is updated to match. `scarno` already
exists on PyPI, so this is a publisher added to an existing project — not a
*pending* publisher, which is only for names that have never been uploaded.

**On GitHub** (*Settings* → *Environments* → *New environment* → `pypi`):

- **Deployment branches and tags:** a custom rule allowing tags matching `v*`.
  This must include *tags*; the default branch-only policy blocks every release,
  since the workflow only ever publishes from a tag.
- **Required reviewers:** `BrettCrawley`. The `publish` job then *pauses* and
  waits for an approval before anything reaches PyPI — see step 5. Omit the
  reviewer if you would rather releases run unattended.

**Nothing else needs configuring in GitHub.** In particular `id-token: write`,
which lets the job mint the OIDC token PyPI exchanges for an upload credential,
is granted in the workflow itself (`permissions:` on the `publish` job) and can
only be granted there. The repository's *Workflow permissions* setting merely
sets the default token scope, which a job-level `permissions:` block overrides;
there is no repository switch for OIDC. The grant is deliberately narrow: only
`publish` holds `id-token: write` and nothing else, and only `release` holds
`contents: write`.

Once the workflow is the release path, **delete any PyPI API token** that was
used for manual uploads of 1.0.0–1.0.3. Keep a project-scoped token in a
password manager only as the break-glass fallback (appendix).

## 1. Decide the version

Semantic versioning on Scarno's observable contract — the CLI flags, the
JSON/SARIF output shape, the classification vocabulary, and the exit codes:

| Change | Bump |
|---|---|
| An exit code changes meaning; a CLI flag is dropped; a JSON field is removed or re-purposed; a dependency is reclassified in a way that makes previously-safe removals unsafe | **major** |
| A new language, analyser, rule ID, flag, or output section | **minor** |
| Bug fix, hardening, docs, dependency or grammar bump | **patch** |

A change to the SARIF or JSON schema is always at least a minor bump: consumers
must be able to tell from the version alone whether their parsing still holds.

## 2. Prepare the tree

```sh
VERSION=1.0.4                          # the version you are releasing
git switch main && git pull            # release from main only
git status --short                     # must be empty
```

The rest of this document uses `$VERSION`; keep it exported through the steps
below.

Add a dated section for the new version at the top of
[`CHANGELOG.md`](../CHANGELOG.md), plus a
`[x.y.z]: .../compare/vx.y.z-1...vx.y.z` link at the bottom. **This is not
optional:** the workflow extracts that section as the GitHub release body and
fails the release if it is empty. Write it for someone deciding whether to
upgrade — what changed for *them*, not which commits landed.

Bump `version` in `pyproject.toml`, then refresh and re-check the lockfile:

```sh
uv lock                                # records the new version
uv lock --check                        # must pass
```

**Commit the lockfile change with the release.** `uv.lock` is tracked, and CI
installs with `uv sync --locked`, so a lockfile that does not match
`pyproject.toml` fails every CI job — including the version bump you just made.

Two things in `README.md` pin the previous tag and must move with it:

- the logo URL (`.../scarno/v1.0.3/branding/scarno-logo.png`) — otherwise the
  PyPI page for the new version shows the old release's banner;
- both `uses: brettcrawley/scarno@v1.0.3` examples in the **GitHub Action**
  section, for the reason in §6.

```sh
grep -n 'scarno/v[0-9]\|brettcrawley/scarno@' README.md   # three hits, all the new tag
```

**`README.md` is the PyPI project page.** PyPI renders it standalone, with no
repository around it, so every link and image in it must be an **absolute URL** —
a relative `docs/LIMITATIONS.md` resolves to a pypi.org 404. Check with:

```sh
grep -noE '\]\((?!http|#)[^)]+\)' -P README.md   # must print nothing
```

## 3. Run every gate locally

CI runs six jobs; all of them can be run here, and the release is a bad time to
discover one fails:

```sh
uv sync --all-extras --dev --locked             # same flag CI uses
uv run pytest                                   # coverage ≥85% + SRTM enforcement
uv run pytest -q --srtm-report=srtm-coverage.json --srtm-fail-on-gap
uv run mypy src/scarno
uv run bandit -r src/ -ll
uv run pip-audit --skip-editable
opengrep scan --config .opengrep/rules/ src/    # needs the opengrep binary
```

Rehearse the build while you are here:

```sh
rm -rf dist
uv build
uv run --no-project --with twine twine check dist/*
uv run --isolated --no-project --python 3.12 \
  --with "./dist/scarno-$VERSION-py3-none-any.whl" scarno --help
```

These artefacts are a rehearsal only — the ones that ship are built by the
workflow from the tag, and only those carry provenance. `dist/` is gitignored.

## 4. Commit, push, and wait for green

```sh
git commit -am "Release $VERSION"
git push origin main
gh run watch "$(gh run list --workflow=CI --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

This is the last cheap moment to abort. Everything after the tag is public.

## 5. Tag — this publishes

```sh
git tag -a "v$VERSION" -m "scarno $VERSION"
git push origin "v$VERSION"
```

Watch it land:

```sh
gh run watch "$(gh run list --workflow=Release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

The workflow builds, checks the tag against `pyproject.toml`, `twine check`s the
metadata, and generates provenance. It then **waits** — the `pypi` environment
requires a reviewer, so the `publish` job sits pending until you approve the
deployment (GitHub emails you; the run page shows *Review deployments*). Approve
it and the upload runs, followed by the GitHub release with your changelog
section as the body and the artefacts plus `multiple.intoto.jsonl` attached.

Nothing has been published until you approve. A run left unapproved expires
harmlessly.

To exercise a change to the release workflow without publishing anything, run it
from a branch — `build` and `provenance` run, publishing is skipped:

```sh
gh workflow run Release --ref main
```

## 6. Point the documented action reference at the new tag

**There is deliberately no floating `v1` tag.** A moving major tag silently
changes what consumers run, and it is the one thing about the composite action
this project can control, since the action is not covered by the SLSA claim
(`action.yml` runs from a git ref, not a signed artefact). So instead of moving a
tag after the release, the README's two `uses:` examples pin the exact version —
which means they are part of step 2, not a step of their own:

```sh
grep -n 'brettcrawley/scarno@' README.md   # both must read @v<the version you are releasing>
```

Consumers who want more than a convention should pin
`brettcrawley/scarno@<commit-sha>`; say so if anyone asks why there is no `@v1`.

## 7. Verify from outside

```sh
uv run --isolated --no-project --python 3.12 --with scarno scarno --help
```

Then open <https://pypi.org/project/scarno/> and confirm the banner renders and
the README links resolve.

Check the provenance landed — a release that silently stops producing it is the
failure nobody notices:

```sh
gh release download "v$VERSION" -D /tmp/rel
gh attestation verify "/tmp/rel/scarno-$VERSION-py3-none-any.whl" --repo BrettCrawley/scarno
curl -sH 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/scarno/ \
  | jq -r --arg v "$VERSION" '.files[] | select(.filename|contains($v)) | .provenance'
```

The `jq` line must print URLs, not `null`. And the SLSA provenance, which is
what carries the L3 claim:

```sh
slsa-verifier verify-artifact "/tmp/rel/scarno-$VERSION-py3-none-any.whl" \
  --provenance-path /tmp/rel/multiple.intoto.jsonl \
  --source-uri github.com/BrettCrawley/scarno \
  --source-tag "v$VERSION"
```

The full acceptance list is [`slsa.md`](slsa.md) §4.

---

## If something goes wrong

- **Bad artefact already published.** You cannot overwrite it. Yank the release
  (`pypi.org` → *Manage* → *Yank*), which hides it from new resolutions while
  leaving existing pins working, then fix forward with a patch version.
- **Wrong tag, nothing published yet.**
  `git tag -d "v$VERSION" && git push --delete origin "v$VERSION"`. Once a
  version is on PyPI, leave the tag alone — it is the provenance record for what
  shipped.
- **The publish job fails with an OIDC/trusted-publisher error.** The four
  fields in §0 must match exactly, including the environment name. A workflow
  renamed or moved is the usual cause.
- **The whole run fails immediately with "This run likely failed because of a
  workflow file issue"** and no job logs. The `provenance` job's declared
  permissions no longer satisfy the generator — see [`slsa.md`](slsa.md) §3.
- **Tag/version mismatch.** The `build` job fails before anything is uploaded.
  Delete the tag, fix `pyproject.toml`, commit, re-tag.
- **Empty release notes.** The `release` job fails if `CHANGELOG.md` has no
  `## [$VERSION]` section. PyPI already has the upload at that point — add the
  section and create the GitHub release by hand.

## Appendix: publishing by hand (break-glass)

Only if the workflow is unavailable and a release cannot wait. This puts a
long-lived token on a laptop, which is what Trusted Publishing exists to avoid.

Note the cost beyond the token: `uv publish` uploads PEP 740 attestations only
if they already exist next to the distributions — it does not generate them —
and a hand build produces no GitHub attestation and no SLSA provenance at all.
Sign explicitly, and accept that the release drops to L0, below every other
release from 1.0.4 on.

```sh
export UV_PUBLISH_TOKEN='pypi-...'     # project-scoped token
rm -rf dist && uv build
uv run --no-project --with twine twine check dist/*
uv run --with pypi-attestations python -m pypi_attestations sign dist/*
uv publish --dry-run dist/*
uv publish dist/*
gh release create "v$VERSION" dist/* --title "scarno $VERSION" --notes-file <(
  awk -v v="$VERSION" '$0 ~ "^## \\[" v "\\]" {f=1; next} /^## \[/{f=0} f' CHANGELOG.md)
```

Rehearsing on TestPyPI first, when the packaging itself has changed:

```sh
uv publish --publish-url https://test.pypi.org/legacy/ \
           --token "$TEST_PYPI_TOKEN" dist/*
uv run --isolated --no-project --python 3.12 \
  --index https://test.pypi.org/simple/ --index-strategy unsafe-best-match \
  --with scarno scarno --help
```

TestPyPI does not mirror all dependencies, hence the fallback index.
