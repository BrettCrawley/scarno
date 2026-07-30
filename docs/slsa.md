# Build provenance: SLSA Build L3

What Scarno does to make a defensible SLSA claim, what that claim covers, and
how anyone downstream checks it. Written against
[SLSA v1.0](https://slsa.dev/spec/v1.0/levels), whose **Build track** is the
only track with stable levels; the Source and Dependency tracks are still
drafts and are out of scope here.

The short version: releases up to and including 1.0.3 were built and uploaded
by hand and carry **no provenance at all** — Build L0. From 1.0.4 every release
is built from a tag by [`release.yml`](../.github/workflows/release.yml),
published over PyPI Trusted Publishing with no API token in existence, and
accompanied by signed provenance generated in a builder the build steps cannot
reach — **Build L3**.

---

## 1. Where we are

### Before — verified on 2026-07-30 against the published 1.0.3 artefacts

```console
$ gh attestation verify scarno-1.0.3-py3-none-any.whl --repo BrettCrawley/scarno
Error: HTTP 404: Not Found (…/attestations/sha256:5bbffabd…)

$ curl -sH 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/scarno/ \
    | jq '.files[].provenance'
null      # ×8 — every file of 1.0.0 through 1.0.3
```

No provenance in either place, so the Build track level was **L0**, not L1.
Uploads were manual `twine`/`uv publish` runs from a workstation against a
long-lived API token, which is the position the release workflow replaces.

### After — what `release.yml` establishes

| Property | Required by | Where |
|---|---|---|
| Build runs on hosted, ephemeral infrastructure | L2 | GitHub-hosted `ubuntu-latest`; no self-hosted runners |
| Build is scripted and consistent, not a laptop | L1 | `build` job, `uv build` |
| Build triggered from an immutable ref | L1 | `on: push: tags: ["v*"]` |
| Tag and packaged version cross-checked | — | `build` job's version check |
| Actions pinned to commit SHAs | — | every `uses:` in `release.yml` bar the generator (see §3) |
| Upload credential is short-lived, not a stored token | — | PyPI Trusted Publishing (OIDC) |
| Upload gated on human approval | — | `pypi` environment, required reviewer |
| Publish job holds no permission but `id-token: write` | — | `publish` job |
| Dependencies hash-pinned and installed `--locked` | — | `uv.lock`, CI `uv sync --locked` |
| Signed provenance produced | L1, L2 | `attest-build-provenance` in `build`; the generator in `provenance` |
| Provenance distributed to consumers | L1 | GitHub attestation store; `multiple.intoto.jsonl` on the release; PEP 740 on PyPI |
| Provenance generated outside user-controlled steps | **L3** | `generator_generic_slsa3.yml`, `provenance` job |

---

## 2. What each level actually requires

Quoting the spec, with the reading that matters for this repository:

**Build L1 — provenance exists.** A consistent build process; provenance
describing the platform, process and top-level inputs; distributed to
consumers. *Protects against: mistakes, e.g. releasing from the wrong commit.*
Unsigned provenance counts.

**Build L2 — hosted build platform.** L1, plus the build "runs on dedicated
infrastructure, not an individual's workstation, and the provenance is tied to
that infrastructure through a digital signature", and verification includes
"validating the authenticity of the provenance".
*Protects against: tampering after the build.* It does **not** protect against
tampering during the build.

**Build L3 — hardened builds.** L2, plus the platform must "prevent runs from
influencing one another, even within the same project" and "prevent secret
material used to sign the provenance from being accessible to the user-defined
build steps".
*Protects against: tampering during the build — insider threat, compromised
credentials, other tenants.*

That last clause is the whole difficulty of L3 on GitHub Actions. A step you
write in your own workflow, running in the same job that signs, is by
definition a user-defined build step with access to the signing identity.
Reaching L3 means moving provenance generation somewhere your build steps
cannot reach.

---

## 3. How L3 is reached

`slsa-framework/slsa-github-generator` provides reusable workflows that
generate and sign provenance in a job whose steps the calling workflow cannot
modify, so the signing identity is never exposed to the build. This is the
route `slsa-verifier` is built to check, and the one an auditor will recognise.

As implemented in [`release.yml`](../.github/workflows/release.yml):

```yaml
  build:
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}   # the subjects the generator signs
    steps:
      # … checkout / setup-uv / version check / uv build / twine check …
      - id: hash
        run: |
          cd dist
          echo "hashes=$(sha256sum ./*.whl ./*.tar.gz | base64 -w0)" >> "$GITHUB_OUTPUT"

  provenance:
    needs: [build]
    permissions:
      actions: read    # read the workflow run that produced the artefacts
      id-token: write  # sign
      contents: write  # required at startup even though upload-assets is false
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
    with:
      base64-subjects: ${{ needs.build.outputs.hashes }}
      upload-assets: false   # the release job attaches it alongside the dists
```

Two details that cost time if you rediscover them yourself:

**This one `uses:` must be a tag, not a SHA.** `slsa-verifier` derives the
expected builder identity from the tag, and a SHA reference makes the
provenance unverifiable. It is the single deliberate exception to the
SHA-pinning rule used everywhere else in the release path — the workflow says
so in a comment, or the next person will "fix" it.

**Grant the calling job `contents: write`, even with `upload-assets: false`.**
GitHub validates a called workflow's *declared* permissions against the
caller's grant when the run starts, and the generator's `upload-assets` job
declares `contents: write` whether or not it runs. Granting only
`contents: read` fails the entire run before any job executes, with no logs and
only "This run likely failed because of a workflow file issue" to go on.

### Why both attestation mechanisms

The `build` job also runs `actions/attest-build-provenance`, which on its own
is L2 — same job, same identity. It is kept because it is what
`gh attestation verify` reads, and that is the command most people already
know. Three artefacts, three verifiers, different audiences:

| Artefact | Where it lives | Verified with |
|---|---|---|
| SLSA provenance (`multiple.intoto.jsonl`) | GitHub release assets | `slsa-verifier` |
| GitHub attestation | GitHub attestation store | `gh attestation verify` |
| PEP 740 attestation | PyPI, per file, in the Simple API | `python -m pypi_attestations` |

The L3 claim rests on the first. `pypa/gh-action-pypi-publish` generates the
third by default, which is why the `publish` job uses it rather than
`uv publish` — uv uploads attestation files that already exist but does not
generate them.

### What else L3 demands

- **Ephemeral, isolated runs.** GitHub-hosted runners satisfy this. Introducing
  a self-hosted runner into the release path would break L3 unless it is
  provably ephemeral and isolated per run — don't.
- **No secrets reachable by build steps.** Already true: the release path holds
  no secrets at all, because publishing is tokenless. Adding any `secrets.*` to
  the `build` job would need re-examining.
- **Provenance completeness.** The generator records the source repository, the
  tag, the workflow, the builder version, and the artefact digests. Nothing to
  do, but review the emitted provenance once and confirm it says what you
  expect.

---

## 4. Acceptance test

Run all four after the first release cut by this workflow. Until they have
passed once, the level is claimed by construction, not demonstrated.

```sh
VERSION=1.0.4
gh release download "v$VERSION" -D /tmp/rel

# 1. SLSA provenance — this is the L3 claim
slsa-verifier verify-artifact "/tmp/rel/scarno-$VERSION-py3-none-any.whl" \
  --provenance-path /tmp/rel/multiple.intoto.jsonl \
  --source-uri github.com/BrettCrawley/scarno \
  --source-tag "v$VERSION"

# 2. GitHub attestation
gh attestation verify "/tmp/rel/scarno-$VERSION-py3-none-any.whl" \
  --repo BrettCrawley/scarno

# 3. PyPI carries a PEP 740 attestation — must print URLs, not null
curl -sH 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/scarno/ \
  | jq -r --arg v "$VERSION" '.files[] | select(.filename|contains($v)) | .provenance'

# 4. …and that attestation verifies
python -m pypi_attestations verify pypi --repo BrettCrawley/scarno \
  "/tmp/rel/scarno-$VERSION-py3-none-any.whl"
```

Check that the provenance names the *generator's* reusable workflow as the
builder (`generator_generic_slsa3.yml@refs/tags/v2.1.0`) rather than this
repository's workflow. That identity is exactly what distinguishes L3 from L2;
if it names `BrettCrawley/scarno/.github/workflows/release.yml`, you are looking
at the L2 attestation, not the L3 provenance.

Note the generator emits an SLSA `v0.2` predicate at v2.1.0. `slsa-verifier`
handles it; a v1-only parser will not.

**Rehearsing.** `release.yml` has a `workflow_dispatch` trigger that runs
`build` and `provenance` and skips publishing, so a change to the provenance
path can be exercised from a branch without touching PyPI:

```sh
gh workflow run Release --ref main
gh run watch "$(gh run list --workflow=Release --limit 1 --json databaseId --jq '.[0].databaseId')"
```

The same rehearsal runs unattended on the 1st of each month, so upstream
breakage in the generator surfaces on a quiet morning rather than on the day a
release depends on it.

---

## 5. How consumers verify

The badge in the README is a claim, like every badge. These commands are the
evidence:

```sh
# Installed from the GitHub release — full SLSA provenance (L3)
slsa-verifier verify-artifact scarno-1.0.4-py3-none-any.whl \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/BrettCrawley/scarno --source-tag v1.0.4

# The same artefact, via GitHub's attestation store
gh attestation verify scarno-1.0.4-py3-none-any.whl --repo BrettCrawley/scarno

# Installed from PyPI instead (PEP 740 attestation)
python -m pypi_attestations verify pypi --repo BrettCrawley/scarno scarno-1.0.4-*.whl
```

---

## 6. What this does not buy

Be precise when claiming a level, because the Build track is narrower than
"supply-chain secure" suggests:

- **It says nothing about the dependencies.** Provenance proves *this* tree
  produced *this* artefact; it makes no claim about `tree-sitter` or anything
  else in `uv.lock`. That is the draft Dependency track. What covers it here is
  `pip-audit` in CI plus the committed, hash-pinned `uv.lock`, which CI installs
  with `--locked` so every job resolves to the same dependency set and a stale
  lockfile fails the build. Note the limit of that: the lockfile pins what
  Scarno is *tested* against, while the published wheel carries the ranges from
  `pyproject.toml` — `>=` floors for most dependencies, `==` for the tree-sitter
  grammars — so what a consumer installs alongside Scarno is resolved on their
  machine, not here.
- **It says nothing about the source being trustworthy.** A malicious commit on
  `main` yields perfectly valid L3 provenance. That is the draft Source track;
  branch protection and review are the controls, and they are worth having on
  their own merits.
- **It does not make the build reproducible.** SLSA v1.0 dropped the old L4;
  bit-for-bit reproducibility is a separate goal.
- **It says nothing about the composite GitHub Action.** `action.yml` runs from
  a git ref, not from a signed artefact. The Build track covers the PyPI
  distributions only. There is no floating `@v1` tag by design: the README pins
  exact version tags, and a consumer wanting immutability rather than
  convention should pin `BrettCrawley/scarno@<commit-sha>`.
- **It does not cover 1.0.0–1.0.3.** Those were hand-built and carry no
  provenance. Nothing can retroactively attest them.

---

## 7. Before changing any of this

Pinned versions were current on 2026-07-30: `attest-build-provenance` v4.1.1,
`gh-action-pypi-publish` v1.14.1, `slsa-github-generator` v2.1.0,
`slsa-verifier` v2.7.1. Re-check the upstream docs when you touch it — this is
fast-moving ground, and the generator's inputs in particular have changed
between major versions.

Releasing procedure, including the one-time PyPI and GitHub setup:
[`releasing.md`](releasing.md).
