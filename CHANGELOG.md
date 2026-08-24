# Changelog

All notable changes to **scarno** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Deleted method overloads were invisible to the cross-version ABI diff.**
  `signature_diff()` matched symbols on `(class, kind, name)` and collapsed
  each match to a single arbitrary signature, so a deleted overload of a
  member that survived under a different parameter list produced no finding at
  all. `URIUtil.encodePath(StringBuilder, String)`, removed between jetty-util
  9.4.51 and 12.0.22, is a `NoSuchMethodError` at any call site compiled
  against it and was reported by nothing — on one measured jar pair, 20 of 20
  such deletions were missed. The diff now matches on the full descriptor
  within a member, so `TS-ABI-RUNTIME-RISK` sees per-overload deletions.
  **Expect more findings after upgrading on dependencies with overloaded APIs**
  — roughly a quarter of the public surface of the sample jar is overloaded.
  A build that passed `--fail-on-severity` on one of these false negatives will
  now fail; that is the fix working, not a regression.
- **ABI diff output varied between identical runs.** Which signature won the
  collapse above depended on per-process string hash randomisation, so the
  `changed` count moved run to run (50–58 across `PYTHONHASHSEED` values on one
  jar pair) and SARIF results appeared and disappeared between otherwise
  identical CI runs. The diff is now a pure function of its inputs. Findings
  also name the overload — `Cls.method(java.lang.String)` rather than
  `Cls.method` — which both tells you which signature went and keeps the
  R-Phase9-01 finding sort total now that one member can yield several
  findings.

  Reported in `docs/SCARNO-BUG-signature-diff.md`; covered by FR-272 / FR-273 /
  FR-274.

## [1.0.4] — 2026-07-30

### Added
- **Automated, provenance-signed releases.** A `Release` workflow
  (`.github/workflows/release.yml`) publishes to PyPI when a `v*` tag is pushed:
  it builds the sdist and wheel from the tagged tree, refuses to continue if the
  tag and `pyproject.toml` version disagree, `twine check`s the metadata, and
  uploads over **PyPI Trusted Publishing** (OIDC) — no API token exists in this
  repository or its secrets. The upload waits on a human approval through the
  `pypi` environment, and the GitHub release is created afterwards with this
  changelog's section as its body.
- **SLSA Build Level 3 provenance.** Every release from this point carries signed
  provenance generated inside `slsa-github-generator`'s reusable workflow, out of
  reach of the build steps and their signing identity — attached to the GitHub
  release as `multiple.intoto.jsonl` and verifiable with `slsa-verifier`.
  Alongside it: a GitHub attestation (`gh attestation verify`) and a PEP 740
  attestation on each PyPI file (`python -m pypi_attestations`). Publishing runs
  only after provenance succeeds, so a provenance failure stops a release before
  the irreversible step. Releases 1.0.0–1.0.3 were built by hand and carry no
  provenance; nothing can retroactively attest them.
- `docs/releasing.md` — the release procedure, the one-time trusted-publisher
  setup, and what to check after a release.
- `docs/slsa.md` — what the Build L3 claim covers, how to verify it, and what it
  explicitly does not cover.

- **`uv.lock` is now committed**, and all six CI jobs install with
  `uv sync --locked`. Every job in every run therefore resolves to the same
  dependency set, and a lockfile left stale after a `pyproject.toml` change fails
  the build instead of quietly resolving something else. Refresh with `uv lock`
  when changing a dependency. This does not change what a consumer installs — the
  published wheel still carries the ranges from `pyproject.toml`.

### Changed
- The composite action is documented as `uses: brettcrawley/scarno@v1.0.4`, an
  exact version tag. There is deliberately no floating `@v1`: a moving major tag
  changes what consumers run without them asking, and the action is the part of
  Scarno that build provenance cannot cover. The README previously showed `@v1`,
  which never existed as a tag.
- README: CI, PyPI, licence, and SLSA Build Level 3 badges; a *CI gates* /
  *Release gates* / *Verifying a release* breakdown under **Development**; and
  every remaining relative link made absolute so it resolves on the PyPI project
  page rather than 404ing.
- `docs/distribution.md`: the PyPI half is now background, pointing at
  `docs/releasing.md` for the procedure that is kept current.

## [1.0.3] — 2026-07-24

### Changed
- GitHub Action Marketplace metadata: shortened `action.yml` `description`
  to under the 125-character Marketplace limit and refreshed it to reflect
  full multi-language support (dropped the stale "once REQ-10+ lands"
  wording). No code or behaviour changes.

## [1.0.2] — 2026-07-24

### Changed
- **GitHub Action** listing renamed to **"Scarno Dependency Pruner"**. The
  bare name "Scarno" collides with an existing GitHub user, and Marketplace
  listing names must be globally unique. The action reference
  (`BrettCrawley/scarno`), the PyPI package, and the `scarno` CLI are all
  unchanged.
- `action.yml` author set to Brett Crawley.

### Added
- This CHANGELOG.

## [1.0.1] — 2026-07-24

### Security
- **Maven analyser — XXE hardening.** The `<exclusions>` re-parse path
  (`_augment_pom_with_exclusions`) now rejects any `<!DOCTYPE>` declaration
  before handing the POM to the stdlib XML parser, closing a residual
  XXE / entity-expansion (billion-laughs) vector when a cached POM is
  re-read for pin-override detection. Defense-in-depth: the primary POM
  parser already rejected DOCTYPEs; this closes the secondary path.

### Fixed
- The README logo now uses an absolute URL, so it renders correctly on the
  PyPI project page (relative paths don't resolve there).

### Internal
- Full `mypy --strict` type hardening across all analysers and reporters —
  no behaviour or API changes.
- CI reliability: all six checks (pytest, SRTM coverage, mypy, bandit,
  pip-audit, opengrep) are green.

## [1.0.0] — 2026-07-24

### Added
- Initial release. Smart dependency pruner that reports which declared
  dependencies are used, unused (safe to remove), or imported-but-undeclared,
  across **Python, Java/Kotlin, JavaScript/TypeScript, Go, C#, and CSS**.
- Additional analysis: diamond and version-conflicting dependencies,
  cross-version ABI / breaking-change detection, and dependency bloat from
  minimal framework use.
- Tree-sitter source analysis per language with exact-pinned grammar wheels.
- Security findings engine (`TS-*` rule IDs) with `# scarno: allow` inline
  suppression; output as markdown, text, JSON, or SARIF.
- GitHub Action (`action.yml`) with SARIF upload, sticky PR comments, and
  step-summary reporting.
- Path-confined, sandboxed file access; adversarial security test suite.
- Optional OS-trust-store TLS via `--native-tls`.

[1.0.4]: https://github.com/BrettCrawley/scarno/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/BrettCrawley/scarno/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/BrettCrawley/scarno/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/BrettCrawley/scarno/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/BrettCrawley/scarno/releases/tag/v1.0.0
