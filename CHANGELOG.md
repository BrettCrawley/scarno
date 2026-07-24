# Changelog

All notable changes to **scarno** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.2]: https://github.com/BrettCrawley/scarno/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/BrettCrawley/scarno/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/BrettCrawley/scarno/releases/tag/v1.0.0
