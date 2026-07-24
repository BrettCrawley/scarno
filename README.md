![Scarno - Cut the dead wood before it catches fire](branding/scarno-logo.png)

# Scarno

Smart dependency pruner for polyglot projects.

Scarno identifies **unused**, **undeclared**, and **suspicious** dependencies
across **Python**, **Java/Kotlin**, **JavaScript/TypeScript/Node.js**, **Go**, and
**C#/.NET** projects. It understands how modern frameworks actually use
dependencies — dependency injection, reflection, annotations, blank imports,
Razor directives, importmaps — so it only recommends removals it is genuinely
confident about, and it is explicit about everything it is *not* sure of.

It is built to be safe to wire into CI: deterministic output, machine-readable
formats (JSON / SARIF / Markdown), stable exit codes, and a conservative
classifier that prefers over-reporting "in use" to silently telling you to
delete something you need.

---

## Contents

- [Why Scarno](#why-scarno)
- [How it works](#how-it-works)
- [Supported languages](#supported-languages)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command-line reference](#command-line-reference)
- [Understanding the output](#understanding-the-output)
  - [Dependency classification](#dependency-classification)
  - [Extra dependency annotations](#extra-dependency-annotations)
  - [Security findings](#security-findings)
  - [Special report sections](#special-report-sections)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Suppressing findings](#suppressing-findings)
- [Remote index fetch](#remote-index-fetch)
- [Recipes](#recipes)
- [GitHub Action](#github-action)
- [Advanced usage](#advanced-usage)
- [Known limitations](#known-limitations)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

---

## Why Scarno

Dependency files rot. Packages get added for a spike and never removed, a
refactor deletes the last import but leaves the manifest line, a transitive
dependency quietly becomes something you rely on directly. Every stale entry is
attack surface, CVE noise, and slower installs.

Scarno answers three questions for every dependency in your project:

1. **Is it actually used?** — by parsing your source code, not just your
   manifest. Real ASTs, real import/usage analysis, framework-aware.
2. **Is it declared?** — imports that resolve to no manifest entry are surfaced
   as `UNDECLARED` so you can pin them before they bite you.
3. **Is it suspicious?** — install-time hooks, `curl | sh`, runtime `pip install`,
   `eval` of network responses, custom registries, native interop and more are
   raised as structured **security findings**.

The design bias is conservative. When Scarno cannot prove something is
unused — reflection, dynamic imports, transitive reachability — it says
`UNCERTAIN` or `IN USE` rather than guessing. The output is meant to be
*trustworthy enough to act on*, with the genuinely ambiguous cases clearly
labelled for human review.

---

## How it works

For each detected ecosystem Scarno runs a three-stage pipeline:

1. **Manifest & lockfile parsing** — every dependency declaration is read from
   the ecosystem's manifest and lock files (see the table below), including
   transitive edges where the lockfile exposes them. This builds the set of
   *declared* dependencies and a dependency graph.
2. **Source analysis** — source files are discovered (respecting `.gitignore` by
   default) and parsed into ASTs via `tree-sitter` (or Python's `ast`). Imports,
   annotations, reflective calls, blank/dot imports, Razor `@using`, ESM/CJS/
   dynamic imports, and per-symbol usage are extracted.
3. **Classification & findings** — declared dependencies are matched against
   observed usage and classified (`SAFE` / `UNCERTAIN` / `IN USE` /
   `UNDECLARED`). `IN USE` is propagated through the dependency graph so a
   package kept alive only as a transitive of something you use is not reported
   as removable. A separate rule engine walks the ASTs to emit security
   findings.

A cross-cutting HTML/template scanner runs regardless of detected languages, so
CDN-only front-ends (no `package.json`) still surface their dependencies.

Polyglot projects are analysed in one pass; results are merged and, in the
human-readable reports, grouped by ecosystem.

---

## Supported languages

| Language | Manifest & lock files | Source analysis |
|----------|----------------------|-----------------|
| Python | `pyproject.toml`, `requirements.txt`, `setup.py`, `setup.cfg`, `Pipfile`, `poetry.lock`, `uv.lock`, `environment.yml`, `Dockerfile`, CI workflows | AST-based import extraction |
| Java/Kotlin | `pom.xml`, `build.gradle(.kts)`, version catalogs | tree-sitter AST (imports, annotations, reflection) |
| JavaScript/TypeScript | `package.json`, lockfiles (npm/yarn/pnpm/bun/Deno), `tsconfig.json` | tree-sitter AST (ESM/CJS/dynamic imports) |
| Go | `go.mod`, `go.sum`, `vendor/modules.txt` | tree-sitter AST (blank/dot/aliased imports) |
| C#/.NET | `*.csproj`, `Directory.Packages.props`, `packages.config`, `*.sln`, `nuget.config` | tree-sitter AST (using directives, Razor `@using`) |
| CSS | `*.css`, `*.scss`, `*.sass`, `*.less` | `@import` / `@use` / `url()` extraction |
| HTML/Templates | `.html`, `.vue`, `.svelte`, `.jsp`, `.ejs`, `.php`, `.erb`, + 20 more | CDN script/stylesheet extraction, ESM imports, importmaps |

Ecosystem identifiers used by the `--language` flag: `pypi`, `maven`, `gradle`,
`npm`, `css`, `go`, `nuget`.

---

## Installation

```bash
pip install scarno
```

Requires **Python 3.12+**. Scarno analyses projects in any of the supported
languages — you do not need the toolchain of the language being analysed
installed, with one optional exception: `--deep-inspection` (JVM ABI diff)
shells out to `javap` and therefore needs a JDK on `PATH`.

Check the install:

```bash
scarno --help
```

---

## Quick start

```bash
# Analyse the current directory, human-readable report to stdout
scarno .

# Analyse a specific project
scarno ../my-service

# Machine-readable report for a script or CI step
scarno . --format json --output scarno.json

# Markdown checklist suitable for a PR comment
scarno . --format markdown --output scarno.md

# Fail the command (exit 3) on any HIGH-or-above security finding
scarno . --fail-on-severity HIGH
```

A first run on a typical project takes a second or two. The text report lists
dependencies grouped by status, then security findings, then warnings.

---

## Command-line reference

```
scarno [OPTIONS] [PATH]
```

`PATH` is the directory to analyse (default: `.`). It must contain at least one
recognised manifest file.

| Option | Argument | Default | Description |
|--------|----------|---------|-------------|
| `--format` | `text` \| `json` \| `markdown` (`md`) \| `sarif` | `text` | Output format. See [Output formats](#output-formats). |
| `--output` | path | stdout | Write the report to a file instead of stdout. When you run from inside the project being analysed, the path must stay within the current working directory. |
| `--fail-on-severity` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | `HIGH` | Exit with code `3` if any unsuppressed finding is at or above this severity. |
| `--language`, `-L` | ecosystem | all detected | Restrict analysis to one or more ecosystems. Repeatable: `-L pypi -L npm`. Values: `pypi`, `maven`, `gradle`, `npm`, `css`, `go`, `nuget`. |
| `--exclude-tests` | flag | off | Drop test-scoped declared dependencies and skip test source files, across every detected ecosystem. |
| `--test-paths` | glob | — | Extra glob (relative to project root) added to the test-path matcher when `--exclude-tests` is on. Repeatable. Max 64 patterns × 256 bytes; no `..` segments; POSIX `/` separators only. |
| `--exclude-dev` | flag | off | **npm only** — drop `devDependencies` during parsing. Independent of `--exclude-tests`. Has no effect (and emits a warning) if no `package.json` is present. |
| `--deep-inspection` | flag | off | Enable the JVM cross-version ABI diff. Spawns `javap` per cached JAR (capped at 256 runs) — slower, but surfaces `NoSuchMethodError`-class runtime risks. JVM projects only; needs a JDK. |
| `--allow-remote-fetch` | flag | off | **REQ-24** — permit outbound HTTPS to fetch cache-miss artefacts (POMs during the transitive walk, JARs during the ABI diff) from configured indexes. Requires `--deep-inspection`. Argv-only — no env/config setter. Without it, configured indexes are validated but inert (zero network). See [Remote index fetch](#remote-index-fetch). |
| `--index` | `ECOSYSTEM=URL` | — | **REQ-24** — register a package index. Repeatable; declaration order within an ecosystem = priority (`maven=https://nexus.corp/repo` first, `maven=https://repo1.maven.org/maven2` second = "try Nexus, fall through to Central on connection failure"). Indexes also resolve from `~/.config/scarno/config.toml` `[indexes]` and `SCARNO_INDEX_<ECO>` env vars; CLI > user-config > env. HTTPS-only. |
| `--allow-private-index-host` | hostname | — | **REQ-24** — permit the named hostname to resolve to RFC 1918 / ULA addresses (`10.x`, `172.16-31.x`, `192.168.x`, `fc00::/7`). Required for corporate Nexus instances on private networks. Repeatable; argv-only. Loopback / link-local / CGNAT / multicast / reserved IPs stay rejected. DNS-rebinding defence (pin-resolved-IP + post-connect `getpeername` re-check) applies identically. Requires `--allow-remote-fetch`. |
| `--native-tls` | flag | off | **REQ-24** — use the OS-native trust store (`truststore` package; same approach as `uv` / `pip` / `hatch`) so corporate CAs deployed to the macOS Keychain / Windows cert store / Linux NSS are trusted automatically. Cert verification + hostname check remain mandatory; only the trust roots change. Argv-only. Requires `--allow-remote-fetch`. |
| `--integrity-cross-check` | flag | off | **REQ-24** — when ≥2 indexes are configured for an ecosystem, fetch each artefact from the top-2 and compare bytes; persistent mismatch (after a retry) → `TS-INTEGRITY-MISMATCH` (HIGH) finding. Doubles fetch volume per artefact. Requires `--allow-remote-fetch`. |
| `--fail-on-remote-severity` | flag | off | **REQ-24** — let `provenance="remote"` findings escalate exit code `3` via `--fail-on-severity`. Off by default: remote findings are visible (with a top-of-report banner) but advisory, because the bytes the analyser saw were network-fetched and may be attacker-influenceable. Requires `--allow-remote-fetch`. |
| `--no-gitignore` | flag | off | Disable `.gitignore` filtering during source-file discovery (analyse ignored files too). |
| `--show-suppressed` | flag | off | Include suppressed findings in the report, marked `suppressed=true`. |
| `--verbose` | flag | off | Emit debug lines to stderr. Suppressed in non-text formats so piped output stays clean. |
| `--help` | flag | — | Show built-in help and exit. |

---

## Understanding the output

### Dependency classification

Every dependency lands in exactly one of four buckets:

| Status | Meaning | What to do |
|--------|---------|-----------|
| **SAFE** | No usage detected anywhere in source. | Candidate for removal — review the reason, then delete the manifest line. |
| **UNCERTAIN** | Dynamic or reflective usage detected (reflection, dynamic import, a dynamic version pin). Scarno cannot prove it is used *or* unused. | Manual review required. Do **not** auto-remove. |
| **IN USE** | Confirmed usage in source, **or** kept alive transitively by something that is in use. | Keep. |
| **UNDECLARED** | Imported in source but not declared in any manifest. | Add it to your manifest and pin a version before it breaks a clean build. |

The `reason` field on each dependency explains *why* it was classified the way
it was — which file imported it, which entry points were used, or which `IN USE`
parent keeps it on the classpath. Read it before acting.

`SAFE` dependencies are sub-grouped into **Direct** (declared in your manifest)
and **Transitive — orphaned** (in the lockfile but reachable from nothing you
use).

### Extra dependency annotations

Beyond the four statuses, a dependency may carry annotations that change the
*recommended action*:

- **Manifest-redundant** — the dependency is a direct manifest declaration that
  is *also* pulled in transitively by an `IN USE` dependency. It stays `IN USE`
  (the artifact is needed at runtime), but the explicit manifest line is
  redundant: removing it leaves the artifact on the classpath via its parent.
  The report names the parent that keeps it alive.
- **Imported directly** — a dependency declared only as a transitive that your
  source nonetheless imports directly. Recommendation: promote it to a
  first-class manifest entry so an upstream change cannot silently remove it.
- **Pinning override** — the dependency is held in place by an explicit pin
  mechanism (Maven `dependencyManagement`/exclusions, npm `overrides`, yarn
  `resolutions`, pnpm `overrides`, Gradle `force`/`strictly`/constraints/
  exclusions). Scarno treats these as load-bearing and will *not* mark them
  removable, even with no source usage — removing them can silently reintroduce
  a vulnerable transitive version. See [Special report sections](#special-report-sections).

### Security findings

Independently of usage classification, a rule engine walks the parsed ASTs and
emits structured findings. Each finding has a stable rule ID, a severity
(`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`), a file/line location, a code snippet,
a human-readable message, and a remediation hint.

| Rule ID(s) | Severity | What it catches |
|-----------|----------|-----------------|
| `TS-SI-001`–`TS-SI-004` | HIGH | Runtime `pip install` via subprocess / `os.system` / `pip.main`. Deps installed at runtime are invisible to SBOM and CVE tooling. |
| `TS-SI-005`, `TS-SI-006` | MEDIUM | Jupyter `!pip install` / `%pip` / `%conda install` magics in notebook cells. |
| `TS-SI-007` | HIGH | `package.json` `preinstall` / `postinstall` / `prepare` lifecycle script — arbitrary code on every `npm install`. |
| `TS-SI-008` | MEDIUM | `.npmrc` overrides the default npm registry. |
| `TS-SI-009` | CRITICAL | Node `child_process.exec` / `execSync` with a value traced to user input — shell injection. |
| `TS-SI-010`, `TS-SI-011` | CRITICAL | `new Function(...)` on tainted input / network response passed to a JS execution sink. |
| `TS-SI-012` | MEDIUM | Go `import "unsafe"` — `unsafe.Pointer` bypasses type safety. |
| `TS-SI-013` | MEDIUM | Go `import "C"` — cgo runs outside Go's memory-safety model. |
| `TS-SI-015` | MEDIUM | `nuget.config` overrides the default NuGet source. |
| `TS-SI-016`, `TS-SI-017` | HIGH | MSBuild `<Exec>` task / `<UsingTask>` loading an external assembly at build time. |
| `TS-SI-018` | MEDIUM | C# `[DllImport(...)]` P/Invoke loading a native library at runtime. |
| `TS-CE-001`–`TS-CE-003` | CRITICAL | `exec`/`eval` of a network response, network value into an execution sink, `pickle.load*` of network data. |
| `TS-CE-004` | HIGH | Dynamic import where the module name comes from input / env / argv / network. |
| `TS-CE-005` | HIGH | `curl … \| sh` in a Dockerfile or CI workflow. |
| `TS-CE-006` | CRITICAL | `subprocess(..., shell=True)` with a command built from external input. |
| `TS-CE-007`, `TS-CE-008` | MEDIUM / HIGH | CSS `@import` / `url(https://…)` from an external host; `url(file:///…)` absolute-path confinement violation. |
| `TS-CE-009` | CRITICAL | Go `exec.Command` with an argument sourced from env / stdin / network. |
| `TS-CE-010`, `TS-CE-011` | CRITICAL | C# `Assembly.Load*` / `Process.Start` on tainted input. |
| `TS-CE-012` | MEDIUM | HTML/template loads a remote script or stylesheet via CDN — outside version control, runs in end-user browsers. |
| `TS-DS-001` | MEDIUM | `setup.py` `install_requires` assigned from a non-literal value. |
| `TS-DS-002` | MEDIUM | `go.mod` `replace` directive pointing at an external URL. |
| `TS-ABI-RUNTIME-RISK` | HIGH | *(`--deep-inspection`)* A symbol your source calls is removed or signature-changed between the declared and resolved version of a transitive — `NoSuchMethodError` imminent. |
| `TS-ABI-DRIFT` | MEDIUM | *(`--deep-inspection`)* ABI surface differs between declared and resolved versions, but the differing symbols are not currently called by your source. |
| `TS-INTEGRITY-MISMATCH` | HIGH | *(`--integrity-cross-check`)* Two configured indexes returned different bytes for the same coordinate after a single jittered retry. One of them is wrong (compromise, MITM, or replica corruption) — the analysis cannot trust either copy until you investigate. See [Remote index fetch](#remote-index-fetch). |

Findings never affect the dependency classification — they are an orthogonal
"this looks dangerous regardless of whether it is used" signal.

### Special report sections

When the relevant data is present, the Markdown and JSON reports add dedicated
sections:

- **Multiple versions detected** — a coordinate declared at more than one
  version across the project, with each version classified independently.
- **Pinning overrides** — dependencies held in place by an explicit pin
  mechanism, grouped by mechanism, with the version they pin to.
- **DO NOT REMOVE — dynamic Gradle pin** — Gradle pins whose target version is
  computed at execute time. These cannot be statically verified, so they are
  classified `UNCERTAIN` and explicitly flagged as keep-no-matter-what.
- **Dependency tree** — an ASCII rendering of the dependency graph (Markdown
  report), so you can see *why* a transitive is reachable.

---

## Output formats

Pick the format with `--format`. All formats are deterministic for a given
project state.

| Format | Best for | Notes |
|--------|----------|-------|
| `text` | Reading at a terminal during local development. | Default. Dependencies grouped by status, then findings, then warnings. Polyglot runs are sub-grouped by ecosystem. |
| `json` | Scripts, custom tooling, dashboards. | Stable schema: `scarno_version`, `analysis_timestamp`, `project_type`, `languages`, `dependencies[]`, `findings[]`, `errors[]`, `dep_graph`. All strings are sanitised. Parse this rather than scraping the text report. |
| `markdown` (`md`) | PR comments, GitHub job summaries, design docs. | Checklist-style, includes the dependency tree and the special sections above. |
| `sarif` | GitHub Code Scanning and other SARIF consumers. | Findings as SARIF results so they appear inline in the "Files changed" view and the Security tab. |

JSON is the contract for automation. The text report is for humans and its exact
layout may shift between versions; the JSON schema is stable.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Analysis complete — no `SAFE` dependencies found. |
| `1` | Analysis complete — at least one `SAFE` dependency found. |
| `2` | Analysis failed — bad path, unsupported/undetected project, or an unhandled error. |
| `3` | Analysis complete — at least one unsuppressed finding at or above `--fail-on-severity` (default `HIGH`). |

Code `3` takes precedence over code `1`: if there is both a `SAFE` dependency
and a threshold-breaching finding, you get `3`. Use this in CI to gate merges on
security findings while still surfacing prune candidates in the report body.

---

## Suppressing findings

Findings can be suppressed two ways. Suppressed findings are hidden from the
report by default and do not count toward `--fail-on-severity`; pass
`--show-suppressed` to see them (marked `suppressed=true`).

**1. Inline comment** — on the offending source line:

```python
subprocess.run(["pip", "install", "requests"])  # scarno: allow TS-SI-001
```

The comment suppresses only the listed rule ID(s) on that line.

**2. Project config** — a `[tool.scarno.findings]` table in `pyproject.toml`:

```toml
[tool.scarno.findings]
# Suppress these rule IDs everywhere in the project.
suppress = ["TS-SI-008", "TS-CE-007"]

# Or suppress per path.
[tool.scarno.findings.paths]
"scripts/bootstrap.py" = ["TS-SI-001"]
"vendor/" = ["TS-CE-012"]
```

Unknown rule IDs in the config produce a warning in the report so typos do not
silently disable nothing. This config is read from `pyproject.toml` regardless
of the project's primary language.

Suppress deliberately and document *why* — a suppressed `CRITICAL` is still a
`CRITICAL`.

---

## Remote index fetch

By default `--deep-inspection` reads only what is already in your local
`~/.m2/repository`. If a JAR or POM is missing, that coordinate is silently
skipped and you get nothing actionable for it. REQ-24 adds an opt-in path that
lets Scarno fetch missing artefacts from package indexes you configure
(Maven Central, corporate Nexus, etc.) so the analysis can complete.

The capability is intentionally narrow and operator-controlled — every gate is
argv-only (no env / config setter), defence in depth applies at every layer,
and there is no path by which a cloned repo can silently turn it on.

### The five argv flags

| Flag | Effect |
|------|--------|
| `--allow-remote-fetch` | The capability gate. Permits outbound HTTPS for cache-miss artefacts. Requires `--deep-inspection`. Without it, configured indexes are validated but **zero network calls happen**. |
| `--allow-private-index-host HOST` | Per-host opt-in to RFC 1918 / ULA addresses. Required when your index is on a private corporate network (`10.x`, `172.16-31.x`, `192.168.x`, `fc00::/7`). Repeatable. Loopback / link-local / CGNAT / multicast / reserved stay blocked. |
| `--native-tls` | Use the OS-native trust store (macOS Keychain, Windows cert store, Linux NSS) via the `truststore` package, so corporate CAs deployed by your IT team are trusted. Cert verification + hostname check remain mandatory. |
| `--integrity-cross-check` | Opt-in adversarial-integrity check. When ≥2 indexes are configured for an ecosystem, each artefact is fetched from the top-2 and bytes compared (with a single jittered retry to absorb CDN replica drift). Persistent disagreement → `TS-INTEGRITY-MISMATCH` (HIGH). Doubles per-artefact fetch volume. |
| `--fail-on-remote-severity` | Opt-in CI gate. Lets `provenance="remote"` findings escalate exit code `3` via `--fail-on-severity`. Off by default because verdicts derived from network-fetched bytes are attacker-influenceable; remote findings stay visible (banner + per-finding tag) but advisory unless you opt in. |

A **corporate Nexus** on a private IP behind your IT department's PKI typically needs three flags together: `--allow-remote-fetch --allow-private-index-host nexus.corp.example.com --native-tls`. The first opens the capability; the second relaxes the SSRF guard for that one host; the third trusts the corp CA. Each is independent — relax only what you actually need.

### Configuring indexes

Three sources, resolved with **CLI > user-config > env** precedence (per
ecosystem; env is dropped entirely when `--allow-remote-fetch` is set):

```bash
# CLI — repeatable, declaration order = priority within an ecosystem
scarno . --deep-inspection --allow-remote-fetch \
  --index maven=https://nexus.corp.example.com/repository/maven-public \
  --index maven=https://repo1.maven.org/maven2 \
  --index npm=https://registry.npmjs.org
```

```toml
# ~/.config/scarno/config.toml — array order = priority
[indexes]
maven = [
  "https://nexus.corp.example.com/repository/maven-public",
  "https://repo1.maven.org/maven2",
]
npm = ["https://registry.npmjs.org"]
```

```bash
# Env (interactive use only; dropped when --allow-remote-fetch is on, with a warning)
export SCARNO_INDEX_MAVEN="https://nexus.corp/repo https://repo1.maven.org/maven2"
```

**Repo-local files (`pyproject.toml` / `.scarno.toml` inside the scanned
tree) are deliberately ignored as an index source** — a malicious repo cannot
inject a fetch target (ARCH-SEC-005).

### What gets fetched, when

When `--allow-remote-fetch` is set:

- **POMs** missing from `~/.m2` are fetched during the Maven transitive-graph
  walk, so transitives whose POMs were never `mvn install`ed locally become
  visible to Scarno.
- **JARs** missing from `~/.m2` are fetched lazily during the cross-version
  ABI diff (only when `_resolve_jar` cannot find them locally).
- **Cache-first throughout.** Both the m2 lookup (operator's already-trusted
  cache) and the quarantined cache at `~/.cache/scarno/fetched/` are
  consulted before any network call. Only true cache-misses go to the index.

### What you'll see in the report

Every fetch attempt produces a per-attempt audit line in `result.errors` (and
therefore in the persistent report — JSON / SARIF / Markdown / text):

```
req24-fetch: REMOTE FETCH ENABLED — about to query 2 index host(s): nexus.corp.example, repo1.maven.org. Your machine's IP address will be visible to those hosts. Both POMs (transitive walker) and JARs (ABI diff) will be fetched on cache-miss; the project's transitive dependency closure will be queried as needed. The audit channel below records every fetch attempt.
req24-fetch: fetched com.google.guava:guava@31.1-jre.pom from https://repo1.maven.org/maven2 (provenance=remote, source=cli, pinned_ip=151.101.x.x)
req24-fetch: fetched com.google.guava:guava@31.1-jre.jar from https://repo1.maven.org/maven2 (provenance=remote, source=cli, pinned_ip=151.101.x.x)
```

The text and markdown reports also show a top-of-report banner:

```
⚠ This analysis fetched 7 artefact(s) from non-cache indexes; 2 finding(s) have provenance=remote (verdict depended on network trust — see --fail-on-remote-severity to gate CI on these).
```

### What's defended, what isn't

| Concern | Control |
|---|---|
| SSRF / DNS rebinding | `SafeHttpsClient` resolves once, validates every returned IP against the IPv4 + IPv6 + IPv4-mapped private/loopback/link-local/CGNAT/multicast/reserved deny-list, pins one IP, connects to the pinned IP literal with SNI = the original hostname, re-checks `getpeername()` post-connect. |
| MITM | HTTPS-only (hard reject of `http://`, `file://`, userinfo at parse AND request time); mandatory cert verification with no API to disable. |
| Compromised single index | Opt-in `--integrity-cross-check` — top-2 priority indexes must agree on the bytes (after retry-once). Defeats a single compromised index; does not defeat a conspiratorial pair. |
| Internal-coord leak to public indexes | HTTP 4xx is authoritative — no fall-through. A coord that 404s on the corp Nexus is NOT then queried at Maven Central. List internal indexes first. |
| Cache poisoning of `~/.m2` | Fetched bytes go to a **quarantined cache** (`~/.cache/scarno/fetched/`, mode 0700, every write through `resolve_and_confine`). Never `~/.m2`, never `node_modules`. |
| Resource exhaustion | Per-run fetch-count cap (128); per-artefact size cap (64 MiB); per-request timeout (30s); total fetch-time budget (5 min); cache TTL (30 d) and total-size cap (1 GiB) with LRU eviction. |
| Argv-only capability | `--allow-remote-fetch`, `--integrity-cross-check`, `--fail-on-remote-severity` cannot be set via env, config, or test helpers — only argv. Static-analysis test asserts no `os.environ` / `config` paths touch the flag in `cli.py`. |
| Repo-local config injection | `security.resolve_user_config_path` is the sole user-config locator; anchored to `Path.home()` / `$XDG_CONFIG_HOME` only; XDG paths under the analysed project tree fall back to `~/.config` with an audit. Static-analysis test asserts no other config-file `open()` exists. |

### What's NOT defended

- **A conspiratorial pair of indexes** — choose a primary you trust independently.
- **The integrity of bytes you opted to fetch** — `provenance="remote"` findings stay advisory by default precisely because the bytes are network-trust-dependent. `--fail-on-remote-severity` opts you into stricter gating, but that is your call.
- **Authenticated registries** — v1 is anonymous-only. The `IndexEndpoint.credential_ref` field is reserved for a future auth layer; v1 sends no credentials and accepts none.
- **`http://` indexes** — hard rejected. Front your internal HTTP-only Nexus with TLS, or use a tunnel.

For the full operator-awareness section (project fingerprinting, IP
disclosure, typosquatting, probe-oracle threats), read [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)
PRV-007 — especially before enabling fetch on a confidential codebase.

---

## Recipes

```bash
# Production-only view of an npm project — drop devDependencies and test files
scarno . -L npm --exclude-dev --exclude-tests

# Polyglot monorepo, but only report on the Python and Go pieces
scarno . -L pypi -L go

# Treat extra directories as tests when pruning test-scoped deps
scarno . --exclude-tests --test-paths "integration/**" --test-paths "e2e/**"

# Full JVM run including the cross-version ABI diff (needs a JDK)
scarno . -L maven -L gradle --deep-inspection

# Same, but allow REQ-24 to fetch missing POMs / JARs from your Nexus + Maven Central
scarno . -L maven --deep-inspection --allow-remote-fetch \
  --index maven=https://nexus.corp.example.com/repository/maven-public \
  --index maven=https://repo1.maven.org/maven2

# Corporate Nexus on a private IP behind internal PKI — three flags together:
#   1. open the capability gate
#   2. permit the nexus hostname to resolve to RFC 1918
#   3. trust the corp CA from the OS keychain (no per-machine SSL_CERT_FILE)
scarno . -L maven --deep-inspection --allow-remote-fetch \
  --allow-private-index-host nexus.corp.example.com \
  --native-tls \
  --index maven=https://nexus.corp.example.com/repository/maven-public

# Paranoid mode — also cross-check that both indexes return identical bytes,
# and let CI fail on findings whose verdict depended on network-fetched bytes
scarno . -L maven --deep-inspection --allow-remote-fetch \
  --index maven=https://nexus.corp.example.com/repository/maven-public \
  --index maven=https://repo1.maven.org/maven2 \
  --integrity-cross-check --fail-on-remote-severity \
  --fail-on-severity HIGH

# Strictest CI gate — fail on anything MEDIUM or worse
scarno . --format sarif --output scarno.sarif --fail-on-severity MEDIUM

# Audit including normally-suppressed findings
scarno . --show-suppressed --format json --output audit.json

# Analyse generated / .gitignore'd code too
scarno . --no-gitignore
```

---

## GitHub Action

Scarno ships a composite action that runs the CLI, uploads SARIF to Code
Scanning, posts a sticky PR comment, writes a job summary, and emits inline
annotations.

```yaml
- uses: brettcrawley/scarno@v1
  with:
    path: .
    format: sarif
    fail-on-severity: HIGH
```

**Inputs** (all optional):

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to analyse, relative to repo root. |
| `format` | `sarif` | Primary report format. |
| `output-file` | `scarno.sarif` | Where the primary report is written. |
| `fail-on-severity` | `HIGH` | Severity threshold for exit code `3`. |
| `show-suppressed` | `false` | Include suppressed findings. |
| `upload-sarif` | `true` | Upload via `github/codeql-action/upload-sarif` (needs `security-events: write`). |
| `comment-on-pr` | `true` | Post a sticky Markdown comment on PRs (needs `pull-requests: write`). |
| `job-summary` | `true` | Write the Markdown report to `$GITHUB_STEP_SUMMARY`. |
| `annotate` | `true` | Emit per-finding `::error` / `::warning` / `::notice` annotations. |
| `scarno-version` | `latest` | Scarno version to install from PyPI. |
| `python-version` | `3.12` | Python runtime version. |

**Outputs:** `safe-count`, `uncertain-count`, `undeclared-count`,
`finding-count`, `highest-severity`, `exit-code`, `sarif-path`, `markdown-path`.

A typical PR-gating job:

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  scarno:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: brettcrawley/scarno@v1
        with:
          fail-on-severity: HIGH
```

See [docs/distribution.md](docs/distribution.md) for packaging and release
details.

---

## Advanced usage

**Cross-version ABI diff (`--deep-inspection`).** For JVM projects, this
compares the public ABI of each transitive's *declared* version against its
*resolved* version by running `javap` over JARs in your local cache. It catches
the case where a version bump silently removes or changes a method your code
calls — a runtime `NoSuchMethodError` you would otherwise only find in
production. It is off by default because it is slow (one `javap` process per
JAR, capped at 64) and needs a JDK. Symbols your source actually calls become
`TS-ABI-RUNTIME-RISK` (HIGH); the rest become `TS-ABI-DRIFT` (MEDIUM).

**Test-scope handling (`--exclude-tests` / `--test-paths`).** `--exclude-tests`
drops test-scoped manifest entries (e.g. Maven `test` scope) and skips test
source files in every ecosystem, so the report reflects only what production
needs. If your tests live somewhere Scarno's default matcher does not
recognise, add globs with `--test-paths` (anchored to the project root; leading
`/` is stripped).

**Populating package caches improves accuracy.** When several dependencies could
own a class with the same simple name, Scarno uses package-cache metadata to
disambiguate. A populated `~/.m2/repository` (Java) or `node_modules` (npm) gives
the analyser more to work with; without it, attribution falls back to
conservative over-reporting.

**Why a dependency is `IN USE` when you did not import it.** Scarno
propagates `IN USE` through the dependency graph: a package reachable only as a
transitive of something you use is kept, because the parent may need it at
runtime and that cannot be disproven without reading the parent's bytecode. The
`reason` field names the parent.

---

## Known limitations

Scarno is intentionally heuristic in several places — type inference is
shallow, attribution under ambiguity prefers over-reporting to silence, and some
ecosystems (C# in particular) lack the metadata sources for definitive
attribution.

**Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before trusting the output for
automated removal decisions.** It is an honest, specific list of what Scarno
does not handle — async/chained return types, generic type parameters,
last-write-wins variable binding, reflective invocation, CDN-loaded assets, and
more. Treat `SAFE` as "strong candidate for removal, verify and delete" rather
than "delete automatically", and never auto-remove anything marked `UNCERTAIN`.

---

## Development

```bash
# Install dependencies (uv-managed)
uv sync --all-extras --dev

# Run the test suite (coverage + SRTM enforcement included)
uv run pytest

# Type check
uv run mypy src

# Security scan
uv run bandit -r src
```

---

## Documentation

- [docs/Specification.md](docs/Specification.md) — full product specification
- [docs/PLAN.md](docs/PLAN.md) — phased development roadmap
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — **what Scarno doesn't handle** (read before relying on output in production)
- [docs/distribution.md](docs/distribution.md) — PyPI + GitHub Action packaging guide
- [docs/requirements/](docs/requirements/) — individual requirement documents
- [docs/scarno-security-architecture.md](docs/scarno-security-architecture.md) — security architecture
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — threat model (unified STRIDE analysis)
- [docs/scarno-test-suite.md](docs/scarno-test-suite.md) — test suite design + SRTM

---

## License

[Apache License 2.0](LICENSE) — see also the [NOTICE](NOTICE) file.

Contributions are accepted under the terms of the [Contributor License
Agreement](CLA.md).
