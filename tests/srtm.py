"""Authoritative list of SRTM requirement IDs Scarno must cover.

Extracted from scarno-test-suite.md (Security Requirements Traceability
Matrix section) plus the functional requirements (FR-*), privacy (PRV-*),
architecture (ARCH-*), threats (T-*, E-*, D-*, S-*, R-*, I-*, GAP-*, Rich-*)
and performance (PERF-*) IDs referenced across the spec.

Every ID in this set must be covered by at least one test carrying
``@pytest.mark.requirement("<ID>")``. The SRTM coverage plugin
(``tests/srtm_plugin.py``) enforces this at test-collection time.

When a new requirement is introduced, add its ID here so coverage gaps are
surfaced immediately in CI.
"""
from __future__ import annotations

# Security requirements
SECURITY_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "SEC-001",
        "SEC-002",
        "SEC-003",
        "SEC-004",
        "SEC-005",
        "SEC-008",
        "SEC-009",
        "SEC-010",
        "SEC-011",
        "SEC-012",
        "SEC-013",
        "SEC-NEW-01",
        "SEC-NEW-02",
        "SEC-NEW-03",
        "SEC-NEW-04",
        "SEC-NEW-05",
        "SEC-NEW-07",
        "SEC-NEW-08",
        "SEC-NEW-09",
        "SEC-NEW-10",
        "SEC-NEW-11",
        "SEC-NEW-12",
        # REQ-2b: YAML safe_load + include-group depth cap
        "SEC-NEW-13",
        "SEC-NEW-14",
        # REQ-2c: workflow YAML bomb, Dockerfile ReDoS, tox interpolation cycle, noxfile AST-only
        "SEC-NEW-15",
        "SEC-NEW-16",
        "SEC-NEW-17",
        "SEC-NEW-18",
        # REQ-6b: tree-sitter parse bounded by size + timeout
        "SEC-NEW-19",
        # Phase 5 — JS/TS/CSS parser hardening
        "SEC-NEW-20",  # package-lock.json / npm-shrinkwrap.json depth cap
        "SEC-NEW-21",  # pnpm-lock.yaml YAML bomb defense (safe_load + anchor cap)
        "SEC-NEW-22",  # yarn.lock v1 bespoke parser is ReDoS-safe
        "SEC-NEW-23",  # tsconfig.json JSONC depth cap
        # Phase 6 — Go parser hardening
        "SEC-NEW-24",  # go.mod line-length + file-size cap (DoS defense)
        # Phase 7 — C#/.NET parser hardening
        "SEC-NEW-25",  # DOCTYPE rejection pre-parse in *.csproj (XXE defense)
        "SEC-NEW-26",  # Directory.Build.props walked up, confined to project root
        "SEC-NEW-27",  # GAV coordinate validation prevents path traversal in ~/.m2 lookup
        "SEC-NEW-28",  # mvn binary resolution validates against $MAVEN_HOME tree
        "SEC-NEW-29",  # JAR path confined to ~/.m2/repository during package discovery
        "SEC-NEW-30",  # .venv metadata path confined to project root
        # REQ-17 — Phase 8 — test-scope, mermaid, symbol tally
        "SEC-NEW-31",  # --test-paths count + length caps
        "SEC-NEW-32",  # Mermaid label sanitiser + reserved-token allowlist + no click directive
        "SEC-NEW-33",  # --test-paths traversal/separator reject + leading-/ strip
        # REQ-17b — Phase 8b — per-language taxonomy + path hardening
        "SEC-NEW-34",  # npm dep-name validator
        "SEC-NEW-35",  # C# .sln Project reference confinement
        # REQ-18 — TypeScript first-class support
        "SEC-NEW-36",  # @types runtime-target re-validation
        # REQ-19 — Phase 9 — per-edge version labels (PR-1)
        "SEC-NEW-37",  # Lockfile size + edge cap (8 MiB / 50 000 edges)
        "SEC-NEW-38",  # sanitise_declared_version (strip control + Mermaid-active + cap 64; per-destination escape per SEC-NEW-54)
        "SEC-NEW-49",  # NEW-ARCH-009 strict-inclusion semantics on the back-compat fixture (Phase 9 PR-1)
        "SEC-NEW-53",  # gradle.lockfile vs gradle dependencies cross-check (Phase 9 PR-1)
        # REQ-20 / REQ-19a — Phase 9 — per-version classification + arch invariants (PR-2)
        "SEC-NEW-39",  # Per-coordinate version cap (64) — SUC-43
        "SEC-NEW-46",  # core/classifier.py centralisation; every analyser routes through it
        "SEC-NEW-47",  # Dependency __post_init__ + classifier mutex assertion (pin_override XOR manifest_redundant)
        "SEC-NEW-50",  # ThreadPoolExecutor worker cap min(8, cpu_count or 1) (partial — full at PR-4)
        "SEC-NEW-52",  # MAVEN_HOME / GRADLE_HOME mandatory verification when set; verbose PATH-fallback warning
        "SEC-NEW-55",  # mvn / gradle argv allowlist — REQ-20 fixed-argv contract (T-Phase9-04 closure)
        "SEC-NEW-57",  # Pin-detector registry symmetric coverage test
        "SEC-NEW-58",  # Subprocess-call-site AST scan — only safe_subprocess_run permitted
        # REQ-21 — Maven pinning detection (PR-3)
        "SEC-NEW-40",  # Maven _MAX_EXCLUSIONS_PER_DEP=128 / _MAX_DM_ENTRIES=2048 caps
        "SEC-NEW-48",  # PinOverrideKind enum coverage by apply_pin_override_safety
        # REQ-22 — Cross-version ABI diff (PR-4, --deep-inspection)
        "SEC-NEW-42",  # _JAVAP_PER_JAR_TIMEOUT_S = 30s enforced
        "SEC-NEW-43",  # _JAVAP_MAX_JARS_PER_RUN = 128 enforced
        "SEC-NEW-44",  # resolve_and_confine + _validate_gav on m2 path
        "SEC-NEW-51",  # abi_diff.py has no subprocess imports (NEW-ARCH-011)
        "SEC-NEW-56",  # --deep-inspection set ONLY from argv (no env / config)
        # REQ-23 — npm pinning (PR-5)
        "SEC-NEW-45",  # _NPM_OVERRIDES_MAX_ENTRIES=2048 + _NPM_OVERRIDES_MAX_NESTING=8 caps
        # REQ-21b — Gradle pinning (PR-6)
        "SEC-NEW-41",  # _GRADLE_MAX_FORCE_DIRECTIVES=256 / _GRADLE_MAX_EXCLUSIONS=256 / _GRADLE_PARSE_TIMEOUT_S=8s
        # REQ-24 — Remote Index Fetch for --deep-inspection
        "SEC-NEW-59",  # ValidatedCoordinate opaque type; per-ecosystem CoordinateValidator
        "SEC-NEW-60",  # SafeHttpsClient sole outbound-HTTPS path; pin-IP; cert mandatory; IPv6 deny-list; HTTP/2 coalescing off
        "SEC-NEW-61",  # No cross-index fallthrough on HTTP 4xx
        "SEC-NEW-62",  # Env-sourced indexes dropped when --allow-remote-fetch is set
        "SEC-NEW-63",  # Redirect policy ≤2 hops, full re-validation per hop, headers dropped on cross-host
        "SEC-NEW-64",  # Quarantined cache root mode 0700
        "SEC-NEW-65",  # Every cache write through resolve_and_confine
        "SEC-NEW-66",  # Total cache size cap (1 GiB default) + LRU eviction
        "SEC-NEW-67",  # Per-artefact TTL (30d default)
        "SEC-NEW-68",  # Per-artefact fetch-time size cap (64 MiB default)
        "SEC-NEW-69",  # Per-run fetch count/time caps, lock-counted
        "SEC-NEW-70",  # IndexEndpoint.coordinate_prefix reserved (v2 surface)
        "SEC-NEW-71",  # TS-INTEGRITY-MISMATCH HIGH-severity finding rule
        "SEC-NEW-72",  # --allow-remote-fetch is argv-only (mirrors SEC-NEW-56)
        "SEC-NEW-73",  # Decompression-bomb caps when reading fetched JARs
        "SEC-NEW-74",  # --integrity-cross-check retries once after jittered backoff before declaring mismatch
    }
)

# Security Finding requirements (REQ-3c)
FINDING_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "SF-001",  # Runtime pip-install pattern detection (TS-SI-001..004)
        "SF-002",  # Notebook pip-install magic detection (TS-SI-005..006)
        "SF-003",  # Remote-code-exec taint (TS-CE-001..003)
        "SF-004",  # Unvalidated dynamic import (TS-CE-004)
        "SF-005",  # Curl-pipe-shell in container/CI (TS-CE-005)
        "SF-006",  # Shell injection in install (TS-CE-006)
        "SF-007",  # setup.py dynamic deps as Finding (TS-DS-001)
        "SF-008",  # Inline suppression honoured
        "SF-009",  # Config-file suppression honoured
        "SF-010",  # Unknown suppression rule-id in config produces warning
        "SF-011",  # Finding snippets sanitised
        "SF-012",  # Rule engine never invokes eval/exec/subprocess on analysed content
        "SF-013",  # Markdown output: heading / code-block / HTML / link injection blocked
        "SF-014",  # SARIF output: JSON injection via adversarial dep names blocked
        "SF-015",  # SARIF output: rule-id catalogue is consistent with findings/rules.py
        # Phase 5 — JS/TS/CSS findings
        "SF-016",  # package.json postinstall → TS-SI-007
        "SF-017",  # .npmrc custom registry → TS-SI-008
        "SF-018",  # Rule engine extended with TS-SI-007..011
        "SF-019",  # CSS remote @import URL → TS-CE-007
        "SF-020",  # CSS file:// URL → TS-CE-008
        # Phase 6 — Go findings
        "SF-021",  # go.mod replace → remote URL → TS-DS-002
        "SF-022",  # Go unsafe.Pointer → TS-SI-012
        "SF-023",  # Go cgo import → TS-SI-013
        "SF-024",  # Go exec.Command + taint → TS-CE-009
        # Phase 7 — C#/.NET findings
        "SF-025",  # nuget.config custom registry → TS-SI-015
        "SF-026",  # MSBuild <Exec> task → TS-SI-016
        "SF-027",  # Custom <UsingTask> DLL → TS-SI-017
        "SF-028",  # Assembly.Load(tainted) → TS-CE-010
        "SF-029",  # Process.Start(tainted) → TS-CE-011
        "SF-030",  # [DllImport] → TS-SI-018
    }
)

# Privacy requirements
PRIVACY_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "PRV-002",
        "PRV-003",
        # REQ-17 — aggregate-only test-skip reporting (no per-file leak)
        "PRV-004",
        # REQ-24 — Remote Index Fetch
        "PRV-005",  # Off-machine disclosure: minimisation gate superseded by mandatory pre-fetch disclosure + LIMITATIONS.md (REQ-24 Option 2)
        "PRV-006",  # Disclosure line names IP exposure explicitly
        "PRV-007",  # Operator-facing docs explain project-fingerprinting risk (PT-005)
    }
)

# Architecture requirements
ARCHITECTURE_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "ARCH-SEC-001",
        "ARCH-SEC-002",
        "ARCH-SEC-004",
        # REQ-24 — Remote Index Fetch
        "ARCH-SEC-005",  # security.resolve_user_config_path is the SOLE user-config locator; home-anchored; XDG-confined
        "ARCH-PERF-001",
    }
)

# Functional requirements — from REQ-1 .. REQ-7 plus Phase 1.5 extensions
FUNCTIONAL_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "FR-001",
        "FR-002",
        "FR-003",
        "FR-005",
        "FR-006",
        "FR-007",
        "FR-009",
        "FR-010",
        "FR-018",
        "FR-019",
        "FR-030",
        "FR-032",
        "FR-033",
        # REQ-2b — extended Python formats
        "FR-040",  # environment.yml parsing
        "FR-041",  # [build-system].requires parsing
        "FR-042",  # [dependency-groups] parsing with include-group
        "FR-043",  # Dependency.source provenance populated
        # REQ-2c — container & CI dep extraction
        "FR-050",  # Dockerfile RUN pip install extraction
        "FR-051",  # GitHub Actions / GitLab CI workflow extraction
        "FR-052",  # tox.ini deps extraction
        "FR-053",  # noxfile.py session.install AST-only extraction
        # REQ-3b — phantom / undeclared / vendored
        "FR-060",  # DependencyStatus.UNDECLARED added
        "FR-061",  # Phantom import detected via importlib.metadata
        "FR-062",  # Vendored-directory detection
        "FR-063",  # .ipynb cell AST extraction
        # REQ-3c — Finding model + exit code 3
        "FR-070",  # Finding dataclass + findings list on AnalysisResult
        "FR-071",  # Text reporter renders SECURITY FINDINGS section
        "FR-072",  # JSON reporter emits findings array
        "FR-073",  # Exit code 3 for HIGH/CRITICAL findings
        "FR-074",  # --fail-on-severity flag
        "FR-075",  # --show-suppressed flag
        # REQ-7 — additional pipeline-friendly output formats
        "FR-080",  # MarkdownReporter with actionable checkboxes
        "FR-081",  # SarifReporter emitting SARIF 2.1.0 JSON
        "FR-082",  # CLI --format accepts markdown | md | sarif
        "FR-083",  # SARIF rule catalogue includes every REQ-3c rule ID
        "FR-084",  # SARIF severity → level mapping (error / warning / note)
        # Process / tooling
        "FR-085",  # Coverage report produced on every pytest run
        # REQ-6b — robust JVM parsing via tree-sitter (Phase 4)
        "FR-086",  # JVM source analysis uses tree-sitter AST, not regex
        "FR-087",  # Comments / string literals / Javadoc excluded from DI + reflection match
        "FR-088",  # Graceful fallback to regex when tree-sitter wheels unavailable
        # REQ-8 — GitHub Action packaging (Phase 4)
        "FR-090",  # action.yml composite action with documented inputs / outputs
        "FR-091",  # SARIF auto-upload via github/codeql-action/upload-sarif
        "FR-092",  # Sticky PR comment (edit-in-place, not spam)
        "FR-093",  # ::error / ::warning / ::notice annotations per finding
        "FR-094",  # $GITHUB_STEP_SUMMARY rendered with Markdown report
        "FR-095",  # Action-smoke CI workflow against a fixture project
        # REQ-9 — Polyglot foundations (Phase 2.5)
        "FR-096",  # Dependency.ecosystem populated for every emitted dep
        "FR-097",  # detect_project_types returns list of applicable types
        "FR-098",  # Orchestrator runs every registered analyser whose language was detected
        "FR-099",  # AnalysisResult.languages populated
        "FR-100",  # Reporters group by ecosystem when multi-language
        "FR-101",  # --language CLI filter
        "FR-102",  # Registry-based analyser lookup
        # REQ-10 — JS/TS manifest + lock parsers (Phase 5)
        "FR-103",  # package.json parsed
        "FR-104",  # npm lock files parsed (yarn v1/Berry, pnpm, bun.lock, npm)
        "FR-105",  # Deno manifest + lock parsed
        "FR-106",  # bun.lockb rejected with warning
        # REQ-11 — JS/TS source analyser (Phase 5)
        "FR-107",  # ESM + CJS imports via tree-sitter
        "FR-108",  # TS triple-slash references extracted
        "FR-109",  # tsconfig paths mapped to local files
        "FR-110",  # Entry points enumerated from node_modules exports
        # REQ-12 — CSS analyser (Phase 5)
        "FR-111",  # @import / @use / url() extraction
        "FR-112",  # Webpack ~ prefix handled
        "FR-113",  # CSS-only deps emitted with ecosystem=npm
        # REQ-13 — Go manifest parser (Phase 6)
        "FR-114",  # go.mod require parsed
        "FR-115",  # go.mod replace/exclude/retract honoured
        "FR-116",  # go.sum version resolution
        "FR-117",  # vendor/modules.txt cross-check
        # REQ-14 — Go source analyser (Phase 6)
        "FR-118",  # ESM-style import declarations via tree-sitter-go
        "FR-119",  # Blank (_) and dot (.) imports IN_USE unconditionally
        "FR-120",  # _test.go files separate test-scope import set
        "FR-121",  # vendor/ directory skipped during scan
        "FR-122",  # Build-tagged files included (conservative)
        # REQ-15 — C#/.NET manifest parser (Phase 7)
        "FR-123",  # *.csproj / *.fsproj / *.vbproj PackageReference parsed
        "FR-124",  # Central Package Management honoured
        "FR-125",  # Legacy packages.config parsed
        "FR-126",  # *.sln multi-project discovery
        "FR-127",  # packages.lock.json resolves versions
        # REQ-16 — C# source analyser (Phase 7)
        "FR-128",  # using directives (regular/static/alias/global) via tree-sitter
        "FR-129",  # Razor / Blazor @using / @inject recognised
        "FR-130",  # Microsoft shared-framework alias table
        # REQ-4b — tiered parent POM / BOM resolution
        "FR-131",  # Parent POM resolved from ~/.m2/repository local cache
        "FR-132",  # Parent POM fetched via mvn dependency:get CLI
        "FR-133",  # BOM imports resolved via tiered POM resolution
        "FR-134",  # Java dependency packages discovered from JAR class entries
        "FR-135",  # Python dependency imports discovered from .venv dist-info metadata
        # REQ-17 — Phase 8
        "FR-150",  # EntryPoint.usage_count populated for every used symbol
        "FR-151",  # Dependency.imported_directly flagged when source imports a transitive directly
        "FR-152",  # Markdown reporter emits Mermaid dependency graph block
        "FR-153",  # --exclude-tests drops test-scoped deps + skips test source files across ecosystems
        "FR-154",  # --test-paths PATTERN extends the test-path matcher with operator overrides
        "FR-155",  # --exclude-dev (npm-only, off by default) drops devDependencies
        "FR-156",  # Markdown 'Transitive — imported directly (promote to first-class)' subsection
        "FR-157",  # --exclude-tests aggregate-only skip reporting (count, not paths)
        # REQ-17b — Phase 8b — per-language entry-point taxonomy
        "FR-160",  # Java method-invocation walker → kind="method"
        "FR-161",  # Java object_creation_expression → kind="constructor"
        "FR-162",  # Java instance-method attribution via variable_types
        "FR-163",  # Java multi-wildcard signature disambiguation
        "FR-164",  # Java DI / reflective activation entry points
        "FR-165",  # Maven transitive dep_graph from ~/.m2/repository
        "FR-166",  # Maven ${project.version} resolves to leaf POM
        "FR-167",  # Python wildcard import + unqualified-name attribution
        "FR-168",  # Python instance-method via assignment / annotation binding
        "FR-169",  # JS named/default/namespace per-symbol tracking
        "FR-170",  # JS constructor + instance-method attribution
        "FR-171",  # C# constructor + method + type-binding
        "FR-172",  # Go selector / composite literal / type-binding
        # REQ-18 — TypeScript first-class support
        "FR-180",  # @types/X runtime-pair detection
        "FR-181",  # import type distinguished from runtime
        "FR-182",  # .d.ts declare module ambient scan
        "FR-183",  # TS decorator entry-point kind
        "FR-184",  # @types/scope__pkg → @scope/pkg mapping
        # REQ-19 — Phase 9 — per-edge version labels (PR-1)
        "FR-190",  # DepEdge dataclass (frozen) with parent/child/declared_version/scope
        "FR-191",  # Maven _emit_dep_edges records declared <version> per <dependency>
        "FR-192",  # Gradle dep-output edge emission with requested (not resolved) version
        "FR-193",  # npm package-lock v2/v3, yarn.lock, pnpm-lock.yaml edge emission
        "FR-194",  # Markdown reporter renders distinct (canonical, version) tree nodes
        "FR-195",  # Backwards-compat: dep_graph derived from dep_edges in __post_init__
        # REQ-19a — Phase 9 — architecture-derived requirements (NEW-ARCH-009 fixture-present)
        "FR-253",  # Frozen pre-Phase-9 fixtures present for json/sarif/text/markdown reporters
        # REQ-20 — Phase 9 — per-version classification (PR-2)
        "FR-200",  # VersionedNode dataclass + AnalysisResult.versioned_nodes / multi_version_coords
        "FR-201",  # Per-version classification: SAFE only when all parent paths SAFE
        "FR-202",  # Per-version classification: IN_USE if any parent path IN_USE
        "FR-203",  # Resolved-version detection (Maven via dependency:tree)
        "FR-204",  # Resolved-version detection (Gradle via dependencies output)
        "FR-205",  # Resolved-version detection (npm/yarn/pnpm lockfile)
        "FR-206",  # "Multiple versions detected" markdown section
        "FR-207",  # SARIF rule TS-DEP-MULTI-VERSION emission
        # REQ-19a — architecture-derived FRs landing with PR-2 / later
        "FR-250",  # core/classifier.py public surface (NEW-ARCH-006)
        "FR-251",  # Dependency.__post_init__ rejects pin_override AND manifest_redundant (NEW-ARCH-007)
        "FR-254",  # register_pin_detector + register_no_pin_mechanism API (NEW-ARCH-012)
        "FR-255",  # security.safe_subprocess_run API (NEW-ARCH-013)
        "FR-252",  # PinOverrideKind enum closed; values match ADR-007 (NEW-ARCH-008)
        # REQ-21 — Maven pinning detection (PR-3)
        "FR-210",  # Maven <exclusions> collected into an index by (group, artifact)
        "FR-211",  # Pattern (a): direct dep matches an excluded transitive
        "FR-212",  # Maven <dependencyManagement> parsed after property resolution
        "FR-213",  # Pattern (b): direct dep DM-pinned and reached transitively
        "FR-214",  # REQ-20 classifier defers to pin_override (status forced IN_USE)
        "FR-215",  # Markdown / JSON / SARIF report sections for pin-overrides
        # REQ-22 — Cross-version ABI diff (PR-4)
        "FR-230",  # --deep-inspection CLI flag plumbed to JvmSourceAnalyser
        "FR-231",  # _m2_jar_path constructs a confined cache path
        "FR-232",  # javap_public_signatures parses javap -public output
        "FR-233",  # signature_diff yields ADDED / REMOVED / CHANGED sets
        "FR-234",  # Source call-set cross-reference produces RUNTIME_RISK Findings
        "FR-235",  # Markdown / SARIF reporting integration (TS-ABI-*)
        "FR-236",  # "JAR not cached" graceful skip with note
        # COMP-004 — CRA / SBOM runtime-risk surfacing
        "COMP-004",
        # REQ-23 — npm pinning (PR-5)
        "FR-240",  # NpmOverride dataclass + extraction from `overrides`
        "FR-241",  # Extraction from `resolutions` (yarn)
        "FR-242",  # Extraction from `pnpm.overrides`
        "FR-243",  # Targeted overrides nesting (one level)
        "FR-244",  # Pin-override flagging on direct dep matches
        "FR-245",  # REQ-20 classifier defers to npm pin flags
        "FR-246",  # Markdown / JSON / SARIF reporter integration
        # REQ-21b — Gradle pinning (PR-6)
        "FR-220",  # Tree-sitter walker emits GradleForceDirective for force()
        "FR-221",  # Walker emits directive for strictly() in version block
        "FR-222",  # Walker emits directive for constraints {} block
        "FR-223",  # Walker emits directive for resolutionStrategy.eachDependency
        "FR-224",  # Walker emits GradleExclusion for exclude(group, module)
        "FR-225",  # Dynamic-pin downgrade to UNCERTAIN
        # REQ-24 — Remote Index Fetch for --deep-inspection
        "FR-256",  # --index ECOSYSTEM=URL CLI flag, repeatable, order = priority
        "FR-257",  # SCARNO_INDEX_<ECO> env vars; dropped under --allow-remote-fetch
        "FR-258",  # User-config ~/.config/scarno/config.toml [indexes] table
        "FR-259",  # Per-ecosystem override precedence: CLI > user-config > env
        "FR-260",  # --allow-remote-fetch argv-only; requires --deep-inspection
        "FR-261",  # --integrity-cross-check argv-only; ≥2 indexes required to be effective
        "FR-262",  # Minimisation: fetch only multi-version-conflict coords (not all dep_edges)
        "FR-263",  # Pre-fetch disclosure line into result.errors (persistent channel)
        "FR-264",  # Per-attempt structured audit line for every fetch (success/failure/skipped)
        "FR-265",  # Finding.provenance field; conservative remote-tagging
        "FR-266",  # Top-of-report banner when fetches occurred
        "FR-267",  # provenance="remote" not escalated by --fail-on-severity by default; --fail-on-remote-severity opt-in
        # REQ-3 — Python entry-point enumeration (PEP 562 lazy loading)
        "FR-271",  # Module-level __getattr__ (PEP 562): surface used lazy symbols; diagnose unenumerable unused surface
        # REQ-22 — overload-aware ABI diff (SCARNO-BUG-signature-diff)
        "FR-272",  # signature_diff matches at descriptor granularity; a deleted overload of a surviving member is reported
        "FR-273",  # signature_diff output is invariant under PYTHONHASHSEED
        "FR-274",  # ABI findings name the overload (descriptor in message) and sort totally
        # COMP-005 — REQ-24 GDPR compliance touchpoint (consent gate + disclosure)
        "COMP-005",  # GDPR — operator IP disclosure to index hosts; consent via --allow-remote-fetch + PUC-006/008
    }
)

# Threat IDs from threat model
THREAT_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "T-01",
        "T-02",
        "T-03",
        "T-06",
        "T-07",
        "T-08",
        "E-01",
        "E-02",
        "D-01",
        "D-02",
        "D-03",
        "D-04",
        "D-06",
        "D-07",
        "S-02",
        "R-01",
        "I-01",
        "I-03",
        "Rich-01",
        "GAP-06",
        # REQ-17 threats
        "T-17",  # Mermaid label injection
        "T-18",  # --test-paths glob blow-up DoS
        "T-19",  # Test-path echo to verbose log
        "T-20",  # Test-path traversal / separator confusion
        # REQ-24 — Remote Index Fetch threats
        "T-39",  # DNS rebinding TOCTOU between hostname check and TCP connect
        "T-40",  # Compromised / MITM'd index serves coordinated artefact + checksum
        "T-41",  # Coordinate typosquat in untrusted manifest redirects ABI verdict
        "T-42",  # Cache TOCTOU between fetch-write and javap-read
        "T-43",  # --integrity-cross-check false positives from CDN replica drift
        "T-44",  # Malicious manifest as probe oracle against operator's internal index
    }
)

# Performance requirements
PERFORMANCE_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "PERF-001",  # requirements.txt -r depth cap (+ 100-dep parse < 1s)
        "PERF-002",  # javap timeout respected (10s per class)
        "PERF-003",  # JS package-lock.json parse bounded (5k-dep < 2s)
        "PERF-004",  # Go go.sum / go.mod parse bounded (10k-line < 1s)
        "PERF-005",  # C# .sln + *.csproj parse bounded (100-project < 2s)
        "PERF-006",  # tree-sitter per-file parse timeout enforced (all langs)
        "PERF-007",  # REQ-17 — Mermaid render < 200ms for 1k deps; matcher within 2× baseline at 32 patterns
        # REQ-19 — Phase 9
        "PERF-010",  # Tree render with version-keyed nodes within absolute time budget; 8 MiB lockfile parse < 500 ms
        # REQ-19a — Phase 9 (NEW-ARCH-010 partial coverage at PR-2; full at PR-4)
        "PERF-017",  # cap counter atomicity under concurrency
        # REQ-21 — Phase 9 — Maven pinning detection (PR-3)
        "PERF-012",  # Maven _detect_pin_overrides < 50 ms on spring-boot-style fixture
        # REQ-22 — Phase 9 — cross-version ABI diff (PR-4)
        "PERF-014",  # Deep inspection 5×2-jar project < 60 s
        "PERF-015",  # signature_diff: O(n log n) — no quadratic blowup
        # REQ-23 — Phase 9 — npm pinning (PR-5)
        "PERF-016",  # npm pin-detection adversarial perf < 100 ms
        # REQ-21b — Phase 9 — Gradle pinning (PR-6)
        "PERF-013",  # Gradle pin detection per project < 100 ms
    }
)

# Requirements covered by static analysis / CI rules rather than unit tests
# (documented here so the SRTM plugin does not report them as gaps)
STATIC_ANALYSIS_COVERED: frozenset[str] = frozenset(
    {
        "PRV-001",  # OpenGrep rule TS-008 enforces no-network policy
        "SEC-006",  # CI pipeline composition — verified via workflow review
        "SEC-007",  # THREAT_MODEL.md existence — via test_docs.py (Phase 0b)
        "COMP-001",  # THREAT_MODEL.md contents — via test_docs.py (Phase 0b)
        "COMP-006",  # EU CRA — out of scope for open-source v1; documented policy carve-out (docs/scarno-security-privacy-analysis.md), not a behavioural requirement
    }
)

# Negative-path / robustness requirements — a systematic catalogue of
# "what should fail, be rejected, or produce a structured error" tests.
# Each category has a dedicated test class in
# ``tests/unit/test_negative_cases.py`` (current phases) and
# ``tests/unit/test_future_negative_cases.py`` (Phase 4 → 7 xfails).
NEGATIVE_TEST_REQUIREMENTS: frozenset[str] = frozenset(
    {
        "NEG-001",  # Wrong-type input in structured dep files handled gracefully
        "NEG-002",  # Truncated / partial input produces error, not crash
        "NEG-003",  # Encoding edges (BOM, CRLF, non-UTF-8 bytes) survive
        "NEG-004",  # Empty-but-well-formed input produces valid empty output
        "NEG-005",  # CLI edge combinations rejected or handled predictably
        "NEG-006",  # Model / API contract holds on degenerate inputs
        "NEG-007",  # Orchestrator / registry failure modes don't leak traceback
    }
)


ALL_REQUIREMENTS: frozenset[str] = (
    SECURITY_REQUIREMENTS
    | FINDING_REQUIREMENTS
    | PRIVACY_REQUIREMENTS
    | ARCHITECTURE_REQUIREMENTS
    | FUNCTIONAL_REQUIREMENTS
    | THREAT_REQUIREMENTS
    | PERFORMANCE_REQUIREMENTS
    | NEGATIVE_TEST_REQUIREMENTS
)

# Subset of ALL_REQUIREMENTS that must have at least one test case.
TEST_REQUIRED_REQUIREMENTS: frozenset[str] = ALL_REQUIREMENTS
