# REQ-24 — Remote Package-Index Fetch for `--deep-inspection`

> **Operators** — for the day-to-day "how do I turn this on" view of
> this feature (the four argv flags, where to put index URLs, what gets
> fetched and when, what the report shows, and the privacy trade-off),
> read the README's [Remote index fetch](../../README.md#remote-index-fetch)
> section first. This document is the requirements / design / SRTM
> source of truth; the README is the user-facing operating manual.

## Overview

REQ-22 (cross-version ABI diff) reads JARs from `~/.m2/repository`
to compute `NoSuchMethodError`-class runtime-risk findings. When a
declared or resolved version is **not in the local cache** —
common in CI, on a fresh checkout, or whenever `mvn`/`gradle`
hasn't materialised a particular transitive — the diff is silently
skipped and the user gets nothing actionable for that coordinate.

REQ-24 lets the operator configure package indexes (Maven Central,
corporate Nexus, npm registry, etc.) and **opt in** to remote fetch
so REQ-22 can complete its analysis. It is the first scarno
component to cross an outbound-network trust boundary — the existing
architecture is *parse, never execute*; *resolve then confine*;
*report, never fetch*. REQ-24 adds a fourth principle for the new
component: **trust the network as little as possible; make every
disclosure visible; gate every capability on argv.**

**Five argv-only capability flags** govern the new behaviour
(three from REQ-24 v1, plus two added by the corporate-Nexus
enablement amendment of 2026-05-20 — see § "Corporate-Nexus
enablement" below):

| Flag | Default | Effect |
|---|---|---|
| `--allow-remote-fetch` | OFF | Permits outbound HTTPS for cache-miss artefacts. Requires `--deep-inspection`. |
| `--integrity-cross-check` | OFF | When ≥2 indexes are configured for an ecosystem, fetches the artefact from the top 2 and compares bytes; mismatch → HIGH-severity finding. |
| `--fail-on-remote-severity` | OFF | Lets `provenance="remote"` findings escalate `--fail-on-severity`. Off by default — remote findings are visible but advisory. |
| `--allow-private-index-host HOST` | — | **Amendment 2026-05-20.** Per-host opt-in to RFC 1918 / ULA addresses. Required for corporate Nexus instances on private networks. Repeatable. Loopback / link-local / CGNAT / multicast / reserved stay rejected. Requires `--allow-remote-fetch`. |
| `--native-tls` | OFF | **Amendment 2026-05-20.** Use the OS-native trust store via the `truststore` package (same approach as `uv` / `pip` / `hatch`). Cert verification + hostname check remain mandatory. Requires `--allow-remote-fetch`. |

**Anonymous v1.** No credentials are accepted, sent, or stored.
The model reserves an `IndexEndpoint.credential_ref` field for a
future authenticated-registry layer (parallel to the
`coordinate_prefix` reservation).

**HTTPS only, hard reject.** `http://`, `file://`, `ftp://`, and
URLs containing userinfo (`user:pass@`) are rejected at parse and
again at request time.

---

## Option 2 amendment — POM + JAR fetching, minimisation relaxed

> Applies to: every section below that references FR-262 / PRV-005 /
> PUC-005 / "minimisation" / "multi-version-conflict subset". Those
> sections describe **REQ-24 v1** as originally specified; the
> current implementation differs as follows.

**What changed.** REQ-24 v1 minimised off-machine disclosure to the
multi-version-conflict subset of coordinates only (FR-262 / PRV-005)
and fetched JARs alone. In practice this surprised operators: "I
configured an index — why isn't Scarno fetching this missing
dep?" Two gates were responsible — the conflict-subset filter and
JAR-only scope.

Option 2 removes both. The current contract:

| Aspect | REQ-24 v1 | REQ-24 + Option 2 (current) |
|---|---|---|
| What's fetched | JARs only | JARs **and POMs** |
| When fetching fires | Only for multi-version-conflict coords | Any cache-miss the analyser or differ asks for |
| POM walking | Local `~/.m2` only | Local `~/.m2` → REQ-24 fetcher → legacy `mvn dependency:get` CLI, in order |
| Lazy vs pre-fetch | Pre-fetch loop over conflict coords | Lazy `find_jar` triggered on cache-miss |
| Disclosure surface | Conflict subset | Full transitive closure (whatever is requested) |
| Cache-first | Yes | Yes — preserved and tightened (m2 hit → no network even for the lazy `find_jar` callback; see H4 in `abi_diff.py`) |

**What's preserved.** Cache-first ordering. Every other REQ-24
security invariant — `SafeHttpsClient` (SSRF guard, pin-IP, mandatory
TLS), no-fallthrough on HTTP 4xx (SEC-NEW-61), quarantined cache
under `~/.cache/scarno/fetched/` (never `~/.m2`), checksum
verification, per-run fetch-count cap, audit logging, pre-fetch
disclosure into `result.errors`, argv-only capability gates,
configuration sources (CLI > user-config > env with env dropped
under fetch). The pre-fetch disclosure line was reworded to reflect
the broader surface ("Both POMs (transitive walker) and JARs (ABI
diff) will be fetched on cache-miss …").

**Privacy trade-off.** The full transitive closure of coordinates
is now disclosed to configured index hosts when fetch is enabled,
not just conflict coords. For confidential codebases this is a
meaningful widening — see the operator-facing summary in
`docs/LIMITATIONS.md` (PRV-007 section). The compensating controls
are visibility (every fetch in the audit channel), cache-first
(only true misses go to the network), and the argv-only fetch gate
(operator must deliberately opt in per-run).

**Requirements affected** (status: superseded — original wording
kept below as historical context):

- **FR-262** (minimise to multi-version-conflict coords) — relaxed.
  The fetcher now serves any coord the orchestrator asks about.
- **PRV-005 / PUC-005** (off-machine disclosure minimised to the
  conflict subset) — relaxed in the same way. Cache-first is now
  the load-bearing disclosure-reducer rather than the minimisation
  filter.

**Tests reflecting the new contract:**
- `tests/integration/test_req24_slice_e_wiring.py::TestLazyFindJarFetchesAnyCoord`
  — asserts non-conflict coords ARE fetched (the inverse of the
  pre-Option-2 TA-332 assertion).
- `tests/integration/test_req24_option2_pom_and_jar_fetch.py` —
  POM fetch wiring through `MavenPomResolver._locate_or_fetch_pom`;
  m2-first cache-priority in `CrossVersionAbiDiffer._resolve_jar`.

---

## Corporate-Nexus enablement amendment (2026-05-20)

> Applies in addition to v1 + Option 2. Adds two argv-only capability
> flags so the original "operator points Scarno at their corp
> Nexus" use case becomes actually reachable. **Does not relax any
> v1 control silently** — every relaxation is an explicit per-run
> operator opt-in, off by default, argv-only.

**Why this was needed.** REQ-24 v1's SSRF guard hard-rejected every
RFC 1918 / ULA address — correct for defeating arbitrary-host SSRF,
but corporate Nexus deployments live on those exact ranges (split-
horizon DNS for `nexus.corp.example.com` typically returns `10.x.x.x`
internally). Separately, `ssl.create_default_context` reads Python's
bundled trust store, which on **macOS and Windows does not include
the OS keychain** — so a corporate CA installed by IT to the keychain
went untrusted and TLS handshakes failed with
`CERTIFICATE_VERIFY_FAILED`. Both had to be fixable for the operator
to use REQ-24 against the most common real-world target, and neither
could be fixed silently without weakening defaults for the public-
index case.

**What's added:**

| Flag | Effect |
|---|---|
| `--allow-private-index-host HOST` (repeatable) | Relaxes `_ip_is_safe` for `HOST` only: RFC 1918 (10/8, 172.16/12, 192.168/16) and ULA (`fc00::/7`) become reachable for that hostname. Loopback, link-local (169.254.x including cloud-metadata at 169.254.169.254), CGNAT, multicast, reserved, and unspecified ranges **stay rejected even with allow-list** — those are not legitimate corp-index endpoints and relaxing them would expand attack surface without operator benefit. |
| `--native-tls` | Swaps `ssl.create_default_context()` for `truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` — same OS-native trust mechanism as `uv` / `pip` / `hatch` / `pdm`. `CERT_REQUIRED` + `check_hostname=True` + TLS 1.2 floor are preserved identically; only the trust roots change. |

**Security invariants preserved** (every one of these still holds when both flags are set):

- HTTPS-only (hard reject of `http://`, `file://`, userinfo).
- DNS-rebinding defence — `SafeHttpsClient` still resolves once,
  validates the IP, pins it, connects to the IP literal, re-checks
  `getpeername()` post-connect. The allow-list does not weaken this;
  it only changes which IPs pass the IP-validation step.
- Cross-host redirects **do NOT inherit** the allow-list — per-hop
  re-validation against the original argv-supplied list (N-13).
- Quarantined cache (mode 0700, every write through
  `resolve_and_confine`), per-run fetch-count cap, audit logging,
  no-fallthrough on 4xx — unchanged.
- Both `--native-tls` and `--allow-private-index-host` require
  `--allow-remote-fetch`; CLI exits 2 with operator-readable message
  otherwise. Argv-only setter pattern enforced by static-analysis
  test (SUC-78).
- `truststore` import is **lazy** (only when `--native-tls` is set),
  so the default path has zero behavioural or supply-chain exposure
  (N-14).

**New requirements** added by the amendment (cross-referenced in §9.12.7 of `THREAT-MODEL.md`):

| ID | Requirement |
|---|---|
| **FR-268** | Argv-only `--allow-private-index-host HOST` (repeatable). Per-host opt-in to private-IP reachability. Repeated for each host explicitly named. |
| **FR-269** | Argv-only `--native-tls` flag. When set, `SafeHttpsClient` constructs its SSL context via `truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` rather than `ssl.create_default_context()`. |
| **FR-270** | Analyser-startup advisory — `--allow-private-index-host HOST` named without a matching `--index` host entry emits an audit warning ("allowance is inert until you also register an index for this host"). |
| **SEC-NEW-75** | `_ip_is_safe(ip, *, allow_private=False)` — when `allow_private=True`, only RFC 1918 + ULA are unblocked. Loopback / link-local / CGNAT / multicast / reserved / unspecified stay blocked regardless. |
| **SEC-NEW-76** | `SafeHttpsClient(private_index_hosts=...)` — opaque `frozenset[str]` of lowercased hostnames, checked per-hop against the CURRENT request hostname (post-redirect — never inherited from origin host). |
| **SEC-NEW-77** | `SafeHttpsClient(native_tls=False)` — when True, native context built; `verify_mode == CERT_REQUIRED`, `check_hostname is True`, and `minimum_version >= TLSv1_2` asserted defensively. |
| **SUC-78** | CLI parse-time: `--allow-private-index-host`, `--native-tls`, `--integrity-cross-check`, `--fail-on-remote-severity` each require `--allow-remote-fetch`; otherwise exit code 2. |
| **SUC-79** | Analyser-startup orphan-host advisory implementation (FR-270). |
| **N-13** | Cross-host redirects MUST NOT inherit `private_index_hosts`. |
| **N-14** | `truststore` import MUST be lazy (inside `_build_native_tls_ssl_context`); top-level `import truststore` in `src/` is forbidden. |
| **N-15** | `--native-tls` MUST NOT bypass `CERT_REQUIRED` or `check_hostname=True`; both branches of `_build_*_ssl_context` assert these. |

**Tests landing with the amendment:**

- `tests/security/test_req24_private_index_host_allowlist.py`:
  - `TestIpSafeRespectsAllowPrivate::test_private_accepted_when_allow_private_true`
    — RFC 1918 + ULA are reachable with the opt-in.
  - `TestIpSafeRespectsAllowPrivate::test_never_relaxed_for_non_private_ranges`
    — loopback, link-local (incl. AWS metadata), CGNAT, multicast,
    reserved, unspecified, IPv6 equivalents, and IPv4-mapped IPv6
    NEVER reachable, even with allow-list (T-45 closure).
  - `TestIpSafeRespectsAllowPrivate::test_default_still_rejects_private`
    — sanity: without the opt-in, behaviour is unchanged.
  - `TestAllowListPermitsCorpNexus::test_corp_host_resolves_to_private_ip_succeeds`
    — headline use case end-to-end.
  - `TestAllowListPermitsCorpNexus::test_non_listed_corp_host_resolving_to_private_ip_fails`
    — allowance is per-host, not blanket.
  - `TestAllowListPermitsCorpNexus::test_loopback_blocked_even_when_host_is_allow_listed`
    — N-13-adjacent: explicit pin on T-45 closure.
  - `TestAllowListPermitsCorpNexus::test_case_insensitive_hostname_match`
    — operator-supplied casing matches lowercased URL host.
  - `TestAllowListPermitsCorpNexus::test_first_safe_ip_wins_when_mixed`
    — deterministic DNS handling.
  - `TestAllowListPermitsCorpNexus::test_empty_allow_list_is_default` /
    `test_whitespace_and_empty_entries_dropped` — constructor hygiene.

- `tests/security/test_req24_native_tls.py`:
  - `TestTruststoreAvailable::test_truststore_importable` — dep
    contract.
  - `TestNativeTLSContext::test_native_context_uses_truststore`
    — context type assertion.
  - `TestNativeTLSContext::test_native_context_verifies_certs` /
    `test_native_context_pins_tls12` — N-15 enforcement.
  - `TestSafeHttpsClientWiring::test_default_client_uses_bundled_context`
    — no behavioural drift for existing callers.
  - `TestSafeHttpsClientWiring::test_native_tls_flag_swaps_context`
    — flag actually takes effect.
  - `TestSafeHttpsClientWiring::test_native_tls_preserves_verification`
    — N-15 again at the public API surface.
  - `TestSafeHttpsClientWiring::test_default_path_still_intact`
    — defaults unchanged across the amendment.

**Operator-facing documentation** for the amendment lives in the
README's [Remote index fetch](../../README.md#remote-index-fetch)
section (five-flag table + corporate-Nexus three-flag recipe).
Threat-level closure trace is in `docs/THREAT-MODEL.md` §9.12.7.

---

## Problem Statement

REQ-22 today silently skips coordinates whose JARs aren't in
`~/.m2`:

```
$ scarno ./service --deep-inspection
…
WARNINGS (3)
  ! abi-diff: declared version com.google.guava:guava@28.0-jre
    not cached in m2; skipping diff.
  ! abi-diff: declared version org.apache.commons:commons-lang3@3.9
    not cached in m2; skipping diff.
  …
```

The user is left without a verdict on exactly the conflicts they
ran `--deep-inspection` to investigate. Manually warming the cache
(`mvn dependency:resolve`) is awkward in CI and impossible for
artefacts behind a corporate Nexus.

REQ-24 closes the gap: with `--allow-remote-fetch` and at least
one configured index, the missing artefact is fetched (HTTPS,
SSRF-guarded, checksummed, size-capped, into a quarantined cache),
the diff completes, and findings derived from the fetched bytes
are tagged `provenance="remote"` so the operator can see which
verdicts depended on network trust.

---

## Solution

### 1. Index configuration sources

Three trusted sources, with explicit precedence:

```text
CLI  >  user-level config  >  env var
```

Per-ecosystem **override** (not merge): the highest-precedence
source that mentions an ecosystem owns its whole list.

**CLI:** `--index ECOSYSTEM=URL`, repeatable; declaration order
within an ecosystem = priority order.

```bash
scarno . --deep-inspection --allow-remote-fetch \
  --index maven=https://nexus.corp.example.com/repository/maven-public \
  --index maven=https://repo1.maven.org/maven2 \
  --index npm=https://registry.npmjs.org
```

**Env vars:** `SCARNO_INDEX_<ECOSYSTEM>`, space-separated URLs,
order = priority. Per-ecosystem env var matches the idiom of
`PIP_INDEX_URL`, `GOPROXY`, `npm_config_registry`. **Dropped with
a warning when `--allow-remote-fetch` is set** (env in CI is
shared mutable state — lower trust in dangerous mode).

**User config:** `~/.config/scarno/config.toml` (or
`$XDG_CONFIG_HOME/scarno/config.toml`), `[indexes]` table,
arrays per ecosystem; array order = priority.

```toml
[indexes]
maven = [
  "https://nexus.corp.example.com/repository/maven-public",
  "https://repo1.maven.org/maven2",
]
npm = ["https://registry.npmjs.org"]
```

**Repo-local config** (`pyproject.toml`, `.scarno.toml` inside
the analysed tree) is **deliberately ignored** as an index source.
A repo-local `[indexes]` key emits a warning in `result.errors` so
it is not silently lost. This is the keystone control: a cloned
repo cannot inject an index URL.

### 2. `security.resolve_user_config_path()` — anchored discovery

A single shared helper is the **sole** way any scarno
component locates a user-config file:

```python
def resolve_user_config_path(name: str) -> Path | None:
    """Return $XDG_CONFIG_HOME/scarno/<name> or
    ~/.config/scarno/<name>; returns None if absent.

    Anchored to Path.home() / $XDG_CONFIG_HOME ONLY — never CWD,
    never the analysed project path. If $XDG_CONFIG_HOME resolves
    under Path.cwd() OR under the analysed project root, falls
    back to ~/.config and emits USER_CONFIG_REJECTED_XDG audit.
    """
```

This closes E1/E2 (the "config discovery anchored anywhere other
than home reintroduces the supply-chain backdoor" finding from the
threat model). A static-analysis test rejects any `open()` of a
config file outside this helper, mirroring the existing TS-003
pattern.

### 3. `--allow-remote-fetch` — argv-only capability gate

Mirrors the SEC-NEW-56 pattern (`--deep-inspection` is argv-only).
`--allow-remote-fetch`:

- Requires `--deep-inspection`. Without it → parse-time hard error
  (not a silent no-op).
- Cannot be set via env, config, `_RunOptions` default,
  `run_analysis()` test helper, or any non-argv path. A security
  test (TA-330) replicates `test_req22_deep_inspection_argv_only.py`
  exactly.
- When OFF: `IndexConfigResolver` still parses + validates index
  URLs (so misconfigurations are caught), but **zero outbound
  packets** leave the machine. Cache misses remain warnings.

### 4. `ValidatedCoordinate` — coordinate is untrusted input

Coordinates parsed from the analysed repo's manifests are
attacker-controlled. URL templating and cache-path construction
must never see a raw `str`:

```python
@final
@dataclass(frozen=True)
class ValidatedCoordinate:
    ecosystem: str
    components: tuple[str, ...]
    # Constructor takes a private _ValidatorToken supplied only by
    # CoordinateValidator.validate(); direct instantiation raises.
```

`CoordinateValidator` is per-ecosystem. Maven's wraps the existing
`_validate_gav`. Validators reject URL/path-reserved characters,
`..`, CRLF, control bytes, and length-cap each component.
Ecosystems without a registered validator are not fetchable —
fail-closed at parse time.

`RemoteArtifactFetcher.fetch()` accepts `ValidatedCoordinate`
**only** — no overload for `str`. A static-analysis lint asserts
no URL/path construction site outside `coordinate_validator.py`
constructs `ValidatedCoordinate` directly.

### 5. `SafeHttpsClient` — the only outbound-HTTPS path

Per request:

```text
1.  Reject scheme != "https" and any URL with userinfo.
2.  Resolve hostname → all A/AAAA records.
3.  For every IP returned, reject if in any of:
      IPv4: loopback / link-local / private (RFC 1918) / CGNAT /
            multicast / reserved
      IPv6: ::1, fc00::/7, fe80::/10, ff00::/8, IPv4-mapped
            equivalents (with zone-id stripped before match)
4.  Pick one valid IP → PIN it.
5.  TCP-connect to the pinned IP:443 (no DNS at connect time);
    SNI = original hostname; Host: header = original hostname.
6.  After connect, re-check getpeername() == pinned IP. If not,
    abort before any bytes are sent.
7.  TLS handshake with mandatory cert verification (not configurable
    on the prod path; injection seam is typed to SafeHttpsClient
    instances, not arbitrary callables).
8.  HTTP/2 connection coalescing / pooling DISABLED across
    distinct request hostnames — one connection per
    (pinned-IP, hostname) tuple, never reused for a different host.
```

This defeats DNS-rebinding TOCTOU (the textbook SSRF bypass
against hostname-only validation). HTTP/2 pool-coalescing
disablement is the implementation invariant that prevents a
modern HTTPS client from quietly reusing a TLS connection for a
different hostname (closing finding N-2 from the closing
threat-model pass).

**Redirect policy:** ≤2 hops. Each hop re-runs steps 1–7. Any
cross-host redirect drops **all** request headers (defines the
auth-header rule for the v2 layer now). >2 hops → reject + audit.

### 6. `RemoteArtifactFetcher` and the quarantined cache

```python
class RemoteArtifactFetcher:
    def fetch(
        self,
        coord: ValidatedCoordinate,
        version: str,
        endpoints: list[IndexEndpoint],
    ) -> Path | None:
        """Returns a path in the quarantined cache, or None
        with a sanitised audit line appended to result.errors."""
```

**Invariants:**

| Invariant | ID | Detail |
|---|---|---|
| HTTPS-only at parse + request time | SEC-NEW-66 | No `http://`, `file://`, `ftp://`, no userinfo. |
| Coordinate-driven; no enumeration | SUC-52 (REQ-22) | Only fetches coords already present in `result.dep_edges`, MINUS those locally cached, MINUS those quarantined. |
| ~~**Minimisation to conflict coords**~~ ⚠ superseded by Option 2 | ~~FR-262 / PRV-005~~ | ~~Only the multi-version-conflict subset is eligible — the rest of `dep_edges` is never disclosed off-machine.~~ See the [Option 2 amendment](#option-2-amendment--pom--jar-fetching-minimisation-relaxed); current behaviour fetches the full transitive closure on cache-miss. |
| Per-artefact size cap | SEC-NEW-68 | 64 MiB at fetch time. |
| Per-run fetch-count cap | SEC-NEW-69 | Lock-counted, mirroring `_JAVAP_MAX_JARS_PER_RUN`. |
| Per-request timeout + total fetch-time budget | SEC-NEW-69 | Bounds Slowloris and aggregate. |
| Decompression-bomb cap on read | SEC-NEW-73 | Cap on decompressed size + entry count when reading the JAR. |
| Checksum verification | (corruption only) | Prefer sha512/sha256; sha1 accepted with warning; no-digest available is a degraded-trust audit line. **TLS is the adversarial-integrity control; checksum is corruption detection** (SUC-66). |
| No fallthrough on HTTP 4xx | SEC-NEW-61 | 4xx is authoritative; only connection-level failures fall through. Prevents leaking internal coords to public indexes. |

**Quarantined cache:**

```text
~/.cache/scarno/fetched/<ecosystem>/<group>/<artifact>/<version>/
```

| Property | ID | Default |
|---|---|---|
| Mode 0700 on cache root | SEC-NEW-64 | Required |
| Every write through `resolve_and_confine` | SEC-NEW-65 | Required |
| Total-size cap with LRU eviction | SEC-NEW-66 | 1 GiB (configurable in user-config only) |
| Per-artefact TTL | SEC-NEW-67 | 30 days (configurable in user-config only) |

**Never** written into `~/.m2/repository`, `node_modules`, or any
other native cache — would let a hostile index poison the user's
real builds.

### 7. Audit + disclosure pipeline

```python
# Pre-fetch — emitted ONCE before any network call:
result.errors.append(
    "About to fetch N artefact(s) from M index host(s) [host1, host2]. "
    "Your machine's IP address will be visible to those hosts. "
    "Coordinates: com.example:lib, com.google.guava:guava, … (+3 more)"
)

# Per-attempt — emitted for every fetch (success / failure / skipped):
result.errors.append(
    "fetched com.google.guava:guava:28.0-jre from "
    "https://repo1.maven.org/maven2 (sha256 ok, provenance=remote)"
)
```

The disclosure and audit lines land in `result.errors` (NOT
stderr-only) so they persist in JSON / SARIF / Markdown output.
**If appending the disclosure fails, the fetch must abort** —
fail-secure on audit emission (closes finding N-4).

A `credential_ref` is **never** logged when the v2 auth layer
lands — the redaction rule is defined in the v1 audit-line format
now, not bolted on later.

### 8. `provenance` on findings + report banner

```python
@dataclass
class Finding:
    # … existing fields …
    provenance: str = "local"  # "local" | "remote"
```

**Conservative tagging:** if EITHER side of an ABI comparison was
sourced from the quarantined cache, the resulting finding carries
`provenance="remote"`. Visible in JSON, SARIF, Markdown,
text reporters.

**Top-of-report banner** when any fetches occurred:

```text
⚠ This analysis fetched 4 artefact(s) from non-cache indexes;
  3 finding(s) have provenance=remote (verdict depended on
  network trust — see --fail-on-remote-severity to gate CI on these).
```

`--fail-on-severity` does **not** escalate `provenance="remote"`
findings by default. Operators who want strict CI gating opt in
with `--fail-on-remote-severity` (argv-only, requires
`--allow-remote-fetch`). Rationale: when an attacker controls the
fetched bytes (T-40 compromised index, T-41 typosquat coordinate),
they can fabricate any verdict; the protection is **visibility**,
not gating. Operators who understand the trade-off can opt into
gating.

### 9. `--integrity-cross-check` — opt-in adversarial integrity

When set AND ≥2 indexes are configured for an ecosystem, the
fetcher pulls the same artefact from the top 2 priority indexes
and compares sha256 of the bytes. Mismatch → reject + emit
`TS-INTEGRITY-MISMATCH` (HIGH).

**Retry-once on mismatch** (SUC-70) absorbs CDN-replica drift:
on byte disagreement, jittered backoff (250ms ± 100ms) and
re-fetch from the disagreeing index; only emit the finding if
disagreement persists. Avoids "boy who cried wolf" eroding the
control.

**Startup warning** when `--allow-remote-fetch` is set AND ≥2
indexes are configured for any ecosystem AND `--integrity-cross-check`
is absent: "indexes for `<eco>` could be cross-checked; pass
`--integrity-cross-check` to verify byte-identical artefacts
across indexes."

---

## Use Cases

```
UC-080: Operator analyses a JVM project where some transitive JARs
        are not in ~/.m2.
Actor: Operator running scarno with --deep-inspection.
Goal: Get cross-version ABI breaking-change findings even when the
      local cache is incomplete.
Preconditions:
  - Indexes configured (CLI / env / user-config).
  - --deep-inspection set.
  - --allow-remote-fetch set on argv.
Main flow:
  1. IndexConfigResolver merges trusted index sources by precedence.
  2. Orchestrator computes the multi-version-conflict subset of
     dep_edges; subtracts coords already in any local cache.
  3. Pre-fetch disclosure line emitted into result.errors.
  4. For each (coord, version): validate coord; SafeHttpsClient
     against the highest-priority eligible index; verify checksum;
     write into the quarantined cache.
  5. CrossVersionAbiDiffer runs against merged local + quarantined
     cache; findings derived from quarantined artefacts are tagged
     provenance="remote".
  6. Report includes the top-of-report banner naming N artefacts
     fetched and M findings with provenance=remote.
Postcondition: ABI findings produced; audit trail of every fetch
               attempt persists in result.errors.

UC-081: Operator runs scarno on a repo with malicious manifests
        WITHOUT --allow-remote-fetch.
Actor: Operator analysing a possibly-hostile repository safely.
Preconditions: --deep-inspection may or may not be set.
Main flow:
  1. IndexConfigResolver parses + validates configured URLs (inert).
  2. NO network call is made regardless of what config says.
  3. Cache misses appear as sanitised warnings.
Postcondition: analysis completes with zero outbound packets.
Trust boundary crossings: NONE outbound. Repo-local config files
                          cannot influence indexes by construction.

UC-082: Operator opts into adversarial-integrity verification.
Actor: Operator running scarno with --allow-remote-fetch
       --integrity-cross-check.
Goal: Detect when a malicious or compromised index serves
      coordinated-but-different bytes.
Preconditions: ≥2 indexes configured for the ecosystem.
Main flow:
  1. For each fetched (coord, version), fetch from the top-2
     priority indexes.
  2. Compare sha256 of the bytes.
  3. On mismatch: jittered backoff + retry once (CDN-drift defence);
     persistent disagreement → reject + emit TS-INTEGRITY-MISMATCH.
Postcondition: bytes that survived the cross-check are analysed;
               disagreements surface as HIGH findings.
```

---

## Abuse Cases

```
SAC-018: Coordinate typosquat redirects ABI verdict
Linked threat: T-41
Attacker type: Repository author / contributor with PR access.
Goal: Make a real breaking change look safe (or vice versa).
Attack flow:
  1. Attacker introduces a near-name dependency
     (com.gooogle.guava:guava — typo) in the repo's pom.xml,
     e.g. as a build-only dep no human reviews.
  2. Operator scans the repo with --deep-inspection
     --allow-remote-fetch.
  3. Scarno fetches the attacker's typosquatted JAR from the
     configured public index.
  4. ABI diff is computed against attacker-prepared bytes.
  5. Operator merges based on a corrupted verdict.
Impact: Scarno's own security output is wrong.
OWASP: A08:2021 Software & Data Integrity Failures.
Mitigated by: SUC-68 (provenance=remote tag + banner makes
              network-trust-dependent verdicts visible) +
              FR-267 (default does not escalate CI failure on
              remote-derived findings; operator opts in only with
              awareness of the trade-off).

SAC-019: Malicious manifest as a probe oracle against operator's index
Linked threat: T-44
Attacker: Repository author of a widely-scanned project.
Goal: Map the operator's internal Nexus contents.
Attack flow:
  1. Attacker declares com.victim-corp:internal-name at multiple
     versions in their public repo's pom.xml.
  2. Each operator who scans the repo with --allow-remote-fetch
     against an internal Nexus issues a probe for that coordinate.
  3. 200 vs 404 responses, accumulated across operators, map names
     present in the operator's Nexus.
Mitigated partially by: SEC-NEW-61 (no fallthrough on 4xx — single
                        index per probe per session); FR-264 (every
                        probe is audited and visible); PRV-007
                        (operator awareness via docs); v2 SEC-NEW-70
                        (coordinate_prefix scoping).

SAC-020: DNS rebinding TOCTOU between hostname validation and connect
Linked threat: T-39
Attacker: External — controls DNS for an operator-configured index
          domain (e.g., compromised authoritative server).
Goal: Trick scarno into connecting to a private/internal IP
      after public-IP validation passes.
Mitigated by: SUC-65 / SEC-NEW-60 — SafeHttpsClient resolves once,
              validates the IP, pins it, connects to the pinned IP;
              pre-connect peer-name re-check; HTTP/2 pool-coalescing
              disabled (closes N-2).
OWASP: A10:2021 SSRF.

SAC-021: Compromised / MITM'd index serves coordinated artefact + checksum
Linked threat: T-40
Attacker: Operator of a configured index, OR network MITM
          (TLS-defeated).
Goal: Control the bytes scarno analyses and thus the ABI verdict.
Mitigated by: SUC-66 (HTTPS-only — TLS is the adversarial-integrity
              control; checksum-from-same-source is corruption
              detection only); SUC-67 (--integrity-cross-check
              opt-in cross-index byte comparison detects the case
              where one of two indexes is compromised).
OWASP: A08:2021 Software & Data Integrity Failures.
```

---

## Privacy

```
PT-005: Linkability — Project fingerprinting across fetch sessions
LINDDUN: Linkability + Identifiability
Affected data: the multi-version-conflict coordinate set per session.
Affected data subjects: operators of confidential codebases; the
                        organisation owning the project.
Description: An index host (or a passive observer at the host)
             records the conflict-coord set per session; the set is
             a project-distinguishing fingerprint that links sessions
             back to a specific project over time.
Likelihood: High (always happens when fetch is used) ·
Impact: Medium for confidential projects.
GDPR relevance: Art. 5(1)(c) data minimisation — even when the
                index host is "legitimate", non-essential disclosure
                violates the minimisation principle.

PT-006: Non-repudiation harming the operator
LINDDUN: Non-repudiation (LINDDUN sense — harming the user)
Description: Index access logs at the index host record the
             operator's IP, timestamp, and the coordinates queried.
             The operator cannot later deny those queries occurred.
Affected data: operator IP + coordinate query log at third party.
Likelihood: High · Impact: Low to Medium depending on context.

PT-007: Unawareness — operator IP disclosure to index hosts
LINDDUN: Unawareness
Description: --allow-remote-fetch is honest about *fetching* but
             does not by default inform the operator that their IP
             address is logged at the index host (a third-party
             data controller).
Likelihood: Medium · Impact: Low (limited PII).

PUC-005: Minimise to multi-version-conflict coordinates
  ⚠ superseded by Option 2 — see top of file. Cache-first ordering
  is now the load-bearing disclosure-reducer in this code path.
Mitigates: PT-005, PAC-005, I1.
Privacy control: Fetcher input is the multi-version-conflict subset
                 of result.dep_edges, NOT all edges. Coordinates
                 with no version conflict are never disclosed.
PbD principle: Privacy by Default; Data Minimisation.
GDPR: Art. 5(1)(c).

PUC-006: Pre-fetch disclosure into the persistent report channel
Mitigates: PT-006, PT-007, PAC-005.
Privacy control: Before the first fetch, a single line is appended
                 to result.errors (NOT stderr-only) naming the
                 count of coordinates and the host(s) about to
                 receive them. Persists in JSON / SARIF / Markdown.
PbD principle: Visibility and Transparency.

PUC-007: Per-attempt audit line for every fetch
Mitigates: R1, PT-006.
Privacy control: Every fetch attempt — success, failure, AND skipped
                 (cap, ineligible, validation reject) — emits a
                 structured line into result.errors with
                 (coord, resolved-host, index-url, digest-algo,
                 outcome). Never logs credential_ref or credentialed
                 URLs (defines the v2 invariant now).
PbD principle: Visibility and Transparency; Accountability.

PUC-008: Disclosure line names IP-disclosure explicitly
Mitigates: PT-007.
Privacy control: PUC-006's disclosure line includes the literal
                 phrase "your machine's IP address will be visible
                 to: <hosts>".
PbD principle: Visibility and Transparency.
```

---

## Performance

```
PERF-018: Remote fetch budget per analysis run
- Per request timeout: 30s (matches javap timeout).
- Per artefact size cap: 64 MiB.
- Per-run fetch-count cap: 128 (mirrors _JAVAP_MAX_JARS_PER_RUN).
- Total fetch-time budget per run: 5 minutes.
- Cross-check (when enabled) doubles fetch volume per artefact —
  acceptable as opt-in.

PERF-019: Cache lookup is constant-time
- Quarantined cache layout mirrors ~/.m2; lookup is O(1) per coord.
- LRU touch on access is O(1) amortised; eviction is O(log N) on
  the size-ordered index.
```

---

## Security Use Cases (Countermeasures)

```
SUC-65: SafeHttpsClient pin-resolved-IP semantics
Mitigates: SAC-020, T-39 (DNS rebinding); extends T-04 SSRF family.
Control: Resolve hostname → all A/AAAA → validate every IP against
         IPv4+IPv6+IPv4-mapped private/loopback/link-local/CGNAT/
         multicast/reserved deny-list → connect to chosen IP
         directly with SNI/Host header set → re-check getpeername()
         matches the pinned IP after connect.
Implementation invariants:
  - Mandatory cert verification non-overridable on the prod path;
    injection seam typed to SafeHttpsClient instances only.
  - HTTP/2 connection coalescing / pooling DISABLED across distinct
    request hostnames.
  - IPv6 zone-id stripped before deny-list match.

SUC-66: HTTPS-only hard reject; TLS as adversarial integrity
Mitigates: SAC-021, T-40 family (MITM).
Control: All non-https:// URLs rejected at parse AND at request time.
         Mandatory cert verification. Project documentation re-frames
         TLS as the adversarial-integrity control; checksum is
         corruption-detection only.

SUC-67: --integrity-cross-check optional cross-index byte comparison
Mitigates: SAC-021, T-40 (compromised single index).
Control: Argv-only flag (mirrors SEC-NEW-56 / --allow-remote-fetch).
         When set, fetches the artefact from the top-2 priority
         indexes for the ecosystem and compares sha256 of bytes.
         Mismatch → reject artefact; emit TS-INTEGRITY-MISMATCH
         (HIGH).

SUC-68: Finding.provenance="remote" tagging + report banner
Mitigates: T-41 (typosquat); SAC-018; T-7 (verdict integrity);
           consistency with TS-SI-008/015.
Control: Every Finding produced from a fetched artefact carries
         provenance="remote". Conservative tagging: if EITHER side
         of a comparison was remote, the finding is remote. By
         default --fail-on-severity does NOT escalate
         provenance="remote" findings — visibility without forced
         CI failure on network-trust-dependent verdicts.

SUC-69: Quarantined cache hardening (split into 5 controls)
  SUC-69a: Cache root mode 0700.                 Mitigates I3, T5.
  SUC-69b: Every cache write through
           resolve_and_confine(candidate, root). Mitigates T5.
  SUC-69c: Total-size cap with LRU eviction.     Mitigates D2.
  SUC-69d: Per-artefact TTL.                     Mitigates D2.
  SUC-69e: Per-artefact size cap at fetch time.  Mitigates D2.

SUC-70: --integrity-cross-check retry-once before declaring mismatch
Mitigates: T-43 (CDN-replica-drift false positive).
Control: On byte disagreement, jittered backoff (250ms ± 100ms)
         and re-fetch from the disagreeing index; only emit
         TS-INTEGRITY-MISMATCH if disagreement persists.

SUC-71: HTTP 4xx is authoritative — no cross-index fallthrough
Mitigates: I2 cross-trust-domain leak; PAC-005 (operator-side).
Control: Fetcher fallback occurs ONLY on connection-level failure
         (DNS, TLS, timeout, 502/503/504). Any other 4xx/5xx is
         final for that index.

SUC-72: Resolver discovery is sole-helper, home-anchored, XDG-confined
Mitigates: E1 (Critical), E2.
Control: All user-config paths resolved via
         security.resolve_user_config_path() — the SOLE locator,
         anchored to Path.home() / $XDG_CONFIG_HOME ONLY.
         If $XDG_CONFIG_HOME resolves under Path.cwd() OR under
         the analysed project root → fall back to ~/.config and
         emit USER_CONFIG_REJECTED_XDG audit. Never walks CWD or
         project-relative paths. A static-analysis test rejects
         config-file open() outside the helper.

SUC-73: ValidatedCoordinate opaque type; non-bypassable validation
Mitigates: T3 (coordinate as untrusted), T-41 (partial — syntactic
           validation cannot catch typosquats by definition).
Control: Fetcher signature accepts ValidatedCoordinate only.
         Construction is module-private (private _ValidatorToken);
         only obtainable via CoordinateValidator.validate(ecosystem,
         raw). Per-ecosystem validators reject URL/path-reserved
         characters, '..', CRLF, control bytes, length-cap each
         component. Ecosystems without a registered validator are
         fail-closed at parse time.

SUC-74: Env-sourced indexes inert in dangerous mode
Mitigates: SC1 (env as CI-shared mutable state).
Control: When --allow-remote-fetch is set, env-sourced indexes are
         dropped with a warning. Only CLI and user-config indexes
         survive into the fetch path.

SUC-75: Redirect policy ≤2 hops with full re-validation per hop
Mitigates: SC3, T4 chain via redirects.
Control: SafeHttpsClient follows ≤2 hops; each hop re-runs
         hostname-resolve → IP-deny → pin → connect → re-check.
         Cross-host redirect drops ALL request headers (defines the
         v2 auth-header rule); >2 hops → reject + audit.

SUC-76: --allow-remote-fetch is argv-only, requires --deep-inspection
Mitigates: E3, E4.
Control: Sole setter is argv. _RunOptions.allow_remote_fetch defaults
         False; run_analysis() helper cannot set it; no env path;
         no config path. --allow-remote-fetch without
         --deep-inspection → parse-time hard error with explanatory
         message. Mirror test_req22_deep_inspection_argv_only.py.
```

---

## Threat Model Additions

| ID | Threat | Mitigation |
|---|---|---|
| T-39 | DNS rebinding TOCTOU between hostname check and connect. | SUC-65 / SEC-NEW-60 — pin-resolved-IP. |
| T-40 | Compromised / MITM'd index serves coordinated artefact + checksum. | SUC-66 (HTTPS-only / TLS) + SUC-67 / SEC-NEW-71 (--integrity-cross-check opt-in). |
| T-41 | Coordinate typosquat in untrusted manifest. | SUC-68 (provenance tag visibility). Deeper mitigation deferred (no clean technical fix without curated allow-list). |
| T-42 | Cache TOCTOU between fetch-write and javap-read. | SEC-NEW-64 (0700) + SEC-NEW-65 (confined writes). Defence-in-depth: re-verify checksum at javap-time (recommended, optional v1). |
| T-43 | --integrity-cross-check false positives from CDN replica drift. | SEC-NEW-74 / SUC-70 — retry-once-on-mismatch. |
| T-44 | Malicious manifest as probe oracle against operator's index. | SEC-NEW-61 (no 4xx fallthrough — single index per probe) + FR-264 (audit visibility) + PRV-007 (operator awareness). v2 deeper fix: SEC-NEW-70 coordinate_prefix scoping. |

---

## Compliance

```
COMP-005: GDPR — Operator IP disclosure to index hosts
Origin: REQ-24 remote fetch.
Scope: GDPR Art. 5(1)(c) data minimisation; Art. 13 information
       to be provided when collecting data from the data subject.
Rationale: When an individual operator runs scarno with
           --allow-remote-fetch, their machine IP is disclosed to
           the configured index hosts (third-party controllers).
           Lawful basis is informed consent — the --allow-remote-fetch
           argv flag is the consent point, made informed by the
           PUC-006/008 pre-fetch disclosure naming hosts and IP
           visibility.
Implementation: PRV-006 disclosure line + PRV-007 operator-facing
                docs section.
Tests: TA-355 (disclosure line content).

COMP-006: CRA — out of scope for scarno as open-source v1
Origin: REQ-24.
Scope: EU CRA (effective Dec 2027 for most obligations).
Rationale: scarno is open-source under Apache-2.0 licence and
           distributed free; under CRA's open-source carve-out
           (commercial activity test) a free-distributed analysis
           tool is currently outside CRA *product* obligations.
           However: (a) scarno SUPPORTS its users' CRA SBOM
           and vulnerability-management obligations — REQ-24's
           remote fetch improves SBOM/ABI accuracy by closing
           transitive coverage gaps; (b) any commercial distribution
           of scarno (paid SaaS wrapper, embedded in a commercial
           product) inherits CRA obligations including SBOM,
           vulnerability disclosure policy, and security-update
           commitments — flagged for downstream packagers.
Implementation: docs/scarno-security-architecture.md is the
                project-level CRA stance; this REQ section affirms
                v1 is in scope of that stance.
```

---

## SRTM (REQ-24)

| Req ID | Description | Test File |
|---|---|---|
| ARCH-SEC-005 | `security.resolve_user_config_path` is the sole user-config locator; home-anchored; XDG-confined | `tests/security/test_req24_user_config_anchoring.py` (TA-325) |
| FR-256 | `--index ECOSYSTEM=URL` repeatable, order=priority | `tests/unit/test_req24_index_cli.py` (TA-326) |
| FR-257 | `SCARNO_INDEX_<ECO>` env vars; dropped under fetch | `tests/unit/test_req24_index_env.py` (TA-327) |
| FR-258 | User-config `[indexes]` table | `tests/unit/test_req24_index_userconfig.py` (TA-328) |
| FR-259 | Per-ecosystem override precedence | `tests/unit/test_req24_index_precedence.py` (TA-329) |
| FR-260 | `--allow-remote-fetch` argv-only; requires `--deep-inspection` | `tests/security/test_req24_allow_remote_fetch_argv_only.py` (TA-330) |
| FR-261 | `--integrity-cross-check` argv-only; ≥2 indexes required | `tests/unit/test_req24_cross_check.py` (TA-331) |
| FR-262 ⚠ superseded by Option 2 | Lazy `find_jar` fetches any cache-miss coord; cache-first ordering replaces the minimisation filter | `tests/integration/test_req24_slice_e_wiring.py::TestLazyFindJarFetchesAnyCoord` + `tests/integration/test_req24_option2_pom_and_jar_fetch.py` |
| FR-263 | Pre-fetch disclosure line into `result.errors` | `tests/unit/test_req24_disclosure.py` (TA-333) |
| FR-264 | Per-attempt structured audit line | `tests/unit/test_req24_audit.py` (TA-334) |
| FR-265 | `Finding.provenance` field; conservative remote-tagging | `tests/unit/test_req24_provenance.py` (TA-335) |
| FR-266 | Top-of-report banner when fetches occurred | `tests/unit/test_req24_banner.py` (TA-336) |
| FR-267 | `provenance="remote"` not escalated by `--fail-on-severity` by default; `--fail-on-remote-severity` opt-in | `tests/unit/test_req24_fail_on_remote_severity.py` (TA-337) |
| SEC-NEW-59 | `ValidatedCoordinate` non-bypassability | `tests/security/test_req24_validated_coord.py` (TA-338) |
| SEC-NEW-60 | `SafeHttpsClient` SSRF + cert + pin-IP + IPv6 + no-coalescing | `tests/security/test_req24_safe_https_client.py` (TA-339..343) |
| SEC-NEW-61 | No 4xx fallthrough | `tests/security/test_req24_no_4xx_fallthrough.py` (TA-344) |
| SEC-NEW-62 | Env indexes dropped under fetch | (TA-327 covers) |
| SEC-NEW-63 | ≤2 hop redirect with re-validation; cross-host header drop | `tests/security/test_req24_redirect_policy.py` (TA-345) |
| SEC-NEW-64 | Cache 0700 | `tests/security/test_req24_cache_perms.py` (TA-346) |
| SEC-NEW-65 | Confined cache writes | `tests/security/test_req24_cache_confined.py` (TA-347) |
| SEC-NEW-66 | Cache size cap + LRU | `tests/unit/test_req24_cache_lru.py` (TA-348) |
| SEC-NEW-67 | Cache TTL | `tests/unit/test_req24_cache_ttl.py` (TA-349) |
| SEC-NEW-68 | Per-artefact size cap | `tests/security/test_req24_size_cap.py` (TA-350) |
| SEC-NEW-69 | Fetch count/time caps | `tests/security/test_req24_fetch_caps.py` (TA-351) |
| SEC-NEW-70 | `coordinate_prefix` reserved field | `tests/unit/test_req24_endpoint_model.py` (TA-352) |
| SEC-NEW-71 | `TS-INTEGRITY-MISMATCH` rule | (TA-331 covers) |
| SEC-NEW-72 | `--allow-remote-fetch` argv-only | (TA-330 covers) |
| SEC-NEW-73 | Decompression-bomb caps | `tests/security/test_req24_decompress_cap.py` (TA-353) |
| SEC-NEW-74 | Cross-check retry-once on mismatch | `tests/unit/test_req24_cross_check_retry.py` (TA-354) |
| PRV-005 ⚠ superseded by Option 2 | Cache-first ordering replaces minimisation; full transitive closure may be disclosed | (see Option 2 tests above) |
| PRV-006 | Disclosure line names IP exposure | `tests/unit/test_req24_ip_disclosure.py` (TA-355) |
| PRV-007 | Documentation of fingerprinting risk | `tests/unit/test_req24_docs_present.py` (TA-356) |
| T-39..T-44 | New threats registered | (mitigations covered above) |
| COMP-005 | GDPR operator-IP disclosure | (TA-355 covers) |

---

## Acceptance Criteria

- [ ] Given `--allow-remote-fetch` is OFF (default), when analysis
  runs, then NO outbound network connection is opened regardless
  of how many indexes are configured (verified via mock
  `SafeHttpsClient` instance counter — must remain at zero).
- [ ] Given `--allow-remote-fetch` is set without
  `--deep-inspection`, when the CLI parses argv, then the process
  exits with code 2 and a sanitised error explaining the
  dependency.
- [ ] Given a malicious repo plants `.config/scarno/config.toml`
  inside its tree with a hostile `[indexes]` entry, when scarno
  is run against that repo (with or without
  `--allow-remote-fetch`), then the hostile entry is NEVER in the
  resolved index list.
- [ ] Given `$XDG_CONFIG_HOME` resolves under the analysed project
  root, when the resolver discovers user config, then it falls back
  to `~/.config` and emits a `USER_CONFIG_REJECTED_XDG` audit line.
- [ ] Given a coordinate with `..` / CRLF / URL-reserved chars in
  any component, when `CoordinateValidator.validate()` is called,
  then validation rejects it before any URL or path is constructed.
- [ ] Given a mock DNS resolver that returns `8.8.8.8` at validation
  time and `169.254.169.254` at connect time, when `SafeHttpsClient`
  issues a request, then the connection is made to `8.8.8.8` (the
  pinned IP), not the rebound address.
- [ ] Given an index responds with HTTP 404 for a coordinate, when
  the fetcher processes the response, then NO request is made to
  the next-priority index.
- [ ] Given `--allow-remote-fetch` is set, when env-sourced indexes
  exist, then they are dropped with a warning and only CLI +
  user-config indexes are honoured.
- [ ] Given `--allow-remote-fetch` is set with ≥2 indexes
  configured for some ecosystem and `--integrity-cross-check` is
  absent, when the analysis starts, then a startup warning suggests
  enabling cross-check.
- [ ] Given `--integrity-cross-check` and two indexes returning
  different bytes for the same coordinate, when the fetcher
  retries once and they still disagree, then a `TS-INTEGRITY-MISMATCH`
  HIGH-severity finding is emitted.
- [ ] Given a fetch occurs, when the report is rendered (any
  format), then a top-of-report banner names the fetched artefact
  count and the count of `provenance="remote"` findings.
- [ ] Given a `provenance="remote"` HIGH finding exists and
  `--fail-on-severity HIGH` is set without `--fail-on-remote-severity`,
  when the CLI exits, then the exit code is NOT 3 (remote findings
  are visible but advisory by default).

---

## Out of Scope (REQ-24 v1)

- **Authenticated registries.** No credentials accepted, sent, or
  stored. The `IndexEndpoint.credential_ref` field is reserved
  for v2; v1 leaves it unset and unsettable.
- **HTTP (non-TLS) indexes.** Hard reject. An internal Nexus on
  plain HTTP must be fronted with TLS — a reasonable bar for a
  security tool.
- **Non-Maven ecosystems for the actual fetcher.** v1 implements
  the fetch path for Maven (the only ecosystem `--deep-inspection`
  uses today). The CLI / config / env surface accepts other
  ecosystem values for forward-compatibility, but ecosystems
  without a registered `RemoteArtifactFetcher` skip with a sanitised
  warning.
- **Coordinate-prefix scoping CLI surface.** `IndexEndpoint.coordinate_prefix`
  is reserved; v2 will surface it as a TOML config option. No CLI
  syntax in v1 (CLI form `--index maven=URL:prefix` would collide
  with URL parsing).
- **Defence-in-depth re-verify checksum at javap-time.**
  Recommended for v2; `0700` cache + `resolve_and_confine` writes
  cover T-42 in v1.

---

## Limitations

- **Coordinate typosquatting (T-41) has no clean static fix.** A
  syntactically valid but attacker-chosen coordinate
  (`com.gooogle.guava:guava`) passes validation. The control is
  visibility (`provenance="remote"` tagging + banner + the
  `--fail-on-remote-severity` opt-in CI gate). Curated
  allow-listing of legitimate coordinates is out of scope.
- **Project fingerprinting at index hosts (PT-005)** is no longer
  reduced by the minimisation filter that REQ-24 v1 specified —
  the Option 2 amendment dropped that gate. Cache-first ordering
  remains (artefacts in `~/.m2` never trigger network calls), but
  any true cache-miss in the project's transitive closure is now
  queryable. The pre-fetch disclosure + per-attempt audit are the
  operator's full visibility. Operators of highly confidential
  codebases should weigh that disclosure before enabling fetch.
- **No fall-through on HTTP 4xx (SEC-NEW-61)** trades operator
  ergonomics (an index that legitimately doesn't have something
  doesn't fall through) for confidentiality. Misconfigured
  priority orders (public index listed before internal) will
  miss legitimate internal coordinates and leak their names.
  Operator-side mitigation: list internal indexes first.
- **Cache poisoning of scarno's quarantined cache (T-42)** is
  contained by `0700` perms. Multi-user systems where another
  privileged user could write to the cache directory are out of
  the threat model — the assumption is single-trust-level home
  directory.
- **`provenance="remote"` finding gating (FR-267)** is advisory by
  default. Operators who require strict CI gating must opt in
  with `--fail-on-remote-severity`, understanding that the gating
  is on attacker-influenceable bytes.
