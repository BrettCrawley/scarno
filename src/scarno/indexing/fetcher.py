# Copyright 2026 Brett Crawley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""REQ-24 / FR-262..264 / SEC-NEW-61..69 — :class:`RemoteArtifactFetcher`.

Fetches a single artefact for a :class:`ValidatedCoordinate` from one
of an ordered list of :class:`IndexEndpoint`. Writes the bytes to a
quarantined cache (NEVER ``~/.m2`` or ``node_modules``) after
checksum verification, then returns the cached path. Failure modes
(invalid URL, network error, wrong checksum, cap exceeded) emit a
sanitised audit line into the caller-supplied warnings list and
return ``None`` — analysis continues.

v1 implements the **Maven** fetch path. The validator already accepts
``npm`` coordinates (Slice B), but ``RemoteArtifactFetcher.fetch`` for
``ecosystem != "maven"`` returns ``None`` with a sanitised "ecosystem
not yet implemented in v1" audit so the failure surface is explicit.
The npm fetch path lands in a future PR.

Invariants (mapping to REQ-24 SRTM):

* SEC-NEW-61 — **HTTP 4xx is authoritative**: do NOT fall through to
  the next endpoint on 401 / 403 / 404. Falling through would leak
  internal coordinate names to public indexes (I2). Only
  connection-level failures (DNS / TLS / timeout / 502 / 503 / 504)
  fall through.
* SEC-NEW-64 — Cache root mode 0700.
* SEC-NEW-65 — Every cache write through ``resolve_and_confine``.
* SEC-NEW-66 — Total cache size cap with LRU eviction.
* SEC-NEW-67 — Per-artefact TTL.
* SEC-NEW-68 — Per-artefact fetch-time size cap.
* SEC-NEW-69 — Per-run fetch count + total time budget; lock-counted.
* FR-263 / FR-264 / PUC-006 / PUC-007 / N-4 — pre-fetch disclosure
  and per-attempt audit are **fail-secure**: if the warnings list
  cannot be appended to, the fetch is aborted before any network
  call.

The cache disambiguates by ecosystem so the same coordinate string
in different ecosystems doesn't collide.
"""
from __future__ import annotations

import hashlib
import os
import random
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from scarno.indexing.endpoint import IndexEndpoint
from scarno.indexing.http_client import (
    HttpResponse,
    SafeHttpsClient,
    SafeHttpsError,
)
from scarno.indexing.validator import ValidatedCoordinate
from scarno.models import Finding, FindingKind, FindingSeverity
from scarno.security import (
    PathEscapeError,
    resolve_and_confine,
    sanitise,
    sanitise_declared_version,
)


# ── Defaults (operator-overridable via __init__ kwargs only) ───────────────


_DEFAULT_MAX_ARTEFACT_BYTES: Final[int] = 64 * 1024 * 1024  # 64 MiB
_DEFAULT_MAX_FETCHES_PER_RUN: Final[int] = 128
_DEFAULT_TOTAL_TIME_BUDGET_S: Final[float] = 300.0  # 5 minutes
_DEFAULT_CACHE_TOTAL_BYTES: Final[int] = 1 * 1024 * 1024 * 1024  # 1 GiB
_DEFAULT_CACHE_TTL_S: Final[float] = 30 * 86400.0  # 30 days
_CACHE_DIR_MODE: Final[int] = 0o700

# REQ-24 / SEC-NEW-74 — cross-check retry-once jittered backoff
# parameters. The retry absorbs CDN replica drift (T-43); a *real*
# attacker who controls one of the indexes can outwait this, but
# they'd then need to also serve the same evil bytes from the OTHER
# index — a much higher bar.
_CROSS_CHECK_BACKOFF_BASE_S: Final[float] = 0.250
_CROSS_CHECK_BACKOFF_JITTER_S: Final[float] = 0.100

# HTTP-status semantics: 4xx is authoritative (do not fall through);
# only these connection-level codes fall through.
_FALLTHROUGH_STATUS_CODES: Final[frozenset[int]] = frozenset({502, 503, 504})

# Checksum precedence: prefer sha512, then sha256, then sha1
# (sha1 accepted with warning per the design — broken for collisions
# but Maven still publishes it widely).
_CHECKSUM_ALGOS: Final[tuple[tuple[str, str], ...]] = (
    ("sha512", ".sha512"),
    ("sha256", ".sha256"),
    ("sha1", ".sha1"),
)


# ── Audit-emit helper (fail-secure per N-4) ────────────────────────────────


def _audit(warnings: list[str], message: str) -> None:
    """Append ``message`` to ``warnings``. The caller is expected to
    provide a real list (not a frozen sequence) so this never raises
    on legitimate input — but if it does, the caller's surrounding
    try/except converts the failure into an aborted fetch (N-4).
    """
    warnings.append(message)


# ── Cache ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _CachePolicy:
    """All cache parameters bundled so the fetcher's __init__ stays
    readable. Defaults are the SRTM values; the operator can override
    only via constructor kwargs."""

    root: Path
    total_size_bytes: int = _DEFAULT_CACHE_TOTAL_BYTES
    ttl_seconds: float = _DEFAULT_CACHE_TTL_S
    per_artefact_max_bytes: int = _DEFAULT_MAX_ARTEFACT_BYTES


def _ensure_cache_dir(path: Path) -> None:
    """Create ``path`` (and its parents) with mode 0700 (SEC-NEW-64).

    Always re-applies the mode on the leaf even if the directory
    pre-exists, in case a previous run created it with a more
    permissive umask. Parent directories above the cache root are
    left at their existing modes.
    """
    if path.exists():
        try:
            path.chmod(_CACHE_DIR_MODE)
        except OSError:
            pass
        return
    # Walk upward to find the first existing ancestor; create everything
    # below with mode 0700.
    ancestors: list[Path] = []
    cur = path
    while not cur.exists():
        ancestors.append(cur)
        cur = cur.parent
    for ancestor in reversed(ancestors):
        try:
            ancestor.mkdir(mode=_CACHE_DIR_MODE, exist_ok=True)
        except OSError as exc:  # pragma: no cover — defensive
            raise OSError(
                f"could not create cache directory {ancestor}: {exc}"
            ) from exc
        # mkdir ignores umask differently across platforms; force the
        # mode after creation.
        try:
            ancestor.chmod(_CACHE_DIR_MODE)
        except OSError:
            pass


def _cache_relative_path(
    coord: ValidatedCoordinate,
    version: str,
    extension: str = "jar",
) -> Path:
    """Return a relative path for ``coord@version`` inside the cache.

    Maven layout mirrors ``~/.m2`` so a familiar ``ls`` shows what
    scarno has fetched. Other ecosystems land in subdirectories
    keyed by ecosystem name. ``version`` MUST already be sanitised
    (callers use :func:`sanitise_declared_version` before this point).

    ``extension`` selects the artefact kind — ``"jar"`` (default,
    pre-Option-2 behaviour) or ``"pom"`` (Option 2 transitive POM
    walking via the index). Validated against an allow-list to keep
    the path layout fixed and defend against a future caller passing
    an attacker-influenced suffix.
    """
    if extension not in {"jar", "pom"}:
        raise ValueError(
            f"_cache_relative_path: extension {extension!r} not in allow-list"
        )
    if coord.ecosystem == "maven":
        group, artifact = coord.components
        group_path = Path(*group.split("."))
        return Path(coord.ecosystem) / group_path / artifact / version / (
            f"{artifact}-{version}.{extension}"
        )
    # Generic fallback for future ecosystems (npm, etc.) — components
    # joined as path segments. v1 doesn't use this; the fetcher
    # short-circuits for non-Maven ecosystems.
    return Path(coord.ecosystem, *coord.components, version, "artefact")


def _file_age_seconds(path: Path) -> float:
    """Return seconds since the file was last touched (atime), falling
    back to mtime when atime isn't reliable."""
    st = path.stat()
    # atime is more accurate for LRU but is sometimes disabled
    # (noatime mount). Fall back to mtime if atime is older than mtime
    # by a suspicious margin.
    return time.time() - max(st.st_atime, st.st_mtime)


def _enforce_cache_cap(policy: _CachePolicy) -> None:
    """LRU-evict files inside ``policy.root`` until the total size is
    under ``policy.total_size_bytes``. Also evicts files past
    ``policy.ttl_seconds``."""
    if not policy.root.exists():
        return
    files: list[tuple[float, int, Path]] = []
    total = 0
    for fp in policy.root.rglob("*"):
        if not fp.is_file():
            continue
        try:
            st = fp.stat()
        except OSError:
            continue
        age = time.time() - max(st.st_atime, st.st_mtime)
        # TTL eviction first (SEC-NEW-67).
        if age > policy.ttl_seconds:
            try:
                fp.unlink()
            except OSError:
                pass
            continue
        files.append((max(st.st_atime, st.st_mtime), st.st_size, fp))
        total += st.st_size
    if total <= policy.total_size_bytes:
        return
    # LRU: oldest first. Evict until under cap (SEC-NEW-66).
    files.sort()  # ascending by access time
    for _atime, size, fp in files:
        if total <= policy.total_size_bytes:
            break
        try:
            fp.unlink()
            total -= size
        except OSError:
            continue


def default_cache_root() -> Path:
    """The canonical quarantined-cache root: ``~/.cache/scarno/fetched``.

    Honours ``$XDG_CACHE_HOME`` like the user-config locator honours
    ``$XDG_CONFIG_HOME``. Unlike the user-config locator (REQ-24's
    keystone), the cache directory is write-side and the threat model
    around it is "don't poison the user's REAL ~/.m2"; an XDG override
    pointing inside the project tree is unfortunate but doesn't
    reintroduce the supply-chain backdoor (the cache is scarno's
    own write surface, not a config input).
    """
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "scarno" / "fetched"


# ── RemoteArtifactFetcher ──────────────────────────────────────────────────


class RemoteArtifactFetcher:
    """Fetch + cache an artefact for a :class:`ValidatedCoordinate`.

    Constructor takes the dependencies it needs (HTTPS client, cache
    policy) and a ``warnings`` list it appends to. The pre-fetch
    disclosure line (FR-263 / PUC-006) and per-attempt audit lines
    (FR-264 / PUC-007) are written here; the caller forwards
    ``warnings`` into ``result.errors`` so the audit persists in the
    rendered report (NOT stderr-only).
    """

    def __init__(
        self,
        *,
        client: SafeHttpsClient,
        warnings: list[str],
        findings: list[Finding] | None = None,
        cross_check: bool = False,
        cache_root: Path | None = None,
        cache_total_bytes: int = _DEFAULT_CACHE_TOTAL_BYTES,
        cache_ttl_seconds: float = _DEFAULT_CACHE_TTL_S,
        per_artefact_max_bytes: int = _DEFAULT_MAX_ARTEFACT_BYTES,
        max_fetches_per_run: int = _DEFAULT_MAX_FETCHES_PER_RUN,
        total_time_budget_s: float = _DEFAULT_TOTAL_TIME_BUDGET_S,
    ) -> None:
        self._client = client
        self._warnings = warnings
        # REQ-24 / FR-261 / SEC-NEW-74 — when True, multi-endpoint
        # fetches go through the cross-check path: fetch from top-2
        # priority indexes, compare sha256, jittered backoff + retry
        # the secondary on mismatch, emit TS-INTEGRITY-MISMATCH
        # (HIGH) on persistent disagreement. Off by default — the
        # operator opts in via --integrity-cross-check.
        self._cross_check = cross_check
        # The list a TS-INTEGRITY-MISMATCH Finding lands in. The
        # caller (JavaAnalyser) passes ``result.findings`` so the
        # finding shows up in the rendered report alongside ABI
        # findings. None when no findings sink is wired (e.g. unit
        # tests of the fetcher in isolation) — cross-check mismatches
        # then go to ``warnings`` only.
        self._findings = findings
        self._cache = _CachePolicy(
            root=(cache_root or default_cache_root()).resolve(),
            total_size_bytes=cache_total_bytes,
            ttl_seconds=cache_ttl_seconds,
            per_artefact_max_bytes=per_artefact_max_bytes,
        )
        self._max_fetches_per_run = max_fetches_per_run
        self._total_time_budget_s = total_time_budget_s
        # Lock-counted state for SEC-NEW-69 (mirrors abi_diff.py's
        # CrossVersionAbiDiffer cap counter).
        self._cap_lock = threading.Lock()
        self._fetches_consumed = 0
        self._wall_clock_start = time.monotonic()
        # Pre-fetch disclosure is emitted lazily on the first fetch
        # attempt (when we know the host(s) for the audit message).
        self._disclosure_emitted = False

    # ── Public API ──────────────────────────────────────────────────────────

    def fetch(
        self,
        coord: ValidatedCoordinate,
        version: str,
        endpoints: list[IndexEndpoint],
        *,
        extension: str = "jar",
    ) -> Path | None:
        """Return the cached path for ``coord@version`` or ``None`` if
        the fetch failed. Audit lines describing every step are
        appended to the constructor-supplied ``warnings`` list.

        ``extension`` selects the artefact kind: ``"jar"`` (default,
        REQ-24 v1) or ``"pom"`` (Option 2 — POMs walked by
        :class:`MavenPomResolver` when the local ``~/.m2`` walk
        misses). All security invariants apply identically: same URL
        construction shape, same checksum verification, same
        quarantined-cache layout under a different filename suffix.
        """
        if extension not in {"jar", "pom"}:
            raise ValueError(
                f"fetch: extension {extension!r} not in allow-list"
            )
        # 1. Validate / sanitise version.
        clean_version = sanitise_declared_version(version)
        if not clean_version or clean_version != version.strip():
            _audit(
                self._warnings,
                f"req24-fetch: rejecting unsafe version "
                f"{sanitise(version)!r} for {sanitise(coord.raw)} "
                "(version did not survive sanitisation)"
            )
            return None

        # 2. Filter endpoints to this ecosystem; respect coordinate_prefix
        #    (v2-reserved field; v1 endpoints leave it None so this is a
        #    no-op).
        eligible = [
            e for e in endpoints
            if e.ecosystem == coord.ecosystem
            and (
                e.coordinate_prefix is None
                or coord.raw.startswith(e.coordinate_prefix)
            )
        ]
        if not eligible:
            _audit(
                self._warnings,
                f"req24-fetch: no eligible index for "
                f"{sanitise(coord.ecosystem)} coord "
                f"{sanitise(coord.raw)}"
            )
            return None

        # 3. v1: only Maven is implemented end-to-end.
        if coord.ecosystem != "maven":
            _audit(
                self._warnings,
                f"req24-fetch: ecosystem {sanitise(coord.ecosystem)!r} "
                "fetcher not yet implemented in v1; skipping "
                f"{sanitise(coord.raw)}@{sanitise(clean_version)}"
            )
            return None

        # 4. Cache lookup.
        cache_path = self._cache_path_for(coord, clean_version, extension)
        if cache_path is None:
            return None
        if cache_path.exists():
            age = _file_age_seconds(cache_path)
            if age <= self._cache.ttl_seconds:
                # Touch atime so LRU eviction doesn't reap it.
                try:
                    os.utime(cache_path, None)
                except OSError:
                    pass
                _audit(
                    self._warnings,
                    f"req24-fetch: cache hit for {sanitise(coord.raw)}"
                    f"@{sanitise(clean_version)}.{extension} ({cache_path})"
                )
                return cache_path

        # 5. Pre-fetch disclosure (PUC-006/008) — emitted ONCE before
        #    the first network call across the lifetime of this
        #    fetcher instance. Names hosts + IP-disclosure side-effect.
        if not self._disclosure_emitted:
            hosts = sorted({
                # urlparse host without scheme noise.
                _hostname_of(e.url) for e in endpoints if _hostname_of(e.url)
            })
            _audit(
                self._warnings,
                f"req24-fetch: REMOTE FETCH ENABLED — about to query "
                f"{len(hosts)} index host(s): {', '.join(hosts)}. "
                "Your machine's IP address will be visible to those hosts. "
                "Both POMs (transitive walker) and JARs (ABI diff) "
                "will be fetched on cache-miss; the project's transitive "
                "dependency closure will be queried as needed. The "
                "audit channel below records every fetch attempt."
            )
            self._disclosure_emitted = True

        # 6. Per-run cap (SEC-NEW-69).
        if not self._try_consume_cap():
            _audit(
                self._warnings,
                f"req24-fetch: per-run fetch cap "
                f"({self._max_fetches_per_run}) reached; skipping "
                f"{sanitise(coord.raw)}@{sanitise(clean_version)}"
            )
            return None
        if self._time_budget_exhausted():
            _audit(
                self._warnings,
                f"req24-fetch: total fetch-time budget "
                f"({self._total_time_budget_s}s) exhausted; skipping "
                f"{sanitise(coord.raw)}@{sanitise(clean_version)}"
            )
            return None

        # 7. Dispatch to cross-check or single-source path.
        eligible.sort(key=lambda e: e.priority)
        if self._cross_check and len(eligible) >= 2:
            # SEC-NEW-74 — fetch from top-2 priority indexes, compare
            # bytes, retry-once on mismatch, emit TS-INTEGRITY-MISMATCH
            # on persistent disagreement.
            return self._fetch_with_cross_check(
                coord, clean_version, eligible[0], eligible[1],
                cache_path, extension,
            )
        # Single-source path: try each endpoint in priority order;
        # HTTP 4xx is authoritative (no fallthrough — SEC-NEW-61).
        for endpoint in eligible:
            outcome = self._try_endpoint(
                endpoint, coord, clean_version, cache_path, extension,
            )
            if outcome is _Outcome.SUCCESS:
                return cache_path
            if outcome is _Outcome.AUTHORITATIVE_NOT_FOUND:
                # 4xx → stop. Do not try the next endpoint.
                return None
            # _Outcome.FALLTHROUGH → try the next endpoint.

        _audit(
            self._warnings,
            f"req24-fetch: all eligible indexes exhausted (connection-"
            f"level failures) for {sanitise(coord.raw)}"
            f"@{sanitise(clean_version)}"
        )
        return None

    def fetch_pom(
        self,
        coord: ValidatedCoordinate,
        version: str,
        endpoints: list[IndexEndpoint],
    ) -> Path | None:
        """Convenience wrapper: fetch the POM for ``coord@version``.

        Used by :class:`MavenPomResolver` when its transitive walk
        encounters a coordinate whose POM isn't in ``~/.m2``. Same
        cache-first / no-4xx-fallthrough / size-cap / quarantined-cache
        guarantees as :meth:`fetch`."""
        return self.fetch(coord, version, endpoints, extension="pom")

    # ── Internals ───────────────────────────────────────────────────────────

    def _cache_path_for(
        self,
        coord: ValidatedCoordinate,
        version: str,
        extension: str = "jar",
    ) -> Path | None:
        rel = _cache_relative_path(coord, version, extension)
        candidate = self._cache.root / rel
        try:
            confined = resolve_and_confine(
                # Pass the parent dir as the candidate to confine,
                # then re-attach the file name. Avoids stat-on-nonexistent
                # weirdness with resolve(strict=False).
                candidate.parent / "_check_",
                self._cache.root,
            )
        except PathEscapeError as exc:
            _audit(
                self._warnings,
                f"req24-fetch: cache path escape for "
                f"{sanitise(coord.raw)}: {sanitise(str(exc))}"
            )
            return None
        # ``confined`` is the parent dir; re-attach the leaf via the
        # original candidate (we've proven the parent is inside the
        # cache root, and the leaf is a single file name from a
        # ValidatedCoordinate so it can't traverse).
        return candidate

    def _try_consume_cap(self) -> bool:
        with self._cap_lock:
            if self._fetches_consumed >= self._max_fetches_per_run:
                return False
            self._fetches_consumed += 1
            return True

    def _time_budget_exhausted(self) -> bool:
        return (
            time.monotonic() - self._wall_clock_start
            > self._total_time_budget_s
        )

    # ── Cross-check fetch (SEC-NEW-74) ──────────────────────────────────────

    def _fetch_with_cross_check(
        self,
        coord: ValidatedCoordinate,
        version: str,
        primary: IndexEndpoint,
        secondary: IndexEndpoint,
        cache_path: Path,
        extension: str = "jar",
    ) -> Path | None:
        """Fetch from ``primary`` AND ``secondary``, compare sha256, and
        retry the secondary once on mismatch (jittered backoff). Emit
        ``TS-INTEGRITY-MISMATCH`` (HIGH) on persistent disagreement.

        On unanimous agreement → write the (verified-twice) bytes to
        the cache and return its path.
        On secondary connection failure → degrade to single-source
        (primary only) with an audit line — this preserves usability
        when the secondary is just down.
        """
        primary_bytes = self._fetch_artefact_bytes(
            coord, version, primary, extension,
        )
        if primary_bytes is None:
            # Primary failed — without it there's no anchor to
            # cross-check against. Fall back to the standard single-
            # source loop (so the secondary still gets a chance).
            for endpoint in (secondary,):
                outcome = self._try_endpoint(
                    endpoint, coord, version, cache_path, extension,
                )
                if outcome is _Outcome.SUCCESS:
                    return cache_path
                if outcome is _Outcome.AUTHORITATIVE_NOT_FOUND:
                    return None
            return None

        secondary_bytes = self._fetch_artefact_bytes(
            coord, version, secondary, extension,
        )
        if secondary_bytes is None:
            # Secondary unreachable — degrade to single-source verdict
            # (primary only). Audit the degradation.
            _audit(
                self._warnings,
                f"req24-fetch: --integrity-cross-check degraded to "
                f"single-source for {sanitise(coord.raw)}@{sanitise(version)} "
                f"({sanitise(secondary.url)} unreachable)"
            )
            return self._finalise_single_source(
                coord, version, primary, primary_bytes, cache_path,
            )

        if hashlib.sha256(primary_bytes).digest() == hashlib.sha256(
            secondary_bytes
        ).digest():
            # Unanimous — verified-twice. Cache and return.
            return self._finalise_single_source(
                coord, version, primary, primary_bytes, cache_path,
            )

        # Mismatch. Jittered backoff and retry the SECONDARY.
        backoff = _CROSS_CHECK_BACKOFF_BASE_S + random.uniform(
            -_CROSS_CHECK_BACKOFF_JITTER_S,
            _CROSS_CHECK_BACKOFF_JITTER_S,
        )
        time.sleep(max(0.0, backoff))
        retry_bytes = self._fetch_artefact_bytes(
            coord, version, secondary, extension,
        )
        if retry_bytes is not None and hashlib.sha256(
            primary_bytes
        ).digest() == hashlib.sha256(retry_bytes).digest():
            # Drift after retry — accept the (now-agreed) bytes.
            _audit(
                self._warnings,
                f"req24-fetch: --integrity-cross-check transient drift "
                f"resolved on retry for {sanitise(coord.raw)}"
                f"@{sanitise(version)}"
            )
            return self._finalise_single_source(
                coord, version, primary, primary_bytes, cache_path,
            )

        # Persistent disagreement — emit TS-INTEGRITY-MISMATCH.
        primary_sha = hashlib.sha256(primary_bytes).hexdigest()
        secondary_sha = hashlib.sha256(
            retry_bytes if retry_bytes is not None else secondary_bytes
        ).hexdigest()
        message = (
            f"{sanitise(coord.raw)}@{sanitise(version)} returned "
            f"different bytes from {sanitise(primary.url)} "
            f"(sha256 {primary_sha}) vs {sanitise(secondary.url)} "
            f"(sha256 {secondary_sha}) after retry-once. One of these "
            "indexes may be compromised, MITM'd, or polluted."
        )
        _audit(
            self._warnings,
            f"req24-fetch: TS-INTEGRITY-MISMATCH — {message}"
        )
        if self._findings is not None:
            self._findings.append(
                Finding(
                    rule_id="TS-INTEGRITY-MISMATCH",
                    kind=FindingKind.ABI_INTEGRITY_MISMATCH,
                    severity=FindingSeverity.HIGH,
                    file_path="",
                    line=0,
                    snippet="",
                    message=message,
                    remediation=(
                        "Treat the affected coordinate's ABI verdicts as "
                        "unreliable. Verify the legitimate hash from your "
                        "trusted index out-of-band; investigate the "
                        "divergent index for compromise or pollution. "
                        "Until resolved, prefer fetching this coordinate "
                        "from a single trusted index."
                    ),
                    package_hint=sanitise(coord.raw),
                    provenance="remote",
                )
            )
        return None

    def _fetch_artefact_bytes(
        self,
        coord: ValidatedCoordinate,
        version: str,
        endpoint: IndexEndpoint,
        extension: str = "jar",
    ) -> bytes | None:
        """Fetch just the artefact bytes from one endpoint, applying
        size cap + 4xx-authoritative semantics, but WITHOUT writing
        to the cache. Returns the body on success, ``None`` on any
        failure (with sanitised audit line). Used by both the
        cross-check path and (indirectly) the single-source path."""
        url = self._artefact_url(endpoint, coord, version, extension)
        try:
            response = self._client.get(url)
        except SafeHttpsError as exc:
            _audit(
                self._warnings,
                f"req24-fetch: connection-level failure for "
                f"{sanitise(coord.raw)}@{sanitise(version)} from "
                f"{sanitise(endpoint.url)}: {sanitise(str(exc))}"
            )
            return None
        if response.status in _FALLTHROUGH_STATUS_CODES:
            _audit(
                self._warnings,
                f"req24-fetch: {response.status} from "
                f"{sanitise(endpoint.url)} (cross-check)"
            )
            return None
        if response.status >= 400:
            _audit(
                self._warnings,
                f"req24-fetch: {response.status} from "
                f"{sanitise(endpoint.url)} for "
                f"{sanitise(coord.raw)}@{sanitise(version)} (cross-check)"
            )
            return None
        if response.status != 200:
            return None
        if len(response.body) > self._cache.per_artefact_max_bytes:
            _audit(
                self._warnings,
                f"req24-fetch: artefact body ({len(response.body)} bytes) "
                f"exceeds per-artefact cap "
                f"({self._cache.per_artefact_max_bytes}) — cross-check"
            )
            return None
        return response.body

    def _finalise_single_source(
        self,
        coord: ValidatedCoordinate,
        version: str,
        endpoint: IndexEndpoint,
        body: bytes,
        cache_path: Path,
    ) -> Path | None:
        """Write the verified bytes to the quarantined cache and emit
        a success audit line. Shared by cross-check (after agreement)
        and single-source-fallback paths."""
        try:
            self._write_cache(cache_path, body)
        except OSError as exc:
            _audit(
                self._warnings,
                f"req24-fetch: cache write failed for "
                f"{sanitise(coord.raw)}@{sanitise(version)}: "
                f"{sanitise(str(exc))}"
            )
            return None
        _enforce_cache_cap(self._cache)
        _audit(
            self._warnings,
            f"req24-fetch: fetched {sanitise(coord.raw)}"
            f"@{sanitise(version)} from {sanitise(endpoint.url)} "
            f"(provenance=remote, source={endpoint.source.value})"
        )
        return cache_path

    def _try_endpoint(
        self,
        endpoint: IndexEndpoint,
        coord: ValidatedCoordinate,
        version: str,
        cache_path: Path,
        extension: str = "jar",
    ) -> "_Outcome":
        artefact_url = self._artefact_url(
            endpoint, coord, version, extension,
        )
        try:
            response = self._client.get(artefact_url)
        except SafeHttpsError as exc:
            _audit(
                self._warnings,
                f"req24-fetch: connection-level failure for "
                f"{sanitise(coord.raw)}@{sanitise(version)} from "
                f"{sanitise(endpoint.url)}: {sanitise(str(exc))} "
                "(fall-through to next index)"
            )
            return _Outcome.FALLTHROUGH

        if response.status in _FALLTHROUGH_STATUS_CODES:
            _audit(
                self._warnings,
                f"req24-fetch: {response.status} from "
                f"{sanitise(endpoint.url)} (fall-through)"
            )
            return _Outcome.FALLTHROUGH

        if response.status >= 400:
            # SEC-NEW-61 — HTTP 4xx (and other 5xx) is authoritative.
            _audit(
                self._warnings,
                f"req24-fetch: {response.status} from "
                f"{sanitise(endpoint.url)} for "
                f"{sanitise(coord.raw)}@{sanitise(version)}; "
                "NOT falling through (would leak coord to next index)"
            )
            return _Outcome.AUTHORITATIVE_NOT_FOUND

        if response.status != 200:
            _audit(
                self._warnings,
                f"req24-fetch: unexpected status {response.status} "
                f"from {sanitise(endpoint.url)}; treating as "
                "authoritative not-found"
            )
            return _Outcome.AUTHORITATIVE_NOT_FOUND

        # Per-artefact size cap (SEC-NEW-68). The HTTPS client also
        # caps response bytes, so this is defence in depth.
        if len(response.body) > self._cache.per_artefact_max_bytes:
            _audit(
                self._warnings,
                f"req24-fetch: artefact body "
                f"({len(response.body)} bytes) exceeds per-artefact cap "
                f"({self._cache.per_artefact_max_bytes}) for "
                f"{sanitise(coord.raw)}@{sanitise(version)}"
            )
            return _Outcome.AUTHORITATIVE_NOT_FOUND

        # Checksum verification (SUC-66 — corruption detection only).
        # TLS is the adversarial-integrity control; this is corruption.
        ok = self._verify_checksum(response, artefact_url, coord, version)
        if not ok:
            return _Outcome.AUTHORITATIVE_NOT_FOUND

        # Write to quarantined cache (SEC-NEW-65 confined; SEC-NEW-64 0700).
        try:
            self._write_cache(cache_path, response.body)
        except OSError as exc:
            _audit(
                self._warnings,
                f"req24-fetch: cache write failed for "
                f"{sanitise(coord.raw)}@{sanitise(version)}: "
                f"{sanitise(str(exc))}"
            )
            return _Outcome.AUTHORITATIVE_NOT_FOUND

        # Eviction pass after a successful write so the cap holds.
        _enforce_cache_cap(self._cache)

        _audit(
            self._warnings,
            f"req24-fetch: fetched {sanitise(coord.raw)}"
            f"@{sanitise(version)}.{extension} from {sanitise(endpoint.url)} "
            f"(provenance=remote, source={endpoint.source.value}, "
            f"pinned_ip={sanitise(response.pinned_ip)})"
        )
        return _Outcome.SUCCESS

    def _verify_checksum(
        self,
        artefact_response: HttpResponse,
        artefact_url: str,
        coord: ValidatedCoordinate,
        version: str,
    ) -> bool:
        body_hashes = {
            algo: hashlib.new(algo, artefact_response.body).hexdigest()
            for algo, _ext in _CHECKSUM_ALGOS
        }
        for algo, ext in _CHECKSUM_ALGOS:
            checksum_url = artefact_url + ext
            try:
                resp = self._client.get(checksum_url)
            except SafeHttpsError:
                continue
            if resp.status != 200:
                continue
            try:
                expected = resp.body.decode("ascii", errors="strict").strip()
                # Maven publishes hashes as hex digits sometimes
                # followed by "  filename"; take the first whitespace-
                # delimited token.
                expected = expected.split()[0].lower()
            except (UnicodeDecodeError, IndexError):
                continue
            actual = body_hashes[algo]
            if actual == expected:
                if algo == "sha1":
                    _audit(
                        self._warnings,
                        f"req24-fetch: WARNING — sha1 is the only "
                        f"available digest for {sanitise(coord.raw)}"
                        f"@{sanitise(version)}; SHA-1 is collision-"
                        "broken and corruption-only protection"
                    )
                return True
            _audit(
                self._warnings,
                f"req24-fetch: checksum mismatch ({algo}) for "
                f"{sanitise(coord.raw)}@{sanitise(version)} from "
                f"{sanitise(artefact_url)}; expected {expected!r}, "
                f"got {actual!r}"
            )
            return False
        # No checksum could be retrieved — degraded-trust audit, but
        # NOT a hard fail (Maven Central JARs sometimes ship without
        # all three).
        _audit(
            self._warnings,
            f"req24-fetch: no digest available for "
            f"{sanitise(coord.raw)}@{sanitise(version)} (no .sha512 / "
            ".sha256 / .sha1 from index); accepting on TLS trust alone"
        )
        return True

    def _write_cache(self, cache_path: Path, body: bytes) -> None:
        _ensure_cache_dir(cache_path.parent)
        # Confine the final write site after the parent dir is created.
        confined = resolve_and_confine(cache_path.parent, self._cache.root)
        target = confined / cache_path.name
        # tmp + atomic rename so a partial write isn't visible.
        tmp = target.with_suffix(target.suffix + ".part")
        with open(tmp, "wb") as fh:
            fh.write(body)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, target)

    def _artefact_url(
        self,
        endpoint: IndexEndpoint,
        coord: ValidatedCoordinate,
        version: str,
        extension: str = "jar",
    ) -> str:
        # Maven layout:
        # <index>/<group_path>/<artifact>/<version>/<artifact>-<version>.<ext>
        if extension not in {"jar", "pom"}:
            raise ValueError(
                f"_artefact_url: extension {extension!r} not in allow-list"
            )
        group, artifact = coord.components
        group_path = group.replace(".", "/")
        base = endpoint.url.rstrip("/")
        return (
            f"{base}/{group_path}/{artifact}/{version}/"
            f"{artifact}-{version}.{extension}"
        )


# ── Helpers + types ─────────────────────────────────────────────────────────


from enum import Enum


class _Outcome(Enum):
    SUCCESS = "success"
    FALLTHROUGH = "fallthrough"
    AUTHORITATIVE_NOT_FOUND = "authoritative_not_found"


def _hostname_of(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or ""
    except (ValueError, AttributeError):
        return ""


# Re-export so the orchestrator can import the cache helper for tests
# and for v2 integration ergonomics.
__all__ = [
    "RemoteArtifactFetcher",
    "default_cache_root",
]
