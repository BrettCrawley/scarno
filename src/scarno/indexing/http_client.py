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

"""REQ-24 / SEC-NEW-60 / SUC-65 — :class:`SafeHttpsClient` is the SOLE
outbound HTTPS path for scarno. Pin-resolved-IP semantics defeat
the textbook DNS-rebinding TOCTOU bypass against hostname-only SSRF
guards (T-39).

Built on stdlib ``http.client`` + ``ssl`` + ``socket`` rather than
``urllib3`` / ``httpx`` so:

* HTTP/2 connection coalescing (N-2 from the closing threat-model
  pass) is **structurally absent** — stdlib ``http.client`` is
  HTTP/1.1 only and creates one connection per request, never reused
  across hostnames.
* No third-party HTTP-client dependency surface to monitor for CVEs.
* Cert verification is mandatory and non-overridable on the prod
  path — there is no constructor parameter for ``verify``.

Per-request flow (executed for every hop, including redirects):

1.  Re-validate URL — HTTPS only, no userinfo, has host.
2.  ``socket.getaddrinfo(host)`` → list of ``(family, sockaddr)``.
3.  Reject every IP in the SSRF deny-list:

    * IPv4 — loopback / link-local / private (RFC 1918) / CGNAT /
      multicast / reserved / unspecified
    * IPv6 — ``::1`` / ``fc00::/7`` / ``fe80::/10`` / ``ff00::/8`` /
      IPv4-mapped equivalents (with zone-id stripped before match —
      N-5)

4.  Pin one valid IP.
5.  ``socket.create_connection((pinned_ip, 443))`` — connect to the IP
    literal directly (no DNS at connect time).
6.  After connect, ``getpeername()`` MUST equal the pinned IP — abort
    before sending any bytes otherwise.
7.  ``ssl_ctx.wrap_socket(sock, server_hostname=hostname)`` — SNI is
    the original hostname; cert verification mandatory.
8.  Send HTTP/1.1 GET. ``Host:`` header explicitly set to the original
    hostname (not the IP literal).
9.  Read response.
10. On 3xx + ``Location`` header: ≤2 hops total; each hop re-runs
    steps 1-9; cross-host redirect drops ALL outgoing request headers
    (defines the v2 auth-header rule now).

Test injection seam: the production path constructs ``SafeHttpsClient``
directly. Tests override ``_open_connection`` on a subclass to mock
the network layer — the constructor never accepts a "callable" for
the network because that would let a future test or call site disable
TLS verification (T6). See ``tests/security/test_req24_safe_https_client.py``.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlparse, urlunparse

from scarno.security import sanitise


# ── Caps and constants ──────────────────────────────────────────────────────


_DEFAULT_TIMEOUT_S: Final[float] = 30.0
_DEFAULT_MAX_REDIRECTS: Final[int] = 2
_DEFAULT_MAX_RESPONSE_BYTES: Final[int] = 64 * 1024 * 1024  # 64 MiB
_USER_AGENT: Final[str] = "scarno/req24"


# ── Errors ──────────────────────────────────────────────────────────────────


class SafeHttpsError(Exception):
    """Any failure of :class:`SafeHttpsClient`. Carries a sanitised
    message suitable for the audit log; never propagates underlying
    socket / ssl exception types upward (those would leak path /
    network details into the report channel)."""


# ── HTTP response container ─────────────────────────────────────────────────


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str
    pinned_ip: str
    hops: int = field(default=1)


# ── SSRF guard ──────────────────────────────────────────────────────────────


# CGNAT (RFC 6598) is sometimes covered by ``IPv4Address.is_private``
# but the Python stdlib classification has shifted across point
# releases. Pin the network explicitly so the deny-list is stable
# across Python versions.
_CGNAT_NETWORK: Final[ipaddress.IPv4Network] = ipaddress.IPv4Network("100.64.0.0/10")


def _ip_is_safe(ip_str: str, *, allow_private: bool = False) -> bool:
    """Return ``True`` iff ``ip_str`` is acceptable as a remote-fetch peer.

    Default (``allow_private=False``) — rejects loopback / link-local /
    private (RFC 1918 + CGNAT) / multicast / reserved / unspecified,
    for both IPv4 and IPv6. This is the SSRF deny-list that protects
    every fetch against arbitrary hosts.

    With ``allow_private=True`` — used only for hostnames the operator
    has explicitly named in ``--allow-private-index-host`` — RFC 1918
    (10/8, 172.16/12, 192.168/16) and ULA (``fc00::/7``) become
    permitted. Loopback / link-local / multicast / CGNAT / reserved /
    unspecified are **still rejected** because none of those are
    valid endpoints for a corporate index server, and allowing them
    would expand attack surface without operator benefit.

    Strips IPv6 zone-id before classification (``fe80::1%eth0`` →
    ``fe80::1`` — N-5) and re-classifies IPv4-mapped IPv6 against the
    embedded IPv4 address (``::ffff:169.254.169.254`` is rejected).
    """
    if "%" in ip_str:
        ip_str = ip_str.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # Re-classify IPv4-mapped IPv6 against the embedded v4 address;
    # otherwise ``::ffff:169.254.169.254`` would slip past the v6
    # checks (which don't know about the v4 ranges).
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK:
        # CGNAT is never relaxed — it sits between RFC 1918 and the
        # public internet and is not a legitimate corp-index range.
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        # Never relaxed — irrelevant for corp indexes, dangerous if reachable.
        return False
    if addr.is_reserved or addr.is_unspecified:
        return False
    if addr.is_private:
        # RFC 1918 (v4) / ULA (v6) — only permitted when the caller
        # opted in for this specific hostname.
        return allow_private
    return True


def _validate_url(url: str) -> tuple[str, int, str]:
    """Re-validate the URL at request time. Returns
    ``(hostname, port, path_with_query)``.

    Mirrors the parse-time gate in :mod:`scarno.indexing.resolver`
    — defence in depth. A bug in the resolver cannot bypass the
    network controls because every request runs this check too.
    """
    try:
        parsed = urlparse(url)
    except (ValueError, AttributeError) as exc:
        raise SafeHttpsError(f"unparseable URL: {sanitise(str(exc))}") from exc
    if parsed.scheme != "https":
        raise SafeHttpsError(
            f"URL scheme must be https (got {sanitise(parsed.scheme)!r})"
        )
    if parsed.username is not None or parsed.password is not None:
        raise SafeHttpsError("URL must not contain userinfo")
    if not parsed.hostname:
        raise SafeHttpsError("URL missing host")
    port = parsed.port if parsed.port is not None else 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return parsed.hostname, port, path


# ── Pinned-IP HTTPS connection ──────────────────────────────────────────────


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """``HTTPSConnection`` that connects to a pinned IP literal but
    uses the ORIGINAL hostname for SNI / cert verification.

    Subclasses ``http.client.HTTPSConnection`` rather than building
    the socket+TLS plumbing from scratch so the well-trodden HTTP/1.1
    parser + chunked-response handling come for free. Only ``connect``
    is overridden — that's where the hostname-vs-IP distinction lives.
    """

    def __init__(
        self,
        *,
        pinned_ip: str,
        hostname: str,
        port: int,
        timeout: float,
        ssl_context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            host=pinned_ip,
            port=port,
            timeout=timeout,
            context=ssl_context,
        )
        self._sni_hostname = hostname
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        family = socket.AF_INET6 if ":" in self._pinned_ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self._pinned_ip, self.port))
            # Pre-TLS peer-name re-check: getpeername() must agree with
            # the IP we asked the kernel to connect to. This is mostly
            # defence-in-depth — the kernel doesn't lie about peer
            # addresses — but if a future kernel patch / proxy / LD_PRELOAD
            # interferes, this catches it before any plaintext leaves.
            peer = sock.getpeername()
            peer_ip = str(peer[0])
            if "%" in peer_ip:
                peer_ip = peer_ip.split("%", 1)[0]
            if peer_ip != self._pinned_ip:
                raise SafeHttpsError(
                    f"peer {sanitise(peer_ip)!r} != pinned "
                    f"{sanitise(self._pinned_ip)!r} "
                    "(possible DNS rebinding mid-connect)"
                )
            # ``HTTPSConnection._context`` is the well-known protected
            # attribute the parent class itself sets in ``__init__``;
            # access via the public-name ``_context`` is consistent with
            # cpython's own subclass examples.
            self.sock = self._context.wrap_socket(  # type: ignore[attr-defined]
                sock, server_hostname=self._sni_hostname
            )
        except SafeHttpsError:
            sock.close()
            raise
        except (OSError, ssl.SSLError) as exc:
            sock.close()
            raise SafeHttpsError(
                f"TLS / connect failed: {sanitise(str(exc))}"
            ) from exc


# ── SafeHttpsClient ─────────────────────────────────────────────────────────


def _build_default_ssl_context() -> ssl.SSLContext:
    """Construct the prod TLS context. Mandatory verification +
    hostname check; no parameter exists to disable either. A future
    contributor wanting to relax this would have to subclass + add a
    method, which is a large enough change to be visible in code review.
    """
    ctx = ssl.create_default_context()
    # ``create_default_context`` already sets verify_mode = CERT_REQUIRED
    # and check_hostname = True; assert defensively in case a future
    # Python release changes the default.
    assert ctx.verify_mode == ssl.CERT_REQUIRED, (
        "ssl.create_default_context returned non-CERT_REQUIRED context"
    )
    assert ctx.check_hostname is True, (
        "ssl.create_default_context returned check_hostname=False"
    )
    # Pin TLS minimum at 1.2 (Python's default since 3.10 is already
    # 1.2 minimum, but make it explicit).
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _build_native_tls_ssl_context() -> ssl.SSLContext:
    """REQ-24 — OS-native trust store via ``truststore`` (the same
    package uv / pip / hatch use).

    macOS: SecureTransport via the Security framework — picks up CAs
    in the user/system Keychain. Windows: SChannel — picks up CAs in
    the Windows certificate store. Linux: OpenSSL + system store
    (typically ``/etc/ssl/certs/``). On every platform a corporate CA
    deployed by IT to the OS trust store is automatically trusted.

    Cert verification and hostname check are MANDATORY here too —
    ``truststore.SSLContext`` enforces both identically to
    ``ssl.create_default_context``. The TLS minimum is pinned at 1.2.
    """
    import truststore  # local import — only loaded when --native-tls is on
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert ctx.verify_mode == ssl.CERT_REQUIRED, (
        "truststore.SSLContext returned non-CERT_REQUIRED context"
    )
    assert ctx.check_hostname is True, (
        "truststore.SSLContext returned check_hostname=False"
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class SafeHttpsClient:
    """The SOLE outbound HTTPS path. See module docstring."""

    def __init__(
        self,
        *,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        max_redirects: int = _DEFAULT_MAX_REDIRECTS,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        private_index_hosts: tuple[str, ...] = (),
        native_tls: bool = False,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if max_redirects < 0 or max_redirects > 5:
            # Cap the cap. >5 redirects is unreasonable for a package
            # registry; the spec sets the budget at 2.
            raise ValueError("max_redirects must be in [0, 5]")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be > 0")
        self._timeout_s = timeout_s
        self._max_redirects = max_redirects
        self._max_response_bytes = max_response_bytes
        # REQ-24 — argv-only ``--native-tls`` swaps the bundled CA
        # store for the OS-native trust store (truststore package).
        # Both branches keep cert verification + hostname check
        # mandatory; there is no path through this constructor that
        # produces an unverifying context.
        self._native_tls = bool(native_tls)
        self._ssl_context = (
            _build_native_tls_ssl_context() if self._native_tls
            else _build_default_ssl_context()
        )
        # REQ-24 — argv-only allow-list for corporate indexes whose DNS
        # resolves to RFC 1918 / ULA addresses. Stored lowercased for
        # exact hostname comparison; never wildcarded (a wildcard would
        # let one allow-list entry cover unrelated subdomains and is a
        # strictly worse mental model than naming each host explicitly).
        # Cross-host redirects do NOT inherit the allowance — the
        # per-hop re-validation in :meth:`get` checks the CURRENT
        # hostname against this set on every hop.
        self._private_index_hosts: frozenset[str] = frozenset(
            h.strip().lower() for h in private_index_hosts if h and h.strip()
        )

    # ── Public API ──────────────────────────────────────────────────────────

    def get(self, url: str) -> HttpResponse:
        """GET ``url``; follow up to ``max_redirects`` hops with full
        re-validation per hop. Raises :class:`SafeHttpsError` on any
        failure."""
        current = url
        prev_host: str | None = None
        for hop in range(self._max_redirects + 1):
            hostname, port, path = _validate_url(current)
            pinned_ip = self._resolve_and_pin(hostname)
            # Cross-host redirect drops all outgoing request headers
            # (defines the v2 auth-header rule today). Same-host
            # redirects retain the host header.
            headers = self._default_headers(hostname)
            response = self._perform_request(
                hostname=hostname,
                port=port,
                path=path,
                pinned_ip=pinned_ip,
                headers=headers,
            )
            if 300 <= response.status < 400 and "location" in {
                k.lower() for k in response.headers
            }:
                location = next(
                    v for k, v in response.headers.items()
                    if k.lower() == "location"
                )
                if hop >= self._max_redirects:
                    raise SafeHttpsError(
                        f"redirect limit exceeded ({self._max_redirects} hops)"
                    )
                # Resolve relative redirects against the current URL.
                current = self._resolve_redirect_target(current, location)
                prev_host = hostname
                continue
            # Final response.
            return HttpResponse(
                status=response.status,
                headers=response.headers,
                body=response.body,
                final_url=current,
                pinned_ip=pinned_ip,
                hops=hop + 1,
            )
        # Loop never exits naturally — the redirect overflow check
        # above raises before this point.
        raise SafeHttpsError("redirect handling fell through")  # pragma: no cover

    # ── Hooks for subclassing in tests ──────────────────────────────────────

    def _resolve_and_pin(self, hostname: str) -> str:
        """Resolve ``hostname`` and return one safe IP, or raise
        :class:`SafeHttpsError`. Subclassed in tests to mock the
        resolver.

        If ``hostname`` (lowercased) is in the operator-supplied
        ``private_index_hosts`` allow-list, the SSRF guard permits
        RFC 1918 / ULA addresses for this hostname only. Loopback /
        link-local / multicast / CGNAT / reserved / unspecified are
        rejected regardless. The DNS-rebinding defence
        (resolve-once-and-pin + getpeername re-check at connect time)
        applies identically to allow-listed hosts.
        """
        host_lc = hostname.strip().lower()
        allow_private = host_lc in self._private_index_hosts
        try:
            infos = socket.getaddrinfo(
                hostname, None,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise SafeHttpsError(
                f"DNS resolution failed for {sanitise(hostname)!r}: "
                f"{sanitise(str(exc))}"
            ) from exc
        for family, _socktype, _proto, _canon, sockaddr in infos:
            ip = str(sockaddr[0])
            if not _ip_is_safe(ip, allow_private=allow_private):
                continue
            return ip
        if allow_private:
            raise SafeHttpsError(
                f"all resolved IPs for {sanitise(hostname)!r} were rejected "
                "even with --allow-private-index-host: loopback / "
                "link-local / CGNAT / multicast / reserved are NEVER "
                "permitted (those ranges are not valid corp-index endpoints)"
            )
        raise SafeHttpsError(
            f"all resolved IPs for {sanitise(hostname)!r} were rejected by "
            "the SSRF deny-list (private / loopback / link-local / "
            "CGNAT / multicast / reserved). If this is a corporate "
            "Nexus on a private IP, pass --allow-private-index-host "
            f"{sanitise(hostname)} to permit RFC 1918 / ULA addresses "
            "for this hostname only."
        )

    def _open_connection(
        self,
        *,
        hostname: str,
        port: int,
        pinned_ip: str,
    ) -> _PinnedHTTPSConnection:
        """Construct the HTTPS connection. Subclassed in tests to
        return a mock connection — keeps the production path
        unchanged."""
        return _PinnedHTTPSConnection(
            pinned_ip=pinned_ip,
            hostname=hostname,
            port=port,
            timeout=self._timeout_s,
            ssl_context=self._ssl_context,
        )

    # ── Internal request helpers ────────────────────────────────────────────

    def _default_headers(self, hostname: str) -> dict[str, str]:
        return {
            "Host": hostname,
            "User-Agent": _USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",  # no pooling — N-2 belt-and-braces
        }

    def _perform_request(
        self,
        *,
        hostname: str,
        port: int,
        path: str,
        pinned_ip: str,
        headers: dict[str, str],
    ) -> HttpResponse:
        conn = self._open_connection(
            hostname=hostname, port=port, pinned_ip=pinned_ip,
        )
        try:
            try:
                conn.request("GET", path, headers=headers)
                http_resp = conn.getresponse()
            except SafeHttpsError:
                raise
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                raise SafeHttpsError(
                    f"HTTPS request failed: {sanitise(str(exc))}"
                ) from exc
            try:
                body = http_resp.read(self._max_response_bytes + 1)
            except (OSError, http.client.HTTPException) as exc:
                raise SafeHttpsError(
                    f"response read failed: {sanitise(str(exc))}"
                ) from exc
            if len(body) > self._max_response_bytes:
                raise SafeHttpsError(
                    f"response body exceeded cap of "
                    f"{self._max_response_bytes} bytes"
                )
            response_headers = {
                k: v for (k, v) in http_resp.getheaders()
            }
            return HttpResponse(
                status=http_resp.status,
                headers=response_headers,
                body=body,
                final_url="",  # filled in by caller
                pinned_ip=pinned_ip,
            )
        finally:
            conn.close()

    def _resolve_redirect_target(self, current: str, location: str) -> str:
        """Resolve a (possibly relative) redirect Location against
        ``current``. The final URL is re-validated by the next loop
        iteration of :meth:`get` — this method just normalises."""
        loc = urlparse(location)
        if loc.scheme and loc.netloc:
            return location
        cur = urlparse(current)
        # Absolute path on same origin.
        if location.startswith("/"):
            return urlunparse((
                cur.scheme, cur.netloc, location, "", "", "",
            ))
        # Relative path — rare in registry redirects but handle it.
        base_path = cur.path.rsplit("/", 1)[0]
        joined = f"{base_path}/{location}"
        return urlunparse((cur.scheme, cur.netloc, joined, "", "", ""))
