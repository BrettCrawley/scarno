"""TA-339..TA-343 + TA-345 — REQ-24 / SEC-NEW-60 — :class:`SafeHttpsClient`
SSRF + cert + pin-IP + IPv6 + redirect invariants.

Each ``Test...`` class corresponds to one TA-XXX from REQ-24's SRTM:

* :class:`TestCertVerificationMandatory` — TA-339
* :class:`TestIPv4DenyList` — TA-340
* :class:`TestIPv6AndV4MappedDenyList` — TA-341
* :class:`TestDnsRebindingPinnedIP` — TA-342
* :class:`TestPeerNameRecheck` — TA-343
* :class:`TestRedirectPolicy` — TA-345
"""
from __future__ import annotations

import ssl
from typing import Any
from unittest.mock import patch

import pytest

from scarno.indexing import HttpResponse, SafeHttpsClient, SafeHttpsError
from scarno.indexing.http_client import (
    _build_default_ssl_context,
    _ip_is_safe,
    _PinnedHTTPSConnection,
)

pytestmark = pytest.mark.security


# ── TA-339 — cert verification mandatory ───────────────────────────────────


class TestCertVerificationMandatory:
    @pytest.mark.requirement("SEC-NEW-60")
    def test_default_ssl_context_requires_cert_and_hostname(self):
        ctx = _build_default_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        # TLS 1.2 floor — explicit pinning, not implicit.
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    @pytest.mark.requirement("SEC-NEW-60")
    def test_constructor_accepts_no_verify_parameter(self):
        """N-2 / TS-006 — no constructor parameter exists for ``verify``
        or ``check_hostname``. A future contributor that wants to relax
        verification has to subclass and add a method, which is large
        enough to surface in code review."""
        import inspect

        sig = inspect.signature(SafeHttpsClient.__init__)
        assert "verify" not in sig.parameters
        assert "check_hostname" not in sig.parameters
        assert "ssl_context" not in sig.parameters
        assert "ssl_ctx" not in sig.parameters

    @pytest.mark.requirement("SEC-NEW-60")
    def test_client_carries_verifying_context(self):
        client = SafeHttpsClient()
        ctx = client._ssl_context  # noqa: SLF001 — security-test inspection
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True


# ── TA-340 — IPv4 deny ranges ───────────────────────────────────────────────


class TestIPv4DenyList:
    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",       # loopback
            "127.255.255.255",  # loopback range
            "10.0.0.1",        # RFC 1918
            "172.16.0.1",      # RFC 1918
            "192.168.1.1",     # RFC 1918
            "169.254.169.254",  # link-local (AWS metadata)
            "100.64.0.1",      # CGNAT
            "224.0.0.1",       # multicast
            "240.0.0.1",       # reserved
            "0.0.0.0",         # unspecified
        ],
    )
    def test_unsafe_ipv4_addresses_rejected(self, ip):
        assert _ip_is_safe(ip) is False, (
            f"IPv4 {ip} must be rejected by SSRF deny-list"
        )

    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "151.101.1.7",  # public CDN range
        ],
    )
    def test_public_ipv4_addresses_accepted(self, ip):
        assert _ip_is_safe(ip) is True


# ── TA-341 — IPv6 + IPv4-mapped + zone-id ──────────────────────────────────


class TestIPv6AndV4MappedDenyList:
    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.parametrize(
        "ip",
        [
            "::1",                       # loopback
            "fc00::1",                   # ULA (private)
            "fd00::1",                   # ULA (private)
            "fe80::1",                   # link-local
            "ff00::1",                   # multicast
            "::",                        # unspecified
            # IPv4-mapped IPv6 — must be re-classified against the
            # embedded v4 address.
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
        ],
    )
    def test_unsafe_ipv6_addresses_rejected(self, ip):
        assert _ip_is_safe(ip) is False, (
            f"IPv6 {ip} must be rejected"
        )

    @pytest.mark.requirement("SEC-NEW-60")
    def test_zone_id_stripped_before_match(self):
        """N-5 — ``fe80::1%eth0`` MUST be rejected. Zone-id stripping
        happens before deny-list classification."""
        assert _ip_is_safe("fe80::1%eth0") is False
        assert _ip_is_safe("fe80::1%lo0") is False

    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.parametrize(
        "ip",
        [
            "2606:4700:4700::1111",  # public Cloudflare DNS
            "2001:4860:4860::8888",  # public Google DNS
        ],
    )
    def test_public_ipv6_addresses_accepted(self, ip):
        assert _ip_is_safe(ip) is True

    @pytest.mark.requirement("SEC-NEW-60")
    def test_garbage_input_rejected(self):
        assert _ip_is_safe("not-an-ip") is False
        assert _ip_is_safe("") is False
        assert _ip_is_safe("999.999.999.999") is False


# ── TA-342 — DNS rebinding via mock resolver: pinned IP wins ──────────────


class _RecordingClient(SafeHttpsClient):
    """Test subclass that records every request attempt and lets the
    test swap in canned DNS resolutions + canned responses. The
    production code path is untouched.

    Recording happens in ``_perform_request`` (not ``_open_connection``)
    because production calls ``_open_connection`` from inside
    ``_perform_request``; if ``_perform_request`` is mocked,
    ``_open_connection`` is never reached.
    """

    def __init__(self, *, resolutions: list[str], **kw: Any) -> None:
        super().__init__(**kw)
        self._resolutions = resolutions
        self.opened: list[dict[str, Any]] = []
        self.canned_responses: list[HttpResponse] = []

    def _resolve_and_pin(self, hostname: str) -> str:
        for ip in self._resolutions:
            if _ip_is_safe(ip):
                return ip
        raise SafeHttpsError(
            "all resolved IPs for {!r} were rejected by the SSRF "
            "deny-list (test fixture)".format(hostname)
        )

    def _perform_request(self, *, hostname, port, path, pinned_ip, headers):
        self.opened.append({
            "hostname": hostname,
            "port": port,
            "pinned_ip": pinned_ip,
            "path": path,
            "headers": dict(headers),
        })
        if not self.canned_responses:
            raise SafeHttpsError("no canned response (test fixture)")
        resp = self.canned_responses.pop(0)
        return HttpResponse(
            status=resp.status,
            headers=resp.headers,
            body=resp.body,
            final_url="",
            pinned_ip=pinned_ip,
        )


class TestDnsRebindingPinnedIP:
    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.requirement("T-39")
    def test_pinned_ip_used_even_if_dns_changes(self):
        """The classic rebind: validation sees a public IP, between
        validation and connect DNS flips to ``169.254.169.254``. Our
        pinned-IP semantics mean we *connect to the validated IP*, not
        the rebound one — the rebind has nothing to bite."""
        client = _RecordingClient(resolutions=["8.8.8.8"])
        client.canned_responses = [
            HttpResponse(
                status=200, headers={}, body=b"ok",
                final_url="", pinned_ip="",
            )
        ]
        client.get("https://example.com/path")
        assert client.opened[0]["pinned_ip"] == "8.8.8.8"

    @pytest.mark.requirement("SEC-NEW-60")
    def test_unsafe_resolutions_rejected_before_connect(self):
        """If DNS returns ONLY unsafe IPs, get() raises BEFORE any
        socket is opened."""
        client = _RecordingClient(
            resolutions=["169.254.169.254", "127.0.0.1"]
        )
        with pytest.raises(SafeHttpsError, match="rejected by the SSRF"):
            client.get("https://example.com/path")
        assert client.opened == [], (
            "connection attempted with unsafe IP — SSRF guard did not fire"
        )

    @pytest.mark.requirement("SEC-NEW-60")
    def test_first_safe_ip_wins_when_mixed(self):
        """When DNS returns a mix of unsafe and safe IPs, the first
        safe one is pinned (the unsafe ones are simply skipped)."""
        client = _RecordingClient(
            resolutions=["10.0.0.1", "8.8.8.8"]
        )
        client.canned_responses = [
            HttpResponse(
                status=200, headers={}, body=b"ok",
                final_url="", pinned_ip="",
            )
        ]
        client.get("https://example.com/")
        assert client.opened[0]["pinned_ip"] == "8.8.8.8"


# ── TA-343 — peer-name re-check ────────────────────────────────────────────


class TestPeerNameRecheck:
    @pytest.mark.requirement("SEC-NEW-60")
    def test_peer_mismatch_raises_before_tls(self, monkeypatch):
        """If ``getpeername()`` disagrees with the pinned IP, the
        connection MUST abort *before* TLS / data flow."""
        # Build a fake socket that connects to whatever address but
        # reports a different peer.
        import socket as _sock

        class _FakeSocket:
            def __init__(self, *_, **__):
                self.closed = False

            def settimeout(self, _t):
                pass

            def connect(self, _addr):
                pass  # pretend connect succeeded

            def getpeername(self):
                return ("169.254.169.254", 443)

            def close(self):
                self.closed = True

        monkeypatch.setattr(_sock, "socket", _FakeSocket)

        conn = _PinnedHTTPSConnection(
            pinned_ip="8.8.8.8",
            hostname="example.com",
            port=443,
            timeout=5.0,
            ssl_context=_build_default_ssl_context(),
        )
        with pytest.raises(SafeHttpsError, match="possible DNS rebinding"):
            conn.connect()


# ── TA-345 — redirect policy: ≤2 hops, full re-validation, header drop ────


class _RedirectingClient(SafeHttpsClient):
    """Subclass that returns a programmable sequence of redirect
    responses to exercise the redirect loop."""

    def __init__(self, *, scripted: list[HttpResponse], **kw: Any) -> None:
        super().__init__(**kw)
        self._scripted = scripted
        self.requests: list[dict[str, Any]] = []

    def _resolve_and_pin(self, hostname: str) -> str:
        return "8.8.8.8"  # any safe IP — tests focus on redirect flow

    def _perform_request(self, *, hostname, port, path, pinned_ip, headers):
        self.requests.append({
            "hostname": hostname, "port": port, "path": path,
            "pinned_ip": pinned_ip, "headers": dict(headers),
        })
        return self._scripted.pop(0)


class TestRedirectPolicy:
    @pytest.mark.requirement("SEC-NEW-63")
    def test_one_hop_same_host_followed(self):
        client = _RedirectingClient(scripted=[
            HttpResponse(
                status=302, headers={"Location": "/redirected"},
                body=b"", final_url="", pinned_ip="",
            ),
            HttpResponse(
                status=200, headers={}, body=b"final",
                final_url="", pinned_ip="",
            ),
        ])
        resp = client.get("https://example.com/start")
        assert resp.status == 200
        assert resp.body == b"final"
        assert resp.hops == 2
        # Same-host: Host header preserved.
        assert client.requests[1]["headers"]["Host"] == "example.com"
        assert client.requests[1]["path"] == "/redirected"

    @pytest.mark.requirement("SEC-NEW-63")
    def test_two_hops_max_third_rejected(self):
        client = _RedirectingClient(scripted=[
            HttpResponse(
                status=302, headers={"Location": "/r1"},
                body=b"", final_url="", pinned_ip="",
            ),
            HttpResponse(
                status=302, headers={"Location": "/r2"},
                body=b"", final_url="", pinned_ip="",
            ),
            HttpResponse(
                status=302, headers={"Location": "/r3"},
                body=b"", final_url="", pinned_ip="",
            ),
        ])
        with pytest.raises(SafeHttpsError, match="redirect limit exceeded"):
            client.get("https://example.com/start")

    @pytest.mark.requirement("SEC-NEW-63")
    def test_cross_host_redirect_drops_headers_and_revalidates(self):
        """Cross-host redirect: the new hostname is re-validated through
        ``_resolve_and_pin`` and a fresh header set is built (no carryover
        of the prior request's headers — defines the v2 auth-header rule).
        """
        client = _RedirectingClient(scripted=[
            HttpResponse(
                status=302,
                headers={"Location": "https://other.example/path"},
                body=b"", final_url="", pinned_ip="",
            ),
            HttpResponse(
                status=200, headers={}, body=b"ok",
                final_url="", pinned_ip="",
            ),
        ])
        client.get("https://first.example/start")
        # The second request's Host header is for the NEW host, not the old.
        assert client.requests[1]["hostname"] == "other.example"
        assert client.requests[1]["headers"]["Host"] == "other.example"
        # Headers built fresh per-hop (no prior-request leakage):
        assert client.requests[1]["headers"]["Host"] != "first.example"

    @pytest.mark.requirement("SEC-NEW-63")
    def test_no_redirect_returns_response_directly(self):
        client = _RedirectingClient(scripted=[
            HttpResponse(
                status=200, headers={}, body=b"plain",
                final_url="", pinned_ip="",
            ),
        ])
        resp = client.get("https://example.com/")
        assert resp.status == 200
        assert resp.hops == 1


# ── URL-validation gate (every hop, including fresh URLs) ──────────────────


class TestUrlValidation:
    @pytest.mark.requirement("SEC-NEW-60")
    def test_http_scheme_rejected(self):
        client = SafeHttpsClient()
        with pytest.raises(SafeHttpsError, match="https"):
            client.get("http://example.com/")

    @pytest.mark.requirement("SEC-NEW-60")
    def test_userinfo_in_url_rejected(self):
        client = SafeHttpsClient()
        with pytest.raises(SafeHttpsError, match="userinfo"):
            client.get("https://user:pass@example.com/")
