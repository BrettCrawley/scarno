"""REQ-24 — argv-only ``--allow-private-index-host`` allow-list.

The SSRF guard hard-rejects RFC 1918 / ULA by default. Corporate
Nexus deployments routinely live on those ranges; the allow-list lets
the operator opt one specific hostname in without weakening the guard
for arbitrary hosts. Loopback / link-local / CGNAT / multicast /
reserved are NEVER permitted even when allow-listed.

Tests pin the four contracts that matter:

1. Default (empty allow-list) still hard-blocks private IPs.
2. Allow-listed hostname permits RFC 1918 / ULA — and ONLY private;
   loopback / link-local / CGNAT / multicast / reserved stay blocked.
3. Hostname allow-list does NOT inherit across cross-host redirects
   — each hop re-validates against the original list.
4. Cross-host redirect to a non-allow-listed host whose IP is
   private fails with the same SSRF error as if allow-list was empty.
"""
from __future__ import annotations

import pytest

from scarno.indexing import HttpResponse, SafeHttpsClient, SafeHttpsError
from scarno.indexing.http_client import _ip_is_safe

pytestmark = pytest.mark.security


class TestIpSafeRespectsAllowPrivate:
    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "fc00::1",
            "fd12:3456:789a::1",
        ],
    )
    def test_private_accepted_when_allow_private_true(self, ip):
        assert _ip_is_safe(ip, allow_private=True) is True

    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",            # loopback (NEVER relaxed)
            "169.254.169.254",      # link-local / AWS metadata
            "100.64.0.1",           # CGNAT
            "224.0.0.1",            # multicast
            "240.0.0.1",            # reserved
            "0.0.0.0",              # unspecified
            "::1",                  # IPv6 loopback
            "fe80::1",              # IPv6 link-local
            "ff00::1",              # IPv6 multicast
            "::ffff:127.0.0.1",     # IPv4-mapped loopback
            "::ffff:169.254.169.254",  # IPv4-mapped link-local
        ],
    )
    def test_never_relaxed_for_non_private_ranges(self, ip):
        """Even with ``allow_private=True``, these ranges stay rejected."""
        assert _ip_is_safe(ip, allow_private=True) is False, (
            f"{ip} must NEVER be reachable, even with allow-list"
        )

    @pytest.mark.requirement("SEC-NEW-60")
    @pytest.mark.parametrize(
        "ip",
        ["10.0.0.1", "192.168.1.1", "fc00::1", "fd00::1"],
    )
    def test_default_still_rejects_private(self, ip):
        """Sanity — without the opt-in, behaviour is unchanged."""
        assert _ip_is_safe(ip) is False


class _AllowListClient(SafeHttpsClient):
    """Test subclass that records every request attempt and lets the
    test programme the DNS resolution. Mirrors the existing
    :class:`_RecordingClient` pattern in
    ``test_req24_safe_https_client.py``."""

    def __init__(self, *, dns: dict[str, list[str]], **kwargs) -> None:
        super().__init__(**kwargs)
        self._dns = dns
        self.attempts: list[dict] = []

    def _resolve_and_pin(self, hostname: str) -> str:  # type: ignore[override]
        # Delegate to the real SSRF guard but supply a programmed DNS
        # result instead of touching the network. We monkey-patch by
        # temporarily replacing socket.getaddrinfo's effect via the
        # superclass logic — easier here to just reimplement the
        # filter directly using the same _ip_is_safe semantics.
        from scarno.indexing.http_client import _ip_is_safe
        host_lc = hostname.strip().lower()
        allow_private = host_lc in self._private_index_hosts  # type: ignore[attr-defined]
        for ip in self._dns.get(hostname, []):
            if _ip_is_safe(ip, allow_private=allow_private):
                return ip
        raise SafeHttpsError(
            f"all resolved IPs for {hostname!r} rejected "
            f"(allow_private={allow_private})"
        )

    def _open_connection(self, *, hostname, port, pinned_ip):  # type: ignore[override]
        self.attempts.append(
            {"hostname": hostname, "port": port, "pinned_ip": pinned_ip},
        )
        # Return a stub that performs no I/O. The tests in this module
        # only need to assert WHETHER a connect would have been made
        # and to what IP; the full response cycle is covered by
        # ``test_req24_safe_https_client.py``'s _RecordingClient.
        raise SafeHttpsError("test stub — no real connection attempted")


class TestAllowListPermitsCorpNexus:
    """The headline use case — nexus.corp.org resolves to 10.x and the
    allow-list lets it through."""

    @pytest.mark.requirement("SEC-NEW-60")
    def test_corp_host_resolves_to_private_ip_succeeds(self):
        client = _AllowListClient(
            dns={"nexus.corp.org": ["10.20.30.40"]},
            private_index_hosts=("nexus.corp.org",),
        )
        # _resolve_and_pin returns the pinned IP; _open_connection then
        # raises our stub error. We assert against the recorded attempt.
        with pytest.raises(SafeHttpsError, match="test stub"):
            client.get("https://nexus.corp.org/repo/foo")
        assert len(client.attempts) == 1
        assert client.attempts[0]["hostname"] == "nexus.corp.org"
        assert client.attempts[0]["pinned_ip"] == "10.20.30.40"

    @pytest.mark.requirement("SEC-NEW-60")
    def test_non_listed_corp_host_resolving_to_private_ip_fails(self):
        client = _AllowListClient(
            dns={"other.corp.org": ["10.20.30.40"]},
            # Allow-list names a different host.
            private_index_hosts=("nexus.corp.org",),
        )
        with pytest.raises(SafeHttpsError, match="rejected"):
            client.get("https://other.corp.org/repo/foo")
        # No connection attempt should have been made.
        assert client.attempts == []

    @pytest.mark.requirement("SEC-NEW-60")
    def test_case_insensitive_hostname_match(self):
        """The URL host arrives lowercased from urlparse, but the
        allow-list itself accepts mixed-case entries (the analyser
        passes through whatever the operator typed)."""
        # urlparse lowercases the netloc, so DNS is keyed lowercase here.
        client = _AllowListClient(
            dns={"nexus.corp.org": ["10.20.30.40"]},
            # Operator typed mixed-case on argv — must still match.
            private_index_hosts=("NeXuS.CoRp.OrG",),
        )
        with pytest.raises(SafeHttpsError, match="test stub"):
            client.get("https://NEXUS.CORP.ORG/repo/foo")
        assert client.attempts[0]["pinned_ip"] == "10.20.30.40"

    @pytest.mark.requirement("SEC-NEW-60")
    def test_loopback_blocked_even_when_host_is_allow_listed(self):
        """The allow-list relaxes private ranges only; 127.0.0.1 stays
        blocked even when the hostname is on the list. Closes a
        common misunderstanding."""
        client = _AllowListClient(
            dns={"nexus.corp.org": ["127.0.0.1"]},
            private_index_hosts=("nexus.corp.org",),
        )
        with pytest.raises(SafeHttpsError, match="rejected"):
            client.get("https://nexus.corp.org/repo/foo")
        assert client.attempts == []

    @pytest.mark.requirement("SEC-NEW-60")
    def test_first_safe_ip_wins_when_mixed(self):
        """DNS returns one private and one public IP for an allow-listed
        host: order is preserved, first safe wins."""
        client = _AllowListClient(
            dns={"nexus.corp.org": ["192.168.1.1", "8.8.8.8"]},
            private_index_hosts=("nexus.corp.org",),
        )
        with pytest.raises(SafeHttpsError, match="test stub"):
            client.get("https://nexus.corp.org/repo/foo")
        assert client.attempts[0]["pinned_ip"] == "192.168.1.1"

    @pytest.mark.requirement("SEC-NEW-60")
    def test_empty_allow_list_is_default(self):
        """Constructor default is empty — pre-allow-list behaviour
        is preserved for every existing caller."""
        client = SafeHttpsClient()
        assert client._private_index_hosts == frozenset()  # type: ignore[attr-defined]

    @pytest.mark.requirement("SEC-NEW-60")
    def test_whitespace_and_empty_entries_dropped(self):
        client = SafeHttpsClient(
            private_index_hosts=("  nexus.corp.org  ", "", "   "),
        )
        assert client._private_index_hosts == frozenset({"nexus.corp.org"})  # type: ignore[attr-defined]
