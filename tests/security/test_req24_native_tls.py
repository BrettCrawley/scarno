"""REQ-24 — argv-only ``--native-tls`` opts into the OS-native trust
store (truststore package, same approach as uv / pip / hatch).

The flag is intended for environments where the corporate CA chain
is installed in the OS keychain rather than the Python-bundled cert
bundle (certifi). Without it, Python's default trust store is used —
which on macOS/Windows does NOT read the OS keychain — and corp PKI
chains fail CERTIFICATE_VERIFY_FAILED.

Contracts pinned by these tests:

1. ``truststore`` is importable (the dep is declared in pyproject).
2. The default ``SafeHttpsClient()`` does NOT use truststore.
3. ``SafeHttpsClient(native_tls=True)`` uses a truststore-backed
   SSLContext.
4. BOTH branches keep ``CERT_REQUIRED`` and ``check_hostname=True``
   — there is no path that produces an unverifying context.
5. Both branches pin TLS minimum at 1.2.
"""
from __future__ import annotations

import ssl

import pytest

from scarno.indexing import SafeHttpsClient
from scarno.indexing.http_client import (
    _build_default_ssl_context,
    _build_native_tls_ssl_context,
)

pytestmark = pytest.mark.security


class TestTruststoreAvailable:
    @pytest.mark.requirement("SEC-NEW-60")
    def test_truststore_importable(self):
        """Declared in pyproject.toml — if this fails the dep was
        dropped without updating the contract."""
        import truststore
        assert hasattr(truststore, "SSLContext")


class TestNativeTLSContext:
    @pytest.mark.requirement("SEC-NEW-60")
    def test_native_context_uses_truststore(self):
        """The native-TLS context must be a ``truststore.SSLContext``
        instance, not a plain ``ssl.SSLContext``."""
        import truststore
        ctx = _build_native_tls_ssl_context()
        assert isinstance(ctx, truststore.SSLContext)

    @pytest.mark.requirement("SEC-NEW-60")
    def test_native_context_verifies_certs(self):
        ctx = _build_native_tls_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    @pytest.mark.requirement("SEC-NEW-60")
    def test_native_context_pins_tls12(self):
        ctx = _build_native_tls_ssl_context()
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


class TestSafeHttpsClientWiring:
    @pytest.mark.requirement("SEC-NEW-60")
    def test_default_client_uses_bundled_context(self):
        """Existing callers — no flag, no change."""
        import truststore
        client = SafeHttpsClient()
        # The default context must be a plain ssl.SSLContext, NOT a
        # truststore.SSLContext (would silently flip behaviour).
        assert not isinstance(client._ssl_context, truststore.SSLContext)  # type: ignore[attr-defined]
        assert client._native_tls is False  # type: ignore[attr-defined]

    @pytest.mark.requirement("SEC-NEW-60")
    def test_native_tls_flag_swaps_context(self):
        import truststore
        client = SafeHttpsClient(native_tls=True)
        assert isinstance(client._ssl_context, truststore.SSLContext)  # type: ignore[attr-defined]
        assert client._native_tls is True  # type: ignore[attr-defined]

    @pytest.mark.requirement("SEC-NEW-60")
    def test_native_tls_preserves_verification(self):
        """Sanity — the opt-in must not weaken verification."""
        client = SafeHttpsClient(native_tls=True)
        ctx = client._ssl_context  # type: ignore[attr-defined]
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    @pytest.mark.requirement("SEC-NEW-60")
    def test_default_path_still_intact(self):
        """The default path must produce the exact same context as
        before — no behavioural drift for existing callers."""
        ctx = _build_default_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
