"""TA-348 + TA-349 — REQ-24 quarantined-cache eviction:
* TA-348 (SEC-NEW-66) — total-size cap + LRU eviction.
* TA-349 (SEC-NEW-67) — per-artefact TTL.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from scarno.indexing.fetcher import _CachePolicy, _enforce_cache_cap


def _write(path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


# ── TA-348 — total-size cap + LRU ──────────────────────────────────────────


class TestSizeCapAndLRU:
    @pytest.mark.requirement("SEC-NEW-66")
    def test_oldest_evicted_first_when_cap_exceeded(self, tmp_path):
        cache = tmp_path / "cache"
        _write(cache / "old.jar", 1000)
        _write(cache / "newer.jar", 1000)
        _write(cache / "newest.jar", 1000)
        # Backdate two of them so eviction order is deterministic.
        now = time.time()
        os.utime(cache / "old.jar", (now - 1000, now - 1000))
        os.utime(cache / "newer.jar", (now - 500, now - 500))
        os.utime(cache / "newest.jar", (now, now))

        policy = _CachePolicy(
            root=cache, total_size_bytes=1500,
            ttl_seconds=999_999, per_artefact_max_bytes=10_000_000,
        )
        _enforce_cache_cap(policy)

        # Total budget 1500; entries are 1000 each. Evict oldest first
        # until under cap. After evicting `old.jar`, total = 2000 > 1500
        # → evict `newer.jar` too. `newest.jar` survives.
        assert not (cache / "old.jar").exists()
        assert not (cache / "newer.jar").exists()
        assert (cache / "newest.jar").exists()

    @pytest.mark.requirement("SEC-NEW-66")
    def test_under_cap_no_eviction(self, tmp_path):
        cache = tmp_path / "cache"
        _write(cache / "small.jar", 100)
        policy = _CachePolicy(
            root=cache, total_size_bytes=10_000,
            ttl_seconds=999_999, per_artefact_max_bytes=10_000_000,
        )
        _enforce_cache_cap(policy)
        assert (cache / "small.jar").exists()


# ── TA-349 — per-artefact TTL ──────────────────────────────────────────────


class TestTTLEviction:
    @pytest.mark.requirement("SEC-NEW-67")
    def test_expired_files_evicted_on_pass(self, tmp_path):
        cache = tmp_path / "cache"
        _write(cache / "fresh.jar", 100)
        _write(cache / "stale.jar", 100)
        now = time.time()
        os.utime(cache / "fresh.jar", (now, now))
        os.utime(cache / "stale.jar", (now - 1_000_000, now - 1_000_000))

        policy = _CachePolicy(
            root=cache, total_size_bytes=10_000_000,
            ttl_seconds=10.0,  # everything older than 10s is expired
            per_artefact_max_bytes=10_000_000,
        )
        _enforce_cache_cap(policy)

        assert (cache / "fresh.jar").exists()
        assert not (cache / "stale.jar").exists()

    @pytest.mark.requirement("SEC-NEW-67")
    def test_ttl_eviction_runs_before_size_cap(self, tmp_path):
        """A file past TTL is evicted *even* if the cache is under
        the size cap (TTL is its own gate, not just a fallback)."""
        cache = tmp_path / "cache"
        _write(cache / "ancient.jar", 100)
        now = time.time()
        os.utime(cache / "ancient.jar", (now - 1_000_000, now - 1_000_000))
        policy = _CachePolicy(
            root=cache, total_size_bytes=10_000_000,
            ttl_seconds=10.0, per_artefact_max_bytes=10_000_000,
        )
        _enforce_cache_cap(policy)
        assert not (cache / "ancient.jar").exists()
