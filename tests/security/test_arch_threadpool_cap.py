"""PR-4 red tests — NEW-ARCH-010 / SEC-NEW-50 / SUC-61 / PERF-017:
ThreadPoolExecutor cap + locked atomic counter (TA-280..284).

Architecture §11.15.4 + ADR-010 require:
- max_workers = min(8, os.cpu_count() or 1) (D-Phase9-01)
- Cap counter under threading.Lock so the SEC-NEW-43 jar cap (128)
  is EXACT under concurrent execution, not approximate.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-50")
def test_threadpool_max_workers_capped_at_8(monkeypatch):
    """TA-280 — cpu_count = 16 produces max_workers == 8."""
    from scarno.analysers.java import abi_diff as _abi

    monkeypatch.setattr(_abi.os, "cpu_count", lambda: 16)
    assert _abi._compute_max_workers() == 8


@pytest.mark.requirement("SEC-NEW-50")
def test_threadpool_max_workers_min_with_cpu_count(monkeypatch):
    """TA-281 — cpu_count = 4 produces max_workers == 4."""
    from scarno.analysers.java import abi_diff as _abi

    monkeypatch.setattr(_abi.os, "cpu_count", lambda: 4)
    assert _abi._compute_max_workers() == 4


@pytest.mark.requirement("SEC-NEW-50")
def test_threadpool_max_workers_None_falls_back_to_1(monkeypatch):
    """TA-282 — cpu_count returning None falls back to 1."""
    from scarno.analysers.java import abi_diff as _abi

    monkeypatch.setattr(_abi.os, "cpu_count", lambda: None)
    assert _abi._compute_max_workers() == 1


@pytest.mark.requirement("PERF-017")
def test_cap_counter_atomic_under_concurrency(tmp_path):
    """TA-283 — concurrent ``_try_consume_cap_slots`` calls produce
    EXACTLY ``_JAVAP_MAX_JARS_PER_RUN / 2`` successful claims (each
    work item costs 2 slots, declared + resolved jar) and the rest
    are cap-rejects. Counter mutated only inside the cap lock — so
    the cap is exact under concurrency, not approximate.

    Probes the SEC-NEW-43 constant rather than hard-coding 64/128 so
    a future bump (or revert) doesn't silently break the assertion.
    """
    from scarno.analysers.java.abi_diff import (
        CrossVersionAbiDiffer,
        _JAVAP_MAX_JARS_PER_RUN,
    )
    import threading

    differ = CrossVersionAbiDiffer(
        m2_root=tmp_path,
        invoke_javap=lambda *_a: None,
    )
    # Stress the cap with twice as many concurrent claims as it can
    # accept so we always observe a non-zero reject count.
    items_per_claim = 2  # declared + resolved
    expected_passes = _JAVAP_MAX_JARS_PER_RUN // items_per_claim
    total_threads = expected_passes * 2  # ensure rejects > 0

    passes = 0
    rejects = 0
    lock = threading.Lock()

    def _try():
        nonlocal passes, rejects
        if differ._try_consume_cap_slots(items_per_claim):
            with lock:
                passes += 1
        else:
            with lock:
                rejects += 1

    threads = [threading.Thread(target=_try) for _ in range(total_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected_rejects = total_threads - expected_passes
    assert passes == expected_passes, (
        f"expected {expected_passes} cap-passes (cap "
        f"{_JAVAP_MAX_JARS_PER_RUN} / {items_per_claim} slots/item), "
        f"got {passes}"
    )
    assert rejects == expected_rejects, (
        f"expected {expected_rejects} cap-rejects, got {rejects}"
    )
