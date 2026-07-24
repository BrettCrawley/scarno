"""PR-4 red test — SEC-NEW-43 / SUC-53: per-run jar cap.

Bumped 128 → 256 so projects with larger multi-version-conflict sets
complete the ABI diff without skipping. The cap is still bounded to
keep adversarial-input runtime predictable. TA-277.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


_EXPECTED_CAP: int = 256


@pytest.mark.requirement("SEC-NEW-43")
def test_javap_max_jars_per_run():
    """TA-277 — Differ caps total inspected jars at the documented
    SEC-NEW-43 value per run.

    Pin the constant; the lock-counted enforcement is exercised by
    ``tests/security/test_arch_threadpool_cap.py``.
    """
    from scarno.analysers.java import abi_diff as _abi

    assert hasattr(_abi, "_JAVAP_MAX_JARS_PER_RUN")
    assert _abi._JAVAP_MAX_JARS_PER_RUN == _EXPECTED_CAP
