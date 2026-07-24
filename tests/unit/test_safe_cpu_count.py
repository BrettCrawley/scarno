"""PR-2 red tests — REQ-19a NEW-ARCH-010 partial (TA-238/239/240):
``_safe_cpu_count`` helper handles None / exception / value cases.

Architecture §11.15.4 places this helper in core/classifier.py so
the REQ-22 differ (PR-4) and any future concurrent code can reuse it.
Full NEW-ARCH-010 coverage (worker cap + locked counter) lands at
PR-4; PR-2 just needs the helper itself.
"""
from __future__ import annotations

import pytest


@pytest.mark.requirement("SEC-NEW-50")
def test_safe_cpu_count_handles_None(monkeypatch):
    """TA-238 — os.cpu_count() returning None falls back to default."""
    from scarno.core import classifier as _cls

    monkeypatch.setattr(_cls.os, "cpu_count", lambda: None)
    assert _cls._safe_cpu_count(default=1) == 1
    assert _cls._safe_cpu_count(default=4) == 4


@pytest.mark.requirement("SEC-NEW-50")
def test_safe_cpu_count_handles_exception(monkeypatch):
    """TA-239 — os.cpu_count() raising falls back to default."""
    from scarno.core import classifier as _cls

    def _raise():
        raise OSError("simulated platform failure")

    monkeypatch.setattr(_cls.os, "cpu_count", _raise)
    assert _cls._safe_cpu_count(default=2) == 2


@pytest.mark.requirement("SEC-NEW-50")
def test_safe_cpu_count_returns_value(monkeypatch):
    """TA-240 — A normal cpu_count return value is passed through."""
    from scarno.core import classifier as _cls

    monkeypatch.setattr(_cls.os, "cpu_count", lambda: 4)
    assert _cls._safe_cpu_count() == 4
