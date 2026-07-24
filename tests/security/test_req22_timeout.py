"""PR-4 red test — SEC-NEW-42: javap per-jar timeout 30s. TA-276."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-42")
def test_javap_per_jar_timeout_30s_constant():
    """TA-276 — The differ exposes a 30s per-jar timeout constant or
    builds the timeout into the invoke_javap wrapper. A hostile JAR
    sleeping > 30s must produce a sanitised error and let analysis
    continue rather than hang.
    """
    from scarno.analysers.java import abi_diff as _abi

    assert hasattr(_abi, "_JAVAP_PER_JAR_TIMEOUT_S")
    assert _abi._JAVAP_PER_JAR_TIMEOUT_S == 30
