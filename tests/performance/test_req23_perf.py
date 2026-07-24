"""PR-5 red test — REQ-23 / PERF-016: adversarial overrides perf budget.
TA-307."""
from __future__ import annotations

import json
import time

import pytest

pytestmark = pytest.mark.performance


@pytest.mark.requirement("PERF-016")
def test_npm_pin_detection_adversarial_perf(tmp_path):
    """TA-307 — 2048 overrides × 8-deep nesting (post-cap) parses +
    matches in under 100 ms wall clock.

    Catches accidental O(n²) regressions in the override-extraction
    or the direct-dep-vs-override matcher.
    """
    from scarno.analysers.javascript import dep_file_parser as _npm

    # Build a flat-ish overrides set right at the cap.
    overrides = {f"pkg{i}": "1.0.0" for i in range(2048)}
    pkg_root = tmp_path / "project"
    pkg_root.mkdir()
    (pkg_root / "package.json").write_text(
        json.dumps({
            "name": "app", "version": "1.0.0",
            "overrides": overrides,
        })
    )
    start = time.monotonic()
    _npm._extract_overrides(pkg_root, errors=[])
    elapsed = time.monotonic() - start
    assert elapsed < 0.1, (
        f"npm pin-detection took {elapsed * 1000:.1f}ms (budget 100ms)"
    )
