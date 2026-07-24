"""TA-356 — REQ-24 / PRV-007 — operator-facing fingerprinting + IP
disclosure section is present in ``docs/LIMITATIONS.md``.

Single source of truth for the documentation-mandated parts of the
REQ-24 control set; if the section is renamed or deleted, this test
fires.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.requirement("PRV-007")
def test_limitations_md_has_req24_section():
    text = (
        Path(__file__).resolve().parent.parent.parent
        / "docs" / "LIMITATIONS.md"
    ).read_text(encoding="utf-8")
    # Header.
    assert "REQ-24 Remote Index Fetch — operator awareness (PRV-007)" in text
    # The four trade-offs the operator must internalise:
    assert "Project fingerprinting" in text
    assert "IP is logged" in text
    assert "advisory by default" in text
    assert "--fail-on-remote-severity" in text
    # The threats named so an operator can find them in THREAT-MODEL.md.
    assert "T-41" in text
    assert "T-44" in text
