"""PR-4 red tests — REQ-22 / FR-230: --deep-inspection CLI flag.

TA-265 / 266 / 267. The flag is OFF by default; setting it requires
the explicit ``--deep-inspection`` argv (no env var, no config file).
When OFF, javap is never spawned for ABI-diff purposes.
"""
from __future__ import annotations

import pytest


@pytest.mark.requirement("FR-230")
def test_deep_inspection_off_by_default():
    """TA-265 — Constructing _RunOptions with no flag yields
    deep_inspection == False."""
    from scarno.cli import _RunOptions

    # _RunOptions is frozen dataclass with all fields keyword. Build
    # with the minimum required set.
    from pathlib import Path
    opts = _RunOptions(
        project_path=Path("."),
        output_path=None,
        format="json",
        verbose=False,
        fail_on_severity=None,
        show_suppressed=False,
    )
    assert hasattr(opts, "deep_inspection"), (
        "_RunOptions must expose a deep_inspection field (FR-230)"
    )
    assert opts.deep_inspection is False


@pytest.mark.requirement("FR-230")
def test_javap_NOT_spawned_when_flag_off(monkeypatch, tmp_path):
    """TA-267 — Running the analyser without --deep-inspection performs
    zero javap calls for ABI-diff purposes.

    We patch the differ's constructor to record invocations; if any
    fires when deep_inspection=False, the test fails red.
    """
    from scarno.analysers.java import source_analyser as _src
    construction_count = {"n": 0}

    # The differ class lives at analysers/java/abi_diff.py and is
    # constructed inside JvmSourceAnalyser.analyse() only when
    # deep_inspection=True. We swap the class with a counter to prove
    # the constructor is not called when the flag is off.
    from scarno.analysers.java import abi_diff as _abi  # noqa: F401

    orig_cls = _abi.CrossVersionAbiDiffer

    class _Counter(orig_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw) -> None:
            construction_count["n"] += 1
            super().__init__(*a, **kw)

    monkeypatch.setattr(_abi, "CrossVersionAbiDiffer", _Counter)

    analyser = _src.JvmSourceAnalyser(deep_inspection=False)
    # Run against a trivial empty project — analyser should not spawn
    # the differ.
    project = tmp_path / "empty"
    project.mkdir()
    analyser.analyse(str(project))
    assert construction_count["n"] == 0
