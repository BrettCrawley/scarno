"""PR-1 red tests — SEC-NEW-37 lockfile size + edge cap (TA-217 / TA-218).

Adversarial lockfile defences:
  * `_LOCKFILE_MAX_BYTES = 8 MiB` — file rejected at pre-parse with a
    sanitised error; partial result still produced.
  * `_LOCKFILE_MAX_EDGES = 50_000` — edge emission stops at the cap;
    truncation note appended.
"""
from __future__ import annotations

import json

import pytest

from scarno.analysers.javascript import dep_file_parser as _npm

pytestmark = pytest.mark.security


# ── TA-217 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-37")
def test_lockfile_size_cap_rejects_9MiB(tmp_path):
    """TA-217 — A 9 MiB synthetic package-lock.json is rejected pre-parse
    with a sanitised "lockfile too large" error; the rest of the analysis
    completes (partial result returned, not raised).
    """
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "package.json").write_text(
        json.dumps({"name": "app", "version": "1.0.0"})
    )
    # 9 MiB of valid JSON content — large filler value to exceed the cap.
    filler = "x" * (9 * 1024 * 1024)
    (project_root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1.0.0"}},
                # adversarial padding pushing the file size over the cap
                "_padding": filler,
            }
        )
    )

    result = _npm.parse_all_npm_dependency_files(  # type: ignore[call-arg]
        str(project_root)
    )
    # The parser must not raise — must return a partial result with an
    # error recorded.
    errors = getattr(result, "errors", None) or []
    if not errors and isinstance(result, tuple):
        for item in result:
            if isinstance(item, list) and item and isinstance(item[0], str):
                errors = item
                break
    assert any(
        ("too large" in msg.lower()) or ("size" in msg.lower())
        for msg in errors
    ), f"expected lockfile-too-large error; got {errors!r}"


# ── TA-218 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("SEC-NEW-37")
def test_lockfile_edge_cap_rejects_60k_edges(tmp_path):
    """TA-218 — A lockfile within the byte cap but containing 60 000 edges
    stops emission at 50 000; a truncation note appears in errors[].
    """
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "package.json").write_text(
        json.dumps({"name": "app", "version": "1.0.0"})
    )
    # Build 60 000 synthetic packages each declaring one dependency.
    packages = {"": {"name": "app", "version": "1.0.0", "dependencies": {}}}
    for i in range(60_000):
        packages[f"node_modules/pkg{i}"] = {
            "version": "1.0.0",
            "dependencies": {f"pkg{i + 1}": "1.0.0"},
        }
    (project_root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": packages,
            }
        )
    )

    result = _npm.parse_all_npm_dependency_files(  # type: ignore[call-arg]
        str(project_root)
    )
    edges = getattr(result, "edges", None) or []
    assert len(edges) <= 50_000, (
        f"edge cap not enforced; got {len(edges)} edges"
    )
    errors = getattr(result, "errors", None) or []
    if not errors and isinstance(result, tuple):
        for item in result:
            if isinstance(item, list) and item and isinstance(item[0], str):
                errors = item
                break
    assert any(
        "truncat" in msg.lower() or "cap" in msg.lower()
        for msg in errors
    ), f"expected edge truncation note; got {errors!r}"
