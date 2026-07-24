"""REQ-24 N-3 + N-8 startup-warning advice from JavaAnalyser."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scarno.indexing import IndexConfigSource, IndexEndpoint
from scarno.models import (
    AnalysisResult,
    DependencyStatus,
    VersionedNode,
)


def _result(tmp_path: Path) -> AnalysisResult:
    return AnalysisResult(
        project_type="java",
        project_path=str(tmp_path),
        multi_version_coords=["com.example:lib"],
        versioned_nodes=[
            VersionedNode(
                canonical="com.example:lib", declared_version="1.0",
                status=DependencyStatus.IN_USE,
            ),
        ],
    )


def _stub_pipeline(monkeypatch, endpoints: list[IndexEndpoint]) -> None:
    from scarno.analysers import java as java_pkg

    class _NopFetcher:
        def __init__(self, **_kw: Any) -> None:
            pass

        def fetch(self, *_a: Any, **_k: Any):
            return None

    monkeypatch.setattr(
        java_pkg, "RemoteArtifactFetcher", _NopFetcher,
    )
    monkeypatch.setattr(
        java_pkg, "SafeHttpsClient", lambda **_kw: None,
    )
    monkeypatch.setattr(
        java_pkg, "resolve_indexes",
        lambda **_kw: (endpoints, []),
    )


@pytest.mark.requirement("SEC-NEW-71")
def test_n3_warns_when_two_indexes_without_cross_check(
    monkeypatch, tmp_path,
):
    """N-3 — when ≥2 indexes for some ecosystem are configured but
    --integrity-cross-check is OFF, suggest enabling it."""
    from scarno.analysers.java import JavaAnalyser

    endpoints = [
        IndexEndpoint("maven", "https://a/repo", 0, IndexConfigSource.CLI),
        IndexEndpoint("maven", "https://b/repo", 1, IndexConfigSource.CLI),
    ]
    _stub_pipeline(monkeypatch, endpoints)

    analyser = JavaAnalyser()
    analyser.allow_remote_fetch = True
    analyser.integrity_cross_check = False

    result = _result(tmp_path)
    # Option 2 — cross-check advice is emitted by ``_maybe_build_fetcher``
    # at fetcher construction time, BEFORE Maven runs.
    analyser._maybe_build_fetcher(tmp_path, result.errors, result.findings)

    n3 = [
        w for w in result.errors
        if "could be cross-checked" in w and "N-3" in w
    ]
    assert n3, f"missing N-3 warning; result.errors: {result.errors}"


@pytest.mark.requirement("FR-261")
def test_n8_warns_when_cross_check_on_with_one_index(
    monkeypatch, tmp_path,
):
    """N-8 — when --integrity-cross-check is ON but only 1 index is
    configured for some ecosystem, audit that cross-check is a no-op
    for that ecosystem."""
    from scarno.analysers.java import JavaAnalyser

    endpoints = [
        IndexEndpoint("maven", "https://a/repo", 0, IndexConfigSource.CLI),
    ]
    _stub_pipeline(monkeypatch, endpoints)

    analyser = JavaAnalyser()
    analyser.allow_remote_fetch = True
    analyser.integrity_cross_check = True

    result = _result(tmp_path)
    # Option 2 — cross-check advice is emitted by ``_maybe_build_fetcher``
    # at fetcher construction time, BEFORE Maven runs.
    analyser._maybe_build_fetcher(tmp_path, result.errors, result.findings)

    n8 = [w for w in result.errors if "N-8" in w]
    assert n8, f"missing N-8 warning; result.errors: {result.errors}"


@pytest.mark.requirement("FR-261")
def test_no_advice_when_two_indexes_and_cross_check_on(
    monkeypatch, tmp_path,
):
    """Happy configuration — neither N-3 nor N-8 fires."""
    from scarno.analysers.java import JavaAnalyser

    endpoints = [
        IndexEndpoint("maven", "https://a/repo", 0, IndexConfigSource.CLI),
        IndexEndpoint("maven", "https://b/repo", 1, IndexConfigSource.CLI),
    ]
    _stub_pipeline(monkeypatch, endpoints)

    analyser = JavaAnalyser()
    analyser.allow_remote_fetch = True
    analyser.integrity_cross_check = True

    result = _result(tmp_path)
    # Option 2 — cross-check advice is emitted by ``_maybe_build_fetcher``
    # at fetcher construction time, BEFORE Maven runs.
    analyser._maybe_build_fetcher(tmp_path, result.errors, result.findings)

    assert not any("N-3" in w for w in result.errors)
    assert not any("N-8" in w for w in result.errors)
