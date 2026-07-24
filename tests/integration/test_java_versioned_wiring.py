"""Regression tests for the REQ-19/20/22 wiring into the live pipeline.

The per-version classifier (``classify_versioned``), the version-keyed
``dep_edges``, and the cross-version ABI differ all existed as tested
components but were never connected to ``JavaAnalyser`` / the CLI merge,
so ``versioned_nodes`` / ``multi_version_coords`` were always empty in a
real run and ``--deep-inspection`` never reached the differ.

These tests lock the wiring in place:

  * ``JavaAnalyser`` runs ``classify_versioned`` over Maven's edges and
    surfaces ``versioned_nodes`` / ``multi_version_coords``.
  * ``--deep-inspection`` constructs the ABI differ (and does not when
    the flag is off).
  * ``_merge_results`` carries the version-keyed fields through.
  * the text + JSON reporters render the multi-version data — using a
    dotted coordinate, which also guards the display-vs-normalised
    coordinate-name join in ``classify_versioned``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import scarno.analysers.java as java_pkg
from scarno.analysers.java import JavaAnalyser
from scarno.analysers.java.maven import MavenPomResolver
from scarno.analysers.java.source_analyser import JvmSourceAnalyser
from scarno.cli import _merge_results
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    DepEdge,
    VersionedNode,
)
from scarno.reporters.json_reporter import JsonReporter
from scarno.reporters.markdown_reporter import MarkdownReporter
from scarno.reporters.text_reporter import TextReporter


# A diamond where ``com.example:shared`` is pulled in at two different
# versions — the canonical multi-version conflict.
_MULTI_VERSION_EDGES = [
    DepEdge(parent="", child="com.example:app-a", declared_version="1.0"),
    DepEdge(parent="", child="com.example:app-b", declared_version="1.0"),
    DepEdge(
        parent="com.example:app-a",
        child="com.example:shared",
        declared_version="2.0",
    ),
    DepEdge(
        parent="com.example:app-b",
        child="com.example:shared",
        declared_version="3.0",
    ),
]


def _maven_deps() -> list[Dependency]:
    return [
        Dependency(
            name="com.example:app-a", version="1.0",
            status=DependencyStatus.IN_USE, reason="", ecosystem="maven",
        ),
        Dependency(
            name="com.example:app-b", version="1.0",
            status=DependencyStatus.IN_USE, reason="", ecosystem="maven",
        ),
        Dependency(
            name="com.example:shared", version="2.0",
            status=DependencyStatus.IN_USE, reason="", ecosystem="maven",
            is_transitive=True,
        ),
    ]


def _patch_jvm_pipeline(monkeypatch) -> None:
    """Stub the Maven resolver (multi-version edges) and the JVM source
    analyser (pass deps straight through) so JavaAnalyser's own wiring
    is what's under test — not the resolvers."""

    def fake_mvn_analyse(self, project_path):  # noqa: ANN001
        return AnalysisResult(
            project_type="java",
            project_path=project_path,
            dependencies=_maven_deps(),
            dep_edges=list(_MULTI_VERSION_EDGES),
        )

    def fake_src_analyse(self, project_path, dependencies=None):  # noqa: ANN001
        return AnalysisResult(
            project_type="java",
            project_path=project_path,
            dependencies=list(dependencies or []),
        )

    monkeypatch.setattr(MavenPomResolver, "analyse", fake_mvn_analyse)
    monkeypatch.setattr(JvmSourceAnalyser, "analyse", fake_src_analyse)


@pytest.mark.requirement("FR-206")
def test_java_analyser_surfaces_versioned_nodes(monkeypatch, tmp_path):
    """JavaAnalyser runs classify_versioned over Maven's dep_edges and
    populates versioned_nodes + multi_version_coords on its result."""
    _patch_jvm_pipeline(monkeypatch)
    (tmp_path / "pom.xml").write_text("<project/>")

    result = JavaAnalyser().analyse(str(tmp_path))

    assert result.dep_edges, "dep_edges dropped — never reached the result"
    assert result.multi_version_coords == ["com.example:shared"]
    shared = [
        n for n in result.versioned_nodes
        if n.canonical == "com.example:shared"
    ]
    assert {n.declared_version for n in shared} == {"2.0", "3.0"}
    # Nearest-wins picks the shortest-path version (2.0) as resolved.
    assert [n.declared_version for n in shared if n.is_resolved] == ["2.0"]


@pytest.mark.requirement("FR-230")
def test_deep_inspection_constructs_abi_differ(monkeypatch, tmp_path):
    """--deep-inspection (the BaseAnalyser attribute the CLI sets) makes
    JavaAnalyser construct the cross-version ABI differ; off does not."""
    _patch_jvm_pipeline(monkeypatch)
    (tmp_path / "pom.xml").write_text("<project/>")

    constructed: list[int] = []

    class _FakeDiffer:
        def __init__(self, *args, **kwargs) -> None:
            constructed.append(1)

        def diff_all(self, result, source_symbols):  # noqa: ANN001
            return []

    monkeypatch.setattr(java_pkg, "CrossVersionAbiDiffer", _FakeDiffer)

    off = JavaAnalyser()
    off.deep_inspection = False
    off.analyse(str(tmp_path))
    assert constructed == [], "differ constructed with --deep-inspection off"

    on = JavaAnalyser()
    on.deep_inspection = True
    on.analyse(str(tmp_path))
    assert constructed == [1], "differ NOT constructed with --deep-inspection on"


@pytest.mark.requirement("FR-206")
def test_merge_results_preserves_versioned_fields():
    """_merge_results must carry dep_edges / versioned_nodes /
    multi_version_coords through — otherwise the reporters never see
    them regardless of what the analysers produced."""
    sub = AnalysisResult(
        project_type="java",
        project_path="/tmp/p",
        dependencies=[],
        dep_edges=[
            DepEdge(parent="", child="com.example:x", declared_version="1.0"),
        ],
        versioned_nodes=[
            VersionedNode(
                canonical="com.example:x", declared_version="1.0",
                status=DependencyStatus.IN_USE,
            ),
        ],
        multi_version_coords=["com.example:x"],
    )
    merged = _merge_results(Path("/tmp/p"), ["java"], [sub])
    assert merged.dep_edges == sub.dep_edges
    assert merged.versioned_nodes == sub.versioned_nodes
    assert merged.multi_version_coords == ["com.example:x"]


@pytest.mark.requirement("FR-206")
def test_text_and_json_reporters_render_multi_version():
    """Both reporters surface the multi-version data. The dotted
    coordinate name is deliberate: it regression-guards the join between
    multi_version_coords and VersionedNode.canonical, which silently
    missed when one side was normalised (``com-google-guava``) and the
    other was not."""
    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/p",
        dependencies=[
            Dependency(
                name="com.google.guava:guava", version="31.1-jre",
                status=DependencyStatus.IN_USE, reason="", ecosystem="maven",
            ),
        ],
        versioned_nodes=[
            VersionedNode(
                canonical="com.google.guava:guava",
                declared_version="28.0-jre",
                status=DependencyStatus.SAFE, removable=True,
            ),
            VersionedNode(
                canonical="com.google.guava:guava",
                declared_version="31.1-jre",
                status=DependencyStatus.IN_USE, is_resolved=True,
            ),
        ],
        multi_version_coords=["com.google.guava:guava"],
    )

    text = TextReporter().render(result)
    assert "MULTIPLE VERSIONS DETECTED" in text
    assert "com.google.guava:guava" in text
    assert "28.0-jre" in text and "31.1-jre" in text
    assert "31.1-jre (resolved)" in text

    payload = json.loads(JsonReporter().render(result))
    assert payload["multi_version_coords"] == ["com.google.guava:guava"]
    assert len(payload["versioned_nodes"]) == 2
    nodes = {n["declared_version"]: n for n in payload["versioned_nodes"]}
    assert nodes["28.0-jre"]["removable"] is True
    assert nodes["31.1-jre"]["is_resolved"] is True


@pytest.mark.requirement("FR-206")
def test_unpinned_version_resolves_instead_of_none():
    """A versioned_node whose edge carried no declared version is shown
    with the resolver's effective version (from the Dependency list),
    not a bare ``(none)`` — in both the text and markdown reporters."""
    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/p",
        dependencies=[
            Dependency(
                name="com.example:lib", version="2.4.0",
                status=DependencyStatus.IN_USE, reason="", ecosystem="maven",
            ),
        ],
        versioned_nodes=[
            VersionedNode(
                canonical="com.example:lib", declared_version=None,
                status=DependencyStatus.IN_USE,
            ),
            VersionedNode(
                canonical="com.example:lib", declared_version="2.0.0",
                status=DependencyStatus.SAFE, removable=True,
            ),
        ],
        multi_version_coords=["com.example:lib"],
    )

    text = TextReporter().render(result)
    assert "(none)" not in text
    assert "2.4.0 (unpinned)" in text

    md = MarkdownReporter().render(result)
    assert "(none)" not in md
    assert "2.4.0 (resolved)" in md


@pytest.mark.requirement("FR-194")
def test_tree_shows_declared_version_for_direct_deps():
    """Direct deps in the ASCII tree render ``name@declared-version``
    from the project's own manifest (the synthetic root edges) — not
    the resolver's effective Dependency.version."""
    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/p",
        dependencies=[
            Dependency(
                name="com.example:app", version="2.0.0",
                status=DependencyStatus.IN_USE, reason="", ecosystem="maven",
            ),
        ],
        dep_edges=[
            DepEdge(
                parent="", child="com.example:app",
                declared_version="1.0.0",
            ),
        ],
    )
    md = MarkdownReporter().render(result)
    assert "com.example:app@1.0.0" in md, (
        "tree should show the declared version 1.0.0"
    )
    assert "com.example:app@2.0.0" not in md, (
        "tree showed Dependency.version instead of the declared version"
    )
