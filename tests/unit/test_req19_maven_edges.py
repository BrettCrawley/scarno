"""PR-1 red tests — REQ-19 Maven edge emission (TA-203 / TA-204 / TA-205).

Maven walker emits a DepEdge per ``<dependency>`` from each walked POM.
Property resolution must precede edge emission (REQ-17b §"Maven property
resolution"). Unresolvable placeholders emit ``declared_version=None``
rather than dropping the edge entirely.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scarno.analysers.java import maven as _maven


def _write_pom(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _build_diamond_m2(tmp_path: Path) -> Path:
    """Construct a fake ~/.m2 layout with a diamond:

        root pom declares alpha 2.0 + beta 3.0
        alpha 2.0  → transitive x 1.1
        beta  3.0  → transitive x 1.2
    """
    m2 = tmp_path / "m2"
    alpha_pom = m2 / "com/example/alpha/2.0/alpha-2.0.pom"
    beta_pom = m2 / "com/example/beta/3.0/beta-3.0.pom"
    _write_pom(
        alpha_pom,
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>alpha</artifactId>
  <version>2.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>x</artifactId>
      <version>1.1</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    _write_pom(
        beta_pom,
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>beta</artifactId>
  <version>3.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>x</artifactId>
      <version>1.2</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    return m2


def _write_root_pom(project_root: Path, body: str) -> None:
    (project_root / "pom.xml").write_text(body)


# ── TA-203 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-191")
def test_maven_emits_dep_edges_with_declared_version(tmp_path, monkeypatch):
    """TA-203 — Maven walker emits one DepEdge per <dependency> with the
    declared version. Diamond produces two distinct edges into x (1.1 and 1.2).
    """
    project_root = tmp_path / "project"
    project_root.mkdir()
    _write_root_pom(
        project_root,
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>alpha</artifactId>
      <version>2.0</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>beta</artifactId>
      <version>3.0</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    fake_m2 = _build_diamond_m2(tmp_path)
    monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

    resolver = _maven.MavenPomResolver()
    result = resolver.analyse(str(project_root))

    # New REQ-19 contract: dep_edges populated.
    versions_for_x = sorted(
        e.declared_version
        for e in result.dep_edges
        if e.child == "com.example:x"
    )
    assert versions_for_x == ["1.1", "1.2"], (
        f"Expected both versions of x as distinct edges; got {versions_for_x}"
    )


# ── TA-204 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-191")
@pytest.mark.requirement("FR-166")
def test_maven_property_resolution_precedes_edge_emission(tmp_path, monkeypatch):
    """TA-204 — When a transitive dep declares <version>${some.prop}</version>
    and the property is defined locally in the parent POM, the emitted
    DepEdge carries the resolved literal version, not the ``${...}`` token.
    """
    project_root = tmp_path / "project"
    project_root.mkdir()
    _write_root_pom(
        project_root,
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>props-parent</artifactId>
      <version>2.0</version>
    </dependency>
  </dependencies>
</project>
""",
    )

    m2 = tmp_path / "m2"
    _write_pom(
        m2 / "com/example/props-parent/2.0/props-parent-2.0.pom",
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>props-parent</artifactId>
  <version>2.0</version>
  <properties>
    <child.version>7.7</child.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>child</artifactId>
      <version>${child.version}</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    monkeypatch.setattr(_maven, "_m2_repo_path", lambda: m2)

    result = _maven.MavenPomResolver().analyse(str(project_root))

    child_edges = [e for e in result.dep_edges if e.child == "com.example:child"]
    assert child_edges, "child edge missing from dep_edges"
    assert child_edges[0].declared_version == "7.7", (
        "Property was not resolved before edge emission; "
        f"got {child_edges[0].declared_version!r}"
    )


# ── TA-205 ──────────────────────────────────────────────────────────────────


@pytest.mark.requirement("FR-191")
def test_maven_unresolvable_version_emits_edge_with_None(tmp_path, monkeypatch):
    """TA-205 — When a <version>${undefined.prop}</version> placeholder cannot
    be resolved, the edge is still emitted with declared_version=None
    (NOT silently dropped).

    Rationale: dropping silently would let an adversarial parent POM
    suppress a real transitive from the report.
    """
    project_root = tmp_path / "project"
    project_root.mkdir()
    _write_root_pom(
        project_root,
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>unresolvable-parent</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    m2 = tmp_path / "m2"
    _write_pom(
        m2 / "com/example/unresolvable-parent/1.0/unresolvable-parent-1.0.pom",
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>unresolvable-parent</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>orphan</artifactId>
      <version>${undefined.version}</version>
    </dependency>
  </dependencies>
</project>
""",
    )
    monkeypatch.setattr(_maven, "_m2_repo_path", lambda: m2)

    result = _maven.MavenPomResolver().analyse(str(project_root))

    orphan_edges = [
        e for e in result.dep_edges if e.child == "com.example:orphan"
    ]
    assert orphan_edges, (
        "orphan edge dropped silently; REQ-19 requires emission with None"
    )
    assert orphan_edges[0].declared_version is None
