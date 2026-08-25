"""``<relativePath>`` must not read a parent POM from outside the project.

The sandbox check ran on the path produced by ``resolve()`` *before*
``pom.xml`` was appended, so it confined the DIRECTORY. A ``pom.xml``
sitting inside a legitimately-confined directory could itself be a
symlink out of the tree; its contents were then parsed, and coordinate
text from an arbitrary file surfaced in the report as dependency data.

This is the Maven twin of the Gradle submodule bug fixed for F19.

Three collateral behaviours are pinned alongside the fix, because two
earlier attempts at it were declined for breaking them:

* a benign monorepo layout that symlinks ``pom.xml`` at a shared parent
  inside the tree must still resolve;
* a symlinked parent must keep anchoring its own grandparent's
  ``<relativePath>`` on the LINK's directory, not the target's, or a
  legitimate project silently inherits from a different grandparent;
* a broken symlink must stay a miss that falls through to the cache and
  fetch tiers, not become a blocked escape.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

_PARENT_XML = (
    '<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>'
    '<artifactId>shared-parent</artifactId><version>1.2.3</version></project>'
)


def _child(relative_path: str, artifact: str = "child") -> str:
    return (
        '<project><modelVersion>4.0.0</modelVersion>'
        '<parent><groupId>g</groupId><artifactId>shared-parent</artifactId>'
        f'<version>1.2.3</version><relativePath>{relative_path}</relativePath>'
        f'</parent><artifactId>{artifact}</artifactId></project>'
    )


def _locate(root: Path, child_dir: Path):
    from scarno.analysers.java import maven as mvn

    errors: list[str] = []
    data = mvn._parse_pom_file(child_dir / "pom.xml", errors)
    assert data is not None
    resolved = mvn.MavenPomResolver()._locate_parent_pom(
        data,
        current_dir=child_dir,
        project_root=root,
        parent_sandbox=root,
        errors=errors,
    )
    return resolved, errors


class TestSymlinkedParentPomBlocked:
    @pytest.mark.requirement("SEC-002")
    def test_pom_inside_confined_dir_may_not_link_out(self, tmp_path):
        root = (tmp_path / "proj").resolve()
        (root / "child").mkdir(parents=True)
        outside = (tmp_path / "outside-secret.xml").resolve()
        outside.write_text(
            '<project><modelVersion>4.0.0</modelVersion><groupId>leaked</groupId>'
            '<artifactId>SECRET</artifactId><version>9.9.9-EXFIL</version></project>'
        )
        # The directory is legitimately inside the sandbox...
        (root / "legit").mkdir()
        # ...but the pom.xml in it points out of the tree.
        (root / "legit" / "pom.xml").symlink_to(outside)
        (root / "child" / "pom.xml").write_text(_child("../legit"))

        resolved, errors = _locate(root, root / "child")

        assert resolved is None, (
            f"read an out-of-tree parent POM: {resolved}"
        )
        assert any("resolves outside" in e for e in errors), errors

    @pytest.mark.requirement("SEC-002")
    def test_direct_file_relative_path_may_not_link_out(self, tmp_path):
        root = (tmp_path / "proj").resolve()
        (root / "child").mkdir(parents=True)
        outside = (tmp_path / "outside.xml").resolve()
        outside.write_text(_PARENT_XML)
        (root / "linked").mkdir()
        (root / "linked" / "pom.xml").symlink_to(outside)
        (root / "child" / "pom.xml").write_text(_child("../linked/pom.xml"))

        resolved, errors = _locate(root, root / "child")
        assert resolved is None
        # Naming the file directly means the initial resolve() already
        # follows the link, so the pre-existing directory guard fires
        # rather than the new one. Either is a block; assert the property,
        # not which guard caught it.
        assert any(
            "escapes project sandbox" in e or "resolves outside" in e
            for e in errors
        ), errors


class TestLegitimateLayoutsPreserved:
    @pytest.mark.requirement("SEC-002")
    def test_in_tree_monorepo_symlink_still_resolves(self, tmp_path):
        """A link that stays inside the project is ordinary layout. The
        name check judges the project-side name, so linking pom.xml at a
        differently-named shared file is fine."""
        root = (tmp_path / "proj").resolve()
        (root / "child").mkdir(parents=True)
        (root / "shared").mkdir()
        (root / "shared" / "parent-pom.xml").write_text(_PARENT_XML)
        (root / "linked").mkdir()
        (root / "linked" / "pom.xml").symlink_to(
            root / "shared" / "parent-pom.xml"
        )
        (root / "child" / "pom.xml").write_text(_child("../linked"))

        resolved, errors = _locate(root, root / "child")

        assert resolved is not None, errors
        assert resolved.read_text() == _PARENT_XML

    @pytest.mark.requirement("SEC-002")
    def test_symlinked_parent_anchors_on_the_link_directory(self, tmp_path):
        """The returned path decides where the grandparent's own
        <relativePath> is resolved from. For a symlinked parent that must
        remain the link's directory — returning the target's would change
        which grandparent a legitimate project inherits."""
        root = (tmp_path / "proj").resolve()
        (root / "child").mkdir(parents=True)
        (root / "shared").mkdir()
        (root / "shared" / "parent-pom.xml").write_text(_PARENT_XML)
        (root / "linked").mkdir()
        (root / "linked" / "pom.xml").symlink_to(
            root / "shared" / "parent-pom.xml"
        )
        (root / "child" / "pom.xml").write_text(_child("../linked"))

        resolved, _ = _locate(root, root / "child")

        assert resolved is not None
        assert resolved.parent == root / "linked", (
            f"anchor moved to the link target: {resolved.parent}"
        )


class TestMissesKeepFallingThrough:
    @pytest.mark.requirement("SEC-002")
    def test_dangling_symlink_is_a_miss_not_a_blocked_escape(self, tmp_path):
        root = (tmp_path / "proj").resolve()
        (root / "child").mkdir(parents=True)
        (root / "dang").mkdir()
        (root / "dang" / "pom.xml").symlink_to(root / "nowhere" / "pom.xml")
        (root / "child" / "pom.xml").write_text(_child("../dang"))

        resolved, errors = _locate(root, root / "child")

        assert resolved is None
        assert not any("resolves outside" in e for e in errors), (
            "a broken link was reported as an escape attempt"
        )
        assert any("not found" in e for e in errors), errors

    @pytest.mark.requirement("SEC-002")
    def test_fifo_named_pom_xml_does_not_hang(self, tmp_path):
        """exists() is true for a FIFO, and parsing one blocks forever
        with no writer — an in-tree FIFO hung the whole analysis."""
        root = (tmp_path / "proj").resolve()
        (root / "child").mkdir(parents=True)
        (root / "fifo").mkdir()
        os.mkfifo(root / "fifo" / "pom.xml")
        (root / "child" / "pom.xml").write_text(_child("../fifo"))

        resolved, errors = _locate(root, root / "child")

        assert resolved is None, "a FIFO was handed back to be parsed"
