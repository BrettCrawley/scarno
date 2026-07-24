"""REQ-17 — Direct-use transitive flagging.

A transitive dependency that is imported directly by project source must
be flagged ``imported_directly=True`` and must NOT be marked SAFE even if
its declared parent is SAFE — the engineer needs to promote it.
"""
from __future__ import annotations

from pathlib import Path

import pytest


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


class TestDependencyModel:
    @pytest.mark.requirement("FR-151")
    def test_dependency_has_imported_directly_field(self):
        from scarno.models import Dependency, DependencyStatus
        d = Dependency(
            name="x", version=None, status=DependencyStatus.UNCERTAIN,
            reason="", source="x", ecosystem="pypi",
        )
        assert hasattr(d, "imported_directly")
        assert d.imported_directly is False


class TestPythonImportedDirectly:
    @pytest.mark.requirement("FR-151")
    def test_transitive_imported_by_source_flagged(self, tmp_path):
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )
        from scarno.models import Dependency, DependencyStatus

        _write(tmp_path / "main.py", "import pytest\npytest.fail('x')\n")
        # 'unused-parent' is the (unused) declared dep; 'pytest' is its
        # transitive that the project source imports directly.
        deps = [
            Dependency(
                name="unused-parent", version="1", status=DependencyStatus.UNCERTAIN,
                reason="", source="pyproject.toml", ecosystem="pypi",
                is_transitive=False,
            ),
            Dependency(
                name="pytest", version="7", status=DependencyStatus.UNCERTAIN,
                reason="", source="lock", ecosystem="pypi",
                is_transitive=True,
            ),
        ]
        graph = {"unused-parent": {"pytest"}}
        updated, _err = analyse_source_files(
            str(tmp_path), deps, dep_graph=graph,
        )
        pytest_dep = next(d for d in updated if d.name == "pytest")
        assert pytest_dep.imported_directly is True
        assert pytest_dep.status != DependencyStatus.SAFE

    @pytest.mark.requirement("FR-151")
    def test_directly_used_transitive_not_orphaned_when_parent_safe(self, tmp_path):
        """Even when the parent is SAFE, a directly-used transitive stays IN_USE."""
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )
        from scarno.models import Dependency, DependencyStatus

        _write(tmp_path / "main.py", "import pytest\n")
        deps = [
            Dependency(
                name="unused-parent", version="1", status=DependencyStatus.UNCERTAIN,
                reason="", source="pyproject.toml", ecosystem="pypi",
                is_transitive=False,
            ),
            Dependency(
                name="pytest", version="7", status=DependencyStatus.UNCERTAIN,
                reason="", source="lock", ecosystem="pypi",
                is_transitive=True,
            ),
        ]
        graph = {"unused-parent": {"pytest"}}
        updated, _err = analyse_source_files(
            str(tmp_path), deps, dep_graph=graph,
        )
        # The parent is unimported -> SAFE.  The transitive used to be
        # orphaned by virtue of its only parent being SAFE; with REQ-17
        # it remains IN_USE because source imports it directly.
        parent = next(d for d in updated if d.name == "unused-parent")
        pytest_dep = next(d for d in updated if d.name == "pytest")
        assert parent.status == DependencyStatus.SAFE
        assert pytest_dep.status == DependencyStatus.IN_USE
        assert pytest_dep.imported_directly is True

    @pytest.mark.requirement("FR-151")
    def test_promotion_reason_text_present(self, tmp_path):
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )
        from scarno.models import Dependency, DependencyStatus

        _write(tmp_path / "main.py", "import pytest\n")
        deps = [
            Dependency(
                name="parent", version="1", status=DependencyStatus.UNCERTAIN,
                reason="", source="pyproject.toml", ecosystem="pypi",
            ),
            Dependency(
                name="pytest", version="7", status=DependencyStatus.UNCERTAIN,
                reason="", source="lock", ecosystem="pypi",
                is_transitive=True,
            ),
        ]
        graph = {"parent": {"pytest"}}
        updated, _ = analyse_source_files(str(tmp_path), deps, dep_graph=graph)
        pytest_dep = next(d for d in updated if d.name == "pytest")
        assert "promote" in pytest_dep.reason.lower()

    @pytest.mark.requirement("FR-151")
    def test_non_directly_used_transitive_still_orphaned(self, tmp_path):
        """A transitive NOT imported by source retains the previous orphan logic."""
        from scarno.analysers.python.source_analyser import (
            analyse_source_files,
        )
        from scarno.models import Dependency, DependencyStatus

        _write(tmp_path / "main.py", "")  # No imports at all.
        deps = [
            Dependency(
                name="parent", version="1", status=DependencyStatus.UNCERTAIN,
                reason="", source="pyproject.toml", ecosystem="pypi",
            ),
            Dependency(
                name="orphan-trans", version="1", status=DependencyStatus.UNCERTAIN,
                reason="", source="lock", ecosystem="pypi",
                is_transitive=True,
            ),
        ]
        graph = {"parent": {"orphan-trans"}}
        updated, _ = analyse_source_files(str(tmp_path), deps, dep_graph=graph)
        orphan = next(d for d in updated if d.name == "orphan-trans")
        # No direct import -> parent SAFE -> orphaned -> SAFE.
        assert orphan.status == DependencyStatus.SAFE
        assert orphan.imported_directly is False
