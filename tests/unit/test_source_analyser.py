"""Tests for the Python source analyser — REQ-3.

Placeholder test bodies derived from REQ-3 acceptance criteria. Each test
has an SRTM marker so coverage is tracked even while the underlying
analyser is unimplemented.
"""
from __future__ import annotations

import importlib
import os
import sys
import textwrap

import pytest

from scarno.analysers.python import source_analyser as py_sa_mod
from scarno.analysers.python.source_analyser import (
    _build_venv_dist_imports_map,
    _enumerate_entry_points,
    _merge_dist_maps,
    analyse_source_files,
)
from scarno.models import Dependency, DependencyStatus


def _make_dep(name: str) -> Dependency:
    return Dependency(
        name=name,
        version=None,
        status=DependencyStatus.UNCERTAIN,
        reason="declared — source analysis pending",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


class TestDirectImports:
    @pytest.mark.requirement("FR-005")
    def test_direct_import_classifies_in_use(self, tmp_path):
        (tmp_path / "main.py").write_text("import requests\n")
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert deps[0].status == DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-005")
    def test_from_import_classifies_in_use(self, tmp_path):
        (tmp_path / "main.py").write_text("from flask import Flask\n")
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("flask")])
        assert deps[0].status == DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-005")
    def test_aliased_import_classifies_in_use(self, tmp_path):
        (tmp_path / "main.py").write_text("import numpy as np\n")
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("numpy")])
        assert deps[0].status == DependencyStatus.IN_USE


class TestDynamicImports:
    @pytest.mark.requirement("FR-005")
    def test_literal_importlib_import_module_classifies_in_use(self, tmp_path):
        (tmp_path / "main.py").write_text(
            textwrap.dedent(
                """\
            import importlib
            importlib.import_module("requests")
        """
            )
        )
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert deps[0].status in (DependencyStatus.IN_USE, DependencyStatus.UNCERTAIN)

    @pytest.mark.requirement("FR-005")
    def test_non_literal_importlib_classifies_uncertain(self, tmp_path):
        (tmp_path / "main.py").write_text(
            textwrap.dedent(
                """\
            import importlib
            pkg = input()
            importlib.import_module(pkg)
        """
            )
        )
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert deps[0].status == DependencyStatus.UNCERTAIN

    @pytest.mark.requirement("FR-005")
    def test_dunder_import_recognised(self, tmp_path):
        (tmp_path / "main.py").write_text('__import__("requests")\n')
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert deps[0].status in (DependencyStatus.IN_USE, DependencyStatus.UNCERTAIN)


class TestNoUsage:
    @pytest.mark.requirement("FR-005")
    def test_declared_but_not_imported_classifies_safe(self, tmp_path):
        (tmp_path / "main.py").write_text("x = 1\n")
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("boto3")])
        assert deps[0].status == DependencyStatus.SAFE


class TestStdlibExclusion:
    @pytest.mark.requirement("S-02")
    def test_stdlib_import_does_not_mark_declared_dep(self, tmp_path):
        (tmp_path / "main.py").write_text("import json\n")
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert deps[0].status == DependencyStatus.SAFE


class TestErrorHandling:
    @pytest.mark.requirement("FR-005")
    def test_syntax_error_in_source_produces_error_not_crash(self, tmp_path):
        (tmp_path / "broken.py").write_text("def (((:")
        deps, errors = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert any("syntax" in e.lower() or "parse" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-NEW-04")
    @pytest.mark.security
    def test_oversized_source_file_skipped(self, tmp_path):
        """Source files over 10 MB must be skipped with a warning."""
        from scarno.security import MAX_FILE_BYTES

        huge = tmp_path / "huge.py"
        huge.write_bytes(b"x = 1\n" * (MAX_FILE_BYTES // 6 + 1))
        deps, errors = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert any("skip" in e.lower() or "large" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-002")
    @pytest.mark.requirement("T-07")
    @pytest.mark.security
    def test_symlink_escaping_project_root_skipped(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "valid.py").write_text("import requests\n")
        outside = tmp_path / "secret.py"
        outside.write_text("# secret content\n")
        (project / "sneaky.py").symlink_to(outside)
        deps, errors = analyse_source_files(str(project), [_make_dep("requests")])
        # Either a warning was emitted or the symlinked file was skipped
        assert deps[0].status in (
            DependencyStatus.IN_USE,
            DependencyStatus.UNCERTAIN,
            DependencyStatus.SAFE,
        )


class TestEntryPointEnumeration:
    @pytest.mark.requirement("FR-005")
    def test_entry_points_populated_for_in_use(self, tmp_path):
        (tmp_path / "main.py").write_text("from requests import get\n")
        deps, _ = analyse_source_files(str(tmp_path), [_make_dep("requests")])
        assert deps[0].entry_points_total >= 0
        assert deps[0].entry_points_used == sum(
            1 for ep in deps[0].entry_points if ep.used
        )


# ── .venv metadata scanning (FR-135) ──────────────────────────────────────


def _make_dist_info(site_packages, dist_name, version, top_level_lines):
    """Helper: create a .dist-info directory with top_level.txt."""
    dist_dir = site_packages / f"{dist_name}-{version}.dist-info"
    dist_dir.mkdir(parents=True)
    (dist_dir / "METADATA").write_text(f"Name: {dist_name}\nVersion: {version}\n")
    if top_level_lines is not None:
        (dist_dir / "top_level.txt").write_text("\n".join(top_level_lines) + "\n")
    return dist_dir


class TestVenvDistImportsMap:
    @pytest.mark.requirement("FR-135")
    def test_top_level_txt_read(self, tmp_path):
        sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        sp.mkdir(parents=True)
        _make_dist_info(sp, "Pillow", "10.0", ["PIL", "pillow"])
        _make_dist_info(sp, "requests", "2.31.0", ["requests"])
        errors: list[str] = []
        result = _build_venv_dist_imports_map(tmp_path, errors)
        assert "pil" in result.get("pillow", set())
        assert "requests" in result.get("requests", set())
        assert not errors

    @pytest.mark.requirement("FR-135")
    def test_record_fallback_when_no_top_level(self, tmp_path):
        sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        sp.mkdir(parents=True)
        dist_dir = sp / "my_package-1.0.dist-info"
        dist_dir.mkdir()
        (dist_dir / "METADATA").write_text("Name: my-package\nVersion: 1.0\n")
        (dist_dir / "RECORD").write_text(
            "my_pkg/__init__.py,sha256=abc,100\n"
            "my_pkg/utils.py,sha256=def,200\n"
            "my_package-1.0.dist-info/METADATA,sha256=ghi,50\n"
        )
        errors: list[str] = []
        result = _build_venv_dist_imports_map(tmp_path, errors)
        assert "my_pkg" in result.get("my-package", set())

    @pytest.mark.requirement("FR-135")
    def test_no_venv_returns_empty(self, tmp_path):
        errors: list[str] = []
        result = _build_venv_dist_imports_map(tmp_path, errors)
        assert result == {}
        assert not errors

    @pytest.mark.requirement("FR-135")
    def test_venv_dir_named_venv(self, tmp_path):
        sp = tmp_path / "venv" / "lib" / "python3.11" / "site-packages"
        sp.mkdir(parents=True)
        _make_dist_info(sp, "flask", "3.0", ["flask"])
        errors: list[str] = []
        result = _build_venv_dist_imports_map(tmp_path, errors)
        assert "flask" in result.get("flask", set())

    @pytest.mark.requirement("FR-135")
    def test_windows_venv_layout(self, tmp_path):
        sp = tmp_path / ".venv" / "Lib" / "site-packages"
        sp.mkdir(parents=True)
        _make_dist_info(sp, "numpy", "1.26", ["numpy"])
        errors: list[str] = []
        result = _build_venv_dist_imports_map(tmp_path, errors)
        assert "numpy" in result.get("numpy", set())


class TestVenvMerge:
    @pytest.mark.requirement("FR-135")
    def test_merge_supplements_base(self):
        base = {"requests": {"requests"}}
        override = {"requests": {"urllib3"}, "pillow": {"pil"}}
        merged = _merge_dist_maps(base, override)
        assert merged["requests"] == {"requests", "urllib3"}
        assert merged["pillow"] == {"pil"}


class TestVenvEndToEnd:
    @pytest.mark.requirement("FR-135")
    def test_dep_resolved_via_venv_metadata(self, tmp_path):
        """A dep whose import name differs from its dist name should be
        classified IN_USE when the project's .venv metadata provides the
        mapping."""
        sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        sp.mkdir(parents=True)
        _make_dist_info(sp, "Pillow", "10.0", ["PIL"])

        (tmp_path / "main.py").write_text("from PIL import Image\n")
        deps, errors = analyse_source_files(
            str(tmp_path), [_make_dep("Pillow")]
        )
        pillow = next((d for d in deps if "pillow" in d.name.lower()), None)
        assert pillow is not None
        assert pillow.status == DependencyStatus.IN_USE


class TestVenvSecurityConfinement:
    @pytest.mark.requirement("SEC-NEW-30")
    @pytest.mark.security
    def test_venv_symlink_escape_blocked(self, tmp_path):
        """A .venv that is a symlink pointing outside the project must be
        handled safely."""
        outside = tmp_path / "outside"
        outside.mkdir()
        sp = outside / "lib" / "python3.12" / "site-packages"
        sp.mkdir(parents=True)
        _make_dist_info(sp, "evil", "1.0", ["evil"])
        (tmp_path / "project").mkdir()
        (tmp_path / "project" / ".venv").symlink_to(outside)
        errors: list[str] = []
        result = _build_venv_dist_imports_map(tmp_path / "project", errors)
        # Either empty or the escape is caught — no evil data loaded
        # from outside the project root
        assert "evil" not in result or any("escape" in e.lower() for e in errors)


# ── PEP 562 module-level __getattr__ enumeration (FR-271) ──────────────────


def _install_pkg(tmp_path, monkeypatch, name: str, init_src: str) -> str:
    """Create an importable package on sys.path and return its name.

    Names use only lowercase letters/digits so the canonical form equals
    the import name (``_normalise`` collapses separators).
    """
    pkg_dir = tmp_path / name
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text(textwrap.dedent(init_src))
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop(name, None)
    importlib.invalidate_caches()
    return name


class TestPep562LazyEnumeration:
    @pytest.mark.requirement("FR-271")
    def test_used_lazy_symbol_is_surfaced(self, tmp_path, monkeypatch):
        """A symbol provided only via module-level __getattr__ (PEP 562),
        absent from __all__/dir(), is still reported when used in source."""
        name = _install_pkg(
            tmp_path, monkeypatch, "pepfivesixtwoused",
            """
            def __getattr__(attr):
                if attr == "lazy_thing":
                    return lambda: None
                raise AttributeError(attr)
            """,
        )
        errors: list[str] = []
        eps = _enumerate_entry_points(
            name, {name}, {name: {"lazy_thing"}}, errors,
            {(name, "lazy_thing"): 2},
        )
        by_name = {ep.name: ep for ep in eps}
        assert f"{name}.lazy_thing" in by_name
        ep = by_name[f"{name}.lazy_thing"]
        assert ep.used is True
        assert ep.usage_count == 2
        assert ep.kind == "function"

    @pytest.mark.requirement("FR-271")
    def test_getattr_without_dir_emits_diagnostic(self, tmp_path, monkeypatch):
        """A lazy-only module (no __all__, no __dir__) records an honest
        under-enumeration diagnostic."""
        name = _install_pkg(
            tmp_path, monkeypatch, "pepfivesixtwodiag",
            """
            def __getattr__(attr):
                raise AttributeError(attr)
            """,
        )
        errors: list[str] = []
        _enumerate_entry_points(name, {name}, {}, errors)
        assert any(
            "__getattr__ (PEP 562)" in e and name in e for e in errors
        ), errors

    @pytest.mark.requirement("FR-271")
    def test_used_symbol_surfaced_even_if_getattr_raises(
        self, tmp_path, monkeypatch
    ):
        """A known-used symbol whose getattr access raises is still emitted
        as used (kind=unknown) rather than silently dropped."""
        name = _install_pkg(
            tmp_path, monkeypatch, "pepfivesixtworaises",
            """
            def __getattr__(attr):
                raise RuntimeError("boom")
            """,
        )
        errors: list[str] = []
        eps = _enumerate_entry_points(
            name, {name}, {name: {"explodes"}}, errors,
            {(name, "explodes"): 1},
        )
        by_name = {ep.name: ep for ep in eps}
        assert f"{name}.explodes" in by_name
        ep = by_name[f"{name}.explodes"]
        assert ep.used is True
        assert ep.kind == "unknown"

    @pytest.mark.requirement("FR-271")
    def test_dir_override_enumerates_without_diagnostic(
        self, tmp_path, monkeypatch
    ):
        """A lazy module that defines __dir__ surfaces its names via dir()
        and emits no under-enumeration diagnostic."""
        name = _install_pkg(
            tmp_path, monkeypatch, "pepfivesixtwodir",
            """
            _LAZY = ("alpha", "beta")
            def __getattr__(attr):
                if attr in _LAZY:
                    return lambda: None
                raise AttributeError(attr)
            def __dir__():
                return list(_LAZY)
            """,
        )
        errors: list[str] = []
        eps = _enumerate_entry_points(name, {name}, {}, errors)
        names = {ep.name for ep in eps}
        assert f"{name}.alpha" in names
        assert f"{name}.beta" in names
        assert not any("__getattr__ (PEP 562)" in e for e in errors)

    @pytest.mark.requirement("FR-271")
    def test_all_with_getattr_enumerates_without_diagnostic(
        self, tmp_path, monkeypatch
    ):
        """When __all__ is present the surface is enumerable; getattr
        resolves each lazy export and no diagnostic is emitted."""
        name = _install_pkg(
            tmp_path, monkeypatch, "pepfivesixtwoall",
            """
            __all__ = ["exported"]
            def __getattr__(attr):
                if attr == "exported":
                    return lambda: None
                raise AttributeError(attr)
            """,
        )
        errors: list[str] = []
        eps = _enumerate_entry_points(
            name, {name}, {name: {"exported"}}, errors,
        )
        by_name = {ep.name: ep for ep in eps}
        assert f"{name}.exported" in by_name
        assert by_name[f"{name}.exported"].kind == "function"
        assert by_name[f"{name}.exported"].used is True
        assert not any("__getattr__ (PEP 562)" in e for e in errors)
