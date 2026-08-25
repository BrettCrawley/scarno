"""JAR listing must bound memory BEFORE the central directory is built.

``zipfile.ZipFile()`` constructs a ``ZipInfo`` for every central-directory
record while it opens the archive — measured at roughly 600 bytes of peak
heap per entry. ``MAX_JAR_ENTRIES`` was checked against the *returned*
``infolist()``, which is after that allocation, so the cap could not
prevent what it exists to prevent: a crafted archive reached ~2 GiB
resident before being told it had too many entries. JARs were also exempt
from every file-size cap.

Both guards now run before the open, and a refusal is reported rather
than silently dropping the dependency from the inventory.
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from scarno.security import (
    MAX_JAR_BYTES,
    MAX_JAR_ENTRIES,
    safe_jar_entries,
)

pytestmark = pytest.mark.security


def _jar(path: Path, entries: int, name_len: int = 8) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        for i in range(entries):
            z.writestr(f"{'p' * name_len}/{i}.class", b"")
    return path


class TestEntryCapEnforcedBeforeMaterialisation:
    @pytest.mark.requirement("SEC-NEW-02")
    def test_declared_count_rejects_without_opening(self, tmp_path, monkeypatch):
        """The refusal must come from the pre-check, not from infolist().
        Making ZipFile explode proves nothing opened the archive."""
        jar = _jar(tmp_path / "many.jar", MAX_JAR_ENTRIES + 50)

        def _explode(*a, **kw):
            raise AssertionError(
                "ZipFile was constructed — the central directory was "
                "materialised before the entry cap ran"
            )

        monkeypatch.setattr(zipfile, "ZipFile", _explode)
        with pytest.raises(ValueError, match="declares"):
            safe_jar_entries(jar)

    @pytest.mark.requirement("SEC-NEW-02")
    def test_ordinary_jar_still_listed(self, tmp_path):
        """The budget must not reject a normal archive — an earlier
        attempt sized it so tightly that a JAR with long paths and fewer
        entries than the cap was refused."""
        jar = _jar(tmp_path / "ok.jar", 500, name_len=180)
        entries = safe_jar_entries(jar)
        assert len(entries) == 500
        assert all(e.endswith(".class") for e in entries)

    @pytest.mark.requirement("SEC-NEW-02")
    def test_entry_cap_boundary_is_inclusive(self, tmp_path):
        jar = _jar(tmp_path / "edge.jar", MAX_JAR_ENTRIES)
        assert len(safe_jar_entries(jar)) == MAX_JAR_ENTRIES

    @pytest.mark.requirement("SEC-NEW-02")
    def test_post_check_still_catches_an_understated_count(
        self, tmp_path, monkeypatch,
    ):
        """The pre-check is advisory. If an archive lies about its entry
        count, the check against what zipfile actually parsed must still
        refuse it."""
        jar = _jar(tmp_path / "liar.jar", MAX_JAR_ENTRIES + 50)
        monkeypatch.setattr(
            "scarno.security._declared_entry_count", lambda p: 1,
        )
        with pytest.raises(ValueError, match="has .* entries"):
            safe_jar_entries(jar)

    @pytest.mark.requirement("SEC-NEW-02")
    def test_unreadable_eocd_falls_through_without_rejecting(
        self, tmp_path, monkeypatch,
    ):
        """A None from the pre-check means 'no opinion', never 'reject' —
        an ordinary archive must still list."""
        jar = _jar(tmp_path / "ok2.jar", 20)
        monkeypatch.setattr(
            "scarno.security._declared_entry_count", lambda p: None,
        )
        assert len(safe_jar_entries(jar)) == 20


class TestJarSizeCap:
    @pytest.mark.requirement("SEC-NEW-04")
    def test_oversize_jar_refused_before_opening(self, tmp_path, monkeypatch):
        jar = _jar(tmp_path / "big.jar", 5)

        class _FakeStat:
            st_size = MAX_JAR_BYTES + 1

        monkeypatch.setattr(Path, "stat", lambda self, **kw: _FakeStat())
        with pytest.raises(ValueError, match="limit"):
            safe_jar_entries(jar)

    @pytest.mark.requirement("SEC-NEW-04")
    def test_size_cap_bounds_peak_memory_by_construction(self):
        """The cap is the backstop behind the advisory pre-check, so the
        arithmetic that justifies it is worth pinning: ~78 bytes on disk
        per minimal entry, ~600 bytes of peak heap each."""
        worst_case_entries = MAX_JAR_BYTES / 78
        worst_case_peak = worst_case_entries * 600
        assert worst_case_peak < 1.5 * 1024**3, (
            f"MAX_JAR_BYTES admits a {worst_case_peak / 1024**3:.1f} GiB "
            f"worst case"
        )


class TestRefusalIsReported:
    @pytest.mark.requirement("SEC-NEW-02")
    def test_inventory_records_why_a_jar_was_skipped(self, tmp_path):
        """Swallowing the ValueError turned a resource guard into
        silently wrong output: the dep vanishes from the inventory and is
        classified on incomplete evidence with nothing said."""
        from scarno.analysers.java.source_analyser import _build_jar_inventory_map
        from scarno.models import Dependency, DependencyStatus

        jar = _jar(tmp_path / "lib-1.0.jar", MAX_JAR_ENTRIES + 5)
        dep = Dependency(
            name="com.example:lib", version="1.0",
            status=DependencyStatus.UNCERTAIN, reason="", ecosystem="maven",
        )
        errors: list[str] = []
        import scarno.analysers.java.source_analyser as sa

        original = sa._locate_dependency_jar
        sa._locate_dependency_jar = lambda d, root, errs: jar
        try:
            inventory = _build_jar_inventory_map([dep], tmp_path, errors)
        finally:
            sa._locate_dependency_jar = original

        assert "com.example:lib" not in inventory
        assert any("jar-inventory" in e for e in errors), errors
        assert any("entries" in e for e in errors), errors


class TestDeclaredEntryCountIsAdvisory:
    @pytest.mark.requirement("SEC-NEW-02")
    def test_file_without_an_eocd_record_returns_none(self, tmp_path):
        """No opinion, not a rejection — the caller falls through to the
        size cap and the post-parse check."""
        from scarno.security import _declared_entry_count

        plain = tmp_path / "not-a-zip.jar"
        plain.write_bytes(b"this file has no end-of-central-directory record")
        assert _declared_entry_count(plain) is None

    @pytest.mark.requirement("SEC-NEW-02")
    def test_unreadable_path_returns_none(self, tmp_path):
        from scarno.security import _declared_entry_count

        assert _declared_entry_count(tmp_path / "absent.jar") is None


class TestUnreadableJarStaysAnOrdinaryMiss:
    @pytest.mark.requirement("SEC-NEW-02")
    def test_oserror_is_not_reported_as_a_resource_refusal(
        self, tmp_path, monkeypatch,
    ):
        """An OSError is a missing or unreadable file, which the locator
        has already accounted for — it must not add a second, confusing
        'skipped' line about resource limits."""
        from scarno.analysers.java import source_analyser as sa
        from scarno.models import Dependency, DependencyStatus

        jar = _jar(tmp_path / "lib-1.0.jar", 3)
        dep = Dependency(
            name="com.example:lib", version="1.0",
            status=DependencyStatus.UNCERTAIN, reason="", ecosystem="maven",
        )
        monkeypatch.setattr(sa, "_locate_dependency_jar", lambda d, r, e: jar)
        monkeypatch.setattr(
            sa, "safe_jar_entries",
            lambda p: (_ for _ in ()).throw(OSError("disk gone")),
        )
        errors: list[str] = []
        inventory = sa._build_jar_inventory_map([dep], tmp_path, errors)

        assert "com.example:lib" not in inventory
        assert not any("jar-inventory" in e for e in errors), errors
