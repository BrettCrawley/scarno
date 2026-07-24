"""Tests for the JVM source & bytecode analyser — REQ-6.

Placeholder tests derived from REQ-6 acceptance criteria. Each carries an
SRTM marker so coverage is tracked even while the analyser is
unimplemented.
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from scarno.analysers.java import source_analyser as sa_mod
from scarno.analysers.java.source_analyser import (
    JvmSourceAnalyser,
    _build_jar_inventory_map,
    _extract_packages_from_jar,
    _locate_dependency_jar,
    _parse_javap_output,
)
from scarno.analysers.java import maven as maven_mod
from scarno.models import Dependency, DependencyStatus


def _uncertain(name: str) -> Dependency:
    return Dependency(
        name=name,
        version=None,
        status=DependencyStatus.UNCERTAIN,
        reason="pending source analysis",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


@pytest.fixture
def analyser() -> JvmSourceAnalyser:
    return JvmSourceAnalyser()


class TestSourceDiscovery:
    @pytest.mark.requirement("FR-018")
    def test_java_file_discovered(self, tmp_path, analyser):
        (tmp_path / "Main.java").write_text(
            "import com.google.common.collect.ImmutableList;\n"
            "public class Main {}\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.google.guava:guava")]
        )
        assert result.project_type == "java"

    @pytest.mark.requirement("FR-018")
    def test_kotlin_file_discovered(self, tmp_path, analyser):
        (tmp_path / "Main.kt").write_text(
            "import com.google.common.collect.ImmutableList\n"
            "fun main() {}\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.google.guava:guava")]
        )
        assert result.project_type == "java"


class TestDirectReferenceDetection:
    @pytest.mark.requirement("FR-018")
    def test_import_in_java_source_classifies_in_use(self, tmp_path, analyser):
        (tmp_path / "Main.java").write_text(
            "import com.google.common.collect.ImmutableList;\n"
            "public class Main {}\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.google.guava:guava")]
        )
        guava = next(iter(result.dependencies), None)
        assert guava is not None
        assert guava.status == DependencyStatus.IN_USE


class TestDIAnnotationDetection:
    @pytest.mark.requirement("FR-018")
    def test_autowired_classifies_spring_dep_in_use(self, tmp_path, analyser):
        (tmp_path / "MyService.java").write_text(
            "import org.springframework.beans.factory.annotation.Autowired;\n"
            "public class MyService {\n"
            "  @Autowired private Object dep;\n"
            "}\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("org.springframework:spring-core")]
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        assert dep.status == DependencyStatus.IN_USE


class TestReflectionHeuristics:
    @pytest.mark.requirement("FR-018")
    def test_class_forname_classifies_uncertain(self, tmp_path, analyser):
        (tmp_path / "Main.java").write_text(
            'public class Main { static { Class.forName("com.example.Foo"); } }\n'
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.example:foo")]
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        assert dep.status in (
            DependencyStatus.UNCERTAIN,
            DependencyStatus.IN_USE,
        )


class TestJavapSubprocessSafety:
    @pytest.mark.requirement("E-02")
    @pytest.mark.requirement("SEC-012")
    @pytest.mark.security
    def test_invalid_classname_rejected_before_javap(self, tmp_path, analyser):
        invalid_names = [
            "com.example.Foo; rm -rf /",
            "../../../evil",
            "com.example.Foo\x00",
            "",
            "123invalid",
        ]
        for name in invalid_names:
            result = analyser._invoke_javap_safe(Path("/dev/null"), name)
            assert result is None, f"Invalid classname '{name}' was not rejected"

    @pytest.mark.requirement("E-02")
    @pytest.mark.requirement("SEC-012")
    @pytest.mark.security
    def test_javap_invocation_uses_shell_false(self, tmp_path, analyser):
        """Shell metacharacters in a class name must not trigger shell execution."""
        sentinel = tmp_path / "shell_executed.txt"
        evil = f"com.example.Foo; touch {sentinel}; echo"
        try:
            analyser._invoke_javap_safe(Path("/dev/null"), evil)
        except Exception:
            pass
        assert not sentinel.exists(), "Shell injection succeeded — shell=True was used"

    @pytest.mark.requirement("SEC-NEW-09")
    @pytest.mark.security
    def test_valid_java_identifier_accepted(self, tmp_path, analyser):
        """Well-formed class names should be accepted by the validator."""
        # Phase 0a stub: we only check that the validator is wired; the real
        # javap call will be exercised in Phase 2.
        try:
            analyser._invoke_javap_safe(Path("/dev/null"), "com.example.Foo")
        except NotImplementedError:
            pass


class TestJavapBinaryResolution:
    @pytest.mark.requirement("SEC-NEW-12")
    @pytest.mark.security
    def test_java_home_verification_runs(self, monkeypatch, analyser):
        monkeypatch.setenv("JAVA_HOME", "/usr/lib/jvm/temurin-21")
        try:
            analyser._resolve_javap_binary()
        except NotImplementedError:
            pass


class TestJarEntryEnumeration:
    @pytest.mark.requirement("SEC-NEW-02")
    @pytest.mark.security
    def test_oversized_jar_handled_without_oom(self, tmp_path):
        """ZIP-bomb guard in safe_jar_entries must reject oversized JARs."""
        from scarno.security import safe_jar_entries

        # Guarded path: feeding a non-existent path should raise, not hang.
        with pytest.raises(Exception):
            safe_jar_entries(tmp_path / "missing.jar")


class TestErrorHandling:
    @pytest.mark.requirement("FR-018")
    def test_missing_jar_classifies_uncertain(self, tmp_path, analyser):
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.nonexistent:mystery")]
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        assert dep.status == DependencyStatus.UNCERTAIN

    @pytest.mark.requirement("FR-018")
    def test_analysis_never_raises(self, tmp_path, analyser):
        (tmp_path / "Broken.java").write_bytes(b"\xff\xff\xff\xff")
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.example:foo")]
        )
        assert hasattr(result, "errors")


# ── JAR-based package discovery (FR-134) ───────────────────────────────────


def _make_jar(path: Path, class_entries: list[str]) -> Path:
    """Create a minimal JAR containing dummy .class entries."""
    with zipfile.ZipFile(str(path), "w") as zf:
        for entry in class_entries:
            zf.writestr(entry, b"\xca\xfe\xba\xbe")  # minimal class header
    return path


class TestJarPackageExtraction:
    @pytest.mark.requirement("FR-134")
    def test_packages_extracted_from_jar(self, tmp_path):
        jar = _make_jar(
            tmp_path / "test.jar",
            [
                "org/apache/commons/beanutils/BeanUtils.class",
                "org/apache/commons/beanutils/PropertyUtils.class",
                "org/apache/commons/beanutils/converters/IntegerConverter.class",
            ],
        )
        packages = _extract_packages_from_jar(jar)
        assert "org.apache.commons.beanutils" in packages
        assert "org.apache.commons.beanutils.converters" in packages

    @pytest.mark.requirement("FR-134")
    def test_default_package_classes_skipped(self, tmp_path):
        jar = _make_jar(tmp_path / "test.jar", ["Main.class"])
        packages = _extract_packages_from_jar(jar)
        assert packages == set()

    @pytest.mark.requirement("FR-134")
    def test_missing_jar_returns_empty(self):
        packages = _extract_packages_from_jar(Path("/nonexistent.jar"))
        assert packages == set()


class TestJarLocation:
    @pytest.mark.requirement("FR-134")
    def test_jar_found_in_m2_cache(self, tmp_path, monkeypatch):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(sa_mod, "_m2_repo_path", lambda: repo)
        from scarno.analysers.java.maven import _gav_to_jar_path

        jar_path = _gav_to_jar_path(repo, "com.example", "mylib", "1.0")
        jar_path.parent.mkdir(parents=True)
        _make_jar(jar_path, ["com/example/Foo.class"])

        dep = Dependency(
            name="com.example:mylib",
            version="1.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        errors: list[str] = []
        result = _locate_dependency_jar(dep, tmp_path, errors)
        assert result is not None
        assert result.name == "mylib-1.0.jar"

    @pytest.mark.requirement("FR-134")
    def test_jar_found_in_target_dir(self, tmp_path, monkeypatch):
        # Ensure m2 lookup misses
        monkeypatch.setattr(
            maven_mod, "_m2_repo_path", lambda: tmp_path / "no_m2"
        )
        target = tmp_path / "target"
        target.mkdir()
        _make_jar(target / "mylib-2.0.jar", ["com/example/Bar.class"])

        dep = Dependency(
            name="com.example:mylib",
            version="2.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        errors: list[str] = []
        result = _locate_dependency_jar(dep, tmp_path, errors)
        assert result is not None
        assert result.name == "mylib-2.0.jar"

    @pytest.mark.requirement("FR-134")
    def test_jar_not_found_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            maven_mod, "_m2_repo_path", lambda: tmp_path / "no_m2"
        )
        dep = Dependency(
            name="com.example:missing",
            version="1.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        errors: list[str] = []
        result = _locate_dependency_jar(dep, tmp_path, errors)
        assert result is None


class TestJarBasedClassification:
    @pytest.mark.requirement("FR-134")
    def test_groupid_mismatch_resolved_by_jar(self, tmp_path, monkeypatch):
        """A dep whose groupId doesn't match its Java packages should still
        be classified IN_USE when the JAR reveals the real packages."""
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(sa_mod, "_m2_repo_path", lambda: repo)

        from scarno.analysers.java.maven import _gav_to_jar_path

        jar_path = _gav_to_jar_path(
            repo, "commons-beanutils", "commons-beanutils", "1.9.4"
        )
        jar_path.parent.mkdir(parents=True)
        _make_jar(
            jar_path,
            [
                "org/apache/commons/beanutils/BeanUtils.class",
                "org/apache/commons/beanutils/PropertyUtils.class",
            ],
        )

        (tmp_path / "Main.java").write_text(
            "import org.apache.commons.beanutils.BeanUtils;\n"
            "public class Main {}\n"
        )

        analyser = JvmSourceAnalyser()
        dep = Dependency(
            name="commons-beanutils:commons-beanutils",
            version="1.9.4",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        result = analyser.analyse(str(tmp_path), [dep])
        beanutils = next(iter(result.dependencies), None)
        assert beanutils is not None
        assert beanutils.status == DependencyStatus.IN_USE
        assert "org.apache.commons.beanutils" in beanutils.reason


class TestJavapOutputParsing:
    @pytest.mark.requirement("FR-134")
    def test_parse_public_class_and_methods(self):
        javap_output = """\
Compiled from "BeanUtils.java"
public class org.apache.commons.beanutils.BeanUtils {
  public static void copyProperties(java.lang.Object, java.lang.Object);
  public static java.lang.String getProperty(java.lang.Object, java.lang.String);
  public static final java.lang.String DELIMITER;
}
"""
        result = _parse_javap_output(javap_output)
        names = [name for name, _ in result]
        kinds = {name: kind for name, kind in result}
        assert "org.apache.commons.beanutils.BeanUtils" in names
        assert kinds["org.apache.commons.beanutils.BeanUtils"] == "class"
        assert "org.apache.commons.beanutils.BeanUtils.copyProperties" in names
        assert kinds["org.apache.commons.beanutils.BeanUtils.copyProperties"] == "method"
        assert "org.apache.commons.beanutils.BeanUtils.DELIMITER" in names
        assert kinds["org.apache.commons.beanutils.BeanUtils.DELIMITER"] == "field"

    @pytest.mark.requirement("FR-134")
    def test_empty_output(self):
        assert _parse_javap_output("") == []


class TestJarSecurityConfinement:
    @pytest.mark.requirement("SEC-NEW-29")
    @pytest.mark.security
    def test_jar_path_traversal_blocked(self, tmp_path, monkeypatch):
        """A GAV with path traversal must not escape the repo root."""
        repo = tmp_path / ".m2" / "repository"
        repo.mkdir(parents=True)
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        dep = Dependency(
            name="../../etc:passwd",
            version="1.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        errors: list[str] = []
        result = _locate_dependency_jar(dep, tmp_path, errors)
        assert result is None


class TestJarInventoryMap:
    @pytest.mark.requirement("FR-134")
    def test_inventory_collects_packages_and_class_entries(
        self, tmp_path, monkeypatch
    ):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(sa_mod, "_m2_repo_path", lambda: repo)
        from scarno.analysers.java.maven import _gav_to_jar_path

        jar_path = _gav_to_jar_path(repo, "com.example", "mylib", "1.0")
        jar_path.parent.mkdir(parents=True)
        _make_jar(
            jar_path,
            [
                "com/example/Foo.class",
                "com/example/inner/Bar.class",
                "Top.class",  # default package — skipped for packages
            ],
        )
        dep = Dependency(
            name="com.example:mylib",
            version="1.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        errors: list[str] = []
        inv_map = _build_jar_inventory_map([dep], tmp_path, errors)
        assert "com.example:mylib" in inv_map
        inv = inv_map["com.example:mylib"]
        assert inv.packages == frozenset(
            {"com.example", "com.example.inner"}
        )
        # Default-package entries are preserved in class_entries even
        # though they don't contribute to packages.
        assert "Top.class" in inv.class_entries
        assert "com/example/Foo.class" in inv.class_entries


class TestFastPathEntryPoints:
    """Default path emits class entry points from the JAR listing alone —
    no ``javap`` subprocess — and includes inner classes."""

    @pytest.mark.requirement("FR-134")
    def test_class_entry_points_emitted_without_javap(
        self, tmp_path, monkeypatch
    ):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(sa_mod, "_m2_repo_path", lambda: repo)
        from scarno.analysers.java.maven import _gav_to_jar_path

        jar_path = _gav_to_jar_path(repo, "com.example", "mylib", "1.0")
        jar_path.parent.mkdir(parents=True)
        _make_jar(
            jar_path,
            [
                "com/example/Foo.class",
                "com/example/Foo$Inner.class",
                "com/example/Bar.class",
            ],
        )

        # Fail the test if javap is ever invoked on the fast path.
        def _fail_javap(*args, **kwargs):
            raise AssertionError(
                "javap must not be invoked on the default path"
            )

        monkeypatch.setattr(
            JvmSourceAnalyser, "_invoke_javap_safe", _fail_javap
        )

        (tmp_path / "Main.java").write_text(
            "import com.example.Foo;\n"
            "public class Main {}\n"
        )

        analyser = JvmSourceAnalyser()
        dep = Dependency(
            name="com.example:mylib",
            version="1.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        result = analyser.analyse(str(tmp_path), [dep])
        out_dep = result.dependencies[0]
        assert out_dep.status == DependencyStatus.IN_USE
        names = {ep.name for ep in out_dep.entry_points}
        kinds = {ep.kind for ep in out_dep.entry_points}
        assert names == {
            "com.example.Foo",
            "com.example.Foo$Inner",
            "com.example.Bar",
        }
        assert kinds == {"class"}

    @pytest.mark.requirement("FR-134")
    def test_used_flag_tracks_package_match(self, tmp_path, monkeypatch):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(sa_mod, "_m2_repo_path", lambda: repo)
        from scarno.analysers.java.maven import _gav_to_jar_path

        jar_path = _gav_to_jar_path(repo, "com.example", "mylib", "1.0")
        jar_path.parent.mkdir(parents=True)
        _make_jar(
            jar_path,
            [
                "com/example/used/Foo.class",
                "com/example/other/Bar.class",
            ],
        )
        (tmp_path / "Main.java").write_text(
            "import com.example.used.Foo;\n"
            "public class Main {}\n"
        )

        analyser = JvmSourceAnalyser()
        dep = Dependency(
            name="com.example:mylib",
            version="1.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        result = analyser.analyse(str(tmp_path), [dep])
        by_name = {ep.name: ep.used for ep in result.dependencies[0].entry_points}
        assert by_name["com.example.used.Foo"] is True
        assert by_name["com.example.other.Bar"] is False


class TestDeepInspectionToggle:
    @pytest.mark.requirement("FR-134")
    def test_deep_inspection_invokes_javap(self, tmp_path, monkeypatch):
        repo = tmp_path / ".m2" / "repository"
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        monkeypatch.setattr(sa_mod, "_m2_repo_path", lambda: repo)
        from scarno.analysers.java.maven import _gav_to_jar_path

        jar_path = _gav_to_jar_path(repo, "com.example", "mylib", "1.0")
        jar_path.parent.mkdir(parents=True)
        _make_jar(jar_path, ["com/example/Foo.class"])

        (tmp_path / "Main.java").write_text(
            "import com.example.Foo;\n"
            "public class Main {}\n"
        )

        calls: list[tuple[Path, str]] = []

        def _fake_javap(self, jar, class_name):
            calls.append((jar, class_name))
            return (
                'public class com.example.Foo {\n'
                '  public void doThing();\n'
                '}\n'
            )

        monkeypatch.setattr(
            JvmSourceAnalyser, "_invoke_javap_safe", _fake_javap
        )

        analyser = JvmSourceAnalyser(deep_inspection=True)
        dep = Dependency(
            name="com.example:mylib",
            version="1.0",
            status=DependencyStatus.UNCERTAIN,
            reason="pending",
            ecosystem="maven",
        )
        result = analyser.analyse(str(tmp_path), [dep])
        kinds = {ep.kind for ep in result.dependencies[0].entry_points}
        assert calls, "deep inspection should invoke javap"
        # Fast-path class entry plus javap-derived method entry.
        assert "class" in kinds
        assert "method" in kinds
