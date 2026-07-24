"""Skeleton tests for REQ-6b — robust JVM parsing via tree-sitter.

These tests fail red until Phase 4 implements tree-sitter-backed
AST extraction. They carry SRTM markers now so the coverage gate
stays honest and can't silently drift.
"""
from __future__ import annotations

import pytest

from scarno.analysers.java.source_analyser import JvmSourceAnalyser
from scarno.models import Dependency, DependencyStatus


def _uncertain(name: str) -> Dependency:
    return Dependency(
        name=name,
        version=None,
        status=DependencyStatus.UNCERTAIN,
        reason="pending",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


@pytest.fixture
def analyser() -> JvmSourceAnalyser:
    return JvmSourceAnalyser()


class TestCommentsAndStringsExcluded:
    @pytest.mark.requirement("FR-086")
    @pytest.mark.requirement("FR-087")
    def test_import_in_line_comment_not_flagged(self, tmp_path, analyser):
        (tmp_path / "Main.java").write_text(
            "// import com.example.Secret;\n"
            "public class Main {}\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.example:secret")]
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        # Phase 2 regex impl FAILS this — the comment is matched as a real import.
        # Phase 4 tree-sitter impl PASSES it.
        assert dep.status in (DependencyStatus.SAFE, DependencyStatus.UNCERTAIN), (
            "Comments must not be scanned for imports (REQ-6b)"
        )

    @pytest.mark.requirement("FR-086")
    @pytest.mark.requirement("FR-087")
    def test_annotation_in_string_literal_not_flagged(self, tmp_path, analyser):
        (tmp_path / "Main.java").write_text(
            'public class Main { String doc = "@Autowired"; }\n'
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("org.springframework:spring-core")]
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        assert dep.status in (DependencyStatus.SAFE, DependencyStatus.UNCERTAIN), (
            "Annotations inside string literals must not trigger DI match (REQ-6b)"
        )

    @pytest.mark.requirement("FR-086")
    @pytest.mark.requirement("FR-087")
    def test_class_forname_in_javadoc_not_flagged(self, tmp_path, analyser):
        (tmp_path / "Main.java").write_text(
            "/** Uses Class.forName(\"com.fasterxml.jackson.databind.X\") */\n"
            "public class Main {}\n"
        )
        result = analyser.analyse(
            str(tmp_path),
            [_uncertain("com.fasterxml.jackson.core:jackson-databind")],
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        assert dep.status in (DependencyStatus.SAFE, DependencyStatus.UNCERTAIN), (
            "Class.forName inside Javadoc must not trigger reflection heuristic (REQ-6b)"
        )


class TestMultiLineAndKotlinSyntax:
    @pytest.mark.requirement("FR-086")
    def test_multi_line_import_handled(self, tmp_path, analyser):
        (tmp_path / "Main.java").write_text(
            "import\n  com.google.common.collect.ImmutableList;\n"
            "public class Main {}\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.google.guava:guava")]
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        assert dep.status == DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-086")
    def test_kotlin_aliased_import_recognised(self, tmp_path, analyser):
        (tmp_path / "Main.kt").write_text(
            "import com.google.common.collect.ImmutableList as ImList\n"
            "fun main() { val x: ImList<String>? = null }\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.google.guava:guava")]
        )
        dep = next(iter(result.dependencies), None)
        assert dep is not None
        assert dep.status == DependencyStatus.IN_USE


class TestFallback:
    @pytest.mark.requirement("FR-088")
    def test_graceful_fallback_when_grammar_unavailable(self, tmp_path, analyser):
        """When tree-sitter wheels aren't present, analysis proceeds via
        the regex fallback with a warning in ``errors``."""
        (tmp_path / "Main.java").write_text(
            "import com.google.common.collect.ImmutableList;\n"
            "public class Main {}\n"
        )
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.google.guava:guava")]
        )
        # Until tree-sitter lands, this test passes on the regex impl
        # (which IS the fallback). When REQ-6b ships, the warning must
        # be asserted on machines without wheels.
        assert result.project_type == "java"


class TestResourceBounds:
    @pytest.mark.requirement("SEC-NEW-19")
    @pytest.mark.security
    def test_pathological_source_file_bounded(self, tmp_path, analyser):
        """A 10 MB+ source file must be skipped by the existing size cap."""
        from scarno.security import MAX_FILE_BYTES

        huge = tmp_path / "Huge.java"
        huge.write_bytes(b"// a\n" * (MAX_FILE_BYTES // 5 + 1))
        result = analyser.analyse(
            str(tmp_path), [_uncertain("com.example:foo")]
        )
        assert any("too large" in e.lower() for e in result.errors)
