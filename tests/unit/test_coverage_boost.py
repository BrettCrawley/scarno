"""Coverage-boost tests targeting uncovered lines in config, notebook_parser,
java/source_analyser, and java/ast_extractor.

Each test carries an ``@pytest.mark.requirement`` so the SRTM plugin
tracks it.
"""
from __future__ import annotations

import json
import textwrap

import pytest


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _uncertain(name: str):
    from scarno.models import Dependency, DependencyStatus

    return Dependency(
        name=name,
        version=None,
        status=DependencyStatus.UNCERTAIN,
        reason="pending source analysis",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1. findings/config.py — lines 35-38, 44, 50-54, 65-78
# ═══════════════════════════════════════════════════════════════════════════


class TestSuppressionConfig:
    """Exercise load_suppression_config edge-cases."""

    @pytest.mark.requirement("SF-009")
    def test_invalid_toml_returns_empty_config(self, tmp_path):
        """Lines 35-38: OSError / TOMLDecodeError branch."""
        from scarno.findings.config import load_suppression_config

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("this is <<<not valid toml>>>")
        config, errors = load_suppression_config(tmp_path)
        assert config.suppress == set()
        assert config.per_path == {}

    @pytest.mark.requirement("SF-009")
    def test_findings_section_not_dict_returns_empty(self, tmp_path):
        """Line 44: section is not a dict."""
        from scarno.findings.config import load_suppression_config

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[tool.scarno]\nfindings = "not a dict"\n'
        )
        config, errors = load_suppression_config(tmp_path)
        assert config.suppress == set()

    @pytest.mark.requirement("SF-010")
    def test_suppress_entry_not_string_produces_error(self, tmp_path):
        """Lines 50-54: non-string entry in suppress list."""
        from scarno.findings.config import load_suppression_config

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[tool.scarno.findings]\nsuppress = [42]\n"
        )
        config, errors = load_suppression_config(tmp_path)
        assert any("must be strings" in e for e in errors)
        assert config.suppress == set()

    @pytest.mark.requirement("SF-010")
    def test_suppress_unknown_rule_id_produces_error(self, tmp_path):
        """Lines 55-60: unknown rule id in suppress list."""
        from scarno.findings.config import load_suppression_config

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[tool.scarno.findings]\nsuppress = ["FAKE-999"]\n'
        )
        config, errors = load_suppression_config(tmp_path)
        assert any("unknown rule id" in e for e in errors)
        assert config.suppress == set()

    @pytest.mark.requirement("SF-009")
    def test_per_path_with_valid_and_unknown_rules(self, tmp_path):
        """Lines 65-78: per-path dict with mixed valid/invalid rule ids."""
        from scarno.findings.config import load_suppression_config

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(textwrap.dedent("""\
            [tool.scarno.findings.paths]
            "src/app.py" = ["TS-SI-001", "BOGUS-123"]
        """))
        config, errors = load_suppression_config(tmp_path)
        assert "src/app.py" in config.per_path
        assert "TS-SI-001" in config.per_path["src/app.py"]
        assert any("BOGUS-123" in e for e in errors)

    @pytest.mark.requirement("SF-009")
    def test_per_path_non_list_value_skipped(self, tmp_path):
        """Line 66-67: per-path value that is not a list is skipped."""
        from scarno.findings.config import load_suppression_config

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(textwrap.dedent("""\
            [tool.scarno.findings.paths]
            "src/app.py" = "not a list"
        """))
        config, errors = load_suppression_config(tmp_path)
        assert config.per_path == {}


# ═══════════════════════════════════════════════════════════════════════════
# 2. notebook_parser.py — lines 50-57, 60-62, 69, 72, 78-87, 95
# ═══════════════════════════════════════════════════════════════════════════


class TestNotebookParser:
    """Exercise extract_code_cells edge-cases."""

    @pytest.mark.requirement("FR-063")
    def test_stat_fails_for_missing_file(self, tmp_path):
        """Lines 50-52: OSError on stat."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        cells, errors = extract_code_cells(tmp_path / "nonexistent.ipynb")
        assert cells.ast_safe_source == ""
        assert any("stat failed" in e for e in errors)

    @pytest.mark.requirement("SEC-NEW-04")
    def test_file_too_large_skipped(self, tmp_path):
        """Lines 53-57: oversized file branch."""
        from scarno.analysers.python.notebook_parser import extract_code_cells
        from scarno.security import MAX_FILE_BYTES

        big = tmp_path / "huge.ipynb"
        big.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        cells, errors = extract_code_cells(big)
        assert cells.ast_safe_source == ""
        assert any("too large" in e for e in errors)

    @pytest.mark.requirement("FR-063")
    def test_unreadable_file(self, tmp_path):
        """Lines 60-62: UnicodeDecodeError branch."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        bad = tmp_path / "bad.ipynb"
        bad.write_bytes(b"\x80\x81\x82\xff" * 100)
        cells, errors = extract_code_cells(bad)
        # Might parse or might raise UnicodeDecodeError depending on the bytes;
        # either an error or an invalid-JSON error is acceptable.
        assert cells.ast_safe_source == "" or len(errors) > 0

    @pytest.mark.requirement("FR-063")
    def test_invalid_json(self, tmp_path):
        """Lines 64-67: JSON decode error."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "bad.ipynb"
        nb.write_text("{invalid json!!")
        cells, errors = extract_code_cells(nb)
        assert any("invalid JSON" in e for e in errors)

    @pytest.mark.requirement("FR-063")
    def test_data_not_dict(self, tmp_path):
        """Line 68-69: top-level JSON is not a dict."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "array.ipynb"
        nb.write_text("[1, 2, 3]")
        cells, errors = extract_code_cells(nb)
        assert cells.ast_safe_source == ""

    @pytest.mark.requirement("FR-063")
    def test_cells_not_list(self, tmp_path):
        """Line 71-72: cells key is not a list."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "nocells.ipynb"
        nb.write_text(json.dumps({"cells": "not a list"}))
        cells, errors = extract_code_cells(nb)
        assert cells.ast_safe_source == ""

    @pytest.mark.requirement("FR-063")
    def test_non_dict_cell_skipped(self, tmp_path):
        """Line 77-78: cell that is not a dict is skipped."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "test.ipynb"
        nb.write_text(json.dumps({
            "cells": ["not a dict", {"cell_type": "code", "source": ["import os\n"]}]
        }))
        cells, errors = extract_code_cells(nb)
        assert "import os" in cells.ast_safe_source

    @pytest.mark.requirement("FR-063")
    def test_non_code_cell_skipped(self, tmp_path):
        """Line 79-80: markdown cell is skipped."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "test.ipynb"
        nb.write_text(json.dumps({
            "cells": [{"cell_type": "markdown", "source": ["# Title"]}]
        }))
        cells, errors = extract_code_cells(nb)
        assert cells.ast_safe_source.strip() == ""

    @pytest.mark.requirement("FR-063")
    def test_source_as_string(self, tmp_path):
        """Lines 84-85: source is a plain string, not a list."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "test.ipynb"
        nb.write_text(json.dumps({
            "cells": [{"cell_type": "code", "source": "x = 1"}]
        }))
        cells, errors = extract_code_cells(nb)
        assert "x = 1" in cells.ast_safe_source

    @pytest.mark.requirement("FR-063")
    def test_source_neither_list_nor_string(self, tmp_path):
        """Lines 86-87: source is an unexpected type."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "test.ipynb"
        nb.write_text(json.dumps({
            "cells": [{"cell_type": "code", "source": 42}]
        }))
        cells, errors = extract_code_cells(nb)
        assert cells.ast_safe_source.strip() == ""

    @pytest.mark.requirement("FR-063")
    def test_magic_lines_stripped_and_preserved(self, tmp_path):
        """Lines 88-95: magic stripping + raw_magics + trailing newline."""
        from scarno.analysers.python.notebook_parser import extract_code_cells

        nb = tmp_path / "test.ipynb"
        nb.write_text(json.dumps({
            "cells": [{
                "cell_type": "code",
                "source": ["!pip install requests\n", "import requests"]
            }]
        }))
        cells, errors = extract_code_cells(nb)
        assert "!pip install requests" in cells.raw_magics
        assert "import requests" in cells.ast_safe_source
        # The magic line should be replaced with a plain newline
        assert "!pip" not in cells.ast_safe_source


# ═══════════════════════════════════════════════════════════════════════════
# 3. java/source_analyser.py — classify_dep, analyse, supports
# ═══════════════════════════════════════════════════════════════════════════


class TestJvmSourceAnalyserClassifyDep:
    """Exercise _classify_dep code paths."""

    @pytest.mark.requirement("FR-018")
    def test_classify_dep_import_match(self):
        """Direct import match returns IN_USE."""
        from scarno.analysers.java.source_analyser import _classify_dep
        from scarno.models import DependencyStatus

        dep = _uncertain("com.google.guava:guava")
        status, reason = _classify_dep(
            dep,
            import_paths={"com.google.common.collect.ImmutableList"},
            annotations=set(),
            reflective_literals=set(),
            have_source_evidence=True,
        )
        assert status == DependencyStatus.IN_USE
        assert "imported" in reason

    @pytest.mark.requirement("FR-018")
    def test_classify_dep_annotation_match(self):
        """DI annotation match returns IN_USE."""
        from scarno.analysers.java.source_analyser import _classify_dep
        from scarno.models import DependencyStatus

        dep = _uncertain("org.springframework:spring-core")
        status, reason = _classify_dep(
            dep,
            import_paths=set(),
            annotations={"Autowired"},
            reflective_literals=set(),
            have_source_evidence=True,
        )
        assert status == DependencyStatus.IN_USE
        assert "@Autowired" in reason

    @pytest.mark.requirement("FR-018")
    def test_classify_dep_reflective_match(self):
        """Reflective class literal match returns UNCERTAIN."""
        from scarno.analysers.java.source_analyser import _classify_dep
        from scarno.models import DependencyStatus

        dep = _uncertain("com.example:mylib")
        status, reason = _classify_dep(
            dep,
            import_paths=set(),
            annotations=set(),
            reflective_literals={"com.example.MyClass"},
            have_source_evidence=True,
        )
        assert status == DependencyStatus.UNCERTAIN
        assert "Class.forName" in reason

    @pytest.mark.requirement("FR-018")
    def test_classify_dep_no_source_evidence(self):
        """No source files → UNCERTAIN."""
        from scarno.analysers.java.source_analyser import _classify_dep
        from scarno.models import DependencyStatus

        dep = _uncertain("com.example:mylib")
        status, reason = _classify_dep(
            dep,
            import_paths=set(),
            annotations=set(),
            reflective_literals=set(),
            have_source_evidence=False,
        )
        assert status == DependencyStatus.UNCERTAIN
        assert "no source files" in reason

    @pytest.mark.requirement("FR-018")
    def test_classify_dep_safe_when_no_match(self):
        """No match with source evidence → SAFE."""
        from scarno.analysers.java.source_analyser import _classify_dep
        from scarno.models import DependencyStatus

        dep = _uncertain("com.example:mylib")
        status, reason = _classify_dep(
            dep,
            import_paths=set(),
            annotations=set(),
            reflective_literals=set(),
            have_source_evidence=True,
        )
        assert status == DependencyStatus.SAFE


class TestJvmSupportsAndAnalyse:
    """Exercise JvmSourceAnalyser.supports() and .analyse()."""

    @pytest.mark.requirement("FR-018")
    def test_supports_false_for_empty_dir(self, tmp_path):
        """Lines 129-135: no .java/.kt files → False."""
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        analyser = JvmSourceAnalyser()
        assert analyser.supports(str(tmp_path)) is False

    @pytest.mark.requirement("FR-018")
    def test_supports_true_with_java_file(self, tmp_path):
        """Lines 129-134: .java file present → True."""
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        (tmp_path / "Main.java").write_text("class Main {}")
        analyser = JvmSourceAnalyser()
        assert analyser.supports(str(tmp_path)) is True

    @pytest.mark.requirement("FR-018")
    def test_supports_false_for_file_path(self, tmp_path):
        """Line 130-131: non-directory path → False."""
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        f = tmp_path / "file.txt"
        f.write_text("hi")
        analyser = JvmSourceAnalyser()
        assert analyser.supports(str(f)) is False

    @pytest.mark.requirement("FR-018")
    def test_analyse_updates_deps(self, tmp_path):
        """Lines 137-203: full analyse path updates deps."""
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser
        from scarno.models import DependencyStatus

        (tmp_path / "Main.java").write_text(
            "import com.google.common.collect.ImmutableList;\n"
            "public class Main {}\n"
        )
        analyser = JvmSourceAnalyser()
        result = analyser.analyse(
            str(tmp_path),
            [_uncertain("com.google.guava:guava"), _uncertain("com.unused:lib")],
        )
        guava = next(d for d in result.dependencies if d.name == "com.google.guava:guava")
        unused = next(d for d in result.dependencies if d.name == "com.unused:lib")
        assert guava.status == DependencyStatus.IN_USE
        assert unused.status == DependencyStatus.SAFE
        assert guava.ecosystem == "maven"

    @pytest.mark.requirement("FR-018")
    def test_analyse_no_deps(self, tmp_path):
        """analyse() with no dependencies produces empty list."""
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        (tmp_path / "Main.java").write_text("class Main {}")
        analyser = JvmSourceAnalyser()
        result = analyser.analyse(str(tmp_path))
        assert result.dependencies == []
        assert result.project_type == "java"


# ═══════════════════════════════════════════════════════════════════════════
# 4. java/ast_extractor.py — Kotlin extractor + helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestAstExtractorKotlin:
    """Exercise extract_kotlin and helpers."""

    @pytest.mark.requirement("FR-086")
    def test_extract_kotlin_import(self):
        """Kotlin import declaration extracted."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_kotlin

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-kotlin not available")
        source = "import com.google.common.collect.ImmutableList\nfun main() {}\n"
        facts = extract_kotlin(source)
        assert "com.google.common.collect.ImmutableList" in facts.imports

    @pytest.mark.requirement("FR-086")
    def test_extract_kotlin_annotation(self):
        """Kotlin annotation extracted."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_kotlin

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-kotlin not available")
        source = textwrap.dedent("""\
            import org.springframework.stereotype.Service

            @Service
            class MyService
        """)
        facts = extract_kotlin(source)
        assert "Service" in facts.annotations

    @pytest.mark.requirement("FR-086")
    def test_extract_kotlin_comment_excluded(self):
        """Comments must not contribute imports."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_kotlin

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-kotlin not available")
        source = "// import com.secret.Hidden\nfun main() {}\n"
        facts = extract_kotlin(source)
        assert "com.secret.Hidden" not in facts.imports

    @pytest.mark.requirement("FR-086")
    def test_extract_kotlin_string_literal_excluded(self):
        """String literals must not contribute imports."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_kotlin

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-kotlin not available")
        source = 'fun main() { val s = "import com.secret.Hidden" }\n'
        facts = extract_kotlin(source)
        assert "com.secret.Hidden" not in facts.imports

    @pytest.mark.requirement("FR-086")
    def test_extract_kotlin_reflective_class_forname(self):
        """Class.forName in Kotlin — the extractor handles both old
        (call_suffix) and current (value_arguments) tree-sitter-kotlin
        AST shapes."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_kotlin

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-kotlin not available")
        source = textwrap.dedent("""\
            fun main() {
                val cls = Class.forName("com.example.MyDriver")
            }
        """)
        facts = extract_kotlin(source)
        assert "com.example.MyDriver" in facts.reflective_literals

    @pytest.mark.requirement("FR-086")
    def test_extract_kotlin_aliased_import(self):
        """Kotlin aliased import extracted."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_kotlin

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-kotlin not available")
        source = "import com.google.common.collect.ImmutableList as ImList\nfun main() {}\n"
        facts = extract_kotlin(source)
        # The import path should still be the full qualified name
        assert any("com.google.common.collect" in imp for imp in facts.imports)


class TestAstExtractorHelpers:
    """Exercise shared helpers in ast_extractor."""

    @pytest.mark.requirement("FR-086")
    def test_bytes_to_str_none(self):
        """_bytes_to_str returns empty string for None."""
        from scarno.analysers.java.ast_extractor import _bytes_to_str

        assert _bytes_to_str(None) == ""

    @pytest.mark.requirement("FR-086")
    def test_bytes_to_str_bytes(self):
        """_bytes_to_str decodes bytes."""
        from scarno.analysers.java.ast_extractor import _bytes_to_str

        assert _bytes_to_str(b"hello") == "hello"

    @pytest.mark.requirement("FR-086")
    def test_bytes_to_str_string_passthrough(self):
        """_bytes_to_str passes through strings."""
        from scarno.analysers.java.ast_extractor import _bytes_to_str

        assert _bytes_to_str("hello") == "hello"

    @pytest.mark.requirement("FR-086")
    def test_extract_java_with_reflection(self):
        """Java Class.forName detected via AST."""
        from scarno.analysers.java.ast_extractor import AST_AVAILABLE, extract_java

        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java not available")
        source = textwrap.dedent("""\
            public class Main {
                void load() throws Exception {
                    Class.forName("com.mysql.cj.jdbc.Driver");
                }
            }
        """)
        facts = extract_java(source)
        assert "com.mysql.cj.jdbc.Driver" in facts.reflective_literals
