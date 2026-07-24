"""REQ-17 — TestScopeMatcher and sanitise_test_paths unit tests.

Pure logic tests for ``scarno.core.test_scope``: pattern validation,
default heuristics per ecosystem, and matcher behaviour.
"""
from __future__ import annotations

import pytest


class TestSanitiseTestPaths:
    @pytest.mark.requirement("FR-154")
    def test_empty_input_returns_empty_tuple(self):
        from scarno.core.test_scope import sanitise_test_paths
        assert sanitise_test_paths(()) == ()

    @pytest.mark.requirement("FR-154")
    def test_well_formed_pattern_passes_through(self):
        from scarno.core.test_scope import sanitise_test_paths
        out = sanitise_test_paths(("it/**/*", "e2e/**/*.ts"))
        assert out == ("it/**/*", "e2e/**/*.ts")

    @pytest.mark.requirement("SEC-NEW-31")
    @pytest.mark.security
    def test_test_paths_count_cap_rejected(self):
        from scarno.core.test_scope import sanitise_test_paths
        too_many = tuple(f"p{i}/*" for i in range(65))
        with pytest.raises(ValueError, match="too many"):
            sanitise_test_paths(too_many)

    @pytest.mark.requirement("SEC-NEW-31")
    @pytest.mark.security
    def test_test_paths_count_cap_at_64_accepted(self):
        from scarno.core.test_scope import sanitise_test_paths
        exact = tuple(f"p{i}/*" for i in range(64))
        out = sanitise_test_paths(exact)
        assert len(out) == 64

    @pytest.mark.requirement("SEC-NEW-31")
    @pytest.mark.security
    def test_test_paths_length_cap_rejected(self):
        from scarno.core.test_scope import sanitise_test_paths
        long_pat = "a" * 257
        with pytest.raises(ValueError, match="too long"):
            sanitise_test_paths((long_pat,))

    @pytest.mark.requirement("SEC-NEW-33")
    @pytest.mark.security
    def test_test_paths_dot_dot_segment_rejected(self):
        from scarno.core.test_scope import sanitise_test_paths
        with pytest.raises(ValueError, match="project root"):
            sanitise_test_paths(("../etc/passwd",))

    @pytest.mark.requirement("SEC-NEW-33")
    @pytest.mark.security
    def test_test_paths_dot_dot_in_middle_rejected(self):
        from scarno.core.test_scope import sanitise_test_paths
        with pytest.raises(ValueError, match="project root"):
            sanitise_test_paths(("tests/../../etc",))

    @pytest.mark.requirement("SEC-NEW-33")
    @pytest.mark.security
    def test_test_paths_backslash_rejected(self):
        from scarno.core.test_scope import sanitise_test_paths
        with pytest.raises(ValueError, match="POSIX"):
            sanitise_test_paths(("tests\\foo",))

    @pytest.mark.requirement("SEC-NEW-33")
    @pytest.mark.security
    def test_test_paths_leading_slash_stripped(self):
        from scarno.core.test_scope import sanitise_test_paths
        out = sanitise_test_paths(("/abs/path/*",))
        assert out == ("abs/path/*",)


class TestTestScopeMatcherDisabled:
    @pytest.mark.requirement("FR-153")
    def test_matcher_returns_false_when_exclude_tests_off(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("python", exclude_tests=False)
        assert m.is_test_path("tests/test_foo.py") is False
        assert m.is_test_path("anything") is False


class TestTestScopeMatcherPython:
    @pytest.mark.requirement("FR-153")
    def test_python_tests_dir_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("python", exclude_tests=True)
        assert m.is_test_path("tests/test_foo.py") is True

    @pytest.mark.requirement("FR-153")
    def test_python_test_underscore_prefix_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("python", exclude_tests=True)
        assert m.is_test_path("src/pkg/test_foo.py") is True

    @pytest.mark.requirement("FR-153")
    def test_python_underscore_test_suffix_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("python", exclude_tests=True)
        assert m.is_test_path("src/pkg/foo_test.py") is True

    @pytest.mark.requirement("FR-153")
    def test_python_conftest_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("python", exclude_tests=True)
        assert m.is_test_path("conftest.py") is True

    @pytest.mark.requirement("FR-153")
    def test_python_production_file_not_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("python", exclude_tests=True)
        assert m.is_test_path("src/pkg/main.py") is False
        assert m.is_test_path("src/pkg/api.py") is False


class TestTestScopeMatcherJs:
    @pytest.mark.requirement("FR-153")
    def test_js_test_suffix_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("javascript", exclude_tests=True)
        assert m.is_test_path("src/foo.test.ts") is True
        assert m.is_test_path("src/foo.test.tsx") is True
        assert m.is_test_path("src/foo.test.js") is True

    @pytest.mark.requirement("FR-153")
    def test_js_spec_suffix_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("javascript", exclude_tests=True)
        assert m.is_test_path("src/foo.spec.ts") is True

    @pytest.mark.requirement("FR-153")
    def test_js_e2e_dir_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("javascript", exclude_tests=True)
        assert m.is_test_path("e2e/login.test.ts") is True

    @pytest.mark.requirement("FR-153")
    def test_js_production_file_not_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("javascript", exclude_tests=True)
        assert m.is_test_path("src/index.ts") is False


class TestTestScopeMatcherJava:
    @pytest.mark.requirement("FR-153")
    def test_java_src_test_dir_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("java", exclude_tests=True)
        assert m.is_test_path("src/test/java/com/example/FooTest.java") is True

    @pytest.mark.requirement("FR-153")
    def test_java_test_suffix_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("java", exclude_tests=True)
        assert m.is_test_path("src/main/java/com/example/FooTest.java") is True
        assert m.is_test_path("src/main/java/com/example/FooTests.java") is True

    @pytest.mark.requirement("FR-153")
    def test_java_production_file_not_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("java", exclude_tests=True)
        assert m.is_test_path("src/main/java/com/example/Foo.java") is False


class TestTestScopeMatcherGo:
    @pytest.mark.requirement("FR-153")
    def test_go_test_suffix_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("go", exclude_tests=True)
        assert m.is_test_path("internal/db/db_test.go") is True

    @pytest.mark.requirement("FR-153")
    def test_go_production_not_matched(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("go", exclude_tests=True)
        assert m.is_test_path("internal/db/db.go") is False


class TestTestScopeMatcherUserPatterns:
    @pytest.mark.requirement("FR-154")
    def test_user_pattern_extends_matcher(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher(
            "java",
            exclude_tests=True,
            user_patterns=("it/**/*",),
        )
        assert m.is_test_path("it/integration/FooIT.java") is True
        # default still matches
        assert m.is_test_path("src/test/java/Foo.java") is True
        # production unaffected
        assert m.is_test_path("src/main/java/Foo.java") is False

    @pytest.mark.requirement("FR-154")
    def test_user_pattern_inert_when_disabled(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher(
            "java",
            exclude_tests=False,
            user_patterns=("it/**/*",),
        )
        assert m.is_test_path("it/integration/FooIT.java") is False


class TestSanitiseEdgeCases:
    @pytest.mark.requirement("FR-154")
    def test_non_string_input_rejected(self):
        from scarno.core.test_scope import sanitise_test_paths
        with pytest.raises(ValueError, match="string"):
            sanitise_test_paths((123,))  # type: ignore[arg-type]

    @pytest.mark.requirement("FR-154")
    def test_blank_pattern_dropped(self):
        from scarno.core.test_scope import sanitise_test_paths
        # An all-slashes pattern reduces to "" after lstrip — drop it.
        out = sanitise_test_paths(("/",))
        assert out == ()


class TestMatcherWindowsSeparator:
    @pytest.mark.requirement("FR-153")
    def test_path_with_backslash_normalised(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("python", exclude_tests=True)
        # Caller may inadvertently pass an os.sep path; matcher normalises.
        assert m.is_test_path("tests\\test_foo.py") is True

    @pytest.mark.requirement("FR-153")
    def test_unknown_language_returns_false_always(self):
        from scarno.core.test_scope import TestScopeMatcher
        m = TestScopeMatcher("klingon", exclude_tests=True)
        assert m.is_test_path("tests/foo.py") is False
        assert m.patterns == ()
