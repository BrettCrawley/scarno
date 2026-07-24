"""REQ-12 — CSS analyser (Phase 5).

Covers ``@import`` / ``@use`` / ``url()`` extraction, Webpack tilde
prefix handling, npm-ecosystem dep emission, and security findings
``TS-CE-007`` (remote import) / ``TS-CE-008`` (``file://`` URL).
"""
from __future__ import annotations

import pytest

from scarno.analysers.css import CssAnalyser
from scarno.models import DependencyStatus


@pytest.fixture()
def analyser():
    return CssAnalyser()


def _run(analyser: CssAnalyser, tmp_path):
    return analyser.analyse(str(tmp_path))


class TestReq12CssExtraction:
    @pytest.mark.requirement("FR-111")
    def test_css_import_quoted_extracts_npm_dep(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text('@import "normalize.css";\n')
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "normalize.css" in names

    @pytest.mark.requirement("FR-111")
    def test_scss_use_extracts_npm_dep(self, analyser, tmp_path):
        (tmp_path / "app.scss").write_text('@use "bootstrap/scss/variables";\n')
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "bootstrap" in names

    @pytest.mark.requirement("FR-111")
    def test_import_url_form_extracts_npm_dep(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text('@import url("some-pkg/theme.css");\n')
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "some-pkg" in names

    @pytest.mark.requirement("FR-111")
    def test_comment_blocks_are_ignored(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text(
            '/* @import "should-not-fire"; */\n'
            '@import "real-pkg";\n'
        )
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "real-pkg" in names
        assert "should-not-fire" not in names

    @pytest.mark.requirement("FR-111")
    def test_scss_line_comment_ignored(self, analyser, tmp_path):
        (tmp_path / "app.scss").write_text(
            '// @import "ghost"\n'
            '@use "bootstrap";\n'
        )
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "bootstrap" in names
        assert "ghost" not in names

    @pytest.mark.requirement("FR-111")
    def test_local_relative_imports_not_emitted(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text(
            '@import "./reset.css";\n'
            '@import "../shared/vars.css";\n'
        )
        result = _run(analyser, tmp_path)
        assert result.dependencies == []


class TestReq12WebpackTilde:
    @pytest.mark.requirement("FR-112")
    def test_tilde_prefix_stripped_from_unscoped(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text('@import "~normalize.css";\n')
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "normalize.css" in names

    @pytest.mark.requirement("FR-112")
    def test_tilde_prefix_stripped_from_scoped(self, analyser, tmp_path):
        (tmp_path / "app.scss").write_text('@use "~@scope/pkg/variables";\n')
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "@scope/pkg" in names


class TestReq12EcosystemTagging:
    @pytest.mark.requirement("FR-113")
    def test_css_only_dep_tagged_ecosystem_npm(self, analyser, tmp_path):
        (tmp_path / "styles.css").write_text('@import "tailwindcss/base";\n')
        result = _run(analyser, tmp_path)
        assert result.dependencies, "expected one dep"
        assert all(d.ecosystem == "npm" for d in result.dependencies)

    @pytest.mark.requirement("FR-113")
    def test_css_dep_status_is_in_use(self, analyser, tmp_path):
        (tmp_path / "styles.css").write_text('@import "normalize.css";\n')
        result = _run(analyser, tmp_path)
        dep = next(d for d in result.dependencies if d.name == "normalize.css")
        assert dep.status is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-113")
    def test_languages_list_is_css(self, analyser, tmp_path):
        (tmp_path / "styles.css").write_text("")
        result = _run(analyser, tmp_path)
        assert result.languages == ["css"]

    @pytest.mark.requirement("FR-113")
    def test_scoped_subpath_trimmed_to_package_root(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text('@import "@scope/pkg/sub/theme.css";\n')
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "@scope/pkg" in names
        assert "@scope/pkg/sub/theme.css" not in names


class TestReq12SecurityFindings:
    @pytest.mark.requirement("SF-019")
    @pytest.mark.security
    def test_remote_https_import_emits_ts_ce_007(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text(
            '@import url("https://fonts.googleapis.com/css?family=Roboto");\n'
        )
        result = _run(analyser, tmp_path)
        rules = [f.rule_id for f in result.findings]
        assert "TS-CE-007" in rules

    @pytest.mark.requirement("SF-019")
    @pytest.mark.security
    def test_remote_http_import_emits_ts_ce_007(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text(
            '@import "http://cdn.example.com/reset.css";\n'
        )
        result = _run(analyser, tmp_path)
        assert any(f.rule_id == "TS-CE-007" for f in result.findings)

    @pytest.mark.requirement("SF-019")
    @pytest.mark.security
    def test_remote_import_url_not_emitted_twice(self, analyser, tmp_path):
        """Regression guard: @import url("https://…") matches both the
        @import-url regex and the generic url() regex; must fire once."""
        (tmp_path / "app.css").write_text(
            '@import url("https://fonts.googleapis.com/css");\n'
        )
        result = _run(analyser, tmp_path)
        count = sum(1 for f in result.findings if f.rule_id == "TS-CE-007")
        assert count == 1, f"TS-CE-007 fired {count} times, expected 1"

    @pytest.mark.requirement("SF-020")
    @pytest.mark.security
    def test_file_url_emits_ts_ce_008(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text(
            '.logo { background: url("file:///etc/hostname"); }\n'
        )
        result = _run(analyser, tmp_path)
        rules = [f.rule_id for f in result.findings]
        assert "TS-CE-008" in rules

    @pytest.mark.requirement("SF-020")
    @pytest.mark.security
    def test_local_relative_url_does_not_fire(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text(
            ".logo { background: url('./images/logo.png'); }\n"
        )
        result = _run(analyser, tmp_path)
        assert result.findings == []


class TestReq12Robustness:
    @pytest.mark.requirement("FR-111")
    def test_excluded_dirs_skipped(self, analyser, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "vendor.css").write_text(
            '@import "third-party";\n'
        )
        result = _run(analyser, tmp_path)
        names = {d.name for d in result.dependencies}
        assert "third-party" not in names

    @pytest.mark.requirement("FR-111")
    def test_empty_target_ignored(self, analyser, tmp_path):
        (tmp_path / "app.css").write_text('@import "";\n')
        result = _run(analyser, tmp_path)
        assert result.dependencies == []
