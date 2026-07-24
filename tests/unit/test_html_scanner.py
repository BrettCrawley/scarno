"""Tests for the HTML / template scanner (cross-cutting front-end dep extraction)."""
from __future__ import annotations

import json

import pytest

from scarno.analysers.html_scanner import HtmlDependency, scan_html_templates


def _names(result):
    return {d.name for d in result.dependencies}


class TestScriptSrcExtraction:
    @pytest.mark.requirement("FR-103")
    def test_cdn_jsdelivr_script_detected(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "vue" in _names(result)
        dep = next(d for d in result.dependencies if d.name == "vue")
        assert dep.version == "3"
        assert dep.source_type == "cdn_script"

    @pytest.mark.requirement("FR-103")
    def test_unpkg_script_detected(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script src="https://unpkg.com/lodash@4.17.21/lodash.min.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "lodash" in _names(result)
        dep = next(d for d in result.dependencies if d.name == "lodash")
        assert dep.version == "4.17.21"

    @pytest.mark.requirement("FR-103")
    def test_cdnjs_script_detected(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "jquery" in _names(result)
        dep = next(d for d in result.dependencies if d.name == "jquery")
        assert dep.version == "3.7.1"

    @pytest.mark.requirement("FR-103")
    def test_local_script_not_extracted_as_dep(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script src="./js/app.js"></script>\n'
            '<script src="/static/vendor.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert result.dependencies == []

    @pytest.mark.requirement("FR-103")
    def test_remote_urls_tracked(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script src="https://example.com/unknown-cdn/lib.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert len(result.remote_urls) == 1
        assert result.remote_urls[0][2] == "script"


class TestLinkStylesheetExtraction:
    @pytest.mark.requirement("FR-111")
    def test_cdn_stylesheet_detected(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3/dist/css/bootstrap.min.css">\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "bootstrap" in _names(result)
        dep = next(d for d in result.dependencies if d.name == "bootstrap")
        assert dep.source_type == "cdn_stylesheet"

    @pytest.mark.requirement("FR-111")
    def test_href_before_rel_also_matched(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<link href="https://cdn.jsdelivr.net/npm/normalize.css@8/normalize.css" rel="stylesheet">\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "normalize.css" in _names(result)


class TestInlineStyleImport:
    @pytest.mark.requirement("SF-019")
    def test_inline_style_remote_import(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<style>\n'
            '  @import url("https://fonts.googleapis.com/css2?family=Roboto");\n'
            '</style>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert len(result.remote_urls) >= 1
        assert any("fonts.googleapis" in url for url, _, _ in result.remote_urls)


class TestScriptModuleImport:
    @pytest.mark.requirement("FR-107")
    def test_esm_import_in_module_script(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script type="module">\n'
            "  import { createApp } from 'vue';\n"
            "  import lodash from 'lodash';\n"
            '</script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        names = _names(result)
        assert "vue" in names
        assert "lodash" in names

    @pytest.mark.requirement("FR-107")
    def test_relative_esm_import_not_extracted(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script type="module">\n'
            "  import { helper } from './utils.js';\n"
            '</script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert result.dependencies == []


class TestImportMap:
    @pytest.mark.requirement("FR-107")
    def test_importmap_extracts_packages(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script type="importmap">\n'
            + json.dumps({
                "imports": {
                    "vue": "https://cdn.jsdelivr.net/npm/vue@3/dist/vue.esm-browser.js",
                    "lodash": "https://cdn.jsdelivr.net/npm/lodash-es@4/lodash.js",
                    "@scope/pkg": "./local/pkg.js",
                }
            })
            + "\n</script>\n"
        )
        result = scan_html_templates(str(tmp_path))
        names = _names(result)
        assert "vue" in names
        assert "lodash-es" in names
        # Local mapping (./local/pkg.js) is correctly not treated as a dep
        assert "@scope/pkg" not in names

    @pytest.mark.requirement("FR-107")
    def test_malformed_importmap_ignored(self, tmp_path):
        (tmp_path / "index.html").write_text(
            '<script type="importmap">\n'
            "  { not valid json\n"
            "</script>\n"
        )
        result = scan_html_templates(str(tmp_path))
        assert result.dependencies == []


class TestTemplateFormats:
    @pytest.mark.requirement("FR-103")
    def test_django_jinja2_template(self, tmp_path):
        (tmp_path / "base.html").write_text(
            '{% load static %}\n'
            '<!DOCTYPE html>\n'
            '<html>\n'
            '<head>\n'
            '  <script src="https://cdn.jsdelivr.net/npm/htmx.org@1.9/dist/htmx.min.js"></script>\n'
            '  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css">\n'
            '</head>\n'
            '<body>{% block content %}{% endblock %}</body>\n'
            '</html>\n'
        )
        result = scan_html_templates(str(tmp_path))
        names = _names(result)
        assert "htmx.org" in names
        assert "bootstrap" in names

    @pytest.mark.requirement("FR-103")
    def test_jsp_template(self, tmp_path):
        (tmp_path / "index.jsp").write_text(
            '<%@ page language="java" %>\n'
            '<html>\n'
            '<head>\n'
            '  <script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"></script>\n'
            '</head>\n'
            '<body><%= request.getAttribute("msg") %></body>\n'
            '</html>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "jquery" in _names(result)

    @pytest.mark.requirement("FR-103")
    def test_vue_sfc(self, tmp_path):
        (tmp_path / "App.vue").write_text(
            '<template><div>{{ msg }}</div></template>\n'
            '<script type="module">\n'
            "  import axios from 'axios';\n"
            "  export default { data() { return { msg: 'hi' } } }\n"
            '</script>\n'
            '<style>@import url("https://fonts.googleapis.com/css2?family=Inter");</style>\n'
        )
        result = scan_html_templates(str(tmp_path))
        names = _names(result)
        assert "axios" in names

    @pytest.mark.requirement("FR-103")
    def test_ejs_template(self, tmp_path):
        (tmp_path / "layout.ejs").write_text(
            '<!DOCTYPE html>\n'
            '<html>\n'
            '<head>\n'
            '  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>\n'
            '</head>\n'
            '<body><%- body %></body>\n'
            '</html>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "react" in _names(result)

    @pytest.mark.requirement("FR-103")
    def test_php_template(self, tmp_path):
        (tmp_path / "index.php").write_text(
            '<?php echo "hello"; ?>\n'
            '<script src="https://cdn.jsdelivr.net/npm/alpinejs@3/dist/cdn.min.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "alpinejs" in _names(result)


class TestWebappIntegration:
    @pytest.mark.requirement("FR-103")
    def test_python_webapp_with_frontend_deps(self):
        """The full webapp fixture: Python backend + CDN frontend deps.
        HTML scanning is done by the CLI orchestrator, not by individual
        analysers — so we verify detection + HTML scanner separately."""
        from scarno.core.detector import detect_project_types

        fixture = "tests/fixtures/webapp_python_frontend"
        types = detect_project_types(fixture)
        assert "python" in types
        assert "css" in types

        # The HTML scanner (cross-cutting, called by CLI) finds bootstrap
        result = scan_html_templates(fixture)
        html_dep_names = _names(result)
        assert "bootstrap" in html_dep_names

    @pytest.mark.requirement("FR-103")
    def test_html_scanner_finds_cdn_deps_in_templates_dir(self):
        result = scan_html_templates("tests/fixtures/webapp_python_frontend")
        names = _names(result)
        assert "vue" in names
        assert "lodash" in names
        assert "bootstrap" in names


class TestRobustness:
    @pytest.mark.requirement("FR-103")
    def test_non_existent_path(self):
        result = scan_html_templates("/does/not/exist")
        assert result.dependencies == []

    @pytest.mark.requirement("FR-103")
    def test_empty_project(self, tmp_path):
        result = scan_html_templates(str(tmp_path))
        assert result.dependencies == []
        assert result.errors == []

    @pytest.mark.requirement("FR-103")
    def test_excluded_dirs_skipped(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "vendor.html").write_text(
            '<script src="https://cdn.jsdelivr.net/npm/evil@1/evil.js"></script>\n'
        )
        result = scan_html_templates(str(tmp_path))
        assert "evil" not in _names(result)

    @pytest.mark.requirement("FR-103")
    def test_binary_file_skipped(self, tmp_path):
        (tmp_path / "image.html").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        result = scan_html_templates(str(tmp_path))
        # Should not crash on binary content
        assert isinstance(result.dependencies, list)
