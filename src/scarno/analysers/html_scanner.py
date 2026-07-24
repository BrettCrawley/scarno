# Copyright 2026 Brett Crawley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""HTML / template scanner for JS + CSS dependency extraction.

Scans HTML files, server-side templates, and single-file components for
front-end dependencies that aren't declared in any package manifest:

  * ``<script src="...">`` — external JS (CDN or local)
  * ``<script type="module">`` with ``import`` statements inside
  * ``<script type="importmap">`` — ES module import maps
  * ``<link rel="stylesheet" href="...">`` — external CSS
  * ``<style>@import ...</style>`` — inline CSS imports
  * CDN URL patterns → extract package name + version

Supported file extensions (all share the same ``<script>``/``<link>``
HTML surface regardless of server-side templating language):

  ``.html``, ``.htm``, ``.jinja``, ``.jinja2``, ``.j2``,
  ``.jsp``, ``.jspx``, ``.tag``,
  ``.cshtml``, ``.vbhtml``,
  ``.ejs``, ``.hbs``, ``.handlebars``, ``.mustache``,
  ``.vue``, ``.svelte``, ``.astro``,
  ``.php``, ``.phtml``, ``.twig``,
  ``.erb``, ``.slim``, ``.haml``,
  ``.pug``, ``.jade``

Safety:
  * Regex-based — never executes or evaluates template content.
  * File-size cap (``MAX_FILE_BYTES``).
  * Excluded directories (node_modules, vendor, etc.).
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from scarno.findings.rules import RULES
from scarno.models import Finding
from scarno.security import MAX_FILE_BYTES, PathEscapeError, resolve_and_confine

_MAX_SNIPPET = 200

# ── File extensions to scan ───────────────────────────────────────────────

_TEMPLATE_EXTS: frozenset[str] = frozenset(
    {
        # Plain HTML
        ".html", ".htm", ".xhtml",
        # Python templates (Django, Jinja2, Flask, Mako)
        ".jinja", ".jinja2", ".j2",
        # Java templates (JSP, Thymeleaf — both use .html or .jsp)
        ".jsp", ".jspx", ".tag",
        # C# / ASP.NET (Razor — .cshtml already scanned by C# analyser
        # for @using, but we also scan for <script>/<link>)
        ".cshtml", ".vbhtml",
        # Node.js templates
        ".ejs", ".hbs", ".handlebars", ".mustache",
        # Single-file components (Vue, Svelte, Astro)
        ".vue", ".svelte", ".astro",
        # PHP
        ".php", ".phtml", ".twig",
        # Ruby
        ".erb", ".slim", ".haml",
        # Pug/Jade (indentation-based, but still emits <script>/<link>)
        ".pug", ".jade",
    }
)

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {"node_modules", ".git", "vendor", "bin", "obj", "dist", "build",
     ".next", ".nuxt", "coverage", "__pycache__"}
)

# ── Regex patterns ────────────────────────────────────────────────────────

# <script src="...">
_SCRIPT_SRC_RE = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*(?P<q>["'])(?P<url>[^"']+)(?P=q)""",
    re.IGNORECASE,
)

# <link rel="stylesheet" href="...">
_LINK_STYLESHEET_RE = re.compile(
    r"""<link\b[^>]*\brel\s*=\s*(?P<q1>["'])stylesheet(?P=q1)[^>]*\bhref\s*=\s*(?P<q2>["'])(?P<url>[^"']+)(?P=q2)""",
    re.IGNORECASE,
)
# Also match href before rel (attribute order varies)
_LINK_STYLESHEET_REV_RE = re.compile(
    r"""<link\b[^>]*\bhref\s*=\s*(?P<q1>["'])(?P<url>[^"']+)(?P=q1)[^>]*\brel\s*=\s*(?P<q2>["'])stylesheet(?P=q2)""",
    re.IGNORECASE,
)

# <style>...@import...</style> — extract content between tags
_STYLE_BLOCK_RE = re.compile(
    r"<style\b[^>]*>(.*?)</style>",
    re.IGNORECASE | re.DOTALL,
)

# @import inside a <style> block
_CSS_IMPORT_RE = re.compile(
    r"""@import\s+(?:url\(\s*)?(?P<q>["'])(?P<url>[^"']+)(?P=q)""",
)

# <script type="module">...import ... from '...';</script>
_SCRIPT_MODULE_BLOCK_RE = re.compile(
    r"""<script\b[^>]*\btype\s*=\s*(?P<q>["'])module(?P=q)[^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)

# ESM import inside a module block
_ESM_IMPORT_RE = re.compile(
    r"""(?:import\s+.*?\s+from\s+|import\s+)(?P<q>["'])(?P<spec>[^"']+)(?P=q)""",
)

# <script type="importmap">...{"imports": {...}}</script>
_IMPORTMAP_BLOCK_RE = re.compile(
    r"""<script\b[^>]*\btype\s*=\s*(?P<q>["'])importmap(?P=q)[^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)

# ── CDN URL → package name resolution ────────────────────────────────────

# Common CDN patterns:
#   https://cdn.jsdelivr.net/npm/<pkg>@<ver>/...
#   https://unpkg.com/<pkg>@<ver>/...
#   https://cdnjs.cloudflare.com/ajax/libs/<pkg>/<ver>/...
#   https://ajax.googleapis.com/ajax/libs/<pkg>/<ver>/...
_CDN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"cdn\.jsdelivr\.net/npm/(?P<pkg>@?[^@/]+(?:/[^@/]+)?)(?:@(?P<ver>[^/]+))?"),
    re.compile(r"unpkg\.com/(?P<pkg>@?[^@/]+(?:/[^@/]+)?)(?:@(?P<ver>[^/]+))?"),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/(?P<pkg>[^/]+)/(?P<ver>[^/]+)"),
    re.compile(r"ajax\.googleapis\.com/ajax/libs/(?P<pkg>[^/]+)/(?P<ver>[^/]+)"),
]


@dataclass
class HtmlDependency:
    """A dependency extracted from an HTML/template file."""
    name: str
    version: str | None
    source_file: str
    source_type: str  # "cdn_script", "cdn_stylesheet", "esm_import", "importmap", "css_import"
    url: str | None = None


@dataclass
class HtmlScanResult:
    """Aggregated results from scanning all HTML/template files."""
    dependencies: list[HtmlDependency] = field(default_factory=list)
    remote_urls: list[tuple[str, str, str]] = field(default_factory=list)  # (url, file, type)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── Public API ────────────────────────────────────────────────────────────


def scan_html_templates(project_path: str) -> HtmlScanResult:
    """Scan all HTML/template files for JS + CSS dependencies.

    Never raises. Returns structured results that callers (JS analyser,
    CSS analyser, polyglot orchestrator) merge into their dep lists.
    """
    result = HtmlScanResult()
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        result.errors.append(f"html_scanner: could not resolve path — {exc}")
        return result
    if not root.is_dir():
        return result

    for raw_path in _iter_template_files(root):
        rel_parts = raw_path.relative_to(root).parts
        if any(p in _EXCLUDED_DIR_NAMES for p in rel_parts):
            continue
        try:
            resolved = resolve_and_confine(raw_path, root)
        except PathEscapeError:
            result.errors.append(
                f"html_scanner: symlink escape blocked: {'/'.join(rel_parts)}"
            )
            continue
        try:
            size = resolved.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            result.errors.append(f"html_scanner: skipped {resolved.name} — too large")
            continue
        try:
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.errors.append(f"html_scanner: read failed {resolved.name} — {exc}")
            continue

        rel = str(resolved.relative_to(root))
        _scan_html(text, rel, result)

    return result


def _iter_template_files(root: Path) -> Iterator[Path]:
    """Yield all template files in the project tree."""
    for raw_path in root.rglob("*"):
        if raw_path.is_file() and raw_path.suffix.lower() in _TEMPLATE_EXTS:
            yield raw_path


def _scan_html(text: str, file_path: str, result: HtmlScanResult) -> None:
    """Extract dependencies from a single HTML/template file."""
    _extract_script_src(text, file_path, result)
    _extract_link_stylesheet(text, file_path, result)
    _extract_style_imports(text, file_path, result)
    _extract_module_imports(text, file_path, result)
    _extract_importmap(text, file_path, result)


# ── Extractors ────────────────────────────────────────────────────────────


def _emit_remote_finding(
    url: str, file_path: str, source_type: str, result: HtmlScanResult
) -> None:
    """Emit a TS-CE-012 finding for a remote script or stylesheet URL."""
    from scarno.security import sanitise

    rule = RULES["TS-CE-012"]
    tag = "<script src>" if source_type == "script" else f"<link {source_type}>"
    result.findings.append(
        Finding(
            rule_id="TS-CE-012",
            kind=rule.kind,
            severity=rule.severity,
            file_path=file_path,
            line=1,
            snippet=sanitise(f'{tag} → {url}')[:_MAX_SNIPPET],
            message=rule.message,
            remediation=rule.remediation,
        )
    )


def _extract_script_src(text: str, file_path: str, result: HtmlScanResult) -> None:
    for m in _SCRIPT_SRC_RE.finditer(text):
        url = m.group("url")
        if _is_remote(url):
            pkg = _resolve_cdn_url(url)
            if pkg:
                result.dependencies.append(HtmlDependency(
                    name=pkg[0], version=pkg[1],
                    source_file=file_path, source_type="cdn_script", url=url,
                ))
            result.remote_urls.append((url, file_path, "script"))
            _emit_remote_finding(url, file_path, "script", result)


def _extract_link_stylesheet(text: str, file_path: str, result: HtmlScanResult) -> None:
    for regex in (_LINK_STYLESHEET_RE, _LINK_STYLESHEET_REV_RE):
        for m in regex.finditer(text):
            url = m.group("url")
            if _is_remote(url):
                pkg = _resolve_cdn_url(url)
                if pkg:
                    result.dependencies.append(HtmlDependency(
                        name=pkg[0], version=pkg[1],
                        source_file=file_path, source_type="cdn_stylesheet", url=url,
                    ))
                result.remote_urls.append((url, file_path, "stylesheet"))
                _emit_remote_finding(url, file_path, "stylesheet", result)


def _extract_style_imports(text: str, file_path: str, result: HtmlScanResult) -> None:
    for block_match in _STYLE_BLOCK_RE.finditer(text):
        block = block_match.group(1)
        for m in _CSS_IMPORT_RE.finditer(block):
            url = m.group("url")
            if _is_remote(url):
                result.remote_urls.append((url, file_path, "css_import"))
                _emit_remote_finding(url, file_path, "css_import", result)
                pkg = _resolve_cdn_url(url)
                if pkg:
                    result.dependencies.append(HtmlDependency(
                        name=pkg[0], version=pkg[1],
                        source_file=file_path, source_type="css_import", url=url,
                    ))


def _extract_module_imports(text: str, file_path: str, result: HtmlScanResult) -> None:
    for block_match in _SCRIPT_MODULE_BLOCK_RE.finditer(text):
        block = block_match.group(2)  # group 1 is the quote
        for m in _ESM_IMPORT_RE.finditer(block):
            spec = m.group("spec")
            if _is_remote(spec):
                pkg = _resolve_cdn_url(spec)
                if pkg:
                    result.dependencies.append(HtmlDependency(
                        name=pkg[0], version=pkg[1],
                        source_file=file_path, source_type="esm_import", url=spec,
                    ))
                _emit_remote_finding(spec, file_path, "esm_import", result)
            elif not spec.startswith(("./", "../", "/")):
                # Bare specifier — npm package reference
                pkg_name = _extract_npm_package_name(spec)
                if pkg_name:
                    result.dependencies.append(HtmlDependency(
                        name=pkg_name, version=None,
                        source_file=file_path, source_type="esm_import",
                    ))


def _extract_importmap(text: str, file_path: str, result: HtmlScanResult) -> None:
    for block_match in _IMPORTMAP_BLOCK_RE.finditer(text):
        body = block_match.group(2)
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        imports = data.get("imports")
        if not isinstance(imports, dict):
            continue
        for key, target in imports.items():
            if not isinstance(key, str) or not isinstance(target, str):
                continue
            if _is_remote(target):
                pkg = _resolve_cdn_url(target)
                if pkg:
                    result.dependencies.append(HtmlDependency(
                        name=pkg[0], version=pkg[1],
                        source_file=file_path, source_type="importmap", url=target,
                    ))
            elif not target.startswith(("./", "../", "/")):
                result.dependencies.append(HtmlDependency(
                    name=key, version=None,
                    source_file=file_path, source_type="importmap",
                ))


# ── CDN resolution ────────────────────────────────────────────────────────


def _resolve_cdn_url(url: str) -> tuple[str, str | None] | None:
    """Try to extract (package_name, version) from a CDN URL."""
    for pattern in _CDN_PATTERNS:
        m = pattern.search(url)
        if m:
            pkg = m.group("pkg")
            ver = m.group("ver") if "ver" in m.groupdict() else None
            return (pkg, ver)
    return None


def _is_remote(url: str) -> bool:
    return url.startswith(("http://", "https://", "//"))


def _extract_npm_package_name(spec: str) -> str | None:
    """Extract npm package name from a bare ESM specifier."""
    if not spec:
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        if len(parts) >= 2:
            return "/".join(parts[:2])
        return spec
    return spec.split("/", 1)[0]
