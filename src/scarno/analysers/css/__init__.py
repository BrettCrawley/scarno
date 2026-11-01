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

"""CSS / SCSS / SASS / LESS analyser — REQ-12.

Extracts npm-backed CSS dependencies referenced via ``@import``,
``@use``, and ``url()`` from stylesheet files. Emits findings for
remote-URL ``@import`` and ``file://`` ``url()`` patterns.

**Scope**: this is NOT a dead-selector analyser. Scarno's remit is
"find unused packages"; CSS support narrows that to stylesheet deps
that come through npm (`~package/...` / bare-specifier `@import`).

``.gitignore`` (FR-278 / SEC-NEW-75): the ``TS-CE-007`` / ``TS-CE-008``
rules read every stylesheet :func:`scarno.core.discovery.discover`
returns, gitignored ones and ``dist`` / ``build`` included. Dependency
extraction reads tracked stylesheets, and gitignored ones according to
``self.gitignore``.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from scarno.core import registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.core.discovery import (
    GITIGNORED_ONLY_REASON,
    GitignoreMode,
    discover,
    gitignored_findings_line,
    load_gitignore_matcher,
    unignored_environments_line,
)
from scarno.findings.rules import RULES
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
)
from scarno.security import sanitise

_MAX_SNIPPET = 200

# Match both quoted and url() forms. Comments are stripped first so
# `// @import "x"` and `/* @import */` can't trigger.
_IMPORT_QUOTED_RE = re.compile(
    r"""@(?:import|use)\s+
        (?P<quote>["'])(?P<target>[^"']+)(?P=quote)""",
    re.VERBOSE,
)
_IMPORT_URL_RE = re.compile(
    r"""@import\s+
        url\(\s*
        (?P<quote>["']?)(?P<target>[^)"']+)(?P=quote)
        \s*\)""",
    re.VERBOSE,
)
_URL_REF_RE = re.compile(
    r"""url\(\s*
        (?P<quote>["']?)(?P<target>[^)"']+)(?P=quote)
        \s*\)""",
    re.VERBOSE,
)

_CSS_EXTS: tuple[str, ...] = ("*.css", "*.scss", "*.sass", "*.less", "*.styl")
_CSS_SUFFIXES: tuple[str, ...] = tuple(ext[1:] for ext in _CSS_EXTS)
# Excluded from dependency extraction only; the rules still read them.
_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {"node_modules", ".git", "dist", "build"}
)


class CssAnalyser(BaseAnalyser):
    """CSS-only fallback analyser.

    Registered under the ``"css"`` language key. The orchestrator only
    routes here when no JS indicators are present — CSS inside a
    JS project is subsumed by the JS analyser.
    """

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        for ext in _CSS_EXTS:
            for _ in root.rglob(ext):
                return True
        return False

    def analyse(self, project_path: str) -> AnalysisResult:
        root = Path(project_path).resolve(strict=False)
        errors: list[str] = []
        findings: list[Finding] = []
        deps: dict[str, Dependency] = {}
        # FR-278 — under GitignoreMode.UNCERTAIN, deps seen only in
        # gitignored stylesheets. Resolved after the walk, so a tracked
        # stylesheet anywhere in the tree wins.
        ignored_deps: dict[str, Dependency] = {}

        found = discover(
            root,
            _CSS_SUFFIXES,
            errors,
            label="css",
            classification_excluded_dirs=_EXCLUDED_DIR_NAMES,
            operator_excludes=self.operator_excludes,
            gitignore_matcher=load_gitignore_matcher(errors, "css"),
        )
        ignored = set(found.ignored)
        rule_only = set(found.rule_only)
        ignored_findings = 0

        for resolved in found.for_rules():
            try:
                text = resolved.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                errors.append(f"css: could not read {resolved.name} — {exc}")
                continue
            rel = resolved.relative_to(root).as_posix()
            file_deps: dict[str, Dependency] = {}
            file_findings: list[Finding] = []
            _scan_css(text, rel, file_deps, file_findings)
            findings.extend(file_findings)

            if resolved in rule_only:
                continue
            target = deps
            if resolved in ignored:
                ignored_findings += len(file_findings)
                if self.gitignore is GitignoreMode.EXCLUDE:
                    continue
                if self.gitignore is GitignoreMode.UNCERTAIN:
                    target = ignored_deps
            for name, dep in file_deps.items():
                target.setdefault(name, dep)

        for name, dep in ignored_deps.items():
            if name not in deps:
                dep.status = DependencyStatus.UNCERTAIN
                dep.reason = GITIGNORED_ONLY_REASON
                deps[name] = dep

        # PRV-008 — fixed literal plus a count. The CLI folds these into
        # one of each per run (core.discovery.consolidate_audit_lines).
        if ignored_findings:
            errors.append(gitignored_findings_line(ignored_findings))
        if found.environment_dirs_unignored:
            errors.append(
                unignored_environments_line(found.environment_dirs_unignored)
            )

        # HTML/template scanning is handled by the CLI orchestrator as a
        # cross-cutting pass (runs once for the whole project, not per
        # analyser) to avoid double-scanning in polyglot mode.

        return AnalysisResult(
            project_type="css",
            project_path=str(root),
            dependencies=list(deps.values()),
            errors=errors,
            findings=findings,
            languages=["css"],
        )


def _scan_css(
    text: str,
    file_path: str,
    deps: dict[str, Dependency],
    findings: list[Finding],
) -> None:
    stripped = _strip_css_comments(text)

    # Track (lineno, target) tuples already emitted via an ``@import`` so
    # the generic ``url()`` pass below doesn't re-fire TS-CE-007 /
    # TS-CE-008 on the same URL (``@import url("https://…")`` matches
    # both _IMPORT_URL_RE and _URL_REF_RE).
    seen_import_urls: set[tuple[int, str]] = set()

    for lineno, line in _iter_lines(stripped):
        for match in _IMPORT_QUOTED_RE.finditer(line):
            target = match.group("target")
            if _is_remote(target) or target.startswith("file:"):
                seen_import_urls.add((lineno, target))
            _process_target(target, file_path, lineno, deps, findings)
        for match in _IMPORT_URL_RE.finditer(line):
            target = match.group("target")
            if _is_remote(target) or target.startswith("file:"):
                seen_import_urls.add((lineno, target))
            _process_target(target, file_path, lineno, deps, findings)
        for match in _URL_REF_RE.finditer(line):
            # url() outside @import — only flag security findings.
            target = match.group("target")
            if (lineno, target) in seen_import_urls:
                continue
            _emit_url_findings(target, file_path, lineno, findings)


def _iter_lines(text: str) -> Iterator[tuple[int, str]]:
    for idx, line in enumerate(text.splitlines(), start=1):
        yield idx, line


def _strip_css_comments(text: str) -> str:
    """Strip ``/* … */`` block comments and ``//`` line comments (SCSS/LESS)."""
    # Block comments
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    # Line comments (SCSS / LESS only; plain CSS doesn't have them, but
    # stripping is harmless)
    text = re.sub(r"^\s*//[^\n]*$", "", text, flags=re.MULTILINE)
    return text


def _process_target(
    target: str,
    file_path: str,
    lineno: int,
    deps: dict[str, Dependency],
    findings: list[Finding],
) -> None:
    # Remote or file:// url — only the security findings matter.
    if _is_remote(target):
        _emit_remote_import_finding(target, file_path, lineno, findings)
        return
    if target.startswith("file:"):
        _emit_file_url_finding(target, file_path, lineno, findings)
        return

    # Local relative / absolute path — skip.
    if target.startswith(("./", "../", "/")):
        return

    package = _extract_css_package_name(target)
    if package is None:
        return
    if package not in deps:
        deps[package] = Dependency(
            name=package,
            version=None,
            status=DependencyStatus.IN_USE,
            reason=f"imported from CSS as '{target}' in {file_path}",
            entry_points=[],
            entry_points_used=0,
            entry_points_total=0,
            source=f"{file_path}:@import",
            ecosystem="npm",  # CSS deps live in npm
        )


def _extract_css_package_name(target: str) -> str | None:
    """Normalise a CSS @import target into an npm package name."""
    if not target:
        return None
    # Strip Webpack tilde prefix (`~normalize.css`)
    if target.startswith("~"):
        target = target[1:]
    # Local file (checked earlier) — belt and braces
    if target.startswith(("./", "../", "/")):
        return None
    if "://" in target:
        return None
    # Scoped: @scope/pkg/path → @scope/pkg
    if target.startswith("@"):
        parts = target.split("/")
        if len(parts) >= 2:
            return "/".join(parts[:2])
        return target
    # Unscoped: pkg/path → pkg; pkg → pkg
    return target.split("/", 1)[0]


def _is_remote(target: str) -> bool:
    return target.startswith(("http://", "https://"))


def _emit_remote_import_finding(
    target: str, file_path: str, lineno: int, findings: list[Finding]
) -> None:
    rule = RULES["TS-CE-007"]
    findings.append(
        Finding(
            rule_id="TS-CE-007",
            kind=rule.kind,
            severity=rule.severity,
            file_path=file_path,
            line=lineno,
            snippet=sanitise(f'@import "{target}"')[:_MAX_SNIPPET],
            message=rule.message,
            remediation=rule.remediation,
        )
    )


def _emit_file_url_finding(
    target: str, file_path: str, lineno: int, findings: list[Finding]
) -> None:
    rule = RULES["TS-CE-008"]
    findings.append(
        Finding(
            rule_id="TS-CE-008",
            kind=rule.kind,
            severity=rule.severity,
            file_path=file_path,
            line=lineno,
            snippet=sanitise(f'url("{target}")')[:_MAX_SNIPPET],
            message=rule.message,
            remediation=rule.remediation,
        )
    )


def _emit_url_findings(
    target: str, file_path: str, lineno: int, findings: list[Finding]
) -> None:
    if _is_remote(target):
        _emit_remote_import_finding(target, file_path, lineno, findings)
    elif target.startswith("file:"):
        _emit_file_url_finding(target, file_path, lineno, findings)


registry.register("css", CssAnalyser)

# REQ-19a / NEW-ARCH-012 — CSS @import has no pinning mechanism.
from scarno.core import classifier as _classifier  # noqa: E402
_classifier.register_no_pin_mechanism("css")
