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

"""Scarno CLI entry point.

Single-command Typer app. ``scarno <path> [OPTIONS]`` runs the
analysis pipeline and writes a text or JSON report to stdout (or a file
via ``--output``).

Exit codes:
  * ``0`` — analysis complete, no ``SAFE`` dependencies found
  * ``1`` — analysis complete, at least one ``SAFE`` dependency found
  * ``2`` — analysis failed (unreadable path, unsupported project type,
    unhandled exception)

``--verbose`` toggles debug lines to stderr. When ``--format=json`` the
CLI keeps stderr quiet beyond the privilege warning and fatal error,
so piped JSON remains parseable regardless of verbosity.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import typer

# Importing the analyser packages triggers their self-registration with
# :mod:`scarno.core.registry` — do NOT prune these "unused" imports.
from scarno.analysers.csharp import CsharpAnalyser  # noqa: F401
from scarno.analysers.css import CssAnalyser  # noqa: F401
from scarno.analysers.go import GoAnalyser  # noqa: F401
from scarno.analysers.java import JavaAnalyser  # noqa: F401
from scarno.analysers.javascript import JavascriptAnalyser  # noqa: F401
from scarno.analysers.python import PythonAnalyser  # noqa: F401
from scarno.core import detector, registry
from scarno.core.base_analyser import BaseAnalyser
from scarno.core.test_scope import sanitise_test_paths
from scarno.models import (
    CANONICAL_ECOSYSTEMS,
    ECOSYSTEM_TO_LANGUAGE,
    AnalysisResult,
    Dependency,
    DependencyStatus,
    DepEdge,
    Finding,
    FindingSeverity,
    VersionedNode,
)
from scarno.reporters.json_reporter import JsonReporter
from scarno.reporters.markdown_reporter import MarkdownReporter
from scarno.reporters.sarif_reporter import SarifReporter
from scarno.reporters.text_reporter import TextReporter
from scarno.security import (
    PathEscapeError,
    check_root_privilege,
    resolve_and_confine,
    sanitise,
)

_SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}

app = typer.Typer(
    name="scarno",
    help="Smart dependency pruner for Java & Python projects.",
    add_completion=False,
    no_args_is_help=False,
    pretty_exceptions_enable=False,
)


class _CliError(Exception):
    """Sanitised user-facing error — message is rendered on stderr and the
    process exits with code 2. Never exposes a traceback in non-verbose
    mode (I-01)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class _RunOptions:
    project_path: Path
    output_path: Path | None
    format: str
    verbose: bool
    fail_on_severity: FindingSeverity | None
    show_suppressed: bool
    # REQ-9 — user-requested ecosystem filter; empty = accept every detected
    # language.  Values are canonical ecosystem strings (``"pypi"`` / ``"npm"``
    # / etc.), validated against ``CANONICAL_ECOSYSTEMS`` at parse time.
    language_filter: tuple[str, ...] = ()
    # REQ-3 — when False, skip .gitignore filtering during source discovery.
    use_gitignore: bool = True
    # REQ-17 — drop test-scoped deps and skip test source files.
    exclude_tests: bool = False
    # REQ-17 — operator-supplied test-path globs (already sanitised).
    test_paths: tuple[str, ...] = ()
    # REQ-17 — npm-only opt-in to drop devDependencies.
    exclude_dev: bool = False
    # REQ-22 — gate the JVM source analyser's cross-version ABI diff.
    # SEC-NEW-56 — set ONLY from the --deep-inspection argv flag. No
    # env-var fallback, no config file, no preset substitution.
    deep_inspection: bool = False
    # REQ-24 / SEC-NEW-72 — capability gate for outbound HTTPS fetches
    # of cache-miss artefacts. Set ONLY from the --allow-remote-fetch
    # argv flag — no env, no config, no test-helper backdoor.
    # Requires deep_inspection (validated at parse time).
    allow_remote_fetch: bool = False
    # REQ-24 / FR-261 — opt-in cross-index byte comparison; argv-only.
    integrity_cross_check: bool = False
    # REQ-24 / FR-267 — escalate provenance="remote" findings into
    # --fail-on-severity (off by default — remote findings are
    # advisory unless the operator opts in). Argv-only.
    fail_on_remote_severity: bool = False
    # REQ-24 / FR-256 — repeatable --index ECOSYSTEM=URL strings,
    # parsed by IndexConfigResolver. Empty = no CLI-supplied indexes.
    cli_indexes: tuple[str, ...] = ()
    # REQ-24 — repeatable --allow-private-index-host HOST argv values.
    # Argv-only (same SEC-NEW-72 pattern). See BaseAnalyser docstring.
    private_index_hosts: tuple[str, ...] = ()
    # REQ-24 — argv-only --native-tls (truststore-backed SSL context).
    native_tls: bool = False


def _echo_err(message: str) -> None:
    """Write to the real stderr so CliRunner captures it when
    ``mix_stderr=True`` (the default) and separates it otherwise."""
    print(message, file=sys.stderr)


def _filter_project_types_by_ecosystem(
    project_types: list[str], ecosystems: tuple[str, ...]
) -> list[str]:
    """REQ-9 — keep only those detected language keys whose ecosystems
    overlap with the user's ``--language`` request."""
    if not ecosystems:
        return project_types
    wanted_langs = {ECOSYSTEM_TO_LANGUAGE[eco] for eco in ecosystems}
    return [pt for pt in project_types if pt in wanted_langs]


def _filter_deps_by_ecosystem(
    deps: list[Dependency], ecosystems: tuple[str, ...]
) -> list[Dependency]:
    if not ecosystems:
        return deps
    allowed = set(ecosystems)
    return [d for d in deps if d.ecosystem in allowed]


def _propagate_in_use_through_graph(
    result: AnalysisResult,
) -> AnalysisResult:
    """Lift SAFE deps to IN_USE when reachable from any IN_USE dep
    via ``dep_graph``.

    Rationale (FR-150): a direct dep declared in the manifest may
    appear as a graph-child of an IN_USE direct dep (the IN_USE parent
    requires it transitively per its own POM / lockfile). We cannot
    prove the parent doesn't need the child at runtime without
    inspecting the parent's bytecode, so we conservatively classify
    the child IN_USE.

    Manifest hygiene: when the lifted dep is itself a direct manifest
    declaration (``is_transitive=False``), the explicit declaration is
    redundant — removing it from pom.xml / pyproject leaves the
    artifact on the classpath via the IN_USE parent. Such deps are
    flagged ``manifest_redundant=True`` and ``redundant_parent`` is
    set to the IN_USE root that keeps them alive, so reporters can
    surface a "remove this manifest line" recommendation alongside
    the IN_USE marker.

    Idempotent for deps already IN_USE / UNCERTAIN / UNDECLARED.
    Single forward sweep with a worklist; visited set bounds total
    work to ``O(|deps| + |edges|)``.
    """
    if not result.dep_graph or not result.dependencies:
        return result
    by_name = {d.name: d for d in result.dependencies}
    in_use_names = {
        d.name for d in result.dependencies
        if d.status is DependencyStatus.IN_USE
    }
    if not in_use_names:
        return result
    lifted_by: dict[str, str] = {}
    visited: set[str] = set()
    worklist: list[tuple[str, str]] = [
        (name, name) for name in in_use_names
    ]
    while worklist:
        current, root = worklist.pop()
        if current in visited:
            continue
        visited.add(current)
        for child in result.dep_graph.get(current, set()):
            if child in visited:
                continue
            lifted_by.setdefault(child, root)
            worklist.append((child, root))

    if not lifted_by:
        return result
    new_deps: list[Dependency] = []
    changed = False
    for dep in result.dependencies:
        if (
            dep.status is DependencyStatus.SAFE
            and dep.name in lifted_by
        ):
            root = lifted_by[dep.name]
            # Manifest-redundancy applies only to deps the user
            # declared themselves (is_transitive=False). For pure
            # lockfile transitives there is no manifest line to remove.
            # FR-251 / NEW-ARCH-007 — a pin-override dep is load-bearing
            # and can never be manifest-redundant (the two flags are
            # mutually exclusive, enforced in Dependency.__post_init__);
            # exclude it so preserving pin_override upstream can't trip
            # the mutex on a direct pinned dep.
            redundant = not dep.is_transitive and not dep.pin_override
            reason = f"transitively required by: {root}"
            if redundant:
                reason += " (direct manifest declaration is redundant)"
            # ``replace`` keeps every other field (pin_override*,
            # is_transitive, ecosystem, …) so the lift is non-destructive.
            new_deps.append(
                replace(
                    dep,
                    status=DependencyStatus.IN_USE,
                    reason=reason,
                    entry_points=list(dep.entry_points),
                    manifest_redundant=redundant,
                    redundant_parent=root if redundant else None,
                )
            )
            changed = True
        else:
            new_deps.append(dep)
    if not changed:
        return result
    # ``replace`` preserves dep_edges / versioned_nodes /
    # multi_version_coords — only the dependency list changes here.
    return replace(result, dependencies=new_deps)


def _merge_results(
    project_path: Path, project_types: list[str], results: list[AnalysisResult]
) -> AnalysisResult:
    deps: list[Dependency] = []
    errors: list[str] = []
    findings: list[Finding] = []
    dep_graph: dict[str, set[str]] = {}
    # REQ-19 / REQ-20 — carry the version-keyed graph and the per-version
    # classifier output through the merge. Each analyser that has migrated
    # to REQ-19 populates these; analysers that haven't contribute empty
    # lists, so a polyglot run still merges cleanly.
    dep_edges: list[DepEdge] = []
    versioned_nodes: list[VersionedNode] = []
    multi_version_coords: list[str] = []
    for r in results:
        deps.extend(r.dependencies)
        errors.extend(r.errors)
        findings.extend(r.findings)
        for parent, children in r.dep_graph.items():
            dep_graph.setdefault(parent, set()).update(children)
        dep_edges.extend(r.dep_edges)
        versioned_nodes.extend(r.versioned_nodes)
        multi_version_coords.extend(r.multi_version_coords)
    return AnalysisResult(
        project_type=project_types[0] if project_types else "unknown",
        project_path=str(project_path),
        dependencies=deps,
        errors=errors,
        findings=findings,
        languages=list(project_types),
        dep_graph=dep_graph,
        dep_edges=dep_edges,
        versioned_nodes=versioned_nodes,
        multi_version_coords=multi_version_coords,
    )


def _render(result: AnalysisResult, fmt: str) -> str:
    if fmt == "json":
        return JsonReporter().render(result)
    if fmt == "text":
        return TextReporter().render(result)
    if fmt in ("markdown", "md"):
        return MarkdownReporter().render(result)
    if fmt == "sarif":
        return SarifReporter().render(result)
    raise _CliError(
        f"Unknown --format value: {fmt!r} "
        f"(expected one of: text, json, markdown, sarif)"
    )


# ── Project-name derivation for the auto-named markdown report ──────────────


_PROJECT_NAME_FILENAME_RE = re.compile(r"[^\w.-]+")
"""Characters that are NOT safe in a derived report filename. The
allow-list is alnum + underscore + dot + hyphen; everything else (incl.
whitespace, slashes, colons) collapses to a single hyphen so the
resulting name is path-safe across every supported OS."""


def _sanitise_project_name_for_filename(name: str) -> str:
    """Return a filename-safe slug of ``name``.

    Spaces and any other unsafe character become ``-``. Leading and
    trailing hyphens / dots are stripped (an empty result returns
    empty so the caller falls back to the no-name path)."""
    collapsed = _PROJECT_NAME_FILENAME_RE.sub("-", name.strip())
    # Collapse runs of hyphens introduced by adjacent unsafe chars.
    while "--" in collapsed:
        collapsed = collapsed.replace("--", "-")
    return collapsed.strip("-.")


def _derive_project_name(project_path: Path) -> str | None:
    """Best-effort project-name lookup across the supported ecosystems.

    Priority order (first match wins):
      1. ``pyproject.toml`` ``[project].name`` (PEP 621)
      2. ``package.json`` ``.name`` (npm)
      3. ``pom.xml`` ``<artifactId>`` (with ``<name>`` as override if
         present, since Maven's ``<name>`` is the human-readable form)
      4. ``go.mod`` ``module`` directive (last path segment)
      5. ``settings.gradle(.kts)`` ``rootProject.name = "..."``
      6. ``*.csproj`` filename stem (without extension)

    Returns ``None`` when no manifest yields a non-empty name. All
    file reads are bounded by :mod:`scarno.security` size caps via
    ``Path.read_text`` with explicit length limits — a manifest larger
    than 1 MiB is treated as missing rather than read.
    """
    if not project_path.is_dir():
        return None

    # 1. pyproject.toml
    name = _read_pyproject_name(project_path / "pyproject.toml")
    if name:
        return name

    # 2. package.json
    name = _read_package_json_name(project_path / "package.json")
    if name:
        return name

    # 3. pom.xml
    name = _read_pom_xml_name(project_path / "pom.xml")
    if name:
        return name

    # 4. go.mod
    name = _read_go_mod_name(project_path / "go.mod")
    if name:
        return name

    # 5. Gradle settings
    for candidate in ("settings.gradle.kts", "settings.gradle"):
        name = _read_gradle_settings_name(project_path / candidate)
        if name:
            return name

    # 6. *.csproj — pick the lexicographically first to be deterministic.
    csproj = sorted(project_path.glob("*.csproj"))
    if csproj:
        stem = csproj[0].stem.strip()
        if stem:
            return stem

    return None


_MANIFEST_MAX_BYTES: int = 1 * 1024 * 1024  # 1 MiB — manifests are tiny


def _safe_read_text(path: Path) -> str | None:
    """Read ``path`` only when it is a regular file ≤ 1 MiB. Returns
    ``None`` on any error / over-size / non-file."""
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MANIFEST_MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _read_pyproject_name(path: Path) -> str | None:
    text = _safe_read_text(path)
    if text is None:
        return None
    try:
        import tomllib
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None
    project = data.get("project")
    if isinstance(project, dict):
        raw = project.get("name")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def _read_package_json_name(path: Path) -> str | None:
    text = _safe_read_text(path)
    if text is None:
        return None
    try:
        import json
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict):
        raw = data.get("name")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def _read_pom_xml_name(path: Path) -> str | None:
    text = _safe_read_text(path)
    if text is None:
        return None
    # Local import — defusedxml is preferred for adversarial XML but the
    # pom-name extraction here is a best-effort filename helper, NOT the
    # security-critical pom walker (which lives in
    # scarno.analysers.java.maven and already has hardening).
    import re as _re
    # Prefer the human-readable <name>; fall back to <artifactId>.
    # Strip Maven namespaces so we don't have to commit to a parser.
    name_match = _re.search(r"<name>\s*([^<]+?)\s*</name>", text)
    if name_match and name_match.group(1).strip():
        return name_match.group(1).strip()
    art_match = _re.search(
        r"<artifactId>\s*([^<]+?)\s*</artifactId>", text,
    )
    if art_match and art_match.group(1).strip():
        return art_match.group(1).strip()
    return None


def _read_go_mod_name(path: Path) -> str | None:
    text = _safe_read_text(path)
    if text is None:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("module "):
            module_path = stripped[len("module "):].strip().strip('"')
            if module_path:
                # Use the last segment as the project name —
                # "github.com/user/myproj" → "myproj".
                return module_path.rsplit("/", 1)[-1] or module_path
    return None


def _read_gradle_settings_name(path: Path) -> str | None:
    text = _safe_read_text(path)
    if text is None:
        return None
    import re as _re
    # Match: rootProject.name = "foo"  /  rootProject.name = 'foo'
    # Kotlin DSL uses '='; Groovy may use '=' or no '=' (legacy).
    match = _re.search(
        r"""rootProject\.name\s*=\s*['"]([^'"]+)['"]""",
        text,
    )
    if match and match.group(1).strip():
        return match.group(1).strip()
    return None


def _derive_default_output_path(project_path: Path) -> Path:
    """Return ``<cwd>/<project-name>-analysis-report.md`` or
    ``<cwd>/analysis-report.md`` when no project name is derivable.

    Always anchored at :func:`Path.cwd` (matches the convention of
    pytest / coverage / flake8). Never writes inside the analysed
    project directory — that would risk accidental commits of the
    report file itself.
    """
    name = _derive_project_name(project_path)
    if name:
        slug = _sanitise_project_name_for_filename(name)
        if slug:
            return Path.cwd() / f"{slug}-analysis-report.md"
    return Path.cwd() / "analysis-report.md"


def _validate_output_target(
    output: Path, project_path: Path, format_: str
) -> Path:
    """Resolve and confine ``--output``.

    Enforces output confinement to the current working directory **when
    the user is inside their project** (``cwd.resolve() == project_path.resolve()``).
    Outside that case the user is doing something more deliberate — they
    supplied an explicit path to analyse and an explicit path to write —
    so we accept arbitrary destinations. This mirrors the convention
    that project-local guardrails apply when the command is invoked
    from within the project tree.
    """
    cwd = Path.cwd().resolve()
    project = project_path.resolve()
    try:
        resolved_output = output.expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise _CliError(f"--output path could not be resolved: {exc}") from exc

    if cwd == project:
        try:
            resolved_output.relative_to(cwd)
        except ValueError as exc:
            raise _CliError(
                f"--output {resolved_output} is outside the current working "
                f"directory {cwd}. Refusing to write to an external location "
                f"by default."
            ) from exc
    return resolved_output


def _exit_code_for(
    result: AnalysisResult,
    fail_on_severity: FindingSeverity | None,
    *,
    fail_on_remote_severity: bool = False,
) -> int:
    # Exit 3 — findings at or above the requested severity.
    threshold = fail_on_severity or FindingSeverity.HIGH
    threshold_rank = _SEVERITY_ORDER[threshold]
    # REQ-24 / FR-267 — provenance="remote" findings are visible but
    # advisory by default; they do NOT escalate exit code 3 unless the
    # operator explicitly opts in with --fail-on-remote-severity. When
    # the attacker controls the fetched bytes (T-40 / T-41) any
    # ABI verdict derived from them is potentially fabricated;
    # gate-by-default would let an attacker manipulate CI passes.
    def _gates_exit_three(f: "Finding") -> bool:
        if f.suppressed:
            return False
        if _SEVERITY_ORDER[f.severity] < threshold_rank:
            return False
        if f.provenance == "remote" and not fail_on_remote_severity:
            return False
        return True
    if any(_gates_exit_three(f) for f in result.findings):
        return 3
    # Exit 1 — SAFE deps present, or MEDIUM findings when threshold is MEDIUM.
    if any(d.status is DependencyStatus.SAFE for d in result.dependencies):
        return 1
    return 0


def _apply_show_suppressed(
    result: AnalysisResult, show_suppressed: bool
) -> AnalysisResult:
    if show_suppressed:
        return result
    # Default: hide suppressed findings from the rendered report.
    # ``replace`` keeps every other field — including dep_edges /
    # versioned_nodes / multi_version_coords — intact.
    visible = [f for f in result.findings if not f.suppressed]
    return replace(result, findings=visible)


def _run(opts: _RunOptions) -> int:
    check_root_privilege()

    # PATH confinement: we always resolve the analysed directory
    # relative to the current working directory and reject paths that
    # can't be made absolute or don't exist (SEC-002).
    try:
        project_path = resolve_and_confine(opts.project_path, Path.cwd())
    except PathEscapeError:
        # Absolute paths that resolve outside CWD are fine to analyse —
        # the confinement-to-CWD rule only applies to relative paths
        # (which Path.cwd() anchors). For an absolute path, fall back to
        # a plain resolve.
        project_path = opts.project_path.expanduser().resolve()

    if not project_path.exists():
        raise _CliError(f"Path does not exist: {project_path}")
    if not project_path.is_dir():
        raise _CliError(f"Path is not a directory: {project_path}")

    project_types = detector.detect_project_types(project_path)
    if not project_types:
        raise _CliError(
            f"No supported project type detected in {project_path}. "
            "Expected one of: pom.xml, build.gradle(.kts), pyproject.toml, "
            "requirements.txt, setup.py, setup.cfg, Pipfile(.lock), "
            "poetry.lock, uv.lock, environment.yml, package.json, go.mod, "
            "*.csproj."
        )

    # REQ-9 — apply the --language ecosystem filter.
    if opts.language_filter:
        filtered = _filter_project_types_by_ecosystem(
            project_types, opts.language_filter
        )
        if not filtered:
            raise _CliError(
                f"--language filter {list(opts.language_filter)} does not "
                f"overlap with detected project types {project_types}"
            )
        project_types = filtered

    # Drop language keys that have no registered analyser (Phase 5 / 6 / 7
    # languages are detected but not yet analysed) — they appear in the
    # ``languages`` list so the reporter surfaces that we saw them, but
    # no analyser runs for them.
    runnable_types = [
        pt for pt in project_types if registry.get_analyser(pt) is not None
    ]
    unrunnable_types = [
        pt for pt in project_types if pt not in runnable_types
    ]

    if opts.verbose and opts.format == "text":
        _echo_err(f"[verbose] project_path={project_path}")
        _echo_err(f"[verbose] detected_types={project_types}")
        _echo_err(f"[verbose] runnable_types={runnable_types}")
        if opts.exclude_tests:
            _echo_err(
                f"[verbose] exclude_tests=True; "
                f"test_paths={list(opts.test_paths)}"
            )
        if opts.exclude_dev:
            _echo_err("[verbose] exclude_dev=True")

    analysers = registry.analysers_for(runnable_types)
    for a in analysers:
        a.use_gitignore = opts.use_gitignore
        a.exclude_tests = opts.exclude_tests
        a.test_paths = opts.test_paths
        a.exclude_dev = opts.exclude_dev
        # REQ-22 — forward the --deep-inspection flag. SEC-NEW-56: this
        # is the ONLY path that sets it; no env / config fallback.
        a.deep_inspection = opts.deep_inspection
        # REQ-24 — forward the REQ-24 capability flags + raw --index
        # strings. SEC-NEW-72: argv-only setters, same SEC-NEW-56 pattern.
        a.allow_remote_fetch = opts.allow_remote_fetch
        a.integrity_cross_check = opts.integrity_cross_check
        a.cli_indexes = opts.cli_indexes
        a.private_index_hosts = opts.private_index_hosts
        a.native_tls = opts.native_tls
    sub_results = [a.analyse(str(project_path)) for a in analysers]

    merged = _merge_results(project_path, project_types, sub_results)

    # HTML/template scanner — discover front-end deps from <script src>,
    # <link stylesheet>, inline <style>@import, ESM imports, importmaps.
    # This runs as a cross-cutting pass regardless of detected languages
    # so CDN-only projects (no package.json) still surface dependencies.
    from scarno.analysers.html_scanner import scan_html_templates
    html = scan_html_templates(str(project_path))
    merged.errors.extend(html.errors)
    merged.findings.extend(html.findings)
    declared_names = {d.name for d in merged.dependencies}
    for html_dep in html.dependencies:
        if html_dep.name not in declared_names:
            declared_names.add(html_dep.name)
            merged.dependencies.append(
                Dependency(
                    name=html_dep.name,
                    version=html_dep.version,
                    status=DependencyStatus.IN_USE,
                    reason=(
                        f"loaded via {html_dep.source_type} in "
                        f"{html_dep.source_file}"
                    ),
                    entry_points=[],
                    entry_points_used=0,
                    entry_points_total=0,
                    source=f"{html_dep.source_file}:{html_dep.source_type}",
                    ecosystem="npm",
                )
            )

    if unrunnable_types:
        for lang in unrunnable_types:
            merged.errors.append(
                f"{lang} detected but no analyser is registered — skipped "
                f"(phase not yet implemented)"
            )

    # REQ-17 — warn when --exclude-dev was passed but no npm project ran.
    if opts.exclude_dev and "javascript" not in runnable_types:
        merged.errors.append(
            "--exclude-dev has no effect outside npm projects "
            "(no package.json detected)"
        )

    # Apply --language post-filter to the dep list too, so polyglot
    # runs can still emit a scoped report.
    if opts.language_filter:
        merged = replace(
            merged,
            dependencies=_filter_deps_by_ecosystem(
                merged.dependencies, opts.language_filter
            ),
        )

    # FR-150 — propagate IN_USE through ``dep_graph``: any SAFE dep
    # that is reachable as a transitive of an IN_USE dep is lifted to
    # IN_USE, because the IN_USE parent may need it at runtime and we
    # cannot prove otherwise without reading the parent's bytecode.
    # When the lifted dep was a direct manifest declaration
    # (``is_transitive=False``), it is additionally flagged
    # ``manifest_redundant=True`` so the report can recommend
    # removing the redundant pom.xml / pyproject line.
    merged = _propagate_in_use_through_graph(merged)

    # Honour --show-suppressed before rendering.
    visible_result = _apply_show_suppressed(merged, opts.show_suppressed)
    result = merged

    rendered = _render(visible_result, opts.format)

    # Resolve the effective output target. When --output is omitted AND
    # --format is markdown (the new default), auto-derive a path of the
    # form ``<project-name>-analysis-report.md`` in CWD. For non-markdown
    # formats the omit-output behaviour is unchanged (stdout) — silently
    # auto-writing a JSON / SARIF / text file would surprise scripts
    # that pipe stdout into other tools.
    effective_output: Path | None = opts.output_path
    if effective_output is None and opts.format in ("markdown", "md"):
        effective_output = _derive_default_output_path(project_path)

    if effective_output is not None:
        target = _validate_output_target(
            effective_output, project_path, opts.format
        )
        target.write_text(rendered, encoding="utf-8")
        # Tell the operator where the report landed — important now
        # that markdown-to-file is the default. Goes to stderr so it
        # never contaminates a piped non-default format.
        _echo_err(f"Report written to {target}")
    else:
        # stdout only — no trailing newline from print() because
        # reporters already return a terminating newline.
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")

    return _exit_code_for(
        result,
        opts.fail_on_severity,
        fail_on_remote_severity=opts.fail_on_remote_severity,
    )


# ── REQ-19a / NEW-ARCH-009 — back-compat regression-test helpers ────────────
#
# Exported for ``tests/integration/test_back_compat.py`` so the strict-
# inclusion fixtures can drive the analysis pipeline directly without
# going through the Typer entry point. Production callers still use
# the Typer ``main`` command below; these helpers are test-only sugar.


def _run_options_default(project_path: Path | None = None) -> _RunOptions:
    """Return a :class:`_RunOptions` with sensible defaults.

    ``project_path`` is filled in by ``run_analysis`` when the caller
    supplies a path; passing ``None`` here yields a placeholder that
    must be overridden before use.
    """
    return _RunOptions(
        project_path=project_path or Path("."),
        output_path=None,
        format="json",
        verbose=False,
        fail_on_severity=None,
        show_suppressed=False,
    )


def run_analysis(
    *,
    path: str | Path,
    opts: _RunOptions,
    output_format: str = "json",
) -> str:
    """Run the analysis pipeline against ``path`` and return the rendered
    output as a string.

    Test-only helper. Reuses every step inside ``_run`` except the
    stdout write and the exit-code calculation: the renderer's output
    is returned to the caller. Honours every flag on ``opts`` except
    ``project_path`` and ``format`` which are overridden by the
    explicit kwargs.
    """
    fresh_opts = _RunOptions(
        project_path=Path(path),
        output_path=None,
        format=output_format,
        verbose=opts.verbose,
        fail_on_severity=opts.fail_on_severity,
        show_suppressed=opts.show_suppressed,
        language_filter=opts.language_filter,
        use_gitignore=opts.use_gitignore,
        exclude_tests=opts.exclude_tests,
        test_paths=opts.test_paths,
        exclude_dev=opts.exclude_dev,
    )
    project_path = fresh_opts.project_path.resolve()
    project_types = detector.detect_project_types(project_path)
    if not project_types:
        # Match _run's behaviour: surface as a sanitised error string in
        # the rendered output rather than raising. For the back-compat
        # fixture (which is a real Python project) this branch never
        # triggers; we keep the early-out as a safety net.
        result = AnalysisResult(
            project_type="unknown",
            project_path=str(project_path),
            errors=["No supported project type detected."],
        )
        return _render(result, output_format)

    runnable_types = [
        pt for pt in project_types
        if registry.get_analyser(pt) is not None
    ]
    analysers = registry.analysers_for(runnable_types)
    for a in analysers:
        a.use_gitignore = fresh_opts.use_gitignore
        a.exclude_tests = fresh_opts.exclude_tests
        a.test_paths = fresh_opts.test_paths
        a.exclude_dev = fresh_opts.exclude_dev
    sub_results = [a.analyse(str(project_path)) for a in analysers]
    merged = _merge_results(project_path, project_types, sub_results)
    merged = _propagate_in_use_through_graph(merged)
    visible = _apply_show_suppressed(merged, fresh_opts.show_suppressed)
    return _render(visible, output_format)


@app.command(name="analyse")
def main(
    path: Path = typer.Argument(
        Path("."),
        help="Directory to analyse.",
        show_default=False,
    ),
    format_: str = typer.Option(
        "markdown",
        "--format",
        help=(
            "Output format: markdown (md, default), text, json, or sarif."
        ),
        case_sensitive=False,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help=(
            "Write results to this file instead of stdout. When omitted "
            "AND --format is markdown (the default), a file named "
            "'<project-name>-analysis-report.md' is written to the "
            "current working directory (or 'analysis-report.md' if no "
            "project name can be derived from the manifest). For other "
            "formats, omitting --output writes to stdout as before."
        ),
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Emit debug lines to stderr.",
    ),
    fail_on_severity: str | None = typer.Option(
        None,
        "--fail-on-severity",
        help="Exit code 3 when any finding at this severity or above is present "
        "(LOW / MEDIUM / HIGH / CRITICAL). Default: HIGH.",
        case_sensitive=False,
    ),
    show_suppressed: bool = typer.Option(
        False,
        "--show-suppressed",
        help="Include suppressed findings in the report (with suppressed=true).",
    ),
    no_gitignore: bool = typer.Option(
        False,
        "--no-gitignore",
        help="Disable .gitignore filtering during source file discovery.",
    ),
    language: list[str] | None = typer.Option(
        None,
        "--language",
        "-L",
        help=(
            "Restrict analysis to one or more ecosystems (repeatable). "
            "Values: pypi, maven, gradle, npm, css, go, nuget. "
            "When omitted, every detected language is analysed."
        ),
        case_sensitive=False,
    ),
    exclude_tests: bool = typer.Option(
        False,
        "--exclude-tests",
        help=(
            "Drop test-scoped declared deps and skip test source files "
            "across all detected ecosystems."
        ),
    ),
    test_paths: list[str] | None = typer.Option(
        None,
        "--test-paths",
        help=(
            "Additional glob (relative to project root) added to the "
            "test-path matcher when --exclude-tests is on. Repeatable. "
            "Max 64 patterns × 256 bytes; no '..' segments; POSIX '/' only."
        ),
    ),
    exclude_dev: bool = typer.Option(
        False,
        "--exclude-dev",
        help=(
            "npm-only: drop devDependencies during parsing. Off by default. "
            "Independent of --exclude-tests."
        ),
    ),
    deep_inspection: bool = typer.Option(
        False,
        "--deep-inspection",
        help=(
            "Enable JVM cross-version ABI diff (REQ-22). Spawns javap per "
            "cached JAR up to 64 times — slower but surfaces "
            "NoSuchMethodError-class runtime risks. Off by default. "
            "SEC-NEW-56: set ONLY by this flag — no env / config path."
        ),
    ),
    allow_remote_fetch: bool = typer.Option(
        False,
        "--allow-remote-fetch",
        help=(
            "REQ-24 — permit outbound HTTPS to fetch cache-miss artefacts "
            "needed for the cross-version ABI diff. Requires "
            "--deep-inspection. Off by default; set ONLY by this argv flag "
            "(SEC-NEW-72) — no env / config path. Without this flag, "
            "configured indexes are validated but inert (zero network)."
        ),
    ),
    integrity_cross_check: bool = typer.Option(
        False,
        "--integrity-cross-check",
        help=(
            "REQ-24 — when ≥2 indexes are configured for an ecosystem, "
            "fetch each artefact from the top-2 priority indexes and "
            "compare bytes; mismatch → TS-INTEGRITY-MISMATCH (HIGH). "
            "Doubles fetch volume. Argv-only. Requires --allow-remote-fetch."
        ),
    ),
    fail_on_remote_severity: bool = typer.Option(
        False,
        "--fail-on-remote-severity",
        help=(
            "REQ-24 — let provenance=\"remote\" findings escalate exit "
            "code 3 via --fail-on-severity. Off by default: remote "
            "findings are visible but advisory (the verdict depended on "
            "network-trust-dependent bytes). Argv-only. Requires "
            "--allow-remote-fetch."
        ),
    ),
    index: list[str] | None = typer.Option(
        None,
        "--index",
        help=(
            "REQ-24 — register a package index for an ecosystem. "
            "Format: ECOSYSTEM=URL (e.g. maven=https://nexus.corp/repo). "
            "Repeatable; declaration order within an ecosystem = priority "
            "(first = primary, rest = secondary fallback). Without "
            "--allow-remote-fetch, indexes are parsed and validated but "
            "no network call is made."
        ),
    ),
    allow_private_index_host: list[str] | None = typer.Option(
        None,
        "--allow-private-index-host",
        help=(
            "REQ-24 — permit the named hostname to resolve to RFC 1918 / "
            "ULA addresses (10.x, 172.16-31.x, 192.168.x, fc00::/7). "
            "Required when your corporate Nexus is on a private network. "
            "Repeatable; argv-only. Loopback / link-local / CGNAT / "
            "multicast / reserved IPs are STILL rejected for safety. "
            "DNS-rebinding defence (pin-resolved-IP + post-connect "
            "getpeername re-check) applies identically."
        ),
    ),
    native_tls: bool = typer.Option(
        False,
        "--native-tls",
        help=(
            "REQ-24 — use the OS-native trust store (truststore package, "
            "same approach as uv / pip / hatch) so corporate CAs deployed "
            "to the macOS Keychain / Windows cert store / Linux NSS are "
            "trusted. Cert verification + hostname check remain mandatory; "
            "only the trust roots change. Argv-only. Requires "
            "--allow-remote-fetch."
        ),
    ),
) -> None:
    """Analyse a project and report dependency usage."""
    fmt = format_.lower()
    language_filter: tuple[str, ...] = ()
    if language:
        normalised = tuple(l.lower() for l in language)
        unknown = [l for l in normalised if l not in CANONICAL_ECOSYSTEMS]
        if unknown:
            _echo_err(
                f"--language value(s) {unknown} not recognised. "
                f"Valid ecosystems: {sorted(CANONICAL_ECOSYSTEMS - {'unknown', 'detected'})}"
            )
            raise typer.Exit(code=2)
        language_filter = normalised
    severity: FindingSeverity | None = None
    if fail_on_severity is not None:
        try:
            severity = FindingSeverity(fail_on_severity.upper())
        except ValueError:
            _echo_err(
                f"--fail-on-severity must be one of LOW, MEDIUM, HIGH, CRITICAL "
                f"(got {fail_on_severity!r})"
            )
            raise typer.Exit(code=2)

    # REQ-17 — sanitise --test-paths (count, length, traversal, separator).
    raw_paths: tuple[str, ...] = tuple(test_paths or ())
    leading_slash_warning = any(
        p.startswith("/") for p in raw_paths
    )
    try:
        sanitised_paths = sanitise_test_paths(raw_paths)
    except ValueError as exc:
        _echo_err(sanitise(str(exc)))
        raise typer.Exit(code=2)
    if leading_slash_warning and verbose:
        _echo_err(
            "[verbose] --test-paths: leading '/' stripped from one or more "
            "patterns (patterns are anchored to the project root)"
        )

    # REQ-24 — cross-flag validation. Each REQ-24 capability composes
    # onto the previous one; setting an outer flag without the inner
    # is a usage error, not a silent no-op.
    if allow_remote_fetch and not deep_inspection:
        _echo_err(
            "--allow-remote-fetch requires --deep-inspection "
            "(remote fetch exists only to serve the cross-version "
            "ABI diff; pass --deep-inspection alongside)."
        )
        raise typer.Exit(code=2)
    if integrity_cross_check and not allow_remote_fetch:
        _echo_err(
            "--integrity-cross-check requires --allow-remote-fetch "
            "(cross-check operates over fetched artefacts)."
        )
        raise typer.Exit(code=2)
    if fail_on_remote_severity and not allow_remote_fetch:
        _echo_err(
            "--fail-on-remote-severity requires --allow-remote-fetch "
            "(remote findings only exist when fetch is enabled)."
        )
        raise typer.Exit(code=2)
    if allow_private_index_host and not allow_remote_fetch:
        _echo_err(
            "--allow-private-index-host requires --allow-remote-fetch "
            "(the host allow-list only affects outbound fetches)."
        )
        raise typer.Exit(code=2)
    if native_tls and not allow_remote_fetch:
        _echo_err(
            "--native-tls requires --allow-remote-fetch "
            "(the OS trust store only affects outbound fetches)."
        )
        raise typer.Exit(code=2)

    opts = _RunOptions(
        project_path=path,
        output_path=output,
        format=fmt,
        verbose=verbose,
        fail_on_severity=severity,
        show_suppressed=show_suppressed,
        language_filter=language_filter,
        use_gitignore=not no_gitignore,
        exclude_tests=exclude_tests,
        test_paths=sanitised_paths,
        exclude_dev=exclude_dev,
        # SEC-NEW-56 — populated ONLY from the argv flag.
        deep_inspection=deep_inspection,
        # SEC-NEW-72 / FR-261 / FR-267 — populated ONLY from argv flags.
        allow_remote_fetch=allow_remote_fetch,
        integrity_cross_check=integrity_cross_check,
        fail_on_remote_severity=fail_on_remote_severity,
        # FR-256 — repeatable --index entries; parsing happens later via
        # IndexConfigResolver so warnings can be emitted into the
        # persistent report channel (FR-263) rather than stderr.
        cli_indexes=tuple(index or ()),
        # REQ-24 — repeatable allow-list for hostnames whose DNS
        # resolves to private (RFC 1918 / ULA) addresses. Argv-only.
        private_index_hosts=tuple(allow_private_index_host or ()),
        # REQ-24 — OS-native trust store for outbound TLS. Argv-only.
        native_tls=native_tls,
    )
    try:
        exit_code = _run(opts)
    except _CliError as exc:
        _echo_err(sanitise(exc.message))
        raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as exc:  # pragma: no cover — defensive
        if verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        else:
            _echo_err(f"Error: {sanitise(str(exc))}")
        raise typer.Exit(code=2)

    raise typer.Exit(code=exit_code)
