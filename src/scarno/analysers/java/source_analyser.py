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

"""JVM source & bytecode analyser — REQ-6.

Classifies each ``Dependency`` returned by the Maven / Gradle resolvers
as ``IN_USE``, ``UNCERTAIN``, or ``SAFE`` by scanning ``.java`` / ``.kt``
source files and, where a JAR is locally available, enumerating entry
points.

Entry-point enumeration has two modes:

  * **Default (fast)** — derive class-level entry points from the
    ``.class`` paths listed in the JAR. No subprocess per class; the
    JAR is opened once (via :func:`safe_jar_entries`) while building
    the inventory map and the entries are cached for later use.
  * **Deep inspection (opt-in)** — pass ``deep_inspection=True`` to
    :class:`JvmSourceAnalyser` to additionally invoke ``javap -public``
    per class and emit method / field entry points with public
    visibility. Slower by orders of magnitude — one subprocess per
    class — and intended for targeted audits, not routine runs.

.. warning::

    **Source scanning is regex-based in Phase 2 — this is a known
    fragility.** The regex extractors below cannot distinguish between
    a real ``import`` / ``@Autowired`` / ``Class.forName(...)`` and the
    same text inside a ``//`` comment, a ``/** Javadoc */`` block, or a
    string literal. For short-term correctness this is acceptable on
    well-formed Spring / Maven projects; for v1 it is not.

    **Replacement is tracked in REQ-6b** — swap to tree-sitter AST
    walkers so annotations / imports / reflection literals are matched
    only against genuine source constructs. The public API of this
    module stays stable across that refactor.

The subprocess call to ``javap`` (deep-inspection mode only) is the
most security-critical surface in this module. Every class name is
validated against a strict Java identifier pattern before the
subprocess is constructed (SEC-NEW-09), ``shell=False`` is
non-negotiable (SEC-012 / E-02), and a 10-second per-class timeout
caps runtime (SEC-012 / PERF-002).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 — wrapped via _invoke_javap_safe with strict validation
from pathlib import Path
from typing import NamedTuple

from scarno.analysers.java.ast_extractor import (
    AST_AVAILABLE,
    ExtractedFacts,
    extract_java,
    extract_kotlin,
)
from scarno.analysers.java.maven import (
    _gav_to_jar_path,
    _is_valid_gav_component,
    _m2_repo_path,
    _validate_gav,
)
from scarno.analysers.name_counts import MAX_FULL_SCANS, count_boundary_refs
from scarno.core.base_analyser import BaseAnalyser
from scarno.models import AnalysisResult, Dependency, DependencyStatus, EntryPoint
from scarno.security import (
    MAX_FILE_BYTES,
    PathEscapeError,
    resolve_and_confine,
    safe_jar_entries,
)

_JAVAP_TIMEOUT_SEC = 10
# A Java identifier: letter/underscore/$ followed by letters/digits/_/$,
# segments separated by dots. Zero tolerance for anything else — this
# string is passed to a subprocess argument list.
_JAVA_IDENT_RE = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$"
)
_IMPORT_JAVA_RE = re.compile(
    r"^\s*import\s+(static\s+)?([A-Za-z_$][A-Za-z0-9_$.]*?)(?:\.\*)?\s*;",
    re.MULTILINE,
)
_IMPORT_KT_RE = re.compile(
    r"^\s*import\s+([A-Za-z_$][A-Za-z0-9_$.]*?)(?:\.\*)?\s*(?:as\s+\w+)?\s*$",
    re.MULTILINE,
)
_ANNOTATION_RE = re.compile(r"@([A-Z][A-Za-z0-9_]*)\b")
_CLASS_FORNAME_RE = re.compile(
    r"""Class\.forName\(\s*["']([A-Za-z_$][A-Za-z0-9_$.]*)["']""",
)
_LOAD_CLASS_RE = re.compile(
    r"""ClassLoader\s*(?:\.\w+\(\))?\s*\.loadClass\(\s*["']([A-Za-z_$][A-Za-z0-9_$.]*)["']""",
)

# Dependency-injection annotation → groupId it belongs to.
_DI_ANNOTATIONS: dict[str, tuple[str, ...]] = {
    "Autowired": ("org.springframework",),
    "Bean": ("org.springframework",),
    "Component": ("org.springframework",),
    "Service": ("org.springframework",),
    "Repository": ("org.springframework",),
    "Controller": ("org.springframework",),
    "RestController": ("org.springframework",),
    "Configuration": ("org.springframework",),
    "Qualifier": ("org.springframework",),
    "Inject": ("com.google.inject", "javax.inject", "jakarta.inject"),
    "Resource": ("javax.annotation", "jakarta.annotation"),
}

# Package prefixes that popular artifacts publish under, when those
# prefixes don't match the Maven ``groupId`` directly. Kept narrow —
# each entry needs a test in ``test_jvm_source_analyser.py``.
_JAVA_PACKAGE_ALIASES: dict[str, tuple[str, ...]] = {
    "com.google.guava:guava": ("com.google.common",),
    "com.google.code.gson:gson": ("com.google.gson",),
    "com.fasterxml.jackson.core:jackson-databind": ("com.fasterxml.jackson",),
    "com.fasterxml.jackson.core:jackson-core": ("com.fasterxml.jackson",),
    "com.fasterxml.jackson.core:jackson-annotations": ("com.fasterxml.jackson.annotation",),
    "joda-time:joda-time": ("org.joda.time",),
    "commons-io:commons-io": ("org.apache.commons.io",),
    "commons-lang:commons-lang": ("org.apache.commons.lang",),
    "org.apache.commons:commons-lang3": ("org.apache.commons.lang3",),
    "org.slf4j:slf4j-api": ("org.slf4j",),
    "ch.qos.logback:logback-classic": ("ch.qos.logback", "org.slf4j"),
    "io.projectreactor:reactor-core": ("reactor.core",),
    "mysql:mysql-connector-java": ("com.mysql",),
}

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        "target",
        "build",
        ".gradle",
        ".idea",
        ".venv",
        "venv",
        "node_modules",
        ".git",
    }
)

_MAX_CLASSES_FOR_JAVAP = 500


class _JarInventory(NamedTuple):
    """Cached view of a dependency JAR's ``.class`` contents.

    Populated once per dep via :func:`_build_jar_inventory_map`. Holds
    the resolved JAR path, the distinct package prefixes (used for
    classification) and the raw class entry paths (consumed by
    :meth:`JvmSourceAnalyser._enumerate_jar_entry_points` so the JAR
    isn't re-opened downstream).
    """

    jar_path: Path
    packages: frozenset[str]
    class_entries: tuple[str, ...]


# ── JAR-based package discovery (FR-134) ────────────────────────────────────


def _locate_dependency_jar(
    dep: Dependency,
    project_root: Path,
    errors: list[str],
) -> Path | None:
    """Locate the JAR for *dep* in the Maven local cache or project target/."""
    parts = dep.name.split(":", 1)
    if len(parts) != 2:
        return None
    group_id, artifact_id = parts
    version = dep.version
    if not version:
        return None
    coords = (group_id, artifact_id, version)
    if not _validate_gav(coords):
        return None

    # Tier 1: Maven local repository.
    repo_root = _m2_repo_path()
    if repo_root.is_dir():
        candidate = _gav_to_jar_path(repo_root, *coords)
        try:
            confined = resolve_and_confine(candidate, repo_root)
            if confined.exists():
                return confined
        except PathEscapeError:
            pass

    # Tier 2: project target/ directory.
    for subdir in ("target", "build/libs"):
        jar_dir = project_root / subdir
        if not jar_dir.is_dir():
            continue
        jar_name = f"{artifact_id}-{version}.jar"
        candidate = jar_dir / jar_name
        try:
            confined = resolve_and_confine(candidate, project_root)
            if confined.exists():
                return confined
        except PathEscapeError:
            pass

    return None


def _extract_packages_from_jar(jar_path: Path) -> set[str]:
    """Derive Java package prefixes from the ``.class`` entries in a JAR."""
    try:
        entries = safe_jar_entries(jar_path)
    except (ValueError, OSError):
        return set()
    packages: set[str] = set()
    for entry in entries:
        # entry looks like "com/example/Foo.class" or "com/example/inner/Bar.class"
        if "/" not in entry:
            continue  # default package — skip
        package = entry.rsplit("/", 1)[0].replace("/", ".")
        packages.add(package)
    return packages


def _build_jar_inventory_map(
    deps: list[Dependency],
    project_root: Path,
    errors: list[str],
) -> dict[str, _JarInventory]:
    """Build ``{dep.name: _JarInventory}`` by inspecting JARs once (FR-134).

    A single :func:`safe_jar_entries` call per JAR populates both the
    package set (used for import/classification matching) and the raw
    class-entry list (consumed by the fast-path entry-point
    enumerator). Deps whose JAR is missing or whose listing fails are
    omitted from the result.
    """
    result: dict[str, _JarInventory] = {}
    for dep in deps:
        jar_path = _locate_dependency_jar(dep, project_root, errors)
        if jar_path is None:
            continue
        try:
            entries = safe_jar_entries(jar_path)
        except (ValueError, OSError):
            continue
        packages: set[str] = set()
        class_entries: list[str] = []
        for entry in entries:
            class_entries.append(entry)
            if "/" not in entry:
                continue  # default package — skip
            packages.add(entry.rsplit("/", 1)[0].replace("/", "."))
        if not class_entries:
            continue
        result[dep.name] = _JarInventory(
            jar_path=jar_path,
            packages=frozenset(packages),
            class_entries=tuple(class_entries),
        )
    return result


# ── analyser ─────────────────────────────────────────────────────────────────


class JvmSourceAnalyser(BaseAnalyser):
    """Source + bytecode analyser for JVM dependencies.

    Parameters
    ----------
    deep_inspection:
        When ``False`` (default) entry-point enumeration emits one
        class-level :class:`EntryPoint` per ``.class`` found in the
        dependency JAR — derived purely from the JAR's path listing,
        so no ``javap`` subprocess is spawned. Inner classes are
        included. This is the fast path and is suitable for routine
        analysis of large Maven projects.

        When ``True`` the analyser additionally invokes ``javap
        -public`` per class and emits method / field entry points
        with public visibility. One subprocess per class makes this
        orders of magnitude slower, so reserve it for targeted
        audits where public-API visibility matters.
    """

    def __init__(self, *, deep_inspection: bool = False) -> None:
        self.deep_inspection = deep_inspection

    def supports(self, project_path: str) -> bool:
        root = Path(project_path)
        if not root.is_dir():
            return False
        for ext in ("*.java", "*.kt"):
            for _ in root.rglob(ext):
                return True
        return False

    def analyse(
        self,
        project_path: str,
        dependencies: list[Dependency] | None = None,
    ) -> AnalysisResult:
        deps = list(dependencies or [])
        errors: list[str] = []
        root = Path(project_path)
        try:
            root = root.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            errors.append(f"jvm_source_analyser: path resolution failed — {exc}")
            return AnalysisResult(
                project_type="java",
                project_path=str(root),
                dependencies=deps,
                errors=errors,
                findings=[],
            )

        source_items = self._gather_source_files(root, errors)
        import_paths: set[str] = set()
        annotations: set[str] = set()
        reflective_literals: set[str] = set()
        # REQ-17 / FR-150 — aggregate per-FQCN reference counts across all files.
        import_counts: dict[str, int] = {}
        # FR-150 — wildcard imports + per-(simple, member) call counts.
        wildcard_imports: set[str] = set()
        method_calls: dict[str, int] = {}
        constructor_calls: dict[str, int] = {}
        # FR-150 — variable-name → declared-type's simple name, used to
        # attribute ``instance.method()`` calls back to the imported
        # class. Aggregated across files; later bindings overwrite
        # earlier ones (best-effort, no full type inference).
        variable_types: dict[str, str] = {}
        # REQ-6b — prefer AST extraction; fall back to regex per-file when
        # tree-sitter isn't available for that language.
        for text, language in source_items:
            facts = self._extract_facts(text, language, errors)
            import_paths |= facts.imports
            annotations |= facts.annotations
            reflective_literals |= facts.reflective_literals
            wildcard_imports |= facts.wildcard_imports
            for fqcn, n in facts.import_counts.items():
                import_counts[fqcn] = import_counts.get(fqcn, 0) + n
            # FR-150 — resolve instance-call receivers via the *current
            # file's* variable_types map BEFORE accumulating into the
            # cross-file counter. ``Splitter sp = …; sp.split(s)`` per
            # this file becomes ``Splitter.split += 1`` in the rolling
            # tally. Per-file scoping matters: if file B uses ``sp`` for
            # a different type, B's resolution can't leak into A.
            for k, n in facts.method_calls.items():
                receiver, dot, method = k.partition(".")
                if not dot or not method:
                    continue
                resolved = facts.variable_types.get(receiver, receiver)
                key = f"{resolved}.{method}"
                method_calls[key] = method_calls.get(key, 0) + n
            for k, n in facts.constructor_calls.items():
                constructor_calls[k] = constructor_calls.get(k, 0) + n
            # FR-150 — keep a cross-file rolling map of variable-type
            # bindings as well; used by the multi-wildcard
            # disambiguator below where it needs to reach across files.
            variable_types.update(facts.variable_types)
        # FR-150 — wildcard imports also contribute to classification:
        # ``import com.x.*;`` IS a use-site for any dep whose package
        # prefix starts with ``com.x``.
        import_paths |= wildcard_imports

        have_source_evidence = bool(source_items)

        # FR-134 — inspect each dependency JAR once to discover its real
        # Java packages (classification) and cache its class entries
        # (entry-point enumeration). Avoids re-opening the JAR later.
        jar_inventory = _build_jar_inventory_map(deps, root, errors)
        jar_packages = {
            name: set(inv.packages) for name, inv in jar_inventory.items()
        }

        # FR-150 — pre-pass: which simple class names are claimed by
        # CONCRETE (non-wildcard) imports across ALL deps. Used by the
        # wildcard-attribution logic so a wildcard'd dep doesn't steal
        # a call that another dep's concrete import already owns.
        claimed_by_concrete: dict[str, str] = {}
        non_wildcard_imports = import_paths - wildcard_imports
        for dep in deps:
            key = dep.name
            parts = key.split(":", 1)
            group_id = parts[0] if parts else ""
            prefixes = _candidate_package_prefixes(
                key, group_id, jar_packages=jar_packages
            )
            for imp in non_wildcard_imports:
                if not _matches_any_prefix(imp, prefixes):
                    continue
                simple = imp.rsplit(".", 1)[-1]
                if simple and simple[:1].isupper():
                    claimed_by_concrete.setdefault(simple, dep.name)

        # FR-150 — multi-wildcard signature disambiguator. When two
        # wildcard'd deps both own a class with the same simple name
        # (e.g. ``Foo`` in ``org.libA.collect`` and ``org.libB.collect``)
        # and source calls ``Foo.bar(…)``, ask each candidate's JAR via
        # javap which class actually exposes ``bar`` and attribute the
        # call to that dep. Returns ``{(simple, method): owner_dep_name}``
        # for unambiguous wins; ambiguous calls (no clash, or no JAR
        # data) are absent and fall through to the wildcard-claim
        # heuristic. Same for constructors via
        # ``{simple: owner_dep_name}``.
        method_owner: dict[tuple[str, str], str] = {}
        ctor_owner: dict[str, str] = {}
        # Map simple class name → list of (dep_name, jar_path, class_entry)
        # candidates from each dep's JAR that wildcards reach.
        clashes = _find_wildcard_clashes(
            deps, wildcard_imports, jar_inventory, jar_packages,
        )
        for simple, candidates in clashes.items():
            if len(candidates) < 2:
                continue
            # Collect all (simple, method) calls observed in source for
            # this clashing class, plus constructor.
            called_methods = {
                key.split(".", 1)[1]
                for key in method_calls
                if key.startswith(simple + ".")
            }
            ctor_called = simple in constructor_calls
            for method in called_methods:
                winners = self._javap_winners_for_method(
                    candidates, method,
                )
                if len(winners) == 1:
                    method_owner[(simple, method)] = winners[0]
            if ctor_called:
                winners = self._javap_winners_for_ctor(candidates, simple)
                if len(winners) == 1:
                    ctor_owner[simple] = winners[0]

        updated: list[Dependency] = []
        for dep in deps:
            new_status, reason = _classify_dep(
                dep,
                import_paths=import_paths,
                annotations=annotations,
                reflective_literals=reflective_literals,
                have_source_evidence=have_source_evidence,
                jar_packages=jar_packages,
            )
            entry_points = self._enumerate_jar_entry_points(
                dep, jar_inventory, import_paths,
                import_counts=import_counts,
            ) if new_status is DependencyStatus.IN_USE else []
            # FR-150 — augment JAR-derived class entries with the
            # source-level signals the JAR doesn't know about: wildcard
            # imports, method invocations, constructor calls, plus
            # synthetic class rows when no JAR was found at all. The
            # synthesiser dedupes via its own ``seen`` set so JAR
            # entries are not duplicated.
            if new_status is DependencyStatus.IN_USE:
                synth = _synthesise_java_entry_points(
                    dep,
                    import_paths=import_paths,
                    wildcard_imports=wildcard_imports,
                    import_counts=import_counts,
                    method_calls=method_calls,
                    constructor_calls=constructor_calls,
                    jar_packages=jar_packages,
                    claimed_by_concrete=claimed_by_concrete,
                    jar_inventory=jar_inventory,
                    method_owner=method_owner,
                    ctor_owner=ctor_owner,
                    already_emitted={ep.name for ep in entry_points},
                )
                entry_points = entry_points + synth
            # FR-150 — when the dep is IN_USE via DI annotation or
            # reflective literal (no concrete imports match), surface a
            # synthetic activation entry point so ``entry_points_used > 0``
            # truthfully reflects the report status. Otherwise the user
            # sees ``IN_USE`` with ``0/N entry points used`` — exactly the
            # confusing state the user reported.
            if new_status is DependencyStatus.IN_USE and (
                not entry_points
                or not any(ep.used for ep in entry_points)
            ):
                activation = _synthesise_activation_entry_point(
                    reason, annotations, reflective_literals,
                )
                if activation is not None:
                    entry_points = [activation, *entry_points]

            updated.append(
                Dependency(
                    name=dep.name,
                    version=dep.version,
                    status=new_status,
                    reason=reason,
                    entry_points=entry_points,
                    entry_points_used=sum(1 for ep in entry_points if ep.used),
                    entry_points_total=len(entry_points),
                    source=dep.source,
                    vendored_path=dep.vendored_path,
                    resolved=dep.resolved,
                    is_type_stub=dep.is_type_stub,
                    ecosystem=dep.ecosystem if dep.ecosystem != "unknown" else "maven",
                    # REQ-19 / REQ-21 — carry the graph- and pin-override
                    # metadata the build-system resolver attached. Dropping
                    # these (the pre-fix behaviour) left the per-version
                    # classifier and the "Pinning overrides" report section
                    # with nothing to work with.
                    is_transitive=dep.is_transitive,
                    imported_directly=dep.imported_directly,
                    manifest_redundant=dep.manifest_redundant,
                    redundant_parent=dep.redundant_parent,
                    pin_override=dep.pin_override,
                    pin_override_kind=dep.pin_override_kind,
                    pin_override_target=dep.pin_override_target,
                )
            )

        return AnalysisResult(
            project_type="java",
            project_path=str(root),
            dependencies=updated,
            errors=errors,
            findings=[],
        )

    # ── filesystem walk ─────────────────────────────────────────────────

    def _gather_source_files(
        self, root: Path, errors: list[str]
    ) -> list[tuple[str, str]]:
        """Return a list of ``(text, language)`` pairs where language is
        ``"java"`` or ``"kotlin"``. Skips excluded dirs, oversized files,
        and confined-path escapes."""
        out: list[tuple[str, str]] = []
        for pattern, language in (("*.java", "java"), ("*.kt", "kotlin")):
            for raw_path in root.rglob(pattern):
                rel_parts = raw_path.relative_to(root).parts
                if any(p in _EXCLUDED_DIR_NAMES for p in rel_parts):
                    continue
                try:
                    resolved = resolve_and_confine(raw_path, root)
                except PathEscapeError:
                    errors.append(
                        f"jvm_source_analyser: symlink escape blocked: "
                        f"{'/'.join(rel_parts)}"
                    )
                    continue
                try:
                    size = resolved.stat().st_size
                except OSError as exc:
                    errors.append(
                        f"jvm_source_analyser: stat failed for {resolved.name} — {exc}"
                    )
                    continue
                if size > MAX_FILE_BYTES:
                    errors.append(
                        f"jvm_source_analyser: skipped {resolved.name} — too large"
                    )
                    continue
                try:
                    text = resolved.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    errors.append(
                        f"jvm_source_analyser: could not read {resolved.name} — {exc}"
                    )
                    continue
                out.append((text, language))
        return out

    def _extract_facts(
        self, text: str, language: str, errors: list[str] | None = None
    ) -> ExtractedFacts:
        """Extract facts via tree-sitter AST if available; otherwise regex.

        The regex fallback is the Phase 2 path — a known-fragile approach
        (misses comment/string/Javadoc exclusion) that's kept so hosts
        without tree-sitter wheels still produce a useful analysis.
        """
        if AST_AVAILABLE:
            try:
                if language == "java":
                    return extract_java(text, errors=errors)
                if language == "kotlin":
                    return extract_kotlin(text, errors=errors)
            except Exception:  # noqa: BLE001 — any grammar error → fallback
                pass
        # Regex-fallback path — also populate import_counts so Java/Kotlin
        # entry-point counts work even without tree-sitter wheels. Counts
        # come from one pass over the file's identifier tokens; a scan per
        # import made a crafted, import-packed file quadratic (CWE-1333).
        imports = _extract_imports(text)
        facts = ExtractedFacts(
            imports=imports,
            annotations=_extract_annotations(text),
            reflective_literals=_extract_reflective_classnames(text),
        )
        pairs = [(fqcn, fqcn.rsplit(".", 1)[-1]) for fqcn in imports]
        counts, uncounted = count_boundary_refs(
            text,
            [
                simple
                for _, simple in pairs
                if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", simple)
            ],
        )
        for fqcn, simple in pairs:
            n = counts.get(simple, 0)
            facts.import_counts[fqcn] = (
                facts.import_counts.get(fqcn, 0) + max(n, 1)
            )
        if uncounted and errors is not None:
            errors.append(
                f"jvm_source_analyser: reference counting capped at "
                f"{MAX_FULL_SCANS} unusual import names — "
                f"{len(uncounted)} more counted as a single reference each"
            )
        return facts

    # ── multi-wildcard signature disambiguation (FR-150) ────────────────

    def _javap_winners_for_method(
        self,
        candidates: list[tuple[str, "_JarInventory", str]],
        method: str,
    ) -> list[str]:
        """For each candidate, ask ``javap`` whether its class declares
        ``method``. Return the dep names that do.

        ``candidates`` items are ``(dep_name, jar_inventory, class_fqcn)``.
        On any javap failure (binary missing, timeout, parse error), the
        candidate is silently dropped — the rest of the report still
        renders, just with the call attributed via the original
        wildcard heuristic instead of signature-based.
        """
        winners: list[str] = []
        for dep_name, inventory, class_fqcn in candidates:
            stdout = self._invoke_javap_safe(inventory.jar_path, class_fqcn)
            if stdout is None:
                continue
            for name, kind in _parse_javap_output(stdout):
                if kind == "method" and name.rsplit(".", 1)[-1] == method:
                    winners.append(dep_name)
                    break
        return winners

    def _javap_winners_for_ctor(
        self,
        candidates: list[tuple[str, "_JarInventory", str]],
        simple: str,
    ) -> list[str]:
        """Constructor-disambiguation analogue.

        ``javap -public`` declares a ``public ClassName(…);`` line per
        public constructor, captured by the existing
        :func:`_parse_javap_output` as a method whose name equals the
        class's simple name.
        """
        winners: list[str] = []
        for dep_name, inventory, class_fqcn in candidates:
            stdout = self._invoke_javap_safe(inventory.jar_path, class_fqcn)
            if stdout is None:
                continue
            for name, kind in _parse_javap_output(stdout):
                if kind == "method" and name.rsplit(".", 1)[-1] == simple:
                    winners.append(dep_name)
                    break
        return winners

    # ── javap subprocess (subclass-internal but unit-tested) ────────────

    def _invoke_javap_safe(
        self,
        jar_path: Path,
        class_name: str,
    ) -> str | None:
        """Invoke ``javap -public`` for ``class_name`` using ``jar_path``.

        Returns ``None`` when:
          * class name is not a valid Java identifier (SEC-NEW-09),
          * ``javap`` binary is missing,
          * the subprocess fails or times out (10 s).

        Always uses ``shell=False`` (SEC-012 / E-02); the argv list is
        constructed from validated strings only. No string interpolation
        into a shell command line.
        """
        if not _is_valid_java_identifier(class_name):
            return None
        javap = self._resolve_javap_binary()
        if javap is None:
            return None
        try:
            completed = subprocess.run(  # noqa: S603 — shell=False + validated argv
                [javap, "-public", "-classpath", str(jar_path), class_name],
                capture_output=True,
                timeout=_JAVAP_TIMEOUT_SEC,
                shell=False,
                check=False,
                text=True,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None
        if completed.returncode != 0:
            return None
        return completed.stdout

    def _resolve_javap_binary(self) -> str | None:
        """Return the path to ``javap``, preferring ``$JAVA_HOME/bin/javap``.

        When ``JAVA_HOME`` is set, we insist that the resolved ``javap``
        sits inside that tree (SEC-NEW-12). If ``JAVA_HOME`` is unset we
        fall back to a ``PATH`` lookup.
        """
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            candidate = Path(java_home) / "bin" / "javap"
            if candidate.exists():
                try:
                    resolved = candidate.resolve()
                    resolved.relative_to(Path(java_home).resolve())
                except (OSError, ValueError):
                    return None
                return str(resolved)
            return None
        found = shutil.which("javap")
        return found

    def _enumerate_jar_entry_points(
        self,
        dep: Dependency,
        jar_inventory: dict[str, _JarInventory],
        import_paths: set[str],
        *,
        import_counts: dict[str, int] | None = None,
    ) -> list[EntryPoint]:
        """Enumerate entry points from the dependency's JAR.

        Fast path (``deep_inspection=False``): emit one class-level
        :class:`EntryPoint` per ``.class`` entry (including inner
        classes) using only the cached JAR listing — no subprocess.

        Deep path (``deep_inspection=True``): additionally invoke
        ``javap -public`` per class to emit public method / field
        entry points. Capped at :data:`_MAX_CLASSES_FOR_JAVAP` classes
        per dep to bound runtime.
        """
        inventory = jar_inventory.get(dep.name)
        if inventory is None or not inventory.packages:
            return []

        counts = import_counts or {}
        entry_points: list[EntryPoint] = []
        inspected = 0
        for class_entry in inventory.class_entries:
            if "/" not in class_entry:
                continue  # default package
            package = class_entry.rsplit("/", 1)[0].replace("/", ".")
            if package not in inventory.packages:
                continue
            # "com/example/Foo$Bar.class" → "com.example.Foo$Bar".
            class_fqcn = class_entry.removesuffix(".class").replace("/", ".")
            used = any(
                imp == package or imp.startswith(package + ".")
                for imp in import_paths
            )
            # REQ-17 / FR-150 — sum import-site references for this class.
            # An import path matches when it equals the class FQCN
            # exactly OR is a wildcard (``com.example.*``) covering the
            # package — for the wildcard case, we attribute the count to
            # the package-level import key.
            usage_count = 0
            if used:
                usage_count = counts.get(class_fqcn, 0)
                # Wildcard imports of the form ``com.example.*`` show up
                # in ``import_paths`` as ``com.example`` — add their
                # count once per class in the package.
                usage_count += counts.get(package, 0)
            entry_points.append(
                EntryPoint(
                    name=class_fqcn, kind="class", used=used,
                    usage_count=usage_count,
                )
            )

            if not self.deep_inspection:
                continue
            if inspected >= _MAX_CLASSES_FOR_JAVAP:
                continue
            stdout = self._invoke_javap_safe(inventory.jar_path, class_fqcn)
            if stdout is None:
                continue
            inspected += 1
            for name, kind in _parse_javap_output(stdout):
                if kind == "class":
                    # Already emitted above from the JAR listing.
                    continue
                # Methods/fields share the class's usage_count; refine
                # later if javap emits per-symbol references.
                entry_points.append(
                    EntryPoint(
                        name=name, kind=kind, used=used,
                        usage_count=usage_count,
                    )
                )
        return entry_points


# ── javap output parsing ───────────────────────────────────────────────────

_JAVAP_CLASS_RE = re.compile(
    r"^public\s+(?:abstract\s+|final\s+)*(?:class|interface|enum)\s+([\w.$]+)"
)
_JAVAP_METHOD_RE = re.compile(
    r"^\s+public\s+.*\s+(\w+)\(.*\);"
)
_JAVAP_FIELD_RE = re.compile(
    r"^\s+public\s+.*\s+(\w+);"
)


def _parse_javap_output(stdout: str) -> list[tuple[str, str]]:
    """Parse ``javap -public`` output into ``(name, kind)`` pairs."""
    results: list[tuple[str, str]] = []
    current_class = ""
    for line in stdout.splitlines():
        m = _JAVAP_CLASS_RE.match(line)
        if m:
            current_class = m.group(1)
            results.append((current_class, "class"))
            continue
        m = _JAVAP_METHOD_RE.match(line)
        if m and current_class:
            results.append((f"{current_class}.{m.group(1)}", "method"))
            continue
        m = _JAVAP_FIELD_RE.match(line)
        if m and current_class:
            results.append((f"{current_class}.{m.group(1)}", "field"))
    return results


# ── classification helpers ───────────────────────────────────────────────────


def _classify_dep(
    dep: Dependency,
    *,
    import_paths: set[str],
    annotations: set[str],
    reflective_literals: set[str],
    have_source_evidence: bool,
    jar_packages: dict[str, set[str]] | None = None,
) -> tuple[DependencyStatus, str]:
    key = dep.name  # "groupId:artifactId"
    parts = key.split(":", 1)
    group_id = parts[0] if parts else ""

    candidate_prefixes = _candidate_package_prefixes(
        key, group_id, jar_packages=jar_packages
    )

    # Direct import match → IN_USE.
    for imp in import_paths:
        if _matches_any_prefix(imp, candidate_prefixes):
            return (
                DependencyStatus.IN_USE,
                f"imported as '{imp}' in project source",
            )

    # DI annotation → IN_USE when the annotation is registered against
    # a groupId that this dep belongs to.
    for ann in annotations:
        dep_groups = _DI_ANNOTATIONS.get(ann)
        if dep_groups is None:
            continue
        if any(group_id.startswith(g) for g in dep_groups):
            return (
                DependencyStatus.IN_USE,
                f"used via @{ann} annotation (framework-wired dependency)",
            )

    # Reflective class-literal match → UNCERTAIN (not safe to remove).
    for literal in reflective_literals:
        if _matches_any_prefix(literal, candidate_prefixes):
            return (
                DependencyStatus.UNCERTAIN,
                f"referenced via Class.forName/ClassLoader.loadClass "
                f"('{literal}') — manual review required",
            )

    # No positive evidence. When we didn't see *any* source files at all
    # (no .java/.kt under the project tree), we cannot confidently call
    # a dep SAFE — there may be a bytecode-only module or an installed
    # JAR we can't inspect. Leave as UNCERTAIN.
    if not have_source_evidence:
        return (
            DependencyStatus.UNCERTAIN,
            "no source files available for analysis — manual review required",
        )
    return DependencyStatus.SAFE, "no reference found in source files"


def _find_wildcard_clashes(
    deps: list[Dependency],
    wildcard_imports: set[str],
    jar_inventory: dict[str, "_JarInventory"],
    jar_packages: dict[str, set[str]] | None,
) -> dict[str, list[tuple[str, "_JarInventory", str]]]:
    """Return ``{simple_name: [(dep_name, inventory, class_fqcn), …]}``
    for each class simple name owned by ≥ 1 wildcard'd dep.

    Only deps that have a JAR inventory contribute — disambiguation
    requires javap'able class files. Without the cache the heuristic
    path runs as before.
    """
    clashes: dict[str, list[tuple[str, "_JarInventory", str]]] = {}
    for dep in deps:
        inventory = jar_inventory.get(dep.name)
        if inventory is None:
            continue
        key = dep.name
        parts = key.split(":", 1)
        group_id = parts[0] if parts else ""
        prefixes = _candidate_package_prefixes(
            key, group_id, jar_packages=jar_packages
        )
        wildcard_pkgs_for_dep = {
            w for w in wildcard_imports if _matches_any_prefix(w, prefixes)
        }
        if not wildcard_pkgs_for_dep:
            continue
        for class_entry in inventory.class_entries:
            if "/" not in class_entry:
                continue
            pkg = class_entry.rsplit("/", 1)[0].replace("/", ".")
            if pkg not in wildcard_pkgs_for_dep:
                continue
            simple = (
                class_entry.rsplit("/", 1)[-1]
                .removesuffix(".class")
                .split("$", 1)[0]
            )
            class_fqcn = (
                class_entry.removesuffix(".class").replace("/", ".")
            )
            clashes.setdefault(simple, []).append(
                (dep.name, inventory, class_fqcn)
            )
    return clashes


def _synthesise_java_entry_points(
    dep: Dependency,
    *,
    import_paths: set[str],
    wildcard_imports: set[str],
    import_counts: dict[str, int],
    method_calls: dict[str, int],
    constructor_calls: dict[str, int],
    jar_packages: dict[str, set[str]] | None,
    claimed_by_concrete: dict[str, str] | None = None,
    jar_inventory: dict[str, "_JarInventory"] | None = None,
    method_owner: dict[tuple[str, str], str] | None = None,
    ctor_owner: dict[str, str] | None = None,
    already_emitted: set[str] | None = None,
) -> list[EntryPoint]:
    """Surface every project-source signal that resolves to this dep
    as an entry point — fallback when the JAR isn't in the local cache.

    Emits four kinds:
      * ``class`` — concrete `import com.x.Y;` line.
      * ``wildcard`` — `import com.x.*;` line; usage_count is the count
        of unqualified-name references attributed to this wildcard via
        the method/constructor walkers.
      * ``method`` — `<simple>.<method>(…)` call where ``<simple>`` is
        the simple name of one of this dep's imports.
      * ``constructor`` — `new <ClassName>(…)` where ``<ClassName>`` is
        the simple name of one of this dep's imports.
    """
    key = dep.name
    parts = key.split(":", 1)
    group_id = parts[0] if parts else ""
    prefixes = _candidate_package_prefixes(
        key, group_id, jar_packages=jar_packages
    )
    out: list[EntryPoint] = []
    seen: set[str] = set(already_emitted or set())
    # Concrete imports (one per imported FQCN).
    matched_simple_names: set[str] = set()
    # Seed simple names from any JAR-derived class entries already
    # emitted by ``_enumerate_jar_entry_points``: they carry the same
    # provenance as concrete imports for downstream attribution.
    for fqcn in already_emitted or set():
        simple = fqcn.rsplit(".", 1)[-1].split("$", 1)[0]
        if simple and simple[:1].isupper():
            matched_simple_names.add(simple)
    for imp in sorted(import_paths - wildcard_imports):
        if not _matches_any_prefix(imp, prefixes):
            continue
        if imp in seen:
            continue
        seen.add(imp)
        simple = imp.rsplit(".", 1)[-1]
        if simple and simple[:1].isupper():
            matched_simple_names.add(simple)
        out.append(
            EntryPoint(
                name=imp,
                kind="class",
                used=True,
                usage_count=import_counts.get(imp, 1),
            )
        )
    # Wildcard imports (one per wildcard'd package).
    # FR-150 — also harvest the simple names that the wildcard could
    # plausibly own. Source: JAR class list when available; otherwise
    # any unqualified call/ctor not already claimed by another dep's
    # concrete import.
    claimed = claimed_by_concrete or {}
    inventory = (jar_inventory or {}).get(dep.name)
    jar_simple_names_in_wildcard: dict[str, set[str]] = {}
    if inventory is not None:
        # Group class FQCNs by package for fast wildcard-package lookup.
        for class_entry in inventory.class_entries:
            if "/" not in class_entry:
                continue
            pkg = class_entry.rsplit("/", 1)[0].replace("/", ".")
            cls = class_entry.rsplit("/", 1)[-1].removesuffix(".class")
            # Strip inner-class suffix for lookup; ``Foo$Bar`` exposes
            # both ``Foo`` and ``Foo$Bar`` as candidates.
            jar_simple_names_in_wildcard.setdefault(pkg, set()).add(cls)
            if "$" in cls:
                jar_simple_names_in_wildcard[pkg].add(cls.split("$", 1)[0])

    wildcard_owned_simple_names: set[str] = set()
    for wild in sorted(wildcard_imports):
        if not _matches_any_prefix(wild, prefixes):
            continue
        wild_label = f"{wild}.*"
        if wild_label in seen:
            continue
        seen.add(wild_label)
        out.append(
            EntryPoint(
                name=wild_label,
                kind="wildcard",
                used=True,
                usage_count=1,
            )
        )
        # Determine which simple names the wildcard owns for
        # downstream method/constructor attribution.
        if wild in jar_simple_names_in_wildcard:
            wildcard_owned_simple_names |= jar_simple_names_in_wildcard[wild]
        else:
            # JAR-less heuristic: any constructor or method-receiver
            # name observed in source that ISN'T claimed by another
            # dep's concrete import is plausibly owned by the wildcard.
            for ctor_name in constructor_calls:
                if claimed.get(ctor_name, dep.name) == dep.name:
                    wildcard_owned_simple_names.add(ctor_name)
            for call_key in method_calls:
                receiver = call_key.split(".", 1)[0]
                if (
                    receiver
                    and receiver[:1].isupper()
                    and claimed.get(receiver, dep.name) == dep.name
                ):
                    wildcard_owned_simple_names.add(receiver)

    # Combine concrete-import names with wildcard-attributed names for
    # the method / constructor attribution loop below.
    matched_simple_names |= wildcard_owned_simple_names
    # Methods called on the simple names we matched. ``Splitter.on(',')``
    # → ``Splitter.on`` keyed by simple receiver. The signature-based
    # disambiguator (`method_owner`) overrides simple-name matching when
    # two wildcard'd deps both could own the receiver — its decision is
    # authoritative.
    m_owner = method_owner or {}
    c_owner = ctor_owner or {}
    for key_str, count in sorted(method_calls.items()):
        receiver, _dot, method = key_str.partition(".")
        decided = m_owner.get((receiver, method))
        if decided is not None:
            if decided != dep.name:
                continue  # another dep won the disambiguation
        elif receiver not in matched_simple_names:
            continue
        label = key_str
        if label in seen:
            continue
        seen.add(label)
        out.append(
            EntryPoint(
                name=label,
                kind="method",
                used=True,
                usage_count=count,
            )
        )
    # Constructors of imported classes.
    for ctor, count in sorted(constructor_calls.items()):
        decided = c_owner.get(ctor)
        if decided is not None:
            if decided != dep.name:
                continue
        elif ctor not in matched_simple_names:
            continue
        label = f"new {ctor}()"
        if label in seen:
            continue
        seen.add(label)
        out.append(
            EntryPoint(
                name=label,
                kind="constructor",
                used=True,
                usage_count=count,
            )
        )
    return out


def _synthesise_activation_entry_point(
    reason: str,
    annotations: set[str],
    reflective_literals: set[str],
) -> EntryPoint | None:
    """Build a single synthetic entry point describing why an IN_USE dep
    is in use when no concrete import / call site references it.

    Triggers when classification fired via ``@Autowired``-style DI
    annotations or via ``Class.forName("…")``. Without this, the user
    sees the confusing ``IN_USE — 0/N entry points used`` row.
    """
    rl = reason.lower()
    if "@" in reason:
        # Pull annotation name from reason text — best effort.
        for ann in sorted(annotations):
            if ann.lower() in rl:
                return EntryPoint(
                    name=f"@{ann} (DI activation)",
                    kind="annotation",
                    used=True,
                    usage_count=1,
                )
        return EntryPoint(
            name="@DI (framework activation)",
            kind="annotation",
            used=True,
            usage_count=1,
        )
    if "class.forname" in rl or "loadclass" in rl or "reflective" in rl:
        for lit in sorted(reflective_literals):
            return EntryPoint(
                name=f"Class.forName({lit!r})",
                kind="reflective",
                used=True,
                usage_count=1,
            )
        return EntryPoint(
            name="Class.forName(…) (reflective)",
            kind="reflective",
            used=True,
            usage_count=1,
        )
    return None


def _candidate_package_prefixes(
    key: str,
    group_id: str,
    *,
    jar_packages: dict[str, set[str]] | None = None,
) -> tuple[str, ...]:
    # JAR-derived packages are authoritative when available (FR-134).
    if jar_packages and key in jar_packages:
        jar_pkgs = tuple(jar_packages[key])
        # Include groupId + aliases as fallback for partial JARs.
        aliased = _JAVA_PACKAGE_ALIASES.get(key, ())
        if group_id:
            return (*jar_pkgs, group_id, *aliased)
        return (*jar_pkgs, *aliased)
    aliased = _JAVA_PACKAGE_ALIASES.get(key, ())
    if group_id:
        return (group_id, *aliased)
    return aliased


def _matches_any_prefix(candidate: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        if candidate == prefix or candidate.startswith(prefix + "."):
            return True
    return False


def _extract_imports(text: str) -> set[str]:
    out: set[str] = set()
    for match in _IMPORT_JAVA_RE.finditer(text):
        out.add(match.group(2))
    for match in _IMPORT_KT_RE.finditer(text):
        out.add(match.group(1))
    return out


def _extract_annotations(text: str) -> set[str]:
    return {match.group(1) for match in _ANNOTATION_RE.finditer(text)}


def _extract_reflective_classnames(text: str) -> set[str]:
    out: set[str] = set()
    for match in _CLASS_FORNAME_RE.finditer(text):
        out.add(match.group(1))
    for match in _LOAD_CLASS_RE.finditer(text):
        out.add(match.group(1))
    return out


def _is_valid_java_identifier(name: str) -> bool:
    """Strict Java fully-qualified identifier check.

    Rejects empty strings, names starting with a digit, names containing
    shell metacharacters, whitespace, NUL bytes, or path components.
    This is the gate that keeps ``_invoke_javap_safe`` safe from shell
    / argv injection (SEC-NEW-09).
    """
    if not name or "\x00" in name:
        return False
    if not _JAVA_IDENT_RE.match(name):
        return False
    return True


# Public alias — some tests (and REQ-6 fixture code) may reach for the
# list of JAR entries directly.
__all__ = ["JvmSourceAnalyser", "safe_jar_entries"]
