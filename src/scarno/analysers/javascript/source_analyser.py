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

"""JavaScript / TypeScript / Node.js source analyser — REQ-11.

Uses tree-sitter-javascript + tree-sitter-typescript to walk `.js`,
`.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts`, `.cts` ASTs. Extracts
ESM static / dynamic imports, CJS `require` calls, TypeScript
triple-slash references, and promotes the existing REQ-3b phantom /
undeclared detection to the npm ecosystem.

Safety:
  * Grammars loaded optionally — fall back to empty-facts / no-op when
    unavailable (REQ-11 graceful-degradation).
  * Every file bounded by ``MAX_FILE_BYTES`` + AST-parse exception
    catch.
  * No dynamic ``import()`` is ever executed — strictly static
    inspection (SEC-001 analogue).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from scarno.models import Dependency, DependencyStatus, EntryPoint
from scarno.security import MAX_FILE_BYTES, PathEscapeError, resolve_and_confine

if TYPE_CHECKING:
    from scarno.core.test_scope import TestScopeMatcher

# Try to load tree-sitter grammars; graceful fallback on import failure.
try:  # pragma: no cover — host-specific import path
    import tree_sitter as _ts
    import tree_sitter_javascript as _ts_js
    import tree_sitter_typescript as _ts_tsx

    _JS_LANG = _ts.Language(_ts_js.language())
    _TS_LANG = _ts.Language(_ts_tsx.language_typescript())
    _TSX_LANG = _ts.Language(_ts_tsx.language_tsx())
    _JS_PARSER = _ts.Parser(_JS_LANG)
    _TS_PARSER = _ts.Parser(_TS_LANG)
    _TSX_PARSER = _ts.Parser(_TSX_LANG)
    JS_AST_AVAILABLE = True
except Exception:  # noqa: BLE001 — optional
    _JS_PARSER = None  # type: ignore[assignment]
    _TS_PARSER = None  # type: ignore[assignment]
    _TSX_PARSER = None  # type: ignore[assignment]
    JS_AST_AVAILABLE = False


# Node.js core modules — the JavaScript equivalent of Python's
# ``sys.stdlib_module_names``. Imports of these (with or without the
# ``node:`` prefix) must NOT be treated as UNDECLARED deps.
_NODE_CORE_MODULES: frozenset[str] = frozenset(
    {
        "assert", "async_hooks", "buffer", "child_process", "cluster",
        "console", "constants", "crypto", "dgram", "diagnostics_channel",
        "dns", "domain", "events", "fs", "http", "http2", "https",
        "inspector", "module", "net", "os", "path", "perf_hooks",
        "process", "punycode", "querystring", "readline", "repl",
        "stream", "string_decoder", "sys", "test", "timers", "tls",
        "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
        "worker_threads", "zlib",
    }
)

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "coverage",
        ".turbo",
        ".cache",
    }
)

_TS_REFERENCE_RE = re.compile(
    r"""///\s*<reference\s+
        (?P<kind>types|path|lib)\s*=\s*
        (?P<quote>["'])(?P<target>[^"']+)(?P=quote)""",
    re.VERBOSE,
)


@dataclass
class _Facts:
    static_imports: set[str] = field(default_factory=set)
    dynamic_literals: set[str] = field(default_factory=set)
    has_nonliteral_dynamic: bool = False
    reference_types: set[str] = field(default_factory=set)
    # FR-110: raw import specifiers before package-name normalization,
    # needed for entry-point matching (e.g. "lodash/merge" stays intact).
    raw_import_specifiers: set[str] = field(default_factory=set)
    # REQ-17 / FR-150: per-specifier import-site counts (one increment
    # per `import "..."` / `require("...")` / `import("...")` site).
    import_specifier_counts: dict[str, int] = field(default_factory=dict)
    # FR-150 — local-name → owning package. Populated from named
    # (``import { foo } from "x"``), default (``import x from "y"``),
    # and namespace (``import * as ns from "z"``) imports. Drives
    # per-symbol attribution and instance-method type binding.
    name_to_package: dict[str, str] = field(default_factory=dict)
    # FR-150 — local-name → original-export name (for renamed imports
    # like ``import { foo as bar }``). The export name is what the
    # entry-point resolver matches against ``package.json`` ``exports``.
    name_to_symbol: dict[str, str] = field(default_factory=dict)
    # FR-150 — namespace import locals (``import * as ns from "x"``).
    # Member access like ``ns.foo()`` is attributed to ``x.foo``.
    namespace_locals: dict[str, str] = field(default_factory=dict)
    # FR-150 — per-(package, symbol) bare-name reference count.
    # Bumped by every Name LOAD that resolves through name_to_symbol.
    symbol_call_counts: dict[tuple[str, str], int] = field(default_factory=dict)
    # FR-150 — per-(package, class, method) instance-method call count.
    method_call_counts: dict[tuple[str, str, str], int] = field(default_factory=dict)
    # FR-150 — per-(package, class) constructor call count.
    constructor_counts: dict[tuple[str, str], int] = field(default_factory=dict)
    # FR-150 — local-name → bound class name for instance-method
    # attribution. Populated from ``const x = new Foo()`` and
    # ``const x: Foo = …`` and TS function-parameter annotations.
    variable_class: dict[str, str] = field(default_factory=dict)
    # REQ-18 / FR-181 — TypeScript ``import type`` distinction.
    # Stored as ``(package, original_export)`` tuples so the resolver
    # can emit ``kind="type-only"`` rows that don't pollute runtime
    # symbol counts.
    type_only_specifiers: set[tuple[str, str]] = field(default_factory=set)
    # REQ-18 / FR-182 — modules covered by an ambient
    # ``declare module "x" { … }`` block in a project ``.d.ts`` file.
    # Treated as a type-only declaration of ``x``.
    ambient_modules: set[str] = field(default_factory=set)
    # REQ-18 / FR-183 — TypeScript decorator call counts keyed by
    # ``(package, decorator_name)``. ``@Component(...)`` after
    # ``import { Component } from "@nestjs/common"`` increments
    # ``("@nestjs/common", "Component")``.
    decorator_counts: dict[tuple[str, str], int] = field(default_factory=dict)


# ── Public entry point ─────────────────────────────────────────────────────


def analyse_npm_sources(
    project_path: str,
    dependencies: list[Dependency],
    *,
    exclude_tests: bool = False,
    user_test_paths: tuple[str, ...] = (),
) -> tuple[list[Dependency], list[str]]:
    """Classify each npm dep as IN_USE / UNCERTAIN / SAFE / UNDECLARED."""
    from scarno.core.test_scope import TestScopeMatcher

    errors: list[str] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"js source: could not resolve path — {exc}")
        return list(dependencies), errors
    if not root.is_dir():
        return list(dependencies), errors

    test_matcher = TestScopeMatcher(
        "javascript",
        exclude_tests=exclude_tests,
        user_patterns=user_test_paths,
    )
    facts = _scan_tree(root, errors, test_matcher=test_matcher)
    tsconfig_paths = _load_tsconfig_paths(root, errors)

    # Every import target that matches a tsconfig-path mapping is a local
    # file reference, not an npm package — drop them early.
    def _is_local_alias(target: str) -> bool:
        for alias in tsconfig_paths:
            if target == alias or target.startswith(alias + "/"):
                return True
        return False

    filtered_static = {
        imp for imp in facts.static_imports if not _is_local_alias(imp)
    }
    filtered_dynamic = {
        imp for imp in facts.dynamic_literals if not _is_local_alias(imp)
    }

    declared = {dep.name for dep in dependencies if dep.ecosystem == "npm"}
    matched_imports: set[str] = set()
    # REQ-18 / FR-182 — modules covered by a project ``declare module
    # "x"`` ambient block contribute to runtime classification too,
    # since the project wouldn't write ambient types for an unused
    # package.
    filtered_static = filtered_static | facts.ambient_modules

    updated: list[Dependency] = []
    # REQ-18 / FR-180 — for @types/X stubs, classify IN_USE iff the
    # paired runtime package is declared AND in use. The pairing
    # information was set on the Dependency by the dep parser
    # (``is_type_stub=True`` plus a reason naming the runtime).
    runtime_in_use: set[str] = {
        dep.name for dep in dependencies
        if dep.ecosystem == "npm"
        and not dep.is_type_stub
        and _classify(dep.name, filtered_static, filtered_dynamic,
                      facts.has_nonliteral_dynamic)[0]
            is DependencyStatus.IN_USE
    }
    for dep in dependencies:
        if dep.ecosystem != "npm":
            updated.append(dep)
            continue
        # FR-180 — @types/X classification overrides the regular
        # `_classify` output when the stub is declared.
        if dep.is_type_stub:
            from scarno.analysers.javascript.dep_file_parser import (
                _runtime_target_for_types_stub,
            )
            runtime_target = _runtime_target_for_types_stub(dep.name) or ""
            if runtime_target in runtime_in_use:
                status = DependencyStatus.IN_USE
                reason = (
                    f"type stubs for '{runtime_target}' which is "
                    f"declared and in use"
                )
            elif runtime_target:
                status = DependencyStatus.SAFE
                reason = (
                    f"type stub for '{runtime_target}' but runtime "
                    f"package not declared — manual review required"
                )
            else:
                status, reason = _classify(
                    dep.name, filtered_static, filtered_dynamic,
                    facts.has_nonliteral_dynamic,
                )
            updated.append(
                Dependency(
                    name=dep.name, version=dep.version,
                    status=status, reason=reason,
                    entry_points=list(dep.entry_points),
                    entry_points_used=dep.entry_points_used,
                    entry_points_total=dep.entry_points_total,
                    source=dep.source, vendored_path=dep.vendored_path,
                    resolved=dep.resolved, is_type_stub=True,
                    ecosystem=dep.ecosystem,
                    is_transitive=dep.is_transitive,
                    # REQ-23 — propagate pin-override flags set by the
                    # npm overrides detector in parse_all_npm_dependency_files.
                    pin_override=dep.pin_override,
                    pin_override_kind=dep.pin_override_kind,
                    pin_override_target=dep.pin_override_target,
                )
            )
            continue
        status, reason = _classify(
            dep.name, filtered_static, filtered_dynamic, facts.has_nonliteral_dynamic
        )
        if status is DependencyStatus.IN_USE:
            matched_imports.add(dep.name)

        # FR-110 — entry-point resolution from node_modules exports.
        # FR-150 — augment with per-specifier usage counts so the user
        # can see how often each export is referenced.
        ep_list, ep_used, ep_total = _resolve_entry_points(
            root, dep.name, facts.raw_import_specifiers,
            specifier_counts=facts.import_specifier_counts,
            symbol_calls=facts.symbol_call_counts,
            method_calls=facts.method_call_counts,
            constructor_calls=facts.constructor_counts,
            name_to_package=facts.name_to_package,
            type_only_specifiers=facts.type_only_specifiers,
            decorator_counts=facts.decorator_counts,
            ambient_modules=facts.ambient_modules,
        )

        updated.append(
            Dependency(
                name=dep.name,
                version=dep.version,
                status=status,
                reason=reason,
                entry_points=ep_list if ep_list else dep.entry_points,
                entry_points_used=ep_used if ep_total > 0 else dep.entry_points_used,
                entry_points_total=ep_total if ep_total > 0 else dep.entry_points_total,
                source=dep.source,
                vendored_path=dep.vendored_path,
                resolved=dep.resolved,
                is_type_stub=dep.is_type_stub,
                ecosystem=dep.ecosystem,
                # REQ-23 — propagate pin-override flags from the
                # parser's npm overrides detector.
                pin_override=dep.pin_override,
                pin_override_kind=dep.pin_override_kind,
                pin_override_target=dep.pin_override_target,
            )
        )

    # REQ-3b analogue — phantom imports (imports with no declaration)
    phantoms = _build_phantom_deps(
        filtered_static, matched_imports, declared
    )
    updated.extend(phantoms)
    return updated, errors


def _scan_tree(
    root: Path,
    errors: list[str],
    *,
    test_matcher: "TestScopeMatcher | None" = None,
) -> _Facts:
    facts = _Facts()
    if not JS_AST_AVAILABLE:
        return facts
    for pattern in ("*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.tsx", "*.mts", "*.cts"):
        for raw_path in root.rglob(pattern):
            rel_parts = raw_path.relative_to(root).parts
            if any(p in _EXCLUDED_DIR_NAMES for p in rel_parts):
                continue
            if test_matcher is not None:
                rel_path_str = "/".join(rel_parts)
                if test_matcher.is_test_path(rel_path_str):
                    continue
            try:
                resolved = resolve_and_confine(raw_path, root)
            except PathEscapeError:
                errors.append(
                    f"js source: symlink escape blocked: {'/'.join(rel_parts)}"
                )
                continue
            try:
                size = resolved.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                errors.append(f"js source: skipped {resolved.name} — too large")
                continue
            try:
                source_bytes = resolved.read_bytes()
            except OSError as exc:
                errors.append(f"js source: read failed {resolved.name} — {exc}")
                continue
            _scan_file(source_bytes, pattern, facts, errors, resolved.name)
    return facts


def _scan_file(
    source: bytes,
    pattern: str,
    facts: _Facts,
    errors: list[str],
    filename: str,
) -> None:
    parser = _select_parser(pattern)
    if parser is None:
        return
    try:
        tree = parser.parse(source)
    except Exception as exc:  # noqa: BLE001 — any grammar failure
        errors.append(f"js source: parse failed for {filename} — {exc}")
        return
    _walk(tree.root_node, facts)


def _select_parser(pattern: str):  # type: ignore[no-untyped-def]
    if not JS_AST_AVAILABLE:
        return None
    if pattern in ("*.ts", "*.mts", "*.cts"):
        return _TS_PARSER
    if pattern == "*.tsx":
        return _TSX_PARSER
    return _JS_PARSER


def _walk(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    t = node.type
    if t == "comment":
        _extract_ts_reference(node, facts)
        return
    if t == "string":
        # Never descend into a string literal — preserves the "no match
        # inside strings" semantic (REQ-6b analogue for JS).
        return
    if t == "import_statement":
        _extract_static_import(node, facts)
        # Don't recurse — children have been handled.
        return
    if t == "call_expression":
        _extract_call_expression(node, facts)
        # Continue descending — nested call expressions are legal.
    if t == "new_expression":
        _record_new_expression(node, facts)
    if t == "member_expression":
        _record_member_expression(node, facts)
    if t == "identifier":
        _record_identifier_ref(node, facts)
    if t in {"lexical_declaration", "variable_declaration"}:
        _record_variable_declarations(node, facts)
    if t in {"required_parameter", "optional_parameter", "formal_parameter"}:
        _record_typed_parameter(node, facts)
    if t == "decorator":
        _record_decorator(node, facts)
    if t == "ambient_declaration":
        _record_ambient_declaration(node, facts)
    for child in node.children:
        _walk(child, facts)


def _record_decorator(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """REQ-18 / FR-183 — record TypeScript decorator usage.

    The decorator's expression is either:
      * ``@Foo`` (arg-less, ``identifier`` child), or
      * ``@Foo(...)`` (``call_expression`` whose first child is the
        decorator name).
    """
    name: str | None = None
    for child in node.children:
        if child.type == "identifier":
            name = _node_text(child)
            break
        if child.type == "call_expression":
            if child.children and child.children[0].type == "identifier":
                name = _node_text(child.children[0])
            break
    if not name:
        return
    pkg = facts.name_to_package.get(name)
    if not pkg:
        return
    facts.decorator_counts[(pkg, name)] = (
        facts.decorator_counts.get((pkg, name), 0) + 1
    )


def _record_ambient_declaration(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """REQ-18 / FR-182 — record ``declare module "x" { … }`` blocks
    found in project ``.d.ts`` files.

    Tree-sitter shape:

    ``ambient_declaration``
      ``declare``
      ``module``
        ``module`` (literal keyword)
        ``string`` (the module name)
        ``statement_block`` (the type surface)

    We treat the module name as a type-only declaration of ``x``: the
    module is in use *for typing*, but no runtime import has been
    observed. Downstream classification can lift this to ``IN_USE``
    with a type-only reason.
    """
    for child in node.children:
        if child.type != "module":
            continue
        for sub in child.children:
            if sub.type == "string":
                literal = _extract_string_literal(sub)
                package = _extract_package_name(literal) if literal else None
                if package:
                    facts.ambient_modules.add(package)
        return


def _extract_static_import(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """Record both the package literal AND each binding (named, default,
    namespace) so per-symbol attribution downstream can resolve.

    REQ-18 / FR-181: detect ``import type … from "x"`` (whole-import
    type-only form) by checking for a top-level ``type`` token between
    ``import`` and ``import_clause``.
    """
    package: str | None = None
    clause_node = None
    whole_import_is_type_only = False
    for child in node.children:
        if child.type == "type":
            whole_import_is_type_only = True
        elif child.type == "string":
            literal = _extract_string_literal(child)
            if literal:
                package = _extract_package_name(literal)
                if package:
                    facts.static_imports.add(package)
                    facts.raw_import_specifiers.add(literal)
                    facts.import_specifier_counts[literal] = (
                        facts.import_specifier_counts.get(literal, 0) + 1
                    )
        elif child.type == "import_clause":
            clause_node = child
    if package is None or clause_node is None:
        return
    _extract_import_clause(
        clause_node, package, facts,
        whole_import_is_type_only=whole_import_is_type_only,
    )


def _extract_import_clause(  # type: ignore[no-untyped-def]
    clause, package: str, facts: _Facts,
    *, whole_import_is_type_only: bool = False,
) -> None:
    """Walk an ``import_clause``: default, named, and namespace bindings.

    ``whole_import_is_type_only`` is True for ``import type … from "x"``
    forms; per-specifier ``type`` keywords are handled inside
    ``_record_import_specifier``.
    """
    for child in clause.children:
        ct = child.type
        if ct == "identifier":
            # Default import: ``import Foo from "x"``.
            local = _node_text(child)
            if local:
                facts.name_to_package[local] = package
                facts.name_to_symbol[local] = "default"
                if whole_import_is_type_only:
                    facts.type_only_specifiers.add((package, "default"))
        elif ct == "namespace_import":
            # ``import * as ns from "x"`` — last identifier is the local.
            for sub in child.children:
                if sub.type == "identifier":
                    local = _node_text(sub)
                    if local:
                        facts.namespace_locals[local] = package
                        if whole_import_is_type_only:
                            facts.type_only_specifiers.add(
                                (package, local)
                            )
        elif ct == "named_imports":
            for spec in child.children:
                if spec.type == "import_specifier":
                    _record_import_specifier(
                        spec, package, facts,
                        whole_import_is_type_only=whole_import_is_type_only,
                    )


def _record_import_specifier(  # type: ignore[no-untyped-def]
    spec, package: str, facts: _Facts,
    *, whole_import_is_type_only: bool = False,
) -> None:
    """Handle ``import { foo }`` / ``import { foo as bar }`` /
    ``import { type foo }`` / ``import type { foo }``.

    Per-specifier type-only is signalled by a ``type`` child token in
    the ``import_specifier`` node.
    """
    idents = [c for c in spec.children if c.type == "identifier"]
    if not idents:
        return
    per_specifier_type = any(c.type == "type" for c in spec.children)
    if len(idents) == 1:
        local = _node_text(idents[0])
        export = local
    else:
        # ``foo as bar`` — first ident is export name, last is local alias.
        export = _node_text(idents[0])
        local = _node_text(idents[-1])
    if local and export:
        facts.name_to_package[local] = package
        facts.name_to_symbol[local] = export
        if whole_import_is_type_only or per_specifier_type:
            facts.type_only_specifiers.add((package, export))


def _record_new_expression(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``new Foo(args)`` — bump ``constructor_counts`` if Foo is imported."""
    callee = None
    for child in node.children:
        if child.type in {"identifier", "member_expression"}:
            callee = child
            break
    if callee is None:
        return
    cls_name: str | None = None
    pkg: str | None = None
    if callee.type == "identifier":
        cls_name = _node_text(callee)
        pkg = facts.name_to_package.get(cls_name or "")
    elif callee.type == "member_expression":
        # ``new ns.Foo(...)`` — only attribute when the receiver is a
        # known namespace-import alias.
        receiver, prop = _split_member(callee)
        if receiver and prop and receiver in facts.namespace_locals:
            pkg = facts.namespace_locals[receiver]
            cls_name = prop
    if pkg and cls_name:
        key = (pkg, cls_name)
        facts.constructor_counts[key] = (
            facts.constructor_counts.get(key, 0) + 1
        )


def _split_member(node) -> tuple[str, str]:  # type: ignore[no-untyped-def]
    """Return ``(receiver_text, property_text)`` for a ``member_expression``."""
    receiver = ""
    prop = ""
    for child in node.children:
        if child.type == "identifier" and not receiver:
            receiver = _node_text(child)
        elif child.type == "property_identifier":
            prop = _node_text(child)
    return receiver, prop


def _record_member_expression(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``obj.method`` — attribute when ``obj`` is imported / typed."""
    receiver, prop = _split_member(node)
    if not receiver or not prop:
        return
    # Namespace import: ``ns.foo`` → bump (pkg, foo).
    if receiver in facts.namespace_locals:
        pkg = facts.namespace_locals[receiver]
        key_s = (pkg, prop)
        facts.symbol_call_counts[key_s] = (
            facts.symbol_call_counts.get(key_s, 0) + 1
        )
        return
    # Default/static usage: ``Lodash.chunk`` after ``import Lodash from "lodash"``.
    if receiver in facts.name_to_package:
        pkg = facts.name_to_package[receiver]
        key_s = (pkg, prop)
        facts.symbol_call_counts[key_s] = (
            facts.symbol_call_counts.get(key_s, 0) + 1
        )
        return
    # Instance call: ``c.set`` after ``const c = new Redis()`` /
    # ``const c: Redis = …`` / ``function f(c: Redis)``.
    cls = facts.variable_class.get(receiver)
    if cls is not None:
        pkg_cls = facts.name_to_package.get(cls)
        if pkg_cls is not None:
            key_m = (pkg_cls, cls, prop)
            facts.method_call_counts[key_m] = (
                facts.method_call_counts.get(key_m, 0) + 1
            )


def _record_identifier_ref(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """Bare ``foo()`` after ``import { foo } from "x"`` increments
    ``symbol_call_counts[(x, foo)]``.

    To avoid double-counting, we only increment when the parent isn't a
    member access whose object is THIS identifier (handled by
    :func:`_record_member_expression`) and not the import_specifier
    itself.
    """
    parent = node.parent  # tree-sitter exposes parent
    if parent is None:
        return
    if parent.type in {
        "import_specifier",
        "named_imports",
        "namespace_import",
        "import_clause",
    }:
        return
    # Skip when the identifier is the *object* of a member_expression
    # (the member walker handles ``obj.x`` access).
    if parent.type == "member_expression":
        # Children order: object, ".", property_identifier. If we are
        # the object position, skip — it'll be handled there.
        first_id = next(
            (c for c in parent.children if c.type == "identifier"),
            None,
        )
        if first_id is node:
            return
    name = _node_text(node)
    sym = facts.name_to_symbol.get(name)
    pkg = facts.name_to_package.get(name)
    if sym is not None and pkg is not None:
        key = (pkg, sym)
        facts.symbol_call_counts[key] = (
            facts.symbol_call_counts.get(key, 0) + 1
        )


def _record_variable_declarations(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``const x = new Foo();`` / ``const x: Foo = …;`` — bind x → Foo."""
    for child in node.children:
        if child.type == "variable_declarator":
            _record_one_declarator(child, facts)


def _record_one_declarator(decl, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """Pull out the variable name + (RHS class name OR TS annotation)."""
    name = ""
    type_anno_text: str | None = None
    rhs_cls: str | None = None
    for child in decl.children:
        ct = child.type
        if ct == "identifier" and not name:
            name = _node_text(child)
        elif ct == "type_annotation":
            type_anno_text = _extract_type_annotation_simple(child)
        elif ct == "new_expression":
            # RHS is `new Foo(...)` — take Foo as the class.
            for sub in child.children:
                if sub.type == "identifier":
                    rhs_cls = _node_text(sub)
                    break
                if sub.type == "member_expression":
                    _, prop = _split_member(sub)
                    if prop:
                        rhs_cls = prop
                    break
    if not name:
        return
    bound = type_anno_text or rhs_cls
    if bound:
        facts.variable_class[name] = bound


def _extract_type_annotation_simple(node) -> str | None:  # type: ignore[no-untyped-def]
    """Return the bare class simple name from a TS type annotation, or None.

    Handles ``: Foo``, ``: lib.Foo``, ``: Foo<X>`` (generic peeled). Falls
    back to the last identifier when the type has multiple segments.
    """
    # Walk to find a type_identifier or generic_type or type_reference.
    candidates: list[str] = []
    stack = list(node.children)
    while stack:
        n = stack.pop()
        if n.type in {"type_identifier"}:
            candidates.append(_node_text(n))
            continue
        # ``predefined_type`` (string/number/boolean) → not a class.
        if n.type == "predefined_type":
            return None
        stack.extend(n.children)
    if not candidates:
        return None
    return candidates[-1]


def _record_typed_parameter(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``function f(x: Foo)`` and ``(x: Foo) => …`` — bind x → Foo."""
    name = ""
    type_anno_text: str | None = None
    for child in node.children:
        ct = child.type
        if ct == "identifier" and not name:
            name = _node_text(child)
        elif ct == "type_annotation":
            type_anno_text = _extract_type_annotation_simple(child)
    if name and type_anno_text:
        facts.variable_class[name] = type_anno_text


def _extract_call_expression(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    callee_type = node.children[0].type if node.children else ""
    callee_text = _node_text(node.children[0]) if node.children else ""
    # ``require('x')`` / ``require.resolve('x')`` / ``import('x')``
    if callee_text in {"require", "require.resolve"}:
        _record_dynamic_first_arg(node, facts)
    elif callee_type == "import":
        # dynamic `import('x')` — ES module syntax
        _record_dynamic_first_arg(node, facts)


def _record_dynamic_first_arg(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    args = _find_child(node, "arguments")
    if args is None:
        return
    first_arg = None
    for child in args.children:
        if child.type in {"string", "identifier", "template_string", "binary_expression"}:
            first_arg = child
            break
    if first_arg is None:
        return
    if first_arg.type == "string":
        literal = _extract_string_literal(first_arg)
        package = _extract_package_name(literal)
        if package:
            facts.dynamic_literals.add(package)
            facts.import_specifier_counts[literal] = (
                facts.import_specifier_counts.get(literal, 0) + 1
            )
        return
    facts.has_nonliteral_dynamic = True


def _extract_ts_reference(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    text = _node_text(node)
    for match in _TS_REFERENCE_RE.finditer(text):
        if match.group("kind") == "types":
            facts.reference_types.add(match.group("target"))


# ── Node helpers ───────────────────────────────────────────────────────────


def _node_text(node) -> str:  # type: ignore[no-untyped-def]
    t = node.text
    if t is None:
        return ""
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else t


def _find_child(node, name: str):  # type: ignore[no-untyped-def]
    for child in node.children:
        if child.type == name:
            return child
    return None


def _extract_string_literal(node) -> str:  # type: ignore[no-untyped-def]
    parts: list[str] = []
    for child in node.children:
        if child.type in {"string_fragment", "string_content"}:
            parts.append(_node_text(child))
    if parts:
        return "".join(parts)
    return _node_text(node).strip("\"'`")


# ── Package-name normalisation ─────────────────────────────────────────────


def _extract_package_name(specifier: str) -> str | None:
    """Turn an import specifier into an npm package name (or None)."""
    if not specifier:
        return None
    # Local files / absolute paths / URLs / Node built-ins
    if specifier.startswith(("./", "../", "/")):
        return None
    if "://" in specifier:
        return None
    bare = specifier[len("node:") :] if specifier.startswith("node:") else specifier
    top = bare.split("/", 1)[0] if not bare.startswith("@") else "/".join(bare.split("/")[:2])
    if top in _NODE_CORE_MODULES or bare.split("/", 1)[0] in _NODE_CORE_MODULES:
        return None
    return top


# ── tsconfig.json paths ────────────────────────────────────────────────────


def _load_tsconfig_paths(root: Path, errors: list[str]) -> set[str]:
    path = root / "tsconfig.json"
    if not path.exists():
        return set()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"tsconfig.json: read failed — {exc}")
        return set()
    cleaned = _strip_json_comments_simple(text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        errors.append(f"tsconfig.json: JSON parse error — {exc}")
        return set()
    if not isinstance(data, dict):
        return set()
    compiler = data.get("compilerOptions")
    if not isinstance(compiler, dict):
        return set()
    paths = compiler.get("paths")
    if not isinstance(paths, dict):
        return set()
    aliases: set[str] = set()
    for key in paths:
        if not isinstance(key, str):
            continue
        # Strip trailing wildcard — `@/*` → `@`
        alias = key.rstrip("/*")
        if alias:
            aliases.add(alias)
    return aliases


def _strip_json_comments_simple(text: str) -> str:
    # Minimal JSONC stripper — the full one lives in dep_file_parser;
    # avoid importing to keep this module standalone.
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            if text[i + 1] == "/":
                end = text.find("\n", i)
                if end < 0:
                    return "".join(out)
                i = end
                continue
            if text[i + 1] == "*":
                end = text.find("*/", i + 2)
                if end < 0:
                    return "".join(out)
                i = end + 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


# ── Classification ─────────────────────────────────────────────────────────


def _classify(
    name: str,
    static: set[str],
    dynamic: set[str],
    has_nonliteral: bool,
) -> tuple[DependencyStatus, str]:
    if name in static:
        return DependencyStatus.IN_USE, f"imported as '{name}' in project source"
    if name in dynamic:
        return (
            DependencyStatus.IN_USE,
            f"dynamically imported via require/import('{name}')",
        )
    if has_nonliteral:
        return (
            DependencyStatus.UNCERTAIN,
            "dynamic import with non-literal module name — manual review required",
        )
    return DependencyStatus.SAFE, "no import or usage found in source files"


# ── FR-110 — entry-point resolution ───────────────────────────────────────


def _resolve_entry_points(
    root: Path,
    package_name: str,
    all_imports: set[str],
    *,
    specifier_counts: dict[str, int] | None = None,
    symbol_calls: dict[tuple[str, str], int] | None = None,
    method_calls: dict[tuple[str, str, str], int] | None = None,
    constructor_calls: dict[tuple[str, str], int] | None = None,
    name_to_package: dict[str, str] | None = None,
    type_only_specifiers: set[tuple[str, str]] | None = None,
    decorator_counts: dict[tuple[str, str], int] | None = None,
    ambient_modules: set[str] | None = None,
) -> tuple[list[EntryPoint], int, int]:
    """Read ``node_modules/<pkg>/package.json`` ``exports`` field and
    compute how many export paths are imported in project source.

    REQ-17 (FR-150): when ``specifier_counts`` is provided, each
    EntryPoint also carries a ``usage_count`` summed across every import
    site that resolves to that export.

    When the package has no ``exports`` field, fall back to surfacing
    each *raw import specifier* the project uses for this package as a
    synthetic entry point. This guarantees that any ``IN_USE`` dep
    surfaces *something* the user can read — addressing the "I can see
    the dep name but not which classes/methods are in use" gap.

    Returns ``(entry_point_list, used_count, total_count)``.
    """
    counts = specifier_counts or {}

    def _count_for_path(import_path: str) -> int:
        # Sum over every raw specifier that resolves to this export path
        # — direct hit, or the prefix form ``<path>/sub``.
        total = 0
        for spec, n in counts.items():
            if spec == import_path or spec.startswith(import_path + "/"):
                total += n
        return total

    # SEC-002 — confine the constructed path to the project root before
    # reading. The dep parser already validates names against the npm
    # spec, so this is defence-in-depth: if any future call site forgets
    # to validate, an attacker-controlled ``..`` segment still cannot
    # escape ``root``.
    pkg_json_raw = root / "node_modules" / package_name / "package.json"
    try:
        pkg_json = resolve_and_confine(pkg_json_raw, root)
    except PathEscapeError:
        return _synthesise_entry_points_from_specifiers(
            package_name, all_imports, counts,
            symbol_calls=symbol_calls,
            method_calls=method_calls,
            constructor_calls=constructor_calls,
            type_only_specifiers=type_only_specifiers,
            decorator_counts=decorator_counts,
            ambient_modules=ambient_modules,
        )
    if not pkg_json.is_file():
        return _synthesise_entry_points_from_specifiers(
            package_name, all_imports, counts,
            symbol_calls=symbol_calls,
            method_calls=method_calls,
            constructor_calls=constructor_calls,
            type_only_specifiers=type_only_specifiers,
            decorator_counts=decorator_counts,
            ambient_modules=ambient_modules,
        )
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _synthesise_entry_points_from_specifiers(
            package_name, all_imports, counts,
            symbol_calls=symbol_calls,
            method_calls=method_calls,
            constructor_calls=constructor_calls,
            type_only_specifiers=type_only_specifiers,
            decorator_counts=decorator_counts,
            ambient_modules=ambient_modules,
        )
    if not isinstance(data, dict):
        return _synthesise_entry_points_from_specifiers(
            package_name, all_imports, counts,
            symbol_calls=symbol_calls,
            method_calls=method_calls,
            constructor_calls=constructor_calls,
            type_only_specifiers=type_only_specifiers,
            decorator_counts=decorator_counts,
            ambient_modules=ambient_modules,
        )

    exports = data.get("exports")
    if not isinstance(exports, dict):
        return _synthesise_entry_points_from_specifiers(
            package_name, all_imports, counts,
            symbol_calls=symbol_calls,
            method_calls=method_calls,
            constructor_calls=constructor_calls,
            type_only_specifiers=type_only_specifiers,
            decorator_counts=decorator_counts,
            ambient_modules=ambient_modules,
        )

    entries: list[EntryPoint] = []
    used = 0
    for key in exports:
        if not isinstance(key, str):
            continue
        # Normalise export key: "." → package root, "./sub" → package/sub
        if key == ".":
            import_path = package_name
        elif key.startswith("./"):
            import_path = f"{package_name}/{key[2:]}"
        else:
            import_path = f"{package_name}/{key}"

        is_used = import_path in all_imports or any(
            imp.startswith(import_path + "/") for imp in all_imports
        )
        if is_used:
            used += 1
        usage_count = _count_for_path(import_path) if is_used else 0
        entries.append(
            EntryPoint(
                name=key, kind="export", used=is_used, usage_count=usage_count,
            )
        )

    # FR-150 — augment with per-symbol / method / constructor entries.
    seen_names = {ep.name for ep in entries}
    extra = _synthesise_symbol_method_ctor_entries(
        package_name,
        symbol_calls=symbol_calls,
        method_calls=method_calls,
        constructor_calls=constructor_calls,
        seen_names=seen_names,
        type_only_specifiers=type_only_specifiers,
        decorator_counts=decorator_counts,
        ambient_modules=ambient_modules,
    )
    entries.extend(extra)
    used = sum(1 for ep in entries if ep.used)
    return entries, used, len(entries)


def _synthesise_symbol_method_ctor_entries(
    package_name: str,
    *,
    symbol_calls: dict[tuple[str, str], int] | None,
    method_calls: dict[tuple[str, str, str], int] | None,
    constructor_calls: dict[tuple[str, str], int] | None,
    seen_names: set[str],
    type_only_specifiers: set[tuple[str, str]] | None = None,
    decorator_counts: dict[tuple[str, str], int] | None = None,
    ambient_modules: set[str] | None = None,
) -> list[EntryPoint]:
    """Build per-symbol / method / constructor entry points for a dep.

    These complement the ``exports``-derived rows: they reflect actual
    source-level use even when ``exports`` is absent or doesn't enumerate
    the imported symbol. Dedups against ``seen_names`` to avoid clashing
    with ``exports`` entries.
    """
    out: list[EntryPoint] = []
    sym_counts = symbol_calls or {}
    method_counts = method_calls or {}
    ctor_counts = constructor_calls or {}

    for (pkg, sym), n in sorted(sym_counts.items()):
        if pkg != package_name or n <= 0:
            continue
        label = f"{package_name}.{sym}"
        if label in seen_names:
            continue
        seen_names.add(label)
        out.append(
            EntryPoint(
                name=label,
                kind="function",
                used=True,
                usage_count=n,
            )
        )
    for (pkg, cls), n in sorted(ctor_counts.items()):
        if pkg != package_name or n <= 0:
            continue
        label = f"new {cls}()"
        if label in seen_names:
            continue
        seen_names.add(label)
        out.append(
            EntryPoint(
                name=label,
                kind="constructor",
                used=True,
                usage_count=n,
            )
        )
    for (pkg, cls, method), n in sorted(method_counts.items()):
        if pkg != package_name or n <= 0:
            continue
        label = f"{cls}.{method}"
        if label in seen_names:
            continue
        seen_names.add(label)
        out.append(
            EntryPoint(
                name=label,
                kind="method",
                used=True,
                usage_count=n,
            )
        )
    # FR-181 — emit one ``kind="type-only"`` row per (package, symbol)
    # in ``type_only_specifiers`` for this package. These complement
    # the runtime-call entries above so the user can see at a glance
    # which symbols are imported as types only.
    type_specs = type_only_specifiers or set()
    for pkg, sym in sorted(type_specs):
        if pkg != package_name:
            continue
        label = f"{package_name}.{sym}"
        type_label = f"type {label}"
        if type_label in seen_names:
            continue
        seen_names.add(type_label)
        out.append(
            EntryPoint(
                name=type_label,
                kind="type-only",
                used=True,
                usage_count=1,
            )
        )
    # FR-183 — TypeScript decorator usage counts.
    decorators = decorator_counts or {}
    for (pkg, dec), n in sorted(decorators.items()):
        if pkg != package_name or n <= 0:
            continue
        label = f"@{dec}"
        if label in seen_names:
            continue
        seen_names.add(label)
        out.append(
            EntryPoint(
                name=label,
                kind="decorator",
                used=True,
                usage_count=n,
            )
        )
    # FR-182 — `.d.ts` ambient ``declare module "x"`` declarations.
    ambient = ambient_modules or set()
    if package_name in ambient:
        label = f"declare module \"{package_name}\""
        if label not in seen_names:
            seen_names.add(label)
            out.append(
                EntryPoint(
                    name=label,
                    kind="ambient-module",
                    used=True,
                    usage_count=1,
                )
            )
    return out


def _synthesise_entry_points_from_specifiers(
    package_name: str,
    all_imports: set[str],
    counts: dict[str, int],
    *,
    symbol_calls: dict[tuple[str, str], int] | None = None,
    method_calls: dict[tuple[str, str, str], int] | None = None,
    constructor_calls: dict[tuple[str, str], int] | None = None,
    type_only_specifiers: set[tuple[str, str]] | None = None,
    decorator_counts: dict[tuple[str, str], int] | None = None,
    ambient_modules: set[str] | None = None,
) -> tuple[list[EntryPoint], int, int]:
    """Fallback when ``node_modules/<pkg>/package.json`` has no usable
    ``exports`` field (or doesn't exist on disk at all).

    Surfaces every import specifier (``import "lodash"`` / ``import
    "lodash/debounce"``) plus any per-symbol / method / constructor
    call counts harvested from source. Without this fallback npm deps
    that ship without an ``exports`` field show no symbols at all.
    """
    entries: list[EntryPoint] = []
    seen: set[str] = set()
    # Each import specifier the project parsed for this package.
    for spec in sorted(all_imports):
        if not (spec == package_name or spec.startswith(package_name + "/")):
            continue
        if spec in seen:
            continue
        seen.add(spec)
        # Render as the relative-to-package-root form the user wrote.
        if spec == package_name:
            label = "."
        else:
            label = "./" + spec[len(package_name) + 1:]
        usage = counts.get(spec, 0) or 0
        entries.append(
            EntryPoint(
                name=label,
                kind="import",
                used=usage > 0,
                usage_count=usage,
            )
        )
    # FR-150 — augment with per-symbol / method / constructor entries.
    seen_names = {ep.name for ep in entries}
    extra = _synthesise_symbol_method_ctor_entries(
        package_name,
        symbol_calls=symbol_calls,
        method_calls=method_calls,
        constructor_calls=constructor_calls,
        seen_names=seen_names,
        type_only_specifiers=type_only_specifiers,
        decorator_counts=decorator_counts,
        ambient_modules=ambient_modules,
    )
    entries.extend(extra)
    used = sum(1 for e in entries if e.used)
    return entries, used, len(entries)


def _build_phantom_deps(
    static_imports: set[str], matched: set[str], declared: set[str]
) -> list[Dependency]:
    phantoms: list[Dependency] = []
    seen: set[str] = set()
    for imp in static_imports:
        if imp in matched or imp in declared or imp in seen:
            continue
        if imp in _NODE_CORE_MODULES:
            continue
        seen.add(imp)
        phantoms.append(
            Dependency(
                name=imp,
                version=None,
                status=DependencyStatus.UNDECLARED,
                reason=(
                    f"imported as '{imp}' in project source but not declared "
                    f"in any package.json section"
                ),
                entry_points=[],
                entry_points_used=0,
                entry_points_total=0,
                source=f"detected:{imp}",
                resolved=False,
                ecosystem="npm",
            )
        )
    return phantoms
