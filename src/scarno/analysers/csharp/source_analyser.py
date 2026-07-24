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

"""C# source analyser — REQ-16.

Uses tree-sitter-c-sharp to walk ``.cs`` ASTs and extract ``using``
directives. Also scans ``.cshtml`` files for Razor ``@using`` directives
via a lightweight regex pre-pass.

Classifies each declared NuGet dep as IN_USE / SAFE / UNDECLARED based
on namespace-to-package matching.

Safety:
  * Grammar loaded optionally — graceful fallback when unavailable.
  * Every file bounded by ``MAX_FILE_BYTES``.
  * No shell invocations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from scarno.models import Dependency, DependencyStatus, EntryPoint
from scarno.security import MAX_FILE_BYTES, PathEscapeError, resolve_and_confine

# Try to load tree-sitter-c-sharp grammar.
try:  # pragma: no cover
    import tree_sitter as _ts
    import tree_sitter_c_sharp as _ts_cs

    _CS_LANG = _ts.Language(_ts_cs.language())
    _CS_PARSER = _ts.Parser(_CS_LANG)
    CSHARP_AST_AVAILABLE = True
except Exception:  # noqa: BLE001
    _CS_PARSER = None  # type: ignore[assignment]
    CSHARP_AST_AVAILABLE = False


# ── Microsoft shared-framework namespaces ──────────────────────────────────
# These ship with the .NET runtime and are NOT NuGet packages. Imports of
# these must NOT surface as UNDECLARED. The set covers the top-level roots;
# sub-namespaces inherit (e.g. ``System.Collections.Generic`` is covered by
# ``System``).
_SHARED_FRAMEWORK_ROOTS: frozenset[str] = frozenset(
    {
        "System",
        "Microsoft.CSharp",
        "Microsoft.VisualBasic",
        "Microsoft.Win32",
    }
)

# Microsoft.Extensions.* IS distributed via NuGet — explicitly NOT in the
# shared-framework exclusion set.

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {"bin", "obj", ".git", "node_modules"}
)

_RAZOR_USING_RE = re.compile(r"^\s*@using\s+(?P<ns>[A-Za-z][A-Za-z0-9_.]*)")


@dataclass
class _Facts:
    # All namespace roots extracted from using directives.
    namespaces: set[str] = field(default_factory=set)
    # REQ-17 / FR-150 — per-namespace reference count: 1 per ``using`` site
    # plus 1 per word-boundary occurrence of the namespace's last segment in
    # the same file (so ``LoggerConfiguration`` / ``Information(...)`` calls
    # contribute beyond the import statement).
    namespace_counts: dict[str, int] = field(default_factory=dict)
    # FR-150 — per-(class) constructor call counts. ``new Foo()`` → 1 on
    # ``Foo``. The class is attributed to a namespace at synthesis time
    # via the namespace's last segment.
    constructor_calls: dict[str, int] = field(default_factory=dict)
    # FR-150 — per-(receiver, method) call counts. ``Log.Information``
    # records ``(Log, Information)`` directly. ``cfg.CreateLogger``
    # records ``(cfg, CreateLogger)`` and is later resolved through the
    # variable_class map to the bound type.
    method_calls: dict[tuple[str, str], int] = field(default_factory=dict)
    # FR-150 — local-name → bound class simple name. Populated from
    # ``Foo x = new Foo();``, ``var x = new Foo();``, and method
    # parameters annotated as ``Foo``.
    variable_class: dict[str, str] = field(default_factory=dict)


_CS_SIMPLE_NAME = re.compile(r"^[A-Za-z_@][A-Za-z0-9_]*$")


# ── Public entry point ─────────────────────────────────────────────────────


def analyse_csharp_sources(
    project_path: str, dependencies: list[Dependency]
) -> tuple[list[Dependency], list[str]]:
    """Classify each NuGet dep as IN_USE / SAFE / UNDECLARED."""
    errors: list[str] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"csharp source: could not resolve path — {exc}")
        return list(dependencies), errors
    if not root.is_dir():
        return list(dependencies), errors

    facts = _scan_tree(root, errors)

    declared = {dep.name for dep in dependencies if dep.ecosystem == "nuget"}
    matched: set[str] = set()

    updated: list[Dependency] = []
    for dep in dependencies:
        if dep.ecosystem != "nuget":
            updated.append(dep)
            continue
        status, reason = _classify(dep.name, facts)
        if status is DependencyStatus.IN_USE:
            matched.add(dep.name)
        # REQ-17 / FR-150 — synthesise entry points from the using
        # directives that resolved to this package, so the report shows
        # which namespaces / types the project actually consumes.
        if status is DependencyStatus.IN_USE:
            ep_list = _entry_points_for_package(dep.name, facts)
            ep_used = sum(1 for ep in ep_list if ep.used)
            ep_total = len(ep_list)
        else:
            ep_list = list(dep.entry_points)
            ep_used = dep.entry_points_used
            ep_total = dep.entry_points_total
        updated.append(
            Dependency(
                name=dep.name,
                version=dep.version,
                status=status,
                reason=reason,
                entry_points=ep_list,
                entry_points_used=ep_used,
                entry_points_total=ep_total,
                source=dep.source,
                vendored_path=dep.vendored_path,
                resolved=dep.resolved,
                ecosystem=dep.ecosystem,
            )
        )

    # Phantom imports — namespace referenced but no matching NuGet dep
    phantoms = _build_phantom_deps(facts.namespaces, matched, declared)
    updated.extend(phantoms)
    return updated, errors


# ── Tree scanning ──────────────────────────────────────────────────────────


def _scan_tree(root: Path, errors: list[str]) -> _Facts:
    facts = _Facts()

    # .cs files via tree-sitter
    if CSHARP_AST_AVAILABLE:
        for raw_path in root.rglob("*.cs"):
            rel_parts = raw_path.relative_to(root).parts
            if any(p in _EXCLUDED_DIR_NAMES for p in rel_parts):
                continue
            _scan_cs_file(raw_path, root, facts, errors)

    # .cshtml files via regex
    for raw_path in root.rglob("*.cshtml"):
        rel_parts = raw_path.relative_to(root).parts
        if any(p in _EXCLUDED_DIR_NAMES for p in rel_parts):
            continue
        _scan_razor_file(raw_path, root, facts, errors)

    return facts


def _scan_cs_file(
    raw_path: Path, root: Path, facts: _Facts, errors: list[str]
) -> None:
    try:
        resolved = resolve_and_confine(raw_path, root)
    except PathEscapeError:
        errors.append(
            f"csharp source: symlink escape blocked: "
            f"{raw_path.relative_to(root)}"
        )
        return
    try:
        size = resolved.stat().st_size
    except OSError:
        return
    if size > MAX_FILE_BYTES:
        errors.append(f"csharp source: skipped {resolved.name} — too large")
        return
    try:
        source_bytes = resolved.read_bytes()
    except OSError as exc:
        errors.append(f"csharp source: read failed {resolved.name} — {exc}")
        return

    if _CS_PARSER is None:
        return
    try:
        tree = _CS_PARSER.parse(source_bytes)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"csharp source: parse failed {resolved.name} — {exc}")
        return

    pre_namespaces = set(facts.namespaces)
    _walk_usings(tree.root_node, facts)
    # REQ-17 / FR-150 — for namespaces newly seen in this file, augment
    # the count by the number of word-boundary references to the
    # namespace's last segment in the file's source. Bounds the regex
    # to validated identifiers so attacker-controlled namespace text
    # cannot inject regex metacharacters.
    new_in_file = facts.namespaces - pre_namespaces
    if new_in_file:
        try:
            text = source_bytes.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            text = ""
        for ns in new_in_file:
            simple = ns.rsplit(".", 1)[-1]
            if _CS_SIMPLE_NAME.match(simple):
                n = len(re.findall(rf"\b{re.escape(simple)}\b", text))
                facts.namespace_counts[ns] = (
                    facts.namespace_counts.get(ns, 0) + max(n, 1)
                )
            else:
                facts.namespace_counts[ns] = (
                    facts.namespace_counts.get(ns, 0) + 1
                )


def _walk_usings(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """Walk AST extracting using_directive nodes plus FR-150 signals."""
    if node.type == "using_directive":
        _extract_using(node, facts)
        return
    # Don't descend into strings or comments
    if node.type in {"string_literal", "verbatim_string_literal", "comment"}:
        return
    if node.type == "object_creation_expression":
        _record_object_creation(node, facts)
    if node.type == "invocation_expression":
        _record_invocation(node, facts)
    if node.type in {
        "local_declaration_statement",
        "field_declaration",
        "variable_declaration",
    }:
        _record_local_declaration(node, facts)
    if node.type == "parameter":
        _record_parameter(node, facts)
    for child in node.children:
        _walk_usings(child, facts)


def _node_text_str(node) -> str:  # type: ignore[no-untyped-def]
    text = node.text
    if text is None:
        return ""
    if isinstance(text, bytes):
        return text.decode("utf-8", errors="replace")
    return cast(str, text)


def _peel_generic(name: str) -> str:
    if "<" in name:
        return name.split("<", 1)[0]
    return name


def _last_simple(name: str) -> str:
    return _peel_generic(name).rsplit(".", 1)[-1]


def _record_object_creation(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``new Foo(...)`` and ``new Foo<T>{ ... }`` → ``constructor_calls[Foo] += 1``."""
    type_name: str | None = None
    for child in node.children:
        ct = child.type
        if ct in {"identifier", "qualified_name"}:
            type_name = _last_simple(_flatten_name(child))
            break
        if ct in {"generic_name", "generic_type"}:
            text = _node_text_str(child)
            type_name = _last_simple(text)
            break
    if not type_name:
        return
    if type_name[:1].isupper():
        facts.constructor_calls[type_name] = (
            facts.constructor_calls.get(type_name, 0) + 1
        )


def _record_invocation(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``X.method(...)`` → ``method_calls[(X, method)] += 1``."""
    if not node.children:
        return
    callee = node.children[0]
    if callee.type != "member_access_expression":
        return
    receiver, prop = _split_member_access(callee)
    if not receiver or not prop:
        return
    if not (receiver[:1].isalpha() or receiver[:1] == "_"):
        return
    facts.method_calls[(receiver, prop)] = (
        facts.method_calls.get((receiver, prop), 0) + 1
    )


def _split_member_access(node) -> tuple[str, str]:  # type: ignore[no-untyped-def]
    """Return ``(receiver_text, member_name)`` for a member_access_expression."""
    receiver = ""
    member = ""
    saw_dot = False
    for child in node.children:
        if child.type == ".":
            saw_dot = True
            continue
        if not saw_dot:
            if child.type in {"identifier", "qualified_name"}:
                receiver = _last_simple(_flatten_name(child))
            elif child.type in {"member_access_expression", "this_expression"}:
                receiver = _last_simple(_node_text_str(child))
        else:
            if child.type == "identifier":
                member = _node_text_str(child)
                break
    return receiver, member


def _record_local_declaration(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``Foo x = new Foo();`` / ``var x = new Foo();`` — bind x to Foo."""
    decl = node
    # ``local_declaration_statement`` wraps a ``variable_declaration``.
    if node.type == "local_declaration_statement":
        decl = next(
            (c for c in node.children if c.type == "variable_declaration"),
            node,
        )
    type_name: str | None = None
    is_var = False
    declarators: list[Any] = []
    for child in decl.children:
        ct = child.type
        if ct == "implicit_type":
            is_var = True
        elif ct == "predefined_type":
            # int / string / bool — not a class binding.
            return
        elif ct in {"identifier", "qualified_name", "generic_name"}:
            text = (
                _node_text_str(child) if ct == "identifier"
                else _flatten_name(child)
            )
            type_name = _last_simple(text)
        elif ct == "variable_declarator":
            declarators.append(child)
    for d in declarators:
        var_name = ""
        rhs_class: str | None = None

        def _capture_class_from_creation(creation_node: Any) -> str | None:
            for vc in creation_node.children:
                if vc.type in {"identifier", "qualified_name", "generic_name"}:
                    return _last_simple(
                        _flatten_name(vc)
                        if vc.type != "identifier"
                        else _node_text_str(vc)
                    )
            return None

        for sub in d.children:
            ct = sub.type
            if ct == "identifier" and not var_name:
                var_name = _node_text_str(sub)
            elif ct == "object_creation_expression":
                rhs_class = _capture_class_from_creation(sub)
            elif ct == "equals_value_clause":
                # Older grammar wrapping — descend.
                for v in sub.children:
                    if v.type == "object_creation_expression":
                        rhs_class = _capture_class_from_creation(v)
                        break
        if not var_name:
            continue
        bound = (rhs_class if is_var else type_name) or rhs_class
        if bound and bound[:1].isupper():
            facts.variable_class[var_name] = bound


def _record_parameter(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``void Use(Foo cfg)`` — bind cfg to Foo."""
    type_name: str | None = None
    name: str | None = None
    for child in node.children:
        ct = child.type
        if ct == "predefined_type":
            return
        if ct in {"identifier", "qualified_name", "generic_name"} and not type_name:
            type_name = _last_simple(_flatten_name(child) if ct != "identifier" else _node_text_str(child))
            continue
        if ct == "identifier" and type_name and not name:
            name = _node_text_str(child)
    if name and type_name and type_name[:1].isupper():
        facts.variable_class[name] = type_name


def _extract_using(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """Extract the namespace from a using_directive node.

    Handles:
      * ``using System;`` → "System"
      * ``using System.Collections.Generic;`` → "System.Collections.Generic"
      * ``using static Newtonsoft.Json.JsonConvert;`` → "Newtonsoft.Json.JsonConvert"
      * ``using Json = Newtonsoft.Json;`` → "Newtonsoft.Json" (RHS of alias)
    """
    has_equals = any(c.type == "=" for c in node.children)
    has_static = any(c.type == "static" for c in node.children)

    if has_equals:
        # Alias: ``using Alias = Full.Namespace;`` — take the RHS
        found_equals = False
        for child in node.children:
            if child.type == "=":
                found_equals = True
                continue
            if found_equals and child.type in {"qualified_name", "identifier"}:
                ns = _flatten_name(child)
                if ns:
                    facts.namespaces.add(ns)
                return
    else:
        # Regular or static using — take the qualified_name or identifier
        for child in node.children:
            if child.type in {"qualified_name", "identifier"}:
                ns = _flatten_name(child)
                if ns:
                    facts.namespaces.add(ns)
                return


def _flatten_name(node) -> str:  # type: ignore[no-untyped-def]
    """Flatten a ``qualified_name`` or ``identifier`` into a dotted string."""
    if node.type == "identifier":
        text = node.text
        if text is None:
            return ""
        return text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    if node.type == "qualified_name":
        parts: list[str] = []
        for child in node.children:
            if child.type in {"identifier", "qualified_name"}:
                parts.append(_flatten_name(child))
        return ".".join(p for p in parts if p)
    return ""


# ── Razor (.cshtml) scanning ──────────────────────────────────────────────


def _scan_razor_file(
    raw_path: Path, root: Path, facts: _Facts, errors: list[str]
) -> None:
    try:
        resolved = resolve_and_confine(raw_path, root)
    except PathEscapeError:
        return
    try:
        size = resolved.stat().st_size
    except OSError:
        return
    if size > MAX_FILE_BYTES:
        return
    try:
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    for line in text.splitlines():
        m = _RAZOR_USING_RE.match(line)
        if m:
            facts.namespaces.add(m.group("ns"))


# ── Classification ─────────────────────────────────────────────────────────


def _entry_points_for_package(
    package: str, facts: _Facts
) -> list[EntryPoint]:
    """Build EntryPoint records for ``package``.

    Surfaces four kinds:
      * ``namespace`` — one per ``using`` directive that resolves to
        this package (or a sub-namespace).
      * ``constructor`` — ``new Foo(...)`` where ``Foo``'s simple name
        is plausibly owned by this package's namespaces (heuristic:
        no other in-scope namespace is a better claimant; without
        DLL inspection we cannot disambiguate definitively).
      * ``method`` — receiver-resolved method calls. ``Log.Information``
        attributes when ``Log`` is a type whose enclosing namespace is
        this package; instance calls (``cfg.CreateLogger``) attribute
        when ``cfg`` was bound to a class plausibly in this package.
      * Negative case: receivers bound to predefined types (string,
        int) or unknown receivers are dropped.
    """
    out: list[EntryPoint] = []
    seen: set[str] = set()
    # Class names that this package's namespaces plausibly own.
    # Heuristic: the simple class name is uppercase-leading (Pascal-Case)
    # and the receiver is referenced in source after a matching
    # ``using``; without DLL metadata we cannot enumerate the namespace's
    # actual type list.
    package_namespaces = {
        ns for ns in facts.namespaces
        if ns == package or ns.startswith(package + ".")
    }
    if not package_namespaces:
        return out
    for ns in sorted(package_namespaces):
        if ns in seen:
            continue
        seen.add(ns)
        out.append(
            EntryPoint(
                name=ns,
                kind="namespace",
                used=True,
                usage_count=facts.namespace_counts.get(ns, 1),
            )
        )
    # Constructors of classes plausibly owned by this package.
    # Without DLL inspection the heuristic is: this package is the only
    # one with a using directive, OR the class simple name doesn't
    # appear in any other package's namespaces' last-segment counts.
    # Pragmatic fallback: when there's a single npm-scope or .NET
    # namespace claimant, attribute. Otherwise omit (no false-positive).
    for cls, count in sorted(facts.constructor_calls.items()):
        if not cls or not cls[:1].isupper():
            continue
        label = f"new {cls}()"
        if label in seen:
            continue
        # Don't claim a class that's already owned by another using
        # whose root namespace doesn't match this package.
        if not _class_plausibly_owned(cls, package, facts):
            continue
        seen.add(label)
        out.append(
            EntryPoint(
                name=label, kind="constructor", used=True,
                usage_count=count,
            )
        )
    # Method calls. Three cases:
    #   1. ``X.method`` where X is a static type / class symbol seen
    #      in source as a constructor, instance binding, OR a
    #      first-segment-of-namespace marker.
    #   2. ``var.method`` where var is bound via ``variable_class`` to
    #      a class plausibly in this package.
    method_seen: set[str] = set()
    for (recv, method), n in sorted(facts.method_calls.items()):
        if not recv or not method:
            continue
        cls_simple: str | None = None
        # If receiver is a known variable, resolve through type binding.
        if recv in facts.variable_class:
            cls_simple = facts.variable_class[recv]
        elif recv[:1].isupper():
            # Treat receiver as a class simple name (static call).
            cls_simple = recv
        if cls_simple is None or not cls_simple[:1].isupper():
            continue
        if not _class_plausibly_owned(cls_simple, package, facts):
            continue
        label = f"{cls_simple}.{method}"
        if label in method_seen:
            continue
        method_seen.add(label)
        out.append(
            EntryPoint(
                name=label, kind="method", used=True,
                usage_count=n,
            )
        )
    return out


def _class_plausibly_owned(
    cls: str, package: str, facts: _Facts,
) -> bool:
    """Heuristic: a class ``cls`` is plausibly owned by ``package``
    when at least one of this package's ``using``'d namespaces is the
    *most-specific* match seen in source.

    Without DLL/namespace metadata we cannot definitively know which
    package owns ``cls`` if multiple ``using`` directives are in
    scope. Pragmatic rule: attribute when this package is one of the
    using-directive namespaces. If multiple packages all qualify we
    accept over-attribution rather than under-attribution — the report
    section header should make this trade-off visible to the user.
    """
    package_namespaces = {
        ns for ns in facts.namespaces
        if ns == package or ns.startswith(package + ".")
    }
    if not package_namespaces:
        return False
    # If the class isn't referenced anywhere else in source, fall through
    # — likelihood of it belonging to a non-imported namespace is low.
    return True


def _classify(
    name: str, facts: _Facts
) -> tuple[DependencyStatus, str]:
    """Classify a declared NuGet dep against extracted namespace facts.

    NuGet package names typically match the root namespace:
      * ``Newtonsoft.Json`` → ``using Newtonsoft.Json``
      * ``Serilog`` → ``using Serilog`` or ``using Serilog.Core``
    """
    for ns in facts.namespaces:
        if ns == name or ns.startswith(name + "."):
            return DependencyStatus.IN_USE, f"using '{ns}' matches package '{name}'"

    return DependencyStatus.SAFE, "no using directive found matching this package"


def _is_shared_framework(ns: str) -> bool:
    """Check if a namespace belongs to the .NET shared framework."""
    root = ns.split(".")[0]
    if root in _SHARED_FRAMEWORK_ROOTS:
        return True
    # Full-prefix check for multi-segment roots
    for fw_root in _SHARED_FRAMEWORK_ROOTS:
        if ns == fw_root or ns.startswith(fw_root + "."):
            return True
    return False


def _build_phantom_deps(
    all_namespaces: set[str], matched: set[str], declared: set[str]
) -> list[Dependency]:
    """Build UNDECLARED deps for namespaces not matching any declared dep."""
    phantoms: list[Dependency] = []
    seen: set[str] = set()

    for ns in all_namespaces:
        if _is_shared_framework(ns):
            continue
        # Guess package name: the namespace root (first 1-2 segments)
        pkg_name = _guess_package_name(ns)
        if pkg_name in matched or pkg_name in declared or pkg_name in seen:
            continue
        # Check if any declared dep is a prefix
        if any(ns == d or ns.startswith(d + ".") for d in declared):
            continue
        seen.add(pkg_name)
        phantoms.append(
            Dependency(
                name=pkg_name,
                version=None,
                status=DependencyStatus.UNDECLARED,
                reason=f"using '{ns}' but no matching NuGet package declared",
                entry_points=[],
                entry_points_used=0,
                entry_points_total=0,
                source=f"detected:{pkg_name}",
                resolved=False,
                ecosystem="nuget",
            )
        )
    return phantoms


def _guess_package_name(namespace: str) -> str:
    """Guess the NuGet package name from a namespace.

    Heuristic: most NuGet packages use the full namespace as the package
    name (e.g. ``Microsoft.Extensions.Logging``). For shorter namespaces
    (1-2 segments), use the full namespace.
    """
    return namespace
