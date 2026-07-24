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

"""Tree-sitter-based AST extractor for Java / Kotlin — REQ-6b.

Replaces the Phase 2 regex scanner with proper AST traversal, so
annotations / imports / reflective literals are matched **only** against
genuine source constructs — never against text inside comments,
Javadoc, or string literals. The public surface is a pair of functions
(:func:`extract_java`, :func:`extract_kotlin`) plus
:data:`AST_AVAILABLE` which indicates whether tree-sitter and the
required grammars are importable on the current host.

When the grammars aren't available (e.g. a platform without pre-built
wheels), callers should fall back to the regex extractors in
:mod:`scarno.analysers.java.source_analyser` — this is the
graceful-degradation path required by REQ-6b acceptance criteria.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Try to import the grammars; fall back quietly if unavailable.
try:  # pragma: no cover — import-time path varies by host
    import tree_sitter as _ts
    import tree_sitter_java as _ts_java
    import tree_sitter_kotlin as _ts_kotlin

    _JAVA_LANG = _ts.Language(_ts_java.language())
    _KOTLIN_LANG = _ts.Language(_ts_kotlin.language())
    _JAVA_PARSER = _ts.Parser(_JAVA_LANG)
    _KOTLIN_PARSER = _ts.Parser(_KOTLIN_LANG)
    AST_AVAILABLE = True
except Exception:  # noqa: BLE001 — optional dep; any failure → regex fallback
    _JAVA_PARSER = None  # type: ignore[assignment]
    _KOTLIN_PARSER = None  # type: ignore[assignment]
    AST_AVAILABLE = False


@dataclass
class ExtractedFacts:
    """Everything the Phase 2 regex pass used to produce, extracted via AST."""

    imports: set[str] = field(default_factory=set)
    annotations: set[str] = field(default_factory=set)
    reflective_literals: set[str] = field(default_factory=set)
    file_path: str = ""
    # REQ-17 / FR-150 — per-FQCN reference count. One increment per
    # ``import`` site plus one per source-level reference to the class's
    # simple name (e.g. ``Splitter.on(',')`` after ``import …Splitter``).
    # Aggregated across every file by the analyser.
    import_counts: dict[str, int] = field(default_factory=dict)
    # FR-150 — wildcard imports ``import com.x.y.*;``. Stored as the
    # package path (sans asterisk). The analyser surfaces these as
    # entry points with kind="wildcard".
    wildcard_imports: set[str] = field(default_factory=set)
    # FR-150 — method-call counts keyed by ``<simple>.<method>``. The
    # ``<simple>`` is the unqualified receiver name (an imported class or
    # an instance variable named after one) — accurate enough for usage
    # reporting without full type inference.
    method_calls: dict[str, int] = field(default_factory=dict)
    # FR-150 — constructor counts keyed by ``<simple>``. ``new Splitter()``
    # increments ``Splitter``.
    constructor_calls: dict[str, int] = field(default_factory=dict)
    # FR-150 — variable-name → declared type's simple name. Populated
    # from ``local_variable_declaration``, ``field_declaration``, and
    # ``formal_parameter`` nodes. Drives instance-method attribution
    # (e.g. ``Splitter sp = …; sp.split(…)`` → bind ``sp`` to
    # ``Splitter`` so ``sp.split`` becomes ``Splitter.split``). Lookups
    # are best-effort and don't perform full Java type inference: a
    # later re-binding inside the same file overwrites earlier ones.
    variable_types: dict[str, str] = field(default_factory=dict)


# ── Shared helpers ──────────────────────────────────────────────────────────


def _bytes_to_str(value: bytes | str | None) -> str:
    """Decode tree-sitter node text to a UTF-8 string.

    ``Node.text`` is typed ``bytes | None`` — a node constructed via
    an ``AbstractSyntaxTree`` without source bytes can lack text.
    Treat ``None`` as empty string; never crash the walker on it.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _join_scoped_identifier(node: "_ts.Node") -> str:
    """Flatten a tree-sitter ``scoped_identifier`` / ``qualified_identifier``
    (chains of ``identifier . identifier``) into a dotted string."""
    parts: list[str] = []
    for child in node.children:
        ctype = child.type
        if ctype == "identifier":
            parts.append(_bytes_to_str(child.text))
        elif ctype in {"scoped_identifier", "qualified_identifier"}:
            parts.append(_join_scoped_identifier(child))
        # skip dots and commas and other punctuation
    return ".".join(p for p in parts if p)


# ── Java extractor ──────────────────────────────────────────────────────────


def extract_java(source: str, file_path: str = "") -> ExtractedFacts:
    """Extract imports, annotations, reflective literals from Java source."""
    facts = ExtractedFacts(file_path=file_path)
    if _JAVA_PARSER is None:
        return facts
    tree = _JAVA_PARSER.parse(source.encode("utf-8"))
    _walk_java(tree.root_node, facts)
    _populate_import_counts(source, facts)
    return facts


# Word-boundary regex for the simple-name reference count. Restricted
# to identifier-like names so an attacker-controlled FQCN cannot inject
# regex metacharacters (REDoS / wrong-match risk).
_JAVA_SIMPLE_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def _populate_import_counts(source: str, facts: ExtractedFacts) -> None:
    """REQ-17 / FR-150 — populate per-FQCN reference counts.

    Each ``import X.Y.Z;`` contributes 1 for the FQCN. We then count
    word-boundary occurrences of the simple name ``Z`` across the
    source. The regex is built only when the simple name passes a
    strict identifier check, so the grammar token never escapes from a
    crafted import path.
    """
    for fqcn in facts.imports:
        # Strip the import-static `X.Y.method` suffix marker — for our
        # purposes the simple name is the last dotted segment.
        simple = fqcn.rsplit(".", 1)[-1]
        if not _JAVA_SIMPLE_NAME.match(simple):
            facts.import_counts[fqcn] = facts.import_counts.get(fqcn, 0) + 1
            continue
        pattern = re.compile(rf"\b{re.escape(simple)}\b")
        # 1 for the import itself + 1 for every additional reference.
        n = len(pattern.findall(source))
        facts.import_counts[fqcn] = facts.import_counts.get(fqcn, 0) + max(n, 1)


def _walk_java(node: "_ts.Node", facts: ExtractedFacts) -> None:
    t = node.type
    # Skip comments + strings — the whole point of REQ-6b.
    if t in {"line_comment", "block_comment"}:
        return
    if t == "string_literal":
        # Never descend into a string — even though tree-sitter gives us
        # a separate ``string_fragment`` node, we want to explicitly skip
        # the whole subtree so no accidental misclassification leaks.
        return

    if t == "import_declaration":
        # Detect ``import …*`` so the wildcard package surfaces as a
        # distinct entry point downstream (FR-150). Without this the
        # user can't tell wildcard imports from concrete-class imports
        # in the report.
        is_wildcard = any(c.type == "asterisk" for c in node.children)
        for child in node.children:
            if child.type == "scoped_identifier":
                path = _join_scoped_identifier(child)
                if is_wildcard:
                    facts.wildcard_imports.add(path)
                else:
                    facts.imports.add(path)
            elif child.type == "identifier":
                # Single-name import (rare but legal) — add as-is
                name = _bytes_to_str(child.text)
                if is_wildcard:
                    facts.wildcard_imports.add(name)
                else:
                    facts.imports.add(name)
        return

    if t in {"marker_annotation", "annotation"}:
        # Children shape: `@` + `identifier` (for marker) or `@` + `scoped_identifier`
        for child in node.children:
            if child.type == "identifier":
                facts.annotations.add(_bytes_to_str(child.text))
                break
            if child.type == "scoped_identifier":
                # Full-name annotations (e.g. @org.springframework.stereotype.Service)
                full = _join_scoped_identifier(child)
                # Annotation short-name lives in the last segment
                facts.annotations.add(full.rsplit(".", 1)[-1])
                break

    if t == "method_invocation":
        _extract_java_reflective(node, facts)
        _record_method_invocation(node, facts)
        # Continue recursing — method_invocation can chain.

    if t == "object_creation_expression":
        _record_constructor_call(node, facts)

    if t in {
        "local_variable_declaration",
        "field_declaration",
        "formal_parameter",
    }:
        _record_variable_binding(node, facts)

    # Recurse
    for child in node.children:
        _walk_java(child, facts)


def _java_type_simple_name(node: "_ts.Node") -> str:
    """Return the simple class name of a Java type node, or ``""``.

    Strips generics (``Splitter`` from ``Splitter<String>``) and
    package qualification (``Splitter`` from
    ``com.google.common.base.Splitter``).
    """
    text = _bytes_to_str(node.text)
    if not text:
        return ""
    if "<" in text:
        text = text.split("<", 1)[0]
    text = text.strip()
    return text.rsplit(".", 1)[-1]


def _record_variable_binding(node: "_ts.Node", facts: ExtractedFacts) -> None:
    """Record ``<type> <name>`` bindings for instance-call attribution.

    Tree-sitter Java surfaces the type as the first non-modifier child
    (``type_identifier``, ``generic_type``, ``scoped_type_identifier``);
    the binding name lives inside one or more ``variable_declarator``
    children (or directly as ``identifier`` for ``formal_parameter``).
    Primitive types are skipped — they can never resolve to a dep.
    """
    type_simple = ""
    type_node_types = {
        "type_identifier",
        "generic_type",
        "scoped_type_identifier",
        "array_type",
    }
    primitive_types = {"integral_type", "floating_point_type",
                       "boolean_type", "void_type"}
    for child in node.children:
        if child.type in primitive_types:
            return
        if child.type in type_node_types:
            type_simple = _java_type_simple_name(child)
            break
    if not type_simple:
        return
    # Only attribute to types that look like class names (start uppercase).
    if not type_simple[:1].isupper():
        return

    if node.type == "formal_parameter":
        # Shape: <modifiers>? <type> <identifier>
        for child in node.children:
            if child.type == "identifier":
                name = _bytes_to_str(child.text)
                if name:
                    facts.variable_types[name] = type_simple
                break
        return

    # local_variable_declaration / field_declaration carry one or more
    # variable_declarator children (one per comma-separated binding).
    for child in node.children:
        if child.type != "variable_declarator":
            continue
        for sub in child.children:
            if sub.type == "identifier":
                name = _bytes_to_str(sub.text)
                if name:
                    facts.variable_types[name] = type_simple
                break


def _record_method_invocation(node: "_ts.Node", facts: ExtractedFacts) -> None:
    """Capture ``<receiver>.<method>(…)`` patterns.

    Tree-sitter Java grammar emits ``method_invocation`` with children
    of (roughly) shape: ``<receiver-expr> . <identifier-name> <argument_list>``.
    We extract the receiver's last simple name (works for
    ``Splitter.on(',')`` where receiver is the identifier ``Splitter``,
    and for ``s.split(',')`` where receiver is identifier ``s``).
    Without full type inference we cannot bind ``s`` back to its
    declared type — the user-facing reporter does the attribution by
    matching the receiver's name against imported simple names.
    """
    receiver_simple: str | None = None
    method_name: str | None = None
    saw_argument_list = False
    # Walk children in order. The method-name is the identifier
    # immediately preceding the argument_list.
    last_identifier = ""
    for child in node.children:
        ct = child.type
        if ct == "argument_list":
            saw_argument_list = True
            method_name = last_identifier or None
            break
        if ct == "identifier":
            # If we haven't yet captured a receiver and this is the
            # first identifier, treat it as the receiver (for plain
            # ``X.m()``). Otherwise it becomes the method name.
            if receiver_simple is None and last_identifier == "":
                receiver_simple = _bytes_to_str(child.text)
            last_identifier = _bytes_to_str(child.text)
        elif ct in {"field_access", "scoped_identifier", "method_invocation"}:
            # Receiver is a chain — take its last identifier as a best-effort.
            chain_text = _bytes_to_str(child.text)
            receiver_simple = chain_text.rsplit(".", 1)[-1]
            last_identifier = ""
    if not (saw_argument_list and method_name and receiver_simple):
        return
    if receiver_simple == method_name:
        return  # bare ``foo()`` — not a receiver.method() pattern
    key = f"{receiver_simple}.{method_name}"
    facts.method_calls[key] = facts.method_calls.get(key, 0) + 1


def _record_constructor_call(node: "_ts.Node", facts: ExtractedFacts) -> None:
    """Capture ``new <ClassName>(…)`` patterns.

    Tree-sitter Java emits ``object_creation_expression`` with shape
    ``new <type-args>? <type-name> <arguments>``. The type name is the
    interesting part; we record its last simple name.
    """
    class_simple: str | None = None
    for child in node.children:
        ct = child.type
        if ct in {"type_identifier"}:
            class_simple = _bytes_to_str(child.text)
            break
        if ct in {"scoped_type_identifier", "generic_type"}:
            text = _bytes_to_str(child.text)
            # Strip generic args ``<…>`` from the tail.
            if "<" in text:
                text = text.split("<", 1)[0]
            class_simple = text.rsplit(".", 1)[-1]
            break
    if not class_simple:
        return
    facts.constructor_calls[class_simple] = (
        facts.constructor_calls.get(class_simple, 0) + 1
    )


def _extract_java_reflective(node: "_ts.Node", facts: ExtractedFacts) -> None:
    """Detect ``Class.forName("…")`` and ``ClassLoader.loadClass("…")``.

    Handles chained receivers too — e.g.
    ``ClassLoader.getSystemClassLoader().loadClass("…")``. For
    ``forName`` we still require a ``Class`` receiver to avoid
    misclassifying unrelated ``*.forName()`` calls; for ``loadClass``
    we accept any receiver (the method name is specific enough that
    false-positives on ``.loadClass(...)`` are unlikely).
    """
    # Shape options:
    #   method_invocation → (receiver)? (identifier name) (argument_list)
    # Receiver can be: identifier | field_access | method_invocation | this
    args_node = None
    name_text = ""
    receiver_text = ""

    # Collect identifiers and the argument list. The *last* identifier
    # in children is the method name; everything before it describes
    # the receiver.
    idents: list[str] = []
    for child in node.children:
        if child.type == "identifier":
            idents.append(_bytes_to_str(child.text))
        elif child.type == "argument_list":
            args_node = child
        elif child.type in {
            "method_invocation",
            "field_access",
            "scoped_identifier",
        }:
            receiver_text = _bytes_to_str(child.text)

    if not idents or args_node is None:
        return
    name_text = idents[-1]
    if name_text not in {"forName", "loadClass"}:
        return
    if not receiver_text and len(idents) >= 2:
        receiver_text = idents[0]

    if name_text == "forName" and receiver_text != "Class":
        return
    if name_text == "loadClass" and not receiver_text:
        # Bare loadClass() with no receiver — don't guess
        return

    for child in args_node.children:
        if child.type == "string_literal":
            literal = _extract_string_literal_text(child)
            if literal:
                facts.reflective_literals.add(literal)
            return


def _extract_string_literal_text(node: "_ts.Node") -> str:
    """Pull the inner text out of a tree-sitter string_literal node."""
    parts: list[str] = []
    for child in node.children:
        if child.type in {"string_fragment", "string_content"}:
            parts.append(_bytes_to_str(child.text))
    return "".join(parts)


# ── Kotlin extractor ────────────────────────────────────────────────────────


def extract_kotlin(source: str, file_path: str = "") -> ExtractedFacts:
    facts = ExtractedFacts(file_path=file_path)
    if _KOTLIN_PARSER is None:
        return facts
    tree = _KOTLIN_PARSER.parse(source.encode("utf-8"))
    _walk_kotlin(tree.root_node, facts)
    _populate_import_counts(source, facts)
    return facts


def _walk_kotlin(node: "_ts.Node", facts: ExtractedFacts) -> None:
    t = node.type
    # Kotlin grammar also has line_comment / block_comment / string_literal.
    if t in {"line_comment", "block_comment", "multiline_comment"}:
        return
    if t in {"string_literal", "line_string_literal", "multi_line_string_literal"}:
        return

    if t == "import":
        _extract_kotlin_import(node, facts)
        return

    # Kotlin annotations: ``@Autowired`` → `annotation` node with a
    # `user_type` or `identifier` child.
    if t in {"annotation", "marker_annotation"}:
        _extract_kotlin_annotation(node, facts)

    # Kotlin reflection: ``Class.forName("…")`` or ``"…".javaClass`` —
    # the call-expression path matches Java's.
    if t == "call_expression":
        _extract_kotlin_reflective(node, facts)

    for child in node.children:
        _walk_kotlin(child, facts)


def _extract_kotlin_import(node: "_ts.Node", facts: ExtractedFacts) -> None:
    """Kotlin ``import com.foo.Bar`` or ``import com.foo.Bar as B``."""
    for child in node.children:
        if child.type == "qualified_identifier":
            facts.imports.add(_join_scoped_identifier(child))
            return
        if child.type == "identifier":
            facts.imports.add(_bytes_to_str(child.text))
            return


def _extract_kotlin_annotation(node: "_ts.Node", facts: ExtractedFacts) -> None:
    # Walk children to find the annotation name
    for child in node.children:
        if child.type == "user_type":
            for sub in child.children:
                if sub.type == "type_identifier":
                    facts.annotations.add(_bytes_to_str(sub.text))
                    return
                if sub.type == "identifier":
                    facts.annotations.add(_bytes_to_str(sub.text))
                    return
        elif child.type == "type_identifier":
            facts.annotations.add(_bytes_to_str(child.text))
            return
        elif child.type == "identifier":
            facts.annotations.add(_bytes_to_str(child.text))
            return


def _extract_kotlin_reflective(node: "_ts.Node", facts: ExtractedFacts) -> None:
    """Detect Kotlin `Class.forName("...")` — AST shape differs from Java."""
    # call_expression children vary by tree-sitter-kotlin version:
    #   - navigation_expression + call_suffix (older)
    #   - navigation_expression + value_arguments (current)
    callee_text = ""
    args_node = None
    for child in node.children:
        if child.type == "navigation_expression":
            callee_text = _bytes_to_str(child.text)
        elif child.type == "call_suffix":
            for sub in child.children:
                if sub.type == "value_arguments":
                    args_node = sub
                    break
        elif child.type == "value_arguments":
            # Current tree-sitter-kotlin: value_arguments is a direct child
            args_node = child
    if not callee_text or args_node is None:
        return
    if not (
        callee_text.endswith(".forName") or callee_text.endswith(".loadClass")
    ):
        return
    for child in args_node.children:
        if child.type == "value_argument":
            for sub in child.children:
                if sub.type in {
                    "string_literal",
                    "line_string_literal",
                    "multi_line_string_literal",
                }:
                    literal = _extract_string_literal_text(sub)
                    if literal:
                        facts.reflective_literals.add(literal)
                    return
