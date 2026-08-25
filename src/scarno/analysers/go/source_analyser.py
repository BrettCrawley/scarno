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

"""Go source analyser — REQ-14.

Uses tree-sitter-go to walk ``.go`` ASTs and extract import paths.
Classifies each declared dep as IN_USE / SAFE / UNCERTAIN / UNDECLARED
based on actual source imports.

Safety:
  * Grammar loaded optionally — graceful fallback when unavailable.
  * Every file bounded by ``MAX_FILE_BYTES``.
  * No shell invocations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import re

from scarno.analysers.name_counts import MAX_FULL_SCANS, count_selector_refs
from scarno.models import Dependency, DependencyStatus, EntryPoint
from scarno.security import MAX_FILE_BYTES, PathEscapeError, resolve_and_confine

# Try to load tree-sitter-go grammar; graceful fallback on import failure.
try:  # pragma: no cover — host-specific import path
    import tree_sitter as _ts
    import tree_sitter_go as _ts_go

    _GO_LANG = _ts.Language(_ts_go.language())
    _GO_PARSER = _ts.Parser(_GO_LANG)
    GO_AST_AVAILABLE = True
except Exception:  # noqa: BLE001 — optional
    _GO_PARSER = None  # type: ignore[assignment]
    GO_AST_AVAILABLE = False


# ── Go standard library ───────────────────────────────────────────────────
# Go stdlib package paths. Includes all top-level and nested packages from
# Go 1.22. Imports of these must NOT appear as UNDECLARED deps.
_GO_STDLIB: frozenset[str] = frozenset(
    {
        "archive/tar", "archive/zip",
        "bufio", "bytes",
        "cmp",
        "compress/bzip2", "compress/flate", "compress/gzip",
        "compress/lzw", "compress/zlib",
        "container/heap", "container/list", "container/ring",
        "context", "crypto",
        "crypto/aes", "crypto/cipher", "crypto/des", "crypto/dsa",
        "crypto/ecdh", "crypto/ecdsa", "crypto/ed25519",
        "crypto/elliptic", "crypto/hmac", "crypto/md5",
        "crypto/rand", "crypto/rc4", "crypto/rsa", "crypto/sha1",
        "crypto/sha256", "crypto/sha512", "crypto/subtle",
        "crypto/tls", "crypto/x509", "crypto/x509/pkix",
        "database/sql", "database/sql/driver",
        "debug/buildinfo", "debug/dwarf", "debug/elf",
        "debug/gosym", "debug/macho", "debug/pe", "debug/plan9obj",
        "embed",
        "encoding", "encoding/ascii85", "encoding/asn1",
        "encoding/base32", "encoding/base64", "encoding/binary",
        "encoding/csv", "encoding/gob", "encoding/hex",
        "encoding/json", "encoding/pem", "encoding/xml",
        "errors", "expvar",
        "flag", "fmt",
        "go/ast", "go/build", "go/build/constraint",
        "go/constant", "go/doc", "go/doc/comment",
        "go/format", "go/importer", "go/parser",
        "go/printer", "go/scanner", "go/token", "go/types",
        "hash", "hash/adler32", "hash/crc32", "hash/crc64",
        "hash/fnv", "hash/maphash",
        "html", "html/template",
        "image", "image/color", "image/color/palette",
        "image/draw", "image/gif", "image/jpeg", "image/png",
        "index/suffixarray",
        "io", "io/fs", "io/ioutil",
        "iter",
        "log", "log/slog", "log/syslog",
        "maps", "math", "math/big", "math/bits", "math/cmplx",
        "math/rand", "math/rand/v2",
        "mime", "mime/multipart", "mime/quotedprintable",
        "net", "net/http", "net/http/cgi", "net/http/cookiejar",
        "net/http/fcgi", "net/http/httptest", "net/http/httptrace",
        "net/http/httputil", "net/http/pprof",
        "net/mail", "net/netip", "net/rpc", "net/rpc/jsonrpc",
        "net/smtp", "net/textproto", "net/url",
        "os", "os/exec", "os/signal", "os/user",
        "path", "path/filepath",
        "plugin",
        "reflect", "regexp", "regexp/syntax",
        "runtime", "runtime/cgo", "runtime/debug",
        "runtime/metrics", "runtime/pprof", "runtime/race",
        "runtime/trace",
        "slices", "sort", "strconv", "strings",
        "structs",
        "sync", "sync/atomic",
        "syscall",
        "testing", "testing/fstest", "testing/iotest",
        "testing/quick", "testing/slogtest",
        "text/scanner", "text/tabwriter", "text/template",
        "text/template/parse",
        "time", "time/tzdata",
        "unicode", "unicode/utf16", "unicode/utf8",
        "unsafe",
    }
)

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {"vendor", ".git", "testdata"}
)


@dataclass
class _Facts:
    # All import paths found in source (non-stdlib, non-C)
    imports: set[str] = field(default_factory=set)
    # Imports that are blank (_) or dot (.) — always IN_USE
    forced_in_use: set[str] = field(default_factory=set)
    # Whether `import "C"` was seen (cgo)
    has_cgo: bool = False
    # Whether `import "unsafe"` was seen
    has_unsafe: bool = False
    # REQ-17 / FR-150 — per-import-path reference count.
    # 1 per ``import`` site + 1 per ``<pkg>.<Selector>`` reference in
    # the same file (e.g. ``errors.New(...)``).
    import_counts: dict[str, int] = field(default_factory=dict)
    # Last-segment → import path map, populated as imports are seen.
    # Used to attribute ``errors.New(...)`` to ``github.com/pkg/errors``.
    _last_segment_index: dict[str, str] = field(default_factory=dict)
    # FR-150 — per-(pkg_last_segment, symbol) selector counts.
    # ``errors.New(...)`` increments ``("errors", "New")``.
    selector_counts: dict[tuple[str, str], int] = field(default_factory=dict)
    # FR-150 — per-(pkg_last_segment, type) composite-literal counts.
    # ``redis.Options{...}`` and ``&redis.Options{...}`` both increment
    # ``("redis", "Options")``.
    composite_counts: dict[tuple[str, str], int] = field(default_factory=dict)
    # FR-150 — per-(pkg_last_segment, type, method) instance method
    # call counts. ``c.Set(...)`` after ``c *redis.Client = ...`` is
    # resolved through ``variable_type`` to ``("redis", "Client", "Set")``.
    method_calls: dict[tuple[str, str, str], int] = field(default_factory=dict)
    # FR-150 — local-name → (pkg_last_segment, type) binding.
    variable_type: dict[str, tuple[str, str]] = field(default_factory=dict)


_GO_PKG_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# ── Public entry point ─────────────────────────────────────────────────────


def analyse_go_sources(
    project_path: str, dependencies: list[Dependency]
) -> tuple[list[Dependency], list[str]]:
    """Classify each Go dep as IN_USE / SAFE / UNDECLARED."""
    errors: list[str] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"go source: could not resolve path — {exc}")
        return list(dependencies), errors
    if not root.is_dir():
        return list(dependencies), errors

    facts = _scan_tree(root, errors)

    declared = {dep.name for dep in dependencies if dep.ecosystem == "go"}
    matched_imports: set[str] = set()

    updated: list[Dependency] = []
    for dep in dependencies:
        if dep.ecosystem != "go":
            updated.append(dep)
            continue
        status, reason = _classify(dep.name, facts)
        if status is DependencyStatus.IN_USE:
            matched_imports.add(dep.name)
        # REQ-17 / FR-150 — surface every import path that resolves to
        # this module as an entry point with its usage count.
        if status is DependencyStatus.IN_USE:
            ep_list = _entry_points_for_module(dep.name, facts)
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

    # Phantom imports — imported but not declared in go.mod
    phantoms = _build_phantom_deps(facts.imports, matched_imports, declared)
    updated.extend(phantoms)
    return updated, errors


# ── Tree scanning ──────────────────────────────────────────────────────────


def _scan_tree(root: Path, errors: list[str]) -> _Facts:
    facts = _Facts()
    if not GO_AST_AVAILABLE:
        return facts
    for raw_path in root.rglob("*.go"):
        rel_parts = raw_path.relative_to(root).parts
        if any(p in _EXCLUDED_DIR_NAMES for p in rel_parts):
            continue
        try:
            resolved = resolve_and_confine(raw_path, root)
        except PathEscapeError:
            errors.append(f"go source: symlink escape blocked: {'/'.join(rel_parts)}")
            continue
        try:
            size = resolved.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            errors.append(f"go source: skipped {resolved.name} — too large")
            continue
        try:
            source_bytes = resolved.read_bytes()
        except OSError as exc:
            errors.append(f"go source: read failed {resolved.name} — {exc}")
            continue
        _scan_file(source_bytes, facts, errors, resolved.name, rel_parts)
    return facts


def _scan_file(
    source: bytes,
    facts: _Facts,
    errors: list[str],
    filename: str,
    rel_parts: tuple[str, ...],
) -> None:
    if _GO_PARSER is None:
        return
    try:
        tree = _GO_PARSER.parse(source)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"go source: parse failed for {filename} — {exc}")
        return

    is_test = filename.endswith("_test.go")
    pre_imports = set(facts.imports)
    _walk_imports(tree.root_node, facts, is_test)
    # REQ-17 / FR-150 — for each newly-seen import in this file, count
    # selector references (``<lastSegment>.Foo``). Counting is bounded to
    # validated Go identifiers to keep pattern building safe, and every
    # name is tallied in one pass over the file's identifier tokens —
    # scanning the whole file once per import was quadratic, so a crafted
    # import-packed file never finished (CWE-1333).
    new_imports = facts.imports - pre_imports
    if new_imports:
        try:
            text = source.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            text = ""
        pairs: list[tuple[str, str]] = []
        for imp in new_imports:
            last = imp.rsplit("/", 1)[-1]
            facts._last_segment_index.setdefault(last, imp)
            pairs.append((imp, last))
        # `\bpkg\.` matches ``errors.``-prefixed selectors.
        counts, uncounted = count_selector_refs(
            text, [last for _, last in pairs if _GO_PKG_NAME_RE.match(last)]
        )
        for imp, last in pairs:
            n = counts.get(last, 0)
            facts.import_counts[imp] = (
                facts.import_counts.get(imp, 0) + max(n, 1)
            )
        if uncounted:
            errors.append(
                f"go source: reference counting capped at {MAX_FULL_SCANS} "
                f"unusual import names in {filename} — {len(uncounted)} more "
                f"counted as a single reference each"
            )


def _walk_imports(node, facts: _Facts, is_test: bool) -> None:  # type: ignore[no-untyped-def]
    """Walk the AST extracting import_spec nodes plus FR-150 signals."""
    if node.type == "import_spec":
        _extract_import_spec(node, facts, is_test)
        return
    if node.type in {"comment", "interpreted_string_literal"}:
        return
    if node.type == "selector_expression":
        _record_selector(node, facts)
    if node.type == "composite_literal":
        _record_composite_literal(node, facts)
    if node.type == "var_spec":
        _record_var_spec(node, facts)
    if node.type == "short_var_declaration":
        _record_short_var_declaration(node, facts)
    if node.type == "parameter_declaration":
        _record_parameter_declaration(node, facts)
    for child in node.children:
        _walk_imports(child, facts, is_test)


def _node_text_str_go(node) -> str:  # type: ignore[no-untyped-def]
    text = node.text
    if text is None:
        return ""
    return text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text


def _split_selector(node) -> tuple[str, str]:  # type: ignore[no-untyped-def]
    """Return ``(receiver_text, member_name)`` for a ``selector_expression``."""
    receiver = ""
    member = ""
    saw_dot = False
    for child in node.children:
        if child.type == ".":
            saw_dot = True
            continue
        if not saw_dot:
            if child.type == "identifier":
                receiver = _node_text_str_go(child)
            elif child.type == "selector_expression":
                # Chained — last segment is the receiver for our
                # purposes (we attribute by simple name).
                receiver = _node_text_str_go(child).rsplit(".", 1)[-1]
        else:
            if child.type == "field_identifier":
                member = _node_text_str_go(child)
                break
    return receiver, member


def _split_qualified_type(node) -> tuple[str, str]:  # type: ignore[no-untyped-def]
    """Return ``(package_identifier, type_identifier)`` from a qualified_type."""
    pkg = ""
    typ = ""
    for child in node.children:
        if child.type == "package_identifier":
            pkg = _node_text_str_go(child)
        elif child.type == "type_identifier":
            typ = _node_text_str_go(child)
    return pkg, typ


def _extract_qualified_type_under(node) -> tuple[str, str] | None:  # type: ignore[no-untyped-def]
    """Find the first qualified_type under ``node`` and split it.

    ``*pkg.Type`` is a ``pointer_type`` containing the qualified_type.
    ``[]pkg.Type`` is a ``slice_type``. We recurse one level looking for it.
    """
    if node.type == "qualified_type":
        return _split_qualified_type(node)
    for child in node.children:
        if child.type == "qualified_type":
            return _split_qualified_type(child)
        if child.type in {"pointer_type", "slice_type", "array_type"}:
            res = _extract_qualified_type_under(child)
            if res is not None:
                return res
    return None


def _record_selector(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``pkg.Member`` → bump ``selector_counts[(pkg_simple, member)]``.

    Only fires when ``pkg`` is a known imported package's last segment
    (e.g. ``errors`` for ``github.com/pkg/errors``) — avoids conflating
    bare-receiver method calls (handled by the variable_type path).
    """
    receiver, member = _split_selector(node)
    if not receiver or not member:
        return
    if receiver in facts._last_segment_index:
        facts.selector_counts[(receiver, member)] = (
            facts.selector_counts.get((receiver, member), 0) + 1
        )
        return
    # Receiver is a bound variable — record a method call.
    bound = facts.variable_type.get(receiver)
    if bound is not None:
        pkg_simple, type_simple = bound
        facts.method_calls[(pkg_simple, type_simple, member)] = (
            facts.method_calls.get((pkg_simple, type_simple, member), 0) + 1
        )


def _record_composite_literal(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``pkg.Type{…}`` → bump ``composite_counts[(pkg, Type)]``."""
    for child in node.children:
        if child.type == "qualified_type":
            pkg, typ = _split_qualified_type(child)
            if pkg and typ and pkg in facts._last_segment_index:
                facts.composite_counts[(pkg, typ)] = (
                    facts.composite_counts.get((pkg, typ), 0) + 1
                )
            return


def _record_var_spec(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``var c *pkg.Client = …`` — bind c to (pkg, Client)."""
    name = ""
    bound: tuple[str, str] | None = None
    for child in node.children:
        ct = child.type
        if ct == "identifier" and not name:
            name = _node_text_str_go(child)
        elif ct in {"qualified_type", "pointer_type", "slice_type", "array_type"}:
            bound = _extract_qualified_type_under(child)
    if name and bound is not None:
        pkg_simple, typ = bound
        if pkg_simple in facts._last_segment_index:
            facts.variable_type[name] = (pkg_simple, typ)


def _record_short_var_declaration(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``c := pkg.NewClient(...)`` — bind c via the call's selector.

    Heuristic: when the RHS is a call to ``pkg.NewX``, bind ``c`` to
    ``(pkg, X)``. Matches the Go ``New<Type>`` convention. When the RHS
    is a call that doesn't match the convention we leave the binding
    unset (no false attribution).
    """
    # Children: expression_list (LHS), :=, expression_list (RHS).
    lhs = None
    rhs = None
    saw_assign = False
    for child in node.children:
        if child.type == "expression_list":
            if not saw_assign:
                lhs = child
            else:
                rhs = child
        elif child.type == ":=":
            saw_assign = True
    if lhs is None or rhs is None:
        return
    lhs_idents = [
        c for c in lhs.children if c.type == "identifier"
    ]
    if not lhs_idents:
        return
    name = _node_text_str_go(lhs_idents[0])
    # Find a call_expression on the RHS.
    rhs_call = None
    for c in rhs.children:
        if c.type == "call_expression":
            rhs_call = c
            break
        if c.type == "unary_expression":
            for sub in c.children:
                if sub.type == "call_expression":
                    rhs_call = sub
                    break
    if rhs_call is None:
        return
    callee = rhs_call.children[0] if rhs_call.children else None
    if callee is None or callee.type != "selector_expression":
        return
    pkg, fn = _split_selector(callee)
    if not pkg or not fn:
        return
    if pkg not in facts._last_segment_index:
        return
    if fn.startswith("New") and len(fn) > 3 and fn[3].isupper():
        facts.variable_type[name] = (pkg, fn[3:])


def _record_parameter_declaration(node, facts: _Facts) -> None:  # type: ignore[no-untyped-def]
    """``func f(c *pkg.Client)`` — bind c to (pkg, Client)."""
    name = ""
    bound: tuple[str, str] | None = None
    for child in node.children:
        ct = child.type
        if ct == "identifier" and not name:
            name = _node_text_str_go(child)
        elif ct in {"qualified_type", "pointer_type", "slice_type", "array_type"}:
            bound = _extract_qualified_type_under(child)
    if name and bound is not None:
        pkg_simple, typ = bound
        if pkg_simple in facts._last_segment_index:
            facts.variable_type[name] = (pkg_simple, typ)


def _extract_import_spec(node, facts: _Facts, is_test: bool) -> None:  # type: ignore[no-untyped-def]
    """Extract import path and classify blank/dot/aliased."""
    path_str: str | None = None
    is_blank = False
    is_dot = False

    for child in node.children:
        if child.type == "interpreted_string_literal":
            path_str = _extract_string_content(child)
        elif child.type == "blank_identifier":
            is_blank = True
        elif child.type == "dot":
            is_dot = True
        # package_identifier (alias) — still counts as import

    if not path_str:
        return

    # Special pseudo-packages
    if path_str == "C":
        facts.has_cgo = True
        return
    if path_str == "unsafe":
        facts.has_unsafe = True
        # Still count as an import for classification
        facts.imports.add(path_str)
        return

    # Skip stdlib
    if _is_stdlib(path_str):
        return

    facts.imports.add(path_str)
    if is_blank or is_dot:
        facts.forced_in_use.add(path_str)
    # FR-150 — populate the last-segment index immediately so the rest
    # of the walk can attribute ``pkg.Member`` selectors and bind
    # ``var c *pkg.Type`` parameters to a known package.
    last = path_str.rsplit("/", 1)[-1]
    facts._last_segment_index.setdefault(last, path_str)


def _extract_string_content(node) -> str:  # type: ignore[no-untyped-def]
    """Get the text content of an interpreted_string_literal."""
    for child in node.children:
        if child.type == "interpreted_string_literal_content":
            text = child.text
            if text is None:
                return ""
            return text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    # Fallback: strip quotes
    text = node.text
    if text is None:
        return ""
    s = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    return s.strip('"')


def _is_stdlib(path: str) -> bool:
    """Check if an import path is a Go standard library package."""
    if path in _GO_STDLIB:
        return True
    # Multi-segment stdlib paths: if the top-level segment matches a
    # known stdlib root, it's stdlib (e.g., "net/http/httptest").
    # Go stdlib packages never have dots in the first segment.
    first_segment = path.split("/", 1)[0]
    return "." not in first_segment and first_segment in {
        p.split("/", 1)[0] for p in _GO_STDLIB
    }


# ── Classification ─────────────────────────────────────────────────────────


def _entry_points_for_module(module: str, facts: _Facts) -> list[EntryPoint]:
    """Build EntryPoint records for ``module``.

    Surfaces five kinds:
      * ``package`` — one per import path that resolves to this module.
      * ``function`` — per-symbol selector counts (``errors.New(...)``).
      * ``constructor`` — composite-literal construction
        (``redis.Options{...}`` / ``&redis.Options{...}``).
      * ``method`` — instance method calls via type-bound variables
        (``c.Set(...)`` after ``c *redis.Client = ...``).
    """
    out: list[EntryPoint] = []
    seen: set[str] = set()
    # Package-level imports.
    package_simples: set[str] = set()
    for imp in sorted(facts.imports):
        if imp != module and not imp.startswith(module + "/"):
            continue
        if imp in seen:
            continue
        seen.add(imp)
        package_simples.add(imp.rsplit("/", 1)[-1])
        out.append(
            EntryPoint(
                name=imp,
                kind="package",
                used=True,
                usage_count=facts.import_counts.get(imp, 1),
            )
        )
    if not package_simples:
        return out
    # Per-symbol selector counts.
    for (pkg_simple, member), n in sorted(facts.selector_counts.items()):
        if pkg_simple not in package_simples or n <= 0:
            continue
        label = f"{pkg_simple}.{member}"
        if label in seen:
            continue
        seen.add(label)
        out.append(
            EntryPoint(
                name=label, kind="function", used=True,
                usage_count=n,
            )
        )
    # Composite-literal "constructors".
    for (pkg_simple, typ), n in sorted(facts.composite_counts.items()):
        if pkg_simple not in package_simples or n <= 0:
            continue
        label = f"{pkg_simple}.{typ}{{}}"
        if label in seen:
            continue
        seen.add(label)
        out.append(
            EntryPoint(
                name=label, kind="constructor", used=True,
                usage_count=n,
            )
        )
    # Instance methods on type-bound variables.
    for (pkg_simple, typ, method), n in sorted(facts.method_calls.items()):
        if pkg_simple not in package_simples or n <= 0:
            continue
        label = f"{typ}.{method}"
        if label in seen:
            continue
        seen.add(label)
        out.append(
            EntryPoint(
                name=label, kind="method", used=True,
                usage_count=n,
            )
        )
    return out


def _classify(
    name: str, facts: _Facts
) -> tuple[DependencyStatus, str]:
    """Classify a declared Go dep against extracted import facts."""
    # Check for exact match or sub-package import
    # e.g., dep "github.com/stretchr/testify" matches import
    # "github.com/stretchr/testify/assert"
    for imp in facts.imports:
        if imp == name or imp.startswith(name + "/"):
            if imp in facts.forced_in_use or name in facts.forced_in_use:
                return DependencyStatus.IN_USE, f"imported as '{imp}' (blank/dot import)"
            return DependencyStatus.IN_USE, f"imported as '{imp}' in project source"

    # Also check if any forced_in_use sub-path matches
    for imp in facts.forced_in_use:
        if imp == name or imp.startswith(name + "/"):
            return DependencyStatus.IN_USE, f"imported as '{imp}' (blank/dot import)"

    return DependencyStatus.SAFE, "no import or usage found in source files"


def _build_phantom_deps(
    all_imports: set[str], matched: set[str], declared: set[str]
) -> list[Dependency]:
    """Build UNDECLARED deps for imports not matching any declared dep."""
    phantoms: list[Dependency] = []
    seen: set[str] = set()

    for imp in all_imports:
        # Find the module root (first two segments for domain-based imports)
        module_root = _guess_module_root(imp)
        if module_root in matched or module_root in declared or module_root in seen:
            continue
        # Also check if the import itself is declared or matched
        if imp in matched or imp in declared:
            continue
        if _is_stdlib(imp):
            continue
        seen.add(module_root)
        phantoms.append(
            Dependency(
                name=module_root,
                version=None,
                status=DependencyStatus.UNDECLARED,
                reason=f"imported as '{imp}' but not declared in go.mod",
                entry_points=[],
                entry_points_used=0,
                entry_points_total=0,
                source=f"detected:{module_root}",
                resolved=False,
                ecosystem="go",
            )
        )
    return phantoms


def _guess_module_root(import_path: str) -> str:
    """Guess the Go module root from an import path.

    Convention: domain-based imports (containing a dot in the first segment)
    use 3 segments for the module root: ``github.com/user/repo``.
    Non-domain imports are typically stdlib (already filtered).
    """
    parts = import_path.split("/")
    if len(parts) >= 3 and "." in parts[0]:
        return "/".join(parts[:3])
    return import_path
