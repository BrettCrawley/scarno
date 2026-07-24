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

"""Python source-code analyser — REQ-3.

Walks the project tree, AST-parses every ``*.py`` file, and turns every
``Dependency`` returned by REQ-2 into one of ``IN_USE``, ``UNCERTAIN``,
or ``SAFE`` based on whether it is actually referenced from source.

For ``IN_USE`` dependencies we also enumerate the installed package's
public symbols (``__all__`` or non-underscore ``dir()``) and mark each
one as ``used`` when a matching ``import`` / ``from … import`` /
``<alias>.symbol`` access appears in the project.

Safety:
  * Source is parsed via ``ast.parse`` — never ``exec``/``eval``
    (SEC-001).
  * File paths are confined via ``resolve_and_confine`` before reading
    (SEC-002, SEC-NEW-05).
  * Files larger than ``MAX_FILE_BYTES`` are skipped with a warning
    (SEC-NEW-04, D-04).
  * Entry-point enumeration is wrapped in broad except — a buggy
    ``__init__.py`` in a third-party package never crashes the analyser.
"""
from __future__ import annotations

import ast
import importlib
import importlib.metadata
import importlib.util
import inspect
import re
import sys
from dataclasses import replace
from pathlib import Path
from collections.abc import Callable
from typing import Any

from scarno.analysers.python.import_aliases import IMPORT_ALIASES
from scarno.analysers.python.notebook_parser import extract_code_cells
from scarno.core.test_scope import TestScopeMatcher
from scarno.findings import apply_rules, load_suppression_config
from scarno.models import Dependency, DependencyStatus, EntryPoint, Finding
from scarno.security import (
    MAX_FILE_BYTES,
    PathEscapeError,
    resolve_and_confine,
)

# REQ-3b — Directory names we treat as vendored / in-repo dep copies.
_VENDOR_DIR_NAMES: frozenset[str] = frozenset(
    {"vendor", "_vendor", "third_party", "thirdparty", "site-packages"}
)

_STDLIB_NAMES: frozenset[str] = frozenset(sys.stdlib_module_names)

_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        "build",
        "dist",
        ".git",
        "node_modules",
    }
)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


# Regex to extract distribution name from a .dist-info directory name.
# Format: "<name>-<version>.dist-info" — name may contain letters, digits,
# hyphens, underscores, dots.
_DIST_INFO_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)-[0-9].*\.dist-info$"
)
# Well-known venv directory names to scan.
_VENV_DIR_NAMES = (".venv", "venv")


# ── .venv metadata scanning (FR-135) ──────────────────────────────────────


def _find_site_packages(project_root: Path) -> Path | None:
    """Locate ``site-packages`` inside the project's virtualenv."""
    for venv_name in _VENV_DIR_NAMES:
        venv_dir = project_root / venv_name
        if not venv_dir.is_dir():
            continue
        # Linux/macOS: lib/pythonX.Y/site-packages
        lib_dir = venv_dir / "lib"
        if lib_dir.is_dir():
            for child in lib_dir.iterdir():
                sp = child / "site-packages"
                if sp.is_dir():
                    return sp
        # Windows: Lib/site-packages
        sp = venv_dir / "Lib" / "site-packages"
        if sp.is_dir():
            return sp
    return None


def _build_venv_dist_imports_map(
    project_root: Path, errors: list[str]
) -> "DistImportsMap":
    """Scan ``.venv`` dist-info metadata for import-name mappings (FR-135).

    Reads ``top_level.txt`` from each ``.dist-info`` directory in the
    project's virtualenv. Falls back to deriving top-level packages from
    ``RECORD`` when ``top_level.txt`` is absent.
    """
    result: DistImportsMap = {}
    site_packages = _find_site_packages(project_root)
    if site_packages is None:
        return result
    # Confine to project root (SEC-NEW-30).
    try:
        site_packages = resolve_and_confine(site_packages, project_root)
    except PathEscapeError:
        errors.append(
            "venv site-packages escapes project root; skipping venv scan"
        )
        return result

    try:
        entries = list(site_packages.iterdir())
    except OSError:
        return result

    for dist_info in entries:
        if not dist_info.name.endswith(".dist-info"):
            continue
        if not dist_info.is_dir():
            continue
        m = _DIST_INFO_RE.match(dist_info.name)
        if m is None:
            continue
        dist_name = m.group(1)
        canonical = _normalise(dist_name)

        import_names: set[str] = set()

        # Prefer top_level.txt — one import name per line.
        top_level = dist_info / "top_level.txt"
        if top_level.exists():
            try:
                size = top_level.stat().st_size
                if size > MAX_FILE_BYTES:
                    continue
                text = top_level.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    name = line.strip()
                    if name and not name.startswith("#"):
                        import_names.add(name.lower())
            except OSError:
                continue
        else:
            # Fallback: derive from RECORD file paths.
            record = dist_info / "RECORD"
            if record.exists():
                try:
                    size = record.stat().st_size
                    if size > MAX_FILE_BYTES:
                        continue
                    text = record.read_text(encoding="utf-8", errors="replace")
                    for line in text.splitlines():
                        path_part = line.split(",", 1)[0].strip()
                        if not path_part or path_part.startswith(".."):
                            continue
                        top = path_part.split("/", 1)[0]
                        if top.endswith(".dist-info") or top.startswith("_"):
                            continue
                        if top.endswith(".py"):
                            top = top.removesuffix(".py")
                        if top and not top.startswith("."):
                            import_names.add(top.lower())
                except OSError:
                    continue

        if import_names:
            result.setdefault(canonical, set()).update(import_names)

    return result


def _merge_dist_maps(
    base: "DistImportsMap", override: "DistImportsMap"
) -> "DistImportsMap":
    """Merge two dist-imports maps. Override entries supplement base."""
    merged = dict(base)
    for dist, imports in override.items():
        merged.setdefault(dist, set()).update(imports)
    return merged


# ── AST visitor ──────────────────────────────────────────────────────────────


class _ImportVisitor(ast.NodeVisitor):
    """Collect top-level imports, dynamic imports, and symbol usages.

    ``usage_counts`` (REQ-17) maps ``(top_module, symbol)`` to the number
    of source-level reference sites observed for that symbol — both
    ``mod.symbol`` attribute accesses and bare-name references for
    ``from mod import symbol``.
    """

    def __init__(self) -> None:
        self.direct_imports: set[str] = set()
        self.dynamic_literals: set[str] = set()
        self.has_nonliteral_dynamic: bool = False
        # top-level module name → set of symbols used
        self.used_symbols: dict[str, set[str]] = {}
        # REQ-17 — (top_module, symbol) → integer usage count.
        self.usage_counts: dict[tuple[str, str], int] = {}
        # local-name → top-level module (for ``import foo as bar`` /
        # ``from foo import bar`` aliasing)
        self._module_aliases: dict[str, str] = {}
        # local-name → (top_module, symbol) — used to count call sites for
        # ``from foo import bar``-style bindings even when the user calls
        # ``bar(...)`` rather than ``foo.bar(...)``.
        self._symbol_aliases: dict[str, tuple[str, str]] = {}
        # FR-150 — top-level modules that were wildcard-imported via
        # ``from x import *``. Surfaced as ``kind="wildcard"`` entry
        # points and used for unqualified-name attribution.
        self.wildcard_modules: set[str] = set()
        # FR-150 — local-name → (top_module, class_symbol). Populated by
        # ``Foo()``-call assignments, ``x: Foo = …`` annotations, and
        # ``def f(x: Foo)`` parameters. Drives instance-method
        # attribution: ``s.method()`` after ``s = Session()`` → record
        # a call to ``requests.Session.method``.
        self._variable_class: dict[str, tuple[str, str]] = {}
        # FR-150 — per (top_module, class_symbol, method) call counts.
        # Aggregated alongside ``usage_counts`` and surfaced as
        # ``kind="method"`` entry points.
        self.method_calls: dict[tuple[str, str, str], int] = {}
        # FR-150 — bare Name LOAD references that aren't already bound
        # via ``_symbol_aliases`` or ``_module_aliases``. Used to
        # attribute usage of names brought in via ``from x import *``
        # (where the visitor doesn't know which symbols the wildcard
        # actually exposed). Counted per identifier across the file.
        self.unqualified_name_refs: dict[str, int] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            self.direct_imports.add(top)
            local = alias.asname or top
            self._module_aliases[local] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level and node.level > 0:
            # Relative import — local code, not a declared dep.
            self.generic_visit(node)
            return
        if not node.module:
            self.generic_visit(node)
            return
        top = node.module.split(".")[0]
        self.direct_imports.add(top)
        bucket = self.used_symbols.setdefault(top, set())
        for alias in node.names:
            if alias.name == "*":
                # FR-150 — record the wildcard'd module separately so
                # the report can distinguish ``from x import *`` from
                # concrete name-imports.
                self.wildcard_modules.add(top)
                continue
            bucket.add(alias.name)
            local = alias.asname or alias.name
            # Track the symbol binding so ``from foo import bar as b`` /
            # ``b()`` still marks ``foo.bar`` as used.
            self._module_aliases[local] = f"{top}.{alias.name}"
            self._symbol_aliases[local] = (top, alias.name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Catch ``mod.symbol`` and ``alias.symbol`` accesses.
        if isinstance(node.value, ast.Name):
            target = self._module_aliases.get(node.value.id)
            if target is not None and "." not in target:
                # target is a top-level module name
                self.used_symbols.setdefault(target, set()).add(node.attr)
                key = (target, node.attr)
                self.usage_counts[key] = self.usage_counts.get(key, 0) + 1
            else:
                # FR-150 — instance method attribution: when
                # ``node.value.id`` is a local variable bound to an
                # imported class (via ``s = Session()`` or ``s: Session
                # = …`` or ``def f(s: Session)``), record the call as
                # ``<top>.<class>.<method>`` so the report distinguishes
                # methods from imports.
                cls_binding = self._variable_class.get(node.value.id)
                if cls_binding is not None:
                    top, cls_simple = cls_binding
                    mkey = (top, cls_simple, node.attr)
                    self.method_calls[mkey] = (
                        self.method_calls.get(mkey, 0) + 1
                    )
                    # Also bump the class symbol's own count — the user
                    # sees ``Session`` used by virtue of method calls
                    # on its instances.
                    ckey = (top, cls_simple)
                    self.usage_counts[ckey] = (
                        self.usage_counts.get(ckey, 0) + 1
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # FR-150 — bind ``x = SomeClass(...)`` so later ``x.method()``
        # attributes back to ``SomeClass``. Only the simple form
        # ``x = ClassName(args)`` is tracked; complex unpacks and
        # multiple-target assignments are deliberately skipped to avoid
        # false bindings.
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
        ):
            self._bind_variable_to_call(node.targets[0].id, node.value.func)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # FR-150 — bind ``x: SomeClass = …`` from the annotation.
        if isinstance(node.target, ast.Name):
            self._bind_variable_to_type_node(node.target.id, node.annotation)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._bind_function_arguments(node.args)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._bind_function_arguments(node.args)
        self.generic_visit(node)

    def _bind_function_arguments(self, args: ast.arguments) -> None:
        """Bind ``def f(x: Foo)`` parameters to their annotations."""
        all_args = (
            list(args.posonlyargs)
            + list(args.args)
            + list(args.kwonlyargs)
        )
        for arg in all_args:
            if arg.annotation is not None:
                self._bind_variable_to_type_node(arg.arg, arg.annotation)
        if args.vararg and args.vararg.annotation:
            self._bind_variable_to_type_node(
                args.vararg.arg, args.vararg.annotation,
            )
        if args.kwarg and args.kwarg.annotation:
            self._bind_variable_to_type_node(
                args.kwarg.arg, args.kwarg.annotation,
            )

    def _bind_variable_to_call(
        self, name: str, func: ast.expr,
    ) -> None:
        """Bind ``name`` to the class identified by a Call's ``func`` node."""
        # Bare ``Foo(...)`` — look up ``Foo`` in the symbol-alias map.
        if isinstance(func, ast.Name):
            mapping = self._symbol_aliases.get(func.id)
            if mapping is not None:
                self._variable_class[name] = mapping
            return
        # Qualified ``mod.Foo(...)`` — receiver is a module alias.
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            mod = self._module_aliases.get(func.value.id)
            if mod is not None and "." not in mod:
                self._variable_class[name] = (mod, func.attr)

    def _bind_variable_to_type_node(
        self, name: str, annotation: ast.expr,
    ) -> None:
        """Bind ``name`` to the class identified by a type-annotation node."""
        # ``x: Foo`` — bare name annotation.
        if isinstance(annotation, ast.Name):
            mapping = self._symbol_aliases.get(annotation.id)
            if mapping is not None:
                self._variable_class[name] = mapping
            return
        # ``x: mod.Foo`` — qualified.
        if isinstance(annotation, ast.Attribute) and isinstance(
            annotation.value, ast.Name
        ):
            mod = self._module_aliases.get(annotation.value.id)
            if mod is not None and "." not in mod:
                self._variable_class[name] = (mod, annotation.attr)
            return
        # ``x: list[Foo]`` / ``x: Optional[Foo]`` — peel one subscript.
        if isinstance(annotation, ast.Subscript):
            self._bind_variable_to_type_node(name, annotation.slice)

    def visit_Name(self, node: ast.Name) -> None:
        # REQ-17 — count bare-name references for ``from mod import sym``
        # bindings (e.g. ``fail(...)`` after ``from pytest import fail``).
        if isinstance(node.ctx, ast.Load):
            mapping = self._symbol_aliases.get(node.id)
            if mapping is not None:
                key = mapping
                self.usage_counts[key] = self.usage_counts.get(key, 0) + 1
            elif (
                node.id not in self._module_aliases
                and not node.id.startswith("_")
                and node.id not in {"True", "False", "None", "self", "cls"}
            ):
                # FR-150 — unqualified reference that may resolve via a
                # wildcard import. Recorded for post-hoc attribution by
                # ``_enumerate_entry_points`` when the dep is
                # wildcard-imported.
                self.unqualified_name_refs[node.id] = (
                    self.unqualified_name_refs.get(node.id, 0) + 1
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "import_module":
            if isinstance(func.value, ast.Name) and func.value.id == "importlib":
                self._consume_dynamic_call(node)
        elif isinstance(func, ast.Attribute) and func.attr == "find_spec":
            if isinstance(func.value, ast.Attribute) and func.value.attr == "util":
                if (
                    isinstance(func.value.value, ast.Name)
                    and func.value.value.id == "importlib"
                ):
                    self._consume_dynamic_call(node)
        elif isinstance(func, ast.Name):
            if func.id in {"__import__", "import_module"}:
                self._consume_dynamic_call(node)
        self.generic_visit(node)

    def _consume_dynamic_call(self, node: ast.Call) -> None:
        if not node.args:
            self.has_nonliteral_dynamic = True
            return
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            top = first.value.split(".")[0]
            if top:
                self.dynamic_literals.add(top)
        else:
            self.has_nonliteral_dynamic = True


# ── File discovery + parsing ─────────────────────────────────────────────────


def _load_gitignore_matcher(
    root: Path, errors: list[str]
) -> "Callable[[str], bool] | None":
    """Return a gitignore match function, or ``None`` if unavailable."""
    try:
        import gitignorefile  # type: ignore[import-untyped]
    except ImportError:
        errors.append(
            "source_analyser: gitignorefile not installed — "
            "skipping .gitignore filtering (install with "
            "`pip install gitignorefile`)"
        )
        return None
    cache: Callable[[str], bool] = gitignorefile.Cache()
    return cache


def _discover_py_files(
    root: Path,
    errors: list[str],
    *,
    use_gitignore: bool = True,
    test_matcher: TestScopeMatcher | None = None,
) -> tuple[list[Path], int]:
    """Return ``(files, test_skip_count)``.

    REQ-17: ``test_matcher`` skips test paths under ``--exclude-tests``.
    The skip count is aggregate-only (no per-file paths leaked) so callers
    can emit a privacy-safe summary line in errors.
    """
    py_files: list[Path] = []
    test_skip_count = 0

    gitignore_match: Callable[[str], bool] | None = None
    if use_gitignore:
        gitignore_match = _load_gitignore_matcher(root, errors)

    try:
        iterator = root.rglob("*.py")
    except OSError as exc:
        errors.append(f"source_analyser: tree walk failed — {exc}")
        return py_files, test_skip_count
    for raw_path in iterator:
        rel_parts = raw_path.relative_to(root).parts
        if any(
            part in _EXCLUDED_DIRS or part.endswith(".egg-info") for part in rel_parts
        ):
            continue
        if gitignore_match is not None and gitignore_match(str(raw_path)):
            continue
        if test_matcher is not None:
            rel_path_str = "/".join(rel_parts)
            if test_matcher.is_test_path(rel_path_str):
                test_skip_count += 1
                continue
        try:
            resolved = resolve_and_confine(raw_path, root)
        except PathEscapeError:
            errors.append(
                f"source_analyser: symlink escape blocked: "
                f"{'/'.join(rel_parts)}"
            )
            continue
        try:
            size = resolved.stat().st_size
        except OSError as exc:
            errors.append(f"source_analyser: stat failed for {resolved.name} — {exc}")
            continue
        if size > MAX_FILE_BYTES:
            errors.append(
                f"source_analyser: skipped {'/'.join(rel_parts)} — file too large "
                f"({size} bytes > {MAX_FILE_BYTES})"
            )
            continue
        py_files.append(resolved)
    return py_files, test_skip_count


def _parse_file(
    path: Path, errors: list[str]
) -> tuple[_ImportVisitor, str, ast.AST] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"source_analyser: could not read {path.name} — {exc}")
        return None
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        errors.append(f"source_analyser: syntax error in {path.name} — {exc}")
        return None
    visitor = _ImportVisitor()
    visitor.visit(tree)
    return visitor, text, tree


# ── Metadata-based dist → import name mapping ────────────────────────────────

# Type alias for the inverted metadata map: canonical dist name → set of import names.
DistImportsMap = dict[str, set[str]]


def _build_dist_to_imports_map() -> DistImportsMap:
    """Invert ``packages_distributions()`` → {canonical_dist: {import_names}}.

    This lets us match imports like ``OpenSSL`` to distribution ``pyopenssl``
    without maintaining a static alias table for every package.
    """
    try:
        fwd = importlib.metadata.packages_distributions()
    except Exception:  # noqa: BLE001 — defensive; never crash analysis
        return {}
    result: DistImportsMap = {}
    for import_name, dists in fwd.items():
        for dist in dists:
            canonical = _normalise(dist)
            result.setdefault(canonical, set()).add(import_name.lower())
    return result


# ── Classification ───────────────────────────────────────────────────────────


def _import_matches_dep(
    import_name: str,
    dep_canonical: str,
    dist_imports: DistImportsMap | None = None,
) -> bool:
    normalised_import = _normalise(import_name)
    if normalised_import == dep_canonical:
        return True
    # Static alias table (fallback for uninstalled packages).
    mapped = IMPORT_ALIASES.get(normalised_import)
    if mapped is not None and _normalise(mapped) == dep_canonical:
        return True
    # Metadata-based: check if this dep's known import names include our import.
    if dist_imports:
        known_imports = dist_imports.get(dep_canonical, set())
        if normalised_import in known_imports:
            return True
    return False


def _find_import_name(
    dep_canonical: str,
    import_set: set[str],
    dist_imports: DistImportsMap | None = None,
) -> str | None:
    for imp in import_set:
        if _import_matches_dep(imp, dep_canonical, dist_imports):
            return imp
    return None


def _classify(
    dep_canonical: str,
    direct: set[str],
    dynamic_literal: set[str],
    has_nonliteral: bool,
    dist_imports: DistImportsMap | None = None,
) -> tuple[DependencyStatus, str]:
    direct_match = _find_import_name(dep_canonical, direct, dist_imports)
    if direct_match is not None:
        return (
            DependencyStatus.IN_USE,
            f"imported as '{direct_match}' in project source",
        )
    literal_match = _find_import_name(dep_canonical, dynamic_literal, dist_imports)
    if literal_match is not None:
        return (
            DependencyStatus.IN_USE,
            f"dynamically imported via importlib/__import__('{literal_match}')",
        )
    if has_nonliteral:
        return (
            DependencyStatus.UNCERTAIN,
            "dynamic import with non-literal module name — manual review required",
        )
    return DependencyStatus.SAFE, "no import or usage found in source files"


# ── Entry-point enumeration ──────────────────────────────────────────────────


def _classify_symbol(obj: Any) -> str:
    if inspect.isfunction(obj) or inspect.isbuiltin(obj):
        return "function"
    if inspect.isclass(obj):
        return "class"
    if inspect.ismethod(obj):
        return "method"
    if isinstance(obj, (int, str, bool, float, bytes)):
        return "constant"
    return "unknown"


def _resolve_import_name(
    dep_canonical: str, direct: set[str]
) -> str | None:
    """Pick the actual source-level import name for this dep."""
    name = _find_import_name(dep_canonical, direct)
    if name is not None:
        return name
    # Reverse alias — dep is the dist name; find the import name that aliases to it.
    for imp_name, dist_name in IMPORT_ALIASES.items():
        if _normalise(dist_name) == dep_canonical and imp_name in direct:
            return imp_name
    return None


def _enumerate_entry_points(
    dep_canonical: str,
    direct: set[str],
    used_symbols: dict[str, set[str]],
    errors: list[str],
    usage_counts: dict[tuple[str, str], int] | None = None,
    *,
    wildcard_modules: set[str] | None = None,
    unqualified_refs: dict[str, int] | None = None,
    method_calls: dict[tuple[str, str, str], int] | None = None,
) -> list[EntryPoint]:
    import_name = _resolve_import_name(dep_canonical, direct)
    if import_name is None:
        return []
    if import_name in _STDLIB_NAMES:
        return []
    try:
        spec = importlib.util.find_spec(import_name)
    except (ImportError, ValueError):
        return []
    if spec is None:
        return []
    try:
        module = importlib.import_module(import_name)
    except Exception as exc:  # noqa: BLE001 — broad by design per REQ-3
        errors.append(
            f"entry_point_enumerator: could not enumerate {dep_canonical} — {exc}"
        )
        return []

    # FR-271 — a buggy or hostile module-level ``__getattr__`` (PEP 562) can
    # raise on ``__all__`` / ``dir()`` access; never let that crash
    # enumeration (the analyser's "a buggy package never crashes us" contract).
    try:
        explicit_all = getattr(module, "__all__", None)
    except Exception:  # noqa: BLE001 — defensive
        explicit_all = None
    if isinstance(explicit_all, (list, tuple)):
        symbol_names = [s for s in explicit_all if isinstance(s, str)]
    else:
        try:
            symbol_names = [n for n in dir(module) if not n.startswith("_")]
        except Exception:  # noqa: BLE001 — defensive
            symbol_names = []

    used = used_symbols.get(import_name, set())
    counts = usage_counts or {}
    wildcard_mods = wildcard_modules or set()
    unq_refs = unqualified_refs or {}
    method_call_counts = method_calls or {}
    is_wildcarded = import_name in wildcard_mods

    # FR-271 — surface symbols observed in source even when they are not
    # exported via ``__all__`` / ``dir()``. Module-level ``__getattr__``
    # (PEP 562) lazily provides attributes that may never appear in
    # ``dir()``; a symbol the project actually imported must still be
    # reported as a used entry point.
    known = set(symbol_names)
    for sym in sorted(used):
        if sym not in known:
            symbol_names.append(sym)
            known.add(sym)

    # FR-271 — a module relying on ``__getattr__`` with neither ``__all__``
    # nor a ``__dir__`` override has an unused lazy surface we cannot
    # enumerate. Record an honest diagnostic rather than implying full
    # coverage. (``__all__`` and ``__dir__`` both make the surface visible.)
    module_dict = vars(module)
    used_all = isinstance(explicit_all, (list, tuple))
    if (
        not used_all
        and callable(module_dict.get("__getattr__"))
        and "__dir__" not in module_dict
    ):
        errors.append(
            f"entry_point_enumerator: {dep_canonical} uses module-level "
            "__getattr__ (PEP 562) without __dir__; unused lazy attributes "
            "may be under-enumerated."
        )

    entry_points: list[EntryPoint] = []
    # FR-150 — surface the wildcard import itself as a distinct row so
    # the user can see ``from x import *`` was used.
    if is_wildcarded:
        entry_points.append(
            EntryPoint(
                name=f"{import_name}.*",
                kind="wildcard",
                used=True,
                usage_count=1,
            )
        )
    for sym in symbol_names:
        is_used = sym in used
        count = counts.get((import_name, sym), 0) if is_used else 0
        # FR-150 — wildcard attribution: when ``from x import *`` and
        # source uses unqualified ``sym`` directly, treat that as a use
        # of ``x.sym``. ``count`` is the number of bare-name references.
        if is_wildcarded and sym in unq_refs:
            is_used = True
            count = max(count, unq_refs[sym])
        try:
            obj = getattr(module, sym)
        except Exception:  # noqa: BLE001 — defensive
            # FR-271 — a lazy attribute we know was used must still be
            # surfaced; classify as ``unknown`` rather than dropping it.
            if is_used:
                entry_points.append(
                    EntryPoint(
                        name=f"{import_name}.{sym}",
                        kind="unknown",
                        used=True,
                        usage_count=count,
                    )
                )
            continue
        entry_points.append(
            EntryPoint(
                name=f"{import_name}.{sym}",
                kind=_classify_symbol(obj),
                used=is_used,
                usage_count=count,
            )
        )

    # FR-150 — instance-method calls: emit one ``kind="method"`` entry per
    # observed ``<class>.<method>`` triple owned by this module.
    method_seen: set[str] = set()
    for (top, cls_simple, method), n in sorted(method_call_counts.items()):
        if top != import_name:
            continue
        label = f"{import_name}.{cls_simple}.{method}"
        if label in method_seen:
            continue
        method_seen.add(label)
        entry_points.append(
            EntryPoint(
                name=label,
                kind="method",
                used=True,
                usage_count=n,
            )
        )
    return entry_points


# ── Public coordinator ───────────────────────────────────────────────────────


def _parse_notebooks(root: Path, errors: list[str]) -> _ImportVisitor | None:
    """Parse every ``*.ipynb`` under ``root`` into a single _ImportVisitor.

    Returns ``None`` when no notebooks are found; otherwise a visitor
    whose sets aggregate all notebook code cells. Notebook parse errors
    append to ``errors``.
    """
    notebooks = list(root.rglob("*.ipynb"))
    if not notebooks:
        return None
    visitor = _ImportVisitor()
    for nb_path in notebooks:
        rel_parts = nb_path.relative_to(root).parts
        if any(part in _EXCLUDED_DIRS for part in rel_parts):
            continue
        try:
            resolved = resolve_and_confine(nb_path, root)
        except PathEscapeError:
            errors.append(
                f"source_analyser: symlink escape blocked: "
                f"{'/'.join(rel_parts)}"
            )
            continue
        cells, nb_errors = extract_code_cells(resolved)
        errors.extend(nb_errors)
        if not cells.ast_safe_source:
            continue
        try:
            tree = ast.parse(cells.ast_safe_source)
        except SyntaxError as exc:
            errors.append(
                f"source_analyser: syntax error in notebook {nb_path.name} — {exc}"
            )
            continue
        visitor.visit(tree)
    return visitor


def _discover_vendored_packages(root: Path) -> dict[str, Path]:
    """Map normalised package name → vendored directory path.

    Looks inside any directory named ``vendor``, ``_vendor``,
    ``third_party``, ``thirdparty``, or ``site-packages`` committed in
    the repo. Each immediate child directory is treated as a vendored
    package if it contains an ``__init__.py``.
    """
    vendored: dict[str, Path] = {}
    for vendor_dir_name in _VENDOR_DIR_NAMES:
        for vendor_dir in root.rglob(vendor_dir_name):
            # Skip virtual-env site-packages; we only care about in-repo copies.
            rel_parts = vendor_dir.relative_to(root).parts
            if any(part in _EXCLUDED_DIRS for part in rel_parts):
                continue
            if not vendor_dir.is_dir():
                continue
            for child in vendor_dir.iterdir():
                if not child.is_dir():
                    continue
                if (child / "__init__.py").exists():
                    vendored.setdefault(_normalise(child.name), child)
    return vendored


def _resolve_import_to_distribution(
    import_name: str,
) -> tuple[str, bool]:
    """Return ``(distribution_name, resolved)`` for an unresolved import.

    Consults :func:`importlib.metadata.packages_distributions` to
    translate an import name into an installed distribution. Falls back
    to the raw import name when no mapping exists.
    """
    try:
        mapping = importlib.metadata.packages_distributions()
    except Exception:  # noqa: BLE001 — defensive; never let lookup crash analysis
        return import_name, False
    dists = mapping.get(import_name)
    if dists:
        return dists[0], True
    # Alias table fallback
    alias = IMPORT_ALIASES.get(_normalise(import_name))
    if alias is not None:
        return alias, True
    return import_name, False


def analyse_source_files(
    project_path: str,
    dependencies: list[Dependency],
    *,
    use_gitignore: bool = True,
    dep_graph: dict[str, set[str]] | None = None,
    exclude_tests: bool = False,
    user_test_paths: tuple[str, ...] = (),
) -> tuple[list[Dependency], list[str]]:
    """Walk the project and update every ``Dependency`` status.

    Phase 1 handles IN_USE / UNCERTAIN / SAFE classification. Phase 1.5
    extends this with ``UNDECLARED`` phantom-import detection (REQ-3b),
    notebook-cell import scanning (REQ-3b), vendored-directory detection
    (REQ-3b), and security findings via the REQ-3c rule engine. Findings
    are attached to the returned dependency list via a side channel —
    :func:`get_last_findings` — because backward-compatible signatures
    matter for REQ-2/3 callers.

    Never raises — all failures are appended to the returned error list.
    """
    deps, errors, _ = analyse_source_files_with_findings(
        project_path, dependencies, use_gitignore=use_gitignore,
        dep_graph=dep_graph,
        exclude_tests=exclude_tests,
        user_test_paths=user_test_paths,
    )
    return deps, errors


def analyse_source_files_with_findings(
    project_path: str,
    dependencies: list[Dependency],
    *,
    use_gitignore: bool = True,
    dep_graph: dict[str, set[str]] | None = None,
    exclude_tests: bool = False,
    user_test_paths: tuple[str, ...] = (),
) -> tuple[list[Dependency], list[str], list[Finding]]:
    """Three-tuple variant of :func:`analyse_source_files` that also
    returns the REQ-3c findings surfaced during the scan."""
    errors: list[str] = []
    findings: list[Finding] = []
    root = Path(project_path)
    try:
        root = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        errors.append(f"source_analyser: could not resolve project path — {exc}")
        return list(dependencies), errors, findings
    if not root.is_dir():
        return list(dependencies), errors, findings

    # Suppression config (pyproject.toml [tool.scarno.findings])
    suppression, supp_errors = load_suppression_config(root)
    errors.extend(supp_errors)

    # Build metadata-based import name resolution map (once per analysis).
    dist_imports = _build_dist_to_imports_map()
    # FR-135 — supplement with the project's .venv metadata (reads
    # top_level.txt from dist-info dirs so we don't need packages
    # installed in Scarno's own environment).
    venv_imports = _build_venv_dist_imports_map(root, errors)
    if venv_imports:
        dist_imports = _merge_dist_maps(dist_imports, venv_imports)

    test_matcher = TestScopeMatcher(
        "python",
        exclude_tests=exclude_tests,
        user_patterns=user_test_paths,
    )
    py_files, test_skip_count = _discover_py_files(
        root, errors, use_gitignore=use_gitignore,
        test_matcher=test_matcher,
    )

    direct_all: set[str] = set()
    dynamic_literal_all: set[str] = set()
    has_nonliteral_dynamic = False
    used_symbols_all: dict[str, set[str]] = {}
    # REQ-17 — (top_module, symbol) -> total reference count across project.
    usage_counts_all: dict[tuple[str, str], int] = {}
    # FR-150 — wildcard modules + per-(top_module, class, method) call counts
    # + unqualified-name references (candidates for wildcard attribution).
    wildcard_modules_all: set[str] = set()
    method_calls_all: dict[tuple[str, str, str], int] = {}
    unqualified_refs_all: dict[str, int] = {}

    for path in py_files:
        parsed = _parse_file(path, errors)
        if parsed is None:
            continue
        visitor, source_text, tree = parsed
        direct_all |= visitor.direct_imports
        dynamic_literal_all |= visitor.dynamic_literals
        if visitor.has_nonliteral_dynamic:
            has_nonliteral_dynamic = True
        for mod, symbols in visitor.used_symbols.items():
            used_symbols_all.setdefault(mod, set()).update(symbols)
        for key, count in visitor.usage_counts.items():
            usage_counts_all[key] = usage_counts_all.get(key, 0) + count
        wildcard_modules_all |= visitor.wildcard_modules
        for mkey, count in visitor.method_calls.items():
            method_calls_all[mkey] = method_calls_all.get(mkey, 0) + count
        for name, count in visitor.unqualified_name_refs.items():
            unqualified_refs_all[name] = (
                unqualified_refs_all.get(name, 0) + count
            )

        # REQ-3c — rule engine on parsed AST.
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        findings.extend(apply_rules(rel, source_text, tree))

    # REQ-3b — also scan notebook code cells.
    nb_visitor = _parse_notebooks(root, errors)
    if nb_visitor is not None:
        direct_all |= nb_visitor.direct_imports
        dynamic_literal_all |= nb_visitor.dynamic_literals
        if nb_visitor.has_nonliteral_dynamic:
            has_nonliteral_dynamic = True
        for mod, symbols in nb_visitor.used_symbols.items():
            used_symbols_all.setdefault(mod, set()).update(symbols)
        for key, count in nb_visitor.usage_counts.items():
            usage_counts_all[key] = usage_counts_all.get(key, 0) + count
        wildcard_modules_all |= nb_visitor.wildcard_modules
        for mkey, count in nb_visitor.method_calls.items():
            method_calls_all[mkey] = method_calls_all.get(mkey, 0) + count
        for name, count in nb_visitor.unqualified_name_refs.items():
            unqualified_refs_all[name] = (
                unqualified_refs_all.get(name, 0) + count
            )
    # FR-150 — wildcard'd modules count toward IN_USE classification.
    direct_all |= wildcard_modules_all

    # REQ-3c — notebook magics → findings.
    findings.extend(_collect_notebook_findings(root, errors))

    # REQ-3c — Dockerfile / workflow curl-pipe-shell findings.
    findings.extend(_collect_shell_findings(root, errors))

    # Apply config-level suppressions.
    if suppression.suppress or suppression.per_path:
        kept: list[Finding] = []
        for f in findings:
            global_suppressed = f.rule_id in suppression.suppress
            path_rules = suppression.per_path.get(f.file_path, set())
            path_suppressed = f.rule_id in path_rules
            if global_suppressed or path_suppressed:
                kept.append(
                    Finding(
                        rule_id=f.rule_id,
                        kind=f.kind,
                        severity=f.severity,
                        file_path=f.file_path,
                        line=f.line,
                        snippet=f.snippet,
                        message=f.message,
                        remediation=f.remediation,
                        package_hint=f.package_hint,
                        suppressed=True,
                    )
                )
            else:
                kept.append(f)
        findings = kept

    # REQ-3b — map out vendored packages so declared deps with a
    # vendored copy get ``vendored_path`` populated.
    vendored = _discover_vendored_packages(root)

    declared_canonical: set[str] = {
        _normalise(dep.name) for dep in dependencies
    }
    matched_imports: set[str] = set()

    updated: list[Dependency] = []
    for dep in dependencies:
        if dep.is_type_stub:
            updated.append(dep)
            continue
        canonical = _normalise(dep.name)

        # Transitive deps: skip source classification — they are not
        # expected to be directly imported. Their status is resolved
        # later via the dependency graph (orphan detection).
        if dep.is_transitive:
            vendored_path_t: str | None = None
            if canonical in vendored:
                vendored_path_t = str(vendored[canonical])
            # REQ-17 — when source imports this transitive directly, mark
            # it IN_USE and recommend promotion. The orphan-resolution
            # pass below special-cases ``imported_directly=True``.
            direct_match = _find_import_name(canonical, direct_all, dist_imports)
            if direct_match is not None:
                matched_imports.add(_normalise(direct_match))
                eps = _enumerate_entry_points(
                    canonical, direct_all, used_symbols_all, errors,
                    usage_counts_all,
                    wildcard_modules=wildcard_modules_all,
                    unqualified_refs=unqualified_refs_all,
                    method_calls=method_calls_all,
                )
                updated.append(
                    replace(
                        dep,
                        status=DependencyStatus.IN_USE,
                        reason=(
                            f"transitive dep used directly by project source — "
                            f"promote to a declared dependency in {dep.source}"
                        ),
                        imported_directly=True,
                        entry_points=eps,
                        entry_points_used=sum(1 for ep in eps if ep.used),
                        entry_points_total=len(eps),
                        vendored_path=vendored_path_t,
                    )
                )
                continue
            updated.append(
                replace(
                    dep,
                    reason="transitive dependency — usage determined by graph",
                    vendored_path=vendored_path_t,
                )
            )
            continue

        status, reason = _classify(
            canonical, direct_all, dynamic_literal_all, has_nonliteral_dynamic,
            dist_imports,
        )
        # Track which imports we matched so we can compute phantom deps below.
        matched = _find_import_name(canonical, direct_all, dist_imports)
        if matched is not None:
            matched_imports.add(_normalise(matched))
        dyn_matched = _find_import_name(canonical, dynamic_literal_all, dist_imports)
        if dyn_matched is not None:
            matched_imports.add(_normalise(dyn_matched))

        entry_points: list[EntryPoint] = []
        if status is DependencyStatus.IN_USE:
            entry_points = _enumerate_entry_points(
                canonical, direct_all, used_symbols_all, errors,
                usage_counts_all,
                wildcard_modules=wildcard_modules_all,
                unqualified_refs=unqualified_refs_all,
                method_calls=method_calls_all,
            )

        vendored_path: str | None = None
        if canonical in vendored:
            vendored_path = str(vendored[canonical])

        updated.append(
            replace(
                dep,
                status=status,
                reason=reason,
                entry_points=entry_points,
                entry_points_used=sum(1 for ep in entry_points if ep.used),
                entry_points_total=len(entry_points),
                vendored_path=vendored_path,
            )
        )

    # CLI tool detection — upgrade SAFE deps that are used as CLI tools.
    from scarno.analysers.python.cli_tool_detector import detect_cli_tool_usage

    cli_tools, cli_errors = detect_cli_tool_usage(project_path)
    errors.extend(cli_errors)
    if cli_tools:
        upgraded: list[Dependency] = []
        for dep in updated:
            canonical = _normalise(dep.name)
            if (
                dep.status is DependencyStatus.SAFE
                and not dep.is_transitive
                and canonical in cli_tools
            ):
                upgraded.append(
                    replace(
                        dep,
                        status=DependencyStatus.IN_USE,
                        reason="invoked as CLI tool (detected in project config/scripts)",
                    )
                )
            else:
                upgraded.append(dep)
        updated = upgraded

    # Resolve transitive dep statuses using the dependency graph.
    # REQ-19a / NEW-ARCH-006: the propagation logic now lives in
    # ``core/classifier.py:classify_canonical`` (extracted so every
    # ecosystem can route through one canonical implementation).
    if dep_graph:
        from scarno.core.classifier import classify_canonical
        updated = classify_canonical(updated, dep_graph)

    # REQ-17 — emit aggregate-only skip summary (PRV-004 / FR-157). No paths.
    if exclude_tests and test_skip_count > 0:
        errors.append(
            f"{test_skip_count} test files skipped (--exclude-tests); "
            f"findings within them not scanned"
        )

    # REQ-3b — surface imports that weren't matched to any declared dep
    # as UNDECLARED entries.
    undeclared_entries = _build_undeclared_deps(
        direct_all=direct_all,
        matched_imports=matched_imports,
        declared_canonical=declared_canonical,
    )
    updated.extend(undeclared_entries)

    return updated, errors, findings


def _classify_canonical_shim(
    deps: list[Dependency],
    graph: dict[str, set[str]],
) -> list[Dependency]:
    """Removed-in-PR-2 shim — delegates to the shared classifier.

    The previous classifier formerly lived in this module as a
    Python-private helper. It was extracted to
    ``src/scarno/core/classifier.py:classify_canonical`` as part
    of REQ-19a / NEW-ARCH-006 centralisation. This shim survives only
    so any in-process caller that imported the old symbol still
    works; new callers should import ``classify_canonical`` directly.
    """
    from scarno.core.classifier import classify_canonical
    return classify_canonical(deps, graph)


_classify_canonical_legacy = _classify_canonical_shim


def _collect_notebook_findings(root: Path, errors: list[str]) -> list[Finding]:
    """Return REQ-3c findings for ``!pip install`` / ``%pip install`` magics."""
    from scarno.findings.engine import scan_notebook_magics

    out: list[Finding] = []
    for nb_path in root.rglob("*.ipynb"):
        rel_parts = nb_path.relative_to(root).parts
        if any(part in _EXCLUDED_DIRS for part in rel_parts):
            continue
        try:
            resolved = resolve_and_confine(nb_path, root)
        except PathEscapeError:
            continue
        cells, _nb_errors = extract_code_cells(resolved)
        if not cells.raw_magics:
            continue
        try:
            rel = str(nb_path.relative_to(root))
        except ValueError:
            rel = nb_path.name
        out.extend(scan_notebook_magics(cells.raw_magics, rel))
    return out


def _collect_shell_findings(root: Path, errors: list[str]) -> list[Finding]:
    """Return REQ-3c findings for Dockerfile / workflow ``curl | sh`` lines."""
    from scarno.findings.engine import scan_shell_script_for_curl_pipe

    out: list[Finding] = []
    candidates: list[Path] = []
    for pattern in ("Dockerfile", "Dockerfile.*", "Containerfile", "*.Dockerfile"):
        candidates.extend(root.rglob(pattern))
    gh_workflows = root / ".github" / "workflows"
    if gh_workflows.is_dir():
        for pattern in ("*.yml", "*.yaml"):
            candidates.extend(gh_workflows.glob(pattern))
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        out.extend(scan_shell_script_for_curl_pipe(text, rel))
    return out


def _build_undeclared_deps(
    direct_all: set[str],
    matched_imports: set[str],
    declared_canonical: set[str],
) -> list[Dependency]:
    """Return a list of ``UNDECLARED`` :class:`Dependency` objects."""
    candidates: list[str] = []
    for imp in direct_all:
        norm = _normalise(imp)
        if norm in _STDLIB_NAMES:
            continue
        if norm in matched_imports:
            continue
        if norm in declared_canonical:
            continue
        candidates.append(imp)

    out: list[Dependency] = []
    seen: set[str] = set()
    for imp in candidates:
        dist_name, resolved = _resolve_import_to_distribution(imp)
        # For resolved phantoms we use the PEP 503 canonical distribution
        # name; for unresolved we preserve the raw import identifier so
        # the user can find the source line that mentioned it.
        display_name = _normalise(dist_name) if resolved else imp
        dedup_key = _normalise(display_name)
        if dedup_key in seen:
            continue
        if dedup_key in declared_canonical:
            continue
        seen.add(dedup_key)
        if resolved:
            reason = (
                f"imported as '{imp}' in project source but not declared in "
                f"any dependency file"
            )
            version: str | None = _try_installed_version(dist_name)
        else:
            reason = (
                f"imported as '{imp}' but neither declared nor installed — "
                f"likely local module or typo"
            )
            version = None
        out.append(
            Dependency(
                name=display_name,
                version=version,
                status=DependencyStatus.UNDECLARED,
                reason=reason,
                entry_points=[],
                entry_points_used=0,
                entry_points_total=0,
                source=f"detected:{imp}",
                resolved=resolved,
                # Resolved phantoms are known PyPI distributions;
                # unresolved ones may be local modules or typos — keep
                # ``detected`` so they stand out in per-ecosystem rendering.
                ecosystem="pypi" if resolved else "detected",
            )
        )
    return out


def _try_installed_version(dist_name: str) -> str | None:
    try:
        return importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        return None
    except Exception:  # noqa: BLE001 — defensive
        return None
