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

"""Rule engine for REQ-3c.

Walks ASTs (AST only — never ``exec``/``eval`` on project source,
SF-012) and emits :class:`Finding` objects for patterns that match the
REQ-3c rule catalogue.

The taint analysis is **intra-procedural** — it tracks taint within a
single function body, not across calls. This is a deliberate bias
towards zero false positives (see ``docs/Specification.md`` — out of scope
for v1).
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass

from scarno.findings.rules import RULES
from scarno.models import Finding, FindingSeverity
from scarno.security import sanitise

_MAX_SNIPPET = 200

# Functions and attributes whose return value is tainted (network / external).
_TAINT_SOURCES: frozenset[str] = frozenset(
    {
        "urlopen",
        "urlretrieve",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "request",
        "getenv",
        "input",
    }
)
_TAINT_SOURCE_MODULES: frozenset[str] = frozenset(
    {"urllib.request", "urllib3", "requests", "httpx", "aiohttp"}
)
# ``os.environ[...]`` / ``sys.argv`` are taint sources.
_TAINT_SOURCE_NAMES: frozenset[str] = frozenset(
    {"os.environ", "os.getenv", "sys.argv", "input"}
)

_NOTEBOOK_PIP_RE = re.compile(r"^\s*[!%]\s*pip\s+install\b", re.IGNORECASE)
_NOTEBOOK_CONDA_RE = re.compile(r"^\s*%\s*conda\s+install\b", re.IGNORECASE)
# ReDoS defence (CWE-1333). The earlier form
# ``curl\s+[^|]+?\s*\|\s*(?:sh|bash|...)`` was ambiguous three ways: ``\s``
# is a subset of ``[^|]``, so the leading ``\s+``, the lazy ``[^|]+?`` and
# the trailing ``\s*`` could all claim the same whitespace. On a line that
# does NOT match — ``curl <spaces> url <spaces> | notashell`` — the engine
# had to try every split before failing, which is cubic in the whitespace
# run: 1.6 KB cost 4.7 s and 3.2 KB cost 37 s, against a 10 MB per-file
# cap. A Dockerfile line was therefore enough to hang the scan *before* it
# could report the HIGH TS-CE-005 that line contains.
#
# The replacement is the same language written unambiguously. Because
# ``\s`` is a subset of ``[^|]``, the old ``\s+[^|]+?\s*`` accepts exactly
# those non-pipe runs that are at least two characters long and start with
# whitespace — so ``\s[^|]+`` accepts the identical set, with a single
# fixed-width ``\s`` and one possessive run that cannot backtrack. The
# length-two floor matters: ``curl |sh`` is rejected by both forms and
# ``curl  |sh`` is accepted by both.
#
# Detection is otherwise untouched: ``[^|]`` cannot cross a ``|``, so the
# old lazy run could never expand past the first pipe either —
# ``curl x | grep y | sh`` did not match before and does not now.
_CURL_PIPE_SHELL_RE = re.compile(
    r"curl\s[^|]++\|\s*+(?:sh|bash|python3?|python)\b"
)


@dataclass
class _RuleContext:
    """Per-file analysis context passed through the AST walker."""

    file_path: str
    source_lines: list[str]
    tainted: set[str]  # variables known to carry external/network content
    # Symbols imported for matching (e.g. ``from urllib.request import urlopen``)
    aliased_taint_names: set[str]
    findings: list[Finding]


def _snippet_for(ctx: _RuleContext, lineno: int) -> str:
    if 0 < lineno <= len(ctx.source_lines):
        raw = ctx.source_lines[lineno - 1]
    else:
        raw = ""
    sanitised = sanitise(raw).rstrip()
    if len(sanitised) > _MAX_SNIPPET:
        sanitised = sanitised[: _MAX_SNIPPET - 1] + "…"
    return sanitised


def _make_finding(
    rule_id: str,
    ctx: _RuleContext,
    lineno: int,
    package_hint: str | None = None,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        kind=rule.kind,
        severity=rule.severity,
        file_path=ctx.file_path,
        line=lineno,
        snippet=_snippet_for(ctx, lineno),
        message=rule.message,
        remediation=rule.remediation,
        package_hint=package_hint,
    )


def _args_contain_pip_install(args: list[ast.expr]) -> str | None:
    """Return the matching rule ID if the Call arglist is a pip-install, else None."""
    flat = []
    for arg in args:
        if isinstance(arg, (ast.List, ast.Tuple)):
            flat.extend(arg.elts)
        else:
            flat.append(arg)
    values: list[str] = []
    for item in flat:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            values.append(item.value)
    # subprocess.run(["python", "-m", "pip", "install", ...]) style → TS-SI-002
    if (
        len(values) >= 4
        and values[0].startswith("python")
        and values[1] == "-m"
        and values[2] == "pip"
        and values[3] == "install"
    ):
        return "TS-SI-002"
    # subprocess.run(["pip", "install", ...]) style → TS-SI-001
    if values and values[0] in ("pip", "pip3") and len(values) > 1 and values[1] == "install":
        return "TS-SI-001"
    # subprocess.run("pip install foo", shell=True) style → TS-SI-001
    joined = " ".join(values)
    if re.search(r"\bpip3?\s+install\b", joined):
        return "TS-SI-001"
    return None


def _os_system_contains_pip_install(args: list[ast.expr]) -> bool:
    if not args:
        return False
    first = args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return bool(re.search(r"\bpip3?\s+install\b", first.value))
    # f-string / concatenation — recursive literal search
    return False


def _is_literal_list(node: ast.expr) -> bool:
    """Return True if *node* is a list/tuple of string constants."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return False
    return all(
        isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        for elt in node.elts
    )


def _call_function_name(call: ast.Call) -> tuple[str, str]:
    """Return (root, full) dotted function name, e.g. ('subprocess', 'subprocess.run')."""
    names: list[str] = []
    node: ast.AST = call.func
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        names.append(node.id)
        names.reverse()
        return names[0], ".".join(names)
    return "", ""


def _is_network_call(call: ast.Call) -> bool:
    root, full = _call_function_name(call)
    if full in {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "os.getenv",
        "os.environ.get",
    }:
        return True
    # Bare `urlopen(...)` or `get(...)` if imported from a known source
    if root in {"urlopen", "urlretrieve", "getenv", "input"}:
        return True
    return False


class _RuleVisitor(ast.NodeVisitor):
    """Top-level visitor that dispatches into function bodies for taint."""

    def __init__(self, ctx: _RuleContext) -> None:
        self.ctx = ctx

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        _analyse_function(node.body, self.ctx)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        _analyse_function(node.body, self.ctx)
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        _analyse_function(node.body, self.ctx)
        self.generic_visit(node)


def _walk_same_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Yield every descendant of ``node`` that stays in the same scope.

    Does NOT descend into nested ``FunctionDef`` / ``AsyncFunctionDef`` /
    ``Lambda`` / ``ClassDef`` bodies — those are processed by their own
    visitor dispatch to avoid double-counting findings.
    """
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(
            child,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
        ):
            continue
        yield from _walk_same_scope(child)


def _analyse_function(body: list[ast.stmt], ctx: _RuleContext) -> None:
    """Run a simple forward taint + rule pass over a block of statements."""
    local_ctx = _RuleContext(
        file_path=ctx.file_path,
        source_lines=ctx.source_lines,
        tainted=set(ctx.tainted),
        aliased_taint_names=ctx.aliased_taint_names,
        findings=ctx.findings,
    )
    for stmt in body:
        # Nested function / class / async defs have their own scope; they
        # are dispatched via visit_FunctionDef etc. Skipping here prevents
        # the same Call from being reported twice.
        if isinstance(
            stmt,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            continue
        for node in _walk_same_scope(stmt):
            if isinstance(node, ast.Assign):
                _process_assign(node, local_ctx)
            elif isinstance(node, ast.Call):
                _process_call(node, local_ctx)


def _process_assign(node: ast.Assign, ctx: _RuleContext) -> None:
    if _expression_is_tainted(node.value, ctx):
        for target in node.targets:
            if isinstance(target, ast.Name):
                ctx.tainted.add(target.id)


def _expression_is_tainted(expr: ast.AST, ctx: _RuleContext) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in ctx.tainted:
            return True
        if isinstance(node, ast.Call) and _is_network_call(node):
            return True
        if isinstance(node, ast.Attribute):
            # ``something.read()`` / ``.text`` on a tainted value
            if isinstance(node.value, ast.Name) and node.value.id in ctx.tainted:
                return True
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                full = _attr_full_name(node.value)
                if full in {"os.environ", "sys.argv"}:
                    return True
    return False


def _attr_full_name(attr: ast.Attribute) -> str:
    names: list[str] = [attr.attr]
    node: ast.AST = attr.value
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        names.append(node.id)
        names.reverse()
        return ".".join(names)
    return ""


def _process_call(call: ast.Call, ctx: _RuleContext) -> None:
    root, full = _call_function_name(call)

    # TS-SI-001 / TS-SI-002 — subprocess / pip._internal.main
    # TS-CE-002 — tainted data to subprocess (non-pip-install)
    # TS-CE-006 — shell=True with tainted input
    if full in {
        "subprocess.run",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.call",
    }:
        pip_rule = _args_contain_pip_install(call.args)
        if pip_rule is not None:
            ctx.findings.append(_make_finding(pip_rule, ctx, call.lineno))
        elif _subprocess_shell_true_with_taint(call, ctx):
            ctx.findings.append(_make_finding("TS-CE-006", ctx, call.lineno))
        elif call.args and _expression_is_tainted(call.args[0], ctx):
            ctx.findings.append(_make_finding("TS-CE-002", ctx, call.lineno))
    if full == "pip.main" or full == "pip._internal.main":
        ctx.findings.append(_make_finding("TS-SI-004", ctx, call.lineno))

    # TS-SI-003 — os.system / os.popen pip install
    # TS-CE-002 — tainted data to os.system / os.popen (non-pip-install)
    if full in {"os.system", "os.popen"}:
        if _os_system_contains_pip_install(call.args):
            ctx.findings.append(_make_finding("TS-SI-003", ctx, call.lineno))
        elif call.args and _expression_is_tainted(call.args[0], ctx):
            ctx.findings.append(_make_finding("TS-CE-002", ctx, call.lineno))

    # TS-CE-001 / TS-CE-002 — exec / eval of tainted data
    is_exec_eval = full in {"exec", "eval"} or (
        root in {"exec", "eval"} and not full
    )
    if is_exec_eval:
        if call.args and _expression_is_tainted(call.args[0], ctx):
            ctx.findings.append(_make_finding("TS-CE-001", ctx, call.lineno))

    # TS-CE-003 — pickle.load* on tainted
    if full in {"pickle.load", "pickle.loads"}:
        if call.args and _expression_is_tainted(call.args[0], ctx):
            ctx.findings.append(_make_finding("TS-CE-003", ctx, call.lineno))

    # TS-DS-001 — setup(install_requires=<non-literal>) in setup.py
    if (
        ctx.file_path.endswith("setup.py")
        and isinstance(call.func, ast.Name)
        and call.func.id == "setup"
    ):
        for kw in call.keywords:
            if kw.arg == "install_requires" and not _is_literal_list(kw.value):
                ctx.findings.append(_make_finding("TS-DS-001", ctx, call.lineno))
                break

    # TS-CE-004 — importlib.import_module / __import__ on tainted
    is_dynamic_import = (
        full == "importlib.import_module"
        or full == "__import__"
        or (isinstance(call.func, ast.Name) and call.func.id == "__import__")
    )
    if is_dynamic_import:
        if call.args and _expression_is_tainted(call.args[0], ctx):
            ctx.findings.append(_make_finding("TS-CE-004", ctx, call.lineno))


def _subprocess_shell_true_with_taint(
    call: ast.Call, ctx: _RuleContext
) -> bool:
    shell_true = False
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            shell_true = True
    if not shell_true:
        return False
    if call.args and _expression_is_tainted(call.args[0], ctx):
        return True
    return False


# ── Notebook magic + Dockerfile curl-pipe-shell (string-level rules) ─────────


def scan_notebook_magics(
    magics: list[str], file_path: str
) -> list[Finding]:
    """Scan stripped Jupyter magic lines for pip-install-style patterns."""
    out: list[Finding] = []
    for idx, line in enumerate(magics, start=1):
        if _NOTEBOOK_PIP_RE.search(line):
            out.append(
                Finding(
                    rule_id="TS-SI-005",
                    kind=RULES["TS-SI-005"].kind,
                    severity=RULES["TS-SI-005"].severity,
                    file_path=file_path,
                    line=idx,
                    snippet=sanitise(line)[:_MAX_SNIPPET],
                    message=RULES["TS-SI-005"].message,
                    remediation=RULES["TS-SI-005"].remediation,
                )
            )
        elif _NOTEBOOK_CONDA_RE.search(line):
            out.append(
                Finding(
                    rule_id="TS-SI-006",
                    kind=RULES["TS-SI-006"].kind,
                    severity=RULES["TS-SI-006"].severity,
                    file_path=file_path,
                    line=idx,
                    snippet=sanitise(line)[:_MAX_SNIPPET],
                    message=RULES["TS-SI-006"].message,
                    remediation=RULES["TS-SI-006"].remediation,
                )
            )
    return out


def scan_shell_script_for_curl_pipe(
    text: str, file_path: str
) -> list[Finding]:
    """Detect ``curl ... | sh`` / ``| bash`` / ``| python`` in a shell block."""
    out: list[Finding] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if _CURL_PIPE_SHELL_RE.search(line):
            out.append(
                Finding(
                    rule_id="TS-CE-005",
                    kind=RULES["TS-CE-005"].kind,
                    severity=RULES["TS-CE-005"].severity,
                    file_path=file_path,
                    line=idx,
                    snippet=sanitise(line)[:_MAX_SNIPPET],
                    message=RULES["TS-CE-005"].message,
                    remediation=RULES["TS-CE-005"].remediation,
                )
            )
    return out


# ── Suppression parsing ──────────────────────────────────────────────────────


_SUPPRESS_RE = re.compile(r"#\s*scarno:\s*allow\s+([A-Z0-9-]+)", re.IGNORECASE)


def inline_suppressions(source_lines: list[str]) -> dict[int, set[str]]:
    """Return a mapping of 1-indexed line number → set of suppressed rule IDs.

    Honours both comments on the triggering line and comments on the
    immediately-preceding line.
    """
    out: dict[int, set[str]] = {}
    for idx, line in enumerate(source_lines, start=1):
        match = _SUPPRESS_RE.search(line)
        if match is None:
            continue
        rule_id = match.group(1).strip()
        out.setdefault(idx, set()).add(rule_id)
        out.setdefault(idx + 1, set()).add(rule_id)
    return out


# ── Public entry point ──────────────────────────────────────────────────────


def apply_rules(
    file_path: str,
    source: str,
    tree: ast.AST,
    notebook_magics: list[str] | None = None,
) -> list[Finding]:
    """Run the rule engine against a parsed source file and return findings.

    The caller is responsible for applying suppression. Inline
    ``# scarno: allow TS-XX-NNN`` comments are parsed here and the
    resulting findings are pre-filtered.
    """
    source_lines = source.splitlines()
    ctx = _RuleContext(
        file_path=file_path,
        source_lines=source_lines,
        tainted=set(),
        aliased_taint_names=set(),
        findings=[],
    )
    _RuleVisitor(ctx).visit(tree)
    if notebook_magics:
        ctx.findings.extend(scan_notebook_magics(notebook_magics, file_path))
    # Apply inline suppressions.
    suppressions = inline_suppressions(source_lines)
    kept: list[Finding] = []
    for f in ctx.findings:
        allowed = suppressions.get(f.line, set())
        if f.rule_id in allowed:
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
    return kept
