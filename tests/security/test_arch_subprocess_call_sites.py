"""PR-2 red tests — REQ-19a NEW-ARCH-013 / SEC-NEW-58 / SUC-64:
subprocess-call-site AST scan (TA-237).

Outside the legacy ``_invoke_javap_safe`` helper (deferred-refactor
per ADR-013), every subprocess invocation in src/scarno/ MUST
flow through ``security.safe_subprocess_run``. An import-graph test
rejects future PRs that re-implement subprocess calls inline.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

_FORBIDDEN_CALLS: tuple[str, ...] = (
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.execvp",
    "os.execve",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.posix_spawn",
    "os.posix_spawnp",
    "os.popen",
)

_GRANDFATHERED = {
    # The single sanctioned subprocess primitive — every other call
    # site routes through it (NEW-ARCH-013 / ADR-013). It IS the
    # wrapper.
    ("security.py", "safe_subprocess_run"),
    # ADR-013 grandfathered exception: legacy javap helper. Targeted
    # for refactor onto safe_subprocess_run as a post-Phase-9 cleanup
    # per architecture §11.15.5.
    ("analysers/java/source_analyser.py", "_invoke_javap_safe"),
}


def _attr_dotted(node: ast.AST) -> str | None:
    """Return the dotted name of an Attribute / Name expression, or None."""
    if isinstance(node, ast.Attribute):
        prefix = _attr_dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    if isinstance(node, ast.Name):
        return node.id
    return None


@pytest.mark.requirement("SEC-NEW-58")
def test_subprocess_call_sites_only_safe_run():
    """TA-237 — AST-walk every *.py under src/scarno/. Reject any
    Call node whose function resolves to a forbidden subprocess /
    spawn API. The legacy javap helper is the only grandfathered
    exception (deferred-refactor per ADR-013)."""
    src_root = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "scarno"
    )
    offenders: list[str] = []
    for py_file in src_root.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(py_file))
        except SyntaxError:
            continue
        # Track which function each Call is inside, so we can skip the
        # grandfathered _invoke_javap_safe.
        rel = str(py_file.relative_to(src_root))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                dotted = _attr_dotted(inner.func)
                if dotted not in _FORBIDDEN_CALLS:
                    continue
                if (rel, node.name) in _GRANDFATHERED:
                    continue
                offenders.append(
                    f"{rel}:{inner.lineno} ({node.name}): {dotted}"
                )
    assert not offenders, (
        "Subprocess calls outside security.safe_subprocess_run + the "
        "grandfathered legacy javap helper:\n  - "
        + "\n  - ".join(offenders)
    )
