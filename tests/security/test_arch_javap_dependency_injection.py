"""PR-4 red tests — NEW-ARCH-011 / SEC-NEW-51: differ module has no
subprocess imports; constructor requires invoke_javap (TA-278 + TA-279).
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-51")
def test_abi_diff_module_no_subprocess_imports():
    """TA-278 — AST-parse analysers/java/abi_diff.py; reject any Import
    / ImportFrom node referencing subprocess / os.exec* / os.spawn* /
    os.posix_spawn / popen / asyncio.subprocess. NEW-ARCH-011: javap
    runs via the injected callable only, never re-spawned locally."""
    abi_path = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "scarno" / "analysers" / "java" / "abi_diff.py"
    )
    text = abi_path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(abi_path))
    forbidden = {
        "subprocess",
        "os.execvp",
        "os.execve",
        "os.spawnv",
        "os.spawnve",
        "os.posix_spawn",
        "popen",
        "asyncio.subprocess",
    }
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden:
                    offenders.append(
                        f"line {node.lineno}: import {alias.name}"
                    )
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in forbidden:
                offenders.append(
                    f"line {node.lineno}: from {mod} import ..."
                )
    assert not offenders, (
        "abi_diff.py imports subprocess / process-spawn APIs — "
        "violates NEW-ARCH-011:\n  - "
        + "\n  - ".join(offenders)
    )


@pytest.mark.requirement("FR-253")
def test_cross_version_abi_differ_init_requires_invoke_javap():
    """TA-279 — CrossVersionAbiDiffer.__init__ has ``invoke_javap`` as
    a required keyword (no default). Constructor must fail without it,
    forcing the JvmSourceAnalyser caller to wire the hardened helper.
    """
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer
    from pathlib import Path

    sig = inspect.signature(CrossVersionAbiDiffer.__init__)
    invoke_javap_param = sig.parameters.get("invoke_javap")
    assert invoke_javap_param is not None
    assert invoke_javap_param.default is inspect.Parameter.empty, (
        "invoke_javap must have no default — the JvmSourceAnalyser "
        "caller must wire _invoke_javap_safe explicitly"
    )

    # Construction without invoke_javap must raise.
    with pytest.raises(TypeError):
        CrossVersionAbiDiffer(m2_root=Path("/tmp"))  # type: ignore[call-arg]
