"""PR-4 red test — SEC-NEW-56 / E-Phase9-01: --deep-inspection set ONLY
from argv. TA-266.

AST-scan of cli.py: the only assignment site for ``deep_inspection``
in ``_RunOptions`` construction must be the argparse / typer handler.
NO env-var fallback, NO config-file fallback, NO preset substitution.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-56")
def test_deep_inspection_set_only_by_argv_flag():
    """TA-266 — Static-AST parse cli.py; assert ``deep_inspection`` is
    only assigned in code paths that originate from the CLI argv
    flag, not from os.environ.get or config-file reads.
    """
    cli_path = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "scarno" / "cli.py"
    )
    text = cli_path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(cli_path))
    # Precondition: --deep-inspection must actually be implemented.
    # Without this check the test passes vacuously on pre-PR-4 code.
    assert "deep_inspection" in text, (
        "cli.py does not mention deep_inspection — PR-4 implementation "
        "has not landed; cannot verify SEC-NEW-56 yet."
    )
    suspicious: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                # Catch direct `deep_inspection = os.environ.get(...)`
                if (
                    isinstance(target, ast.Name)
                    and target.id == "deep_inspection"
                ):
                    value_src = ast.unparse(node.value)
                    if "os.environ" in value_src or "config" in value_src.lower():
                        suspicious.append(
                            f"line {node.lineno}: {value_src}"
                        )
        if isinstance(node, ast.keyword) and node.arg == "deep_inspection":
            value_src = ast.unparse(node.value)
            if "os.environ" in value_src:
                suspicious.append(
                    f"line {node.lineno}: deep_inspection={value_src}"
                )
    assert not suspicious, (
        "deep_inspection is assigned from env / config in cli.py — "
        "violates SEC-NEW-56:\n  - "
        + "\n  - ".join(suspicious)
    )
