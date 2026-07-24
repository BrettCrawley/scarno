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

"""Jupyter notebook (`.ipynb`) reader — REQ-3b.

Extracts the source text of code cells from a notebook so the Python
source analyser can run its AST import detection and the REQ-3c rule
engine can scan for ``!pip install`` / ``%pip install`` magics.

Safety:
  * Uses ``json.loads`` only — no execution of notebook code.
  * Strips Jupyter magic lines (``!…`` / ``%…``) before handing source to
    ``ast.parse`` so a cell with ``!pip install foo`` doesn't produce a
    spurious syntax error. The stripped magics are retained in
    :attr:`NotebookCells.raw_magics` for REQ-3c rule matching.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from scarno.security import MAX_FILE_BYTES

_MAGIC_RE = re.compile(r"^\s*[!%]")


@dataclass
class NotebookCells:
    """Source text of the code cells of a notebook plus magic lines."""

    # Concatenated AST-safe cell source (magics stripped).
    ast_safe_source: str = ""
    # Original magic lines per cell, preserved for rule matching.
    raw_magics: list[str] = field(default_factory=list)


def extract_code_cells(
    notebook_path: str | Path,
) -> tuple[NotebookCells, list[str]]:
    """Return ``(cells, errors)`` for a notebook.

    ``cells.ast_safe_source`` concatenates every code cell's source with
    magics stripped. ``cells.raw_magics`` preserves the stripped magic
    lines for rule-engine matching. On any parse error, ``cells`` is
    returned empty and the error list is non-empty.
    """
    errors: list[str] = []
    path = Path(notebook_path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        errors.append(f"notebook: stat failed for {path.name} — {exc}")
        return NotebookCells(), errors
    if size > MAX_FILE_BYTES:
        errors.append(
            f"notebook: skipped {path.name} — file too large ({size} bytes)"
        )
        return NotebookCells(), errors
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"notebook: could not read {path.name} — {exc}")
        return NotebookCells(), errors
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors.append(f"notebook: invalid JSON in {path.name} — {exc}")
        return NotebookCells(), errors
    if not isinstance(data, dict):
        return NotebookCells(), errors
    cells = data.get("cells")
    if not isinstance(cells, list):
        return NotebookCells(), errors

    out = NotebookCells()
    buf: list[str] = []
    for cell in cells:
        if not isinstance(cell, dict):
            continue
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source")
        if isinstance(source, list):
            source_text = "".join(s for s in source if isinstance(s, str))
        elif isinstance(source, str):
            source_text = source
        else:
            continue
        for line in source_text.splitlines(keepends=True):
            if _MAGIC_RE.match(line):
                out.raw_magics.append(line.rstrip("\n"))
                buf.append("\n")  # keep line numbers aligned
            else:
                buf.append(line)
        if not source_text.endswith("\n"):
            buf.append("\n")
    out.ast_safe_source = "".join(buf)
    return out, errors
