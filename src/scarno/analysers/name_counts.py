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

"""Single-pass simple-name reference counting (REQ-17 / FR-150).

The JVM, Go, and C# source analysers all need the same number: how many
times does an imported symbol's simple name appear in a source file.
Each used to compute it with one full-file ``re.findall`` **per import**,
which is O(file size x import count) — a crafted source file holding
hundreds of thousands of distinct imports (within the 10 MiB per-file
cap) pinned a CPU for hours and the scan never returned (CWE-1333).

Both helpers here answer the same question in **one** pass over the
file's identifier tokens, and both are exact: Python's ``\\b`` is defined
against the word-character class ``\\w``, so ``\\bname\\b`` can only ever
match a maximal ``\\w+`` run that equals *name* — provided *name* itself
is made only of word characters. Tallying maximal runs therefore yields
precisely ``len(re.findall(rf"\\b{re.escape(name)}\\b", source))``.

A name containing a non-word character (Java's ``$``, C#'s leading
``@``) cannot be settled that way, so it keeps the original per-name
scan. Those names do not occur in idiomatic source, but they are
attacker-reachable, so the number of such scans per file is capped by
:data:`MAX_FULL_SCANS`. Names beyond the cap are *returned to the
caller* rather than dropped, so the caller can record the shortfall on
its error channel — never a silent change of analysis output.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

__all__ = [
    "MAX_FULL_SCANS",
    "count_boundary_refs",
    "count_selector_refs",
]

# A maximal run of word characters — exactly the class Python's ``\b``
# is defined against, so one pass of this pattern enumerates every
# position a word-only name could match at.
_WORD_RUN = re.compile(r"\w+")

#: Per-file ceiling on names that still need their own full-source scan
#: because they contain a non-word character. Bounds that fallback at
#: O(MAX_FULL_SCANS x file size) instead of O(imports x file size).
MAX_FULL_SCANS = 64


def _partition(names: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split *names* into (word-character-only, everything else).

    Duplicates are collapsed — two FQCNs sharing a simple name need the
    name counted once. The "everything else" list is sorted so the
    :data:`MAX_FULL_SCANS` cut is deterministic even though callers
    iterate sets.
    """
    word_only: list[str] = []
    mixed: list[str] = []
    seen: set[str] = set()
    for name in names:
        if not name or name in seen:
            continue
        seen.add(name)
        if _WORD_RUN.fullmatch(name):
            word_only.append(name)
        else:
            mixed.append(name)
    mixed.sort()
    return word_only, mixed


def _scan_mixed(
    source: str, mixed: list[str], tail: str
) -> tuple[dict[str, int], list[str]]:
    """Per-name fallback for names holding a non-word character.

    Returns the counts obtained plus the names left uncounted because
    :data:`MAX_FULL_SCANS` was reached.
    """
    counts: dict[str, int] = {}
    for name in mixed[:MAX_FULL_SCANS]:
        counts[name] = len(re.findall(rf"\b{re.escape(name)}{tail}", source))
    return counts, mixed[MAX_FULL_SCANS:]


def count_boundary_refs(
    source: str, names: Iterable[str]
) -> tuple[dict[str, int], list[str]]:
    """Count ``\\b<name>\\b`` occurrences in *source* for every name.

    Equivalent to ``len(re.findall(rf"\\b{re.escape(name)}\\b", source))``
    per name, computed in a single pass. Returns ``(counts, uncounted)``
    where *uncounted* lists the names skipped by the
    :data:`MAX_FULL_SCANS` cap; they are absent from *counts*.
    """
    word_only, mixed = _partition(names)
    counts: dict[str, int] = dict.fromkeys(word_only, 0)
    if word_only:
        for match in _WORD_RUN.finditer(source):
            token = match.group()
            if token in counts:
                counts[token] += 1
    if not mixed:
        return counts, []
    mixed_counts, uncounted = _scan_mixed(source, mixed, r"\b")
    counts.update(mixed_counts)
    return counts, uncounted


def count_selector_refs(
    source: str, names: Iterable[str]
) -> tuple[dict[str, int], list[str]]:
    """Count ``\\b<name>.`` (selector-prefix) occurrences in *source*.

    The Go analyser counts ``pkg.Symbol`` selectors rather than bare
    references. A trailing ``.`` is itself a non-word character, so the
    name must again be a maximal word run — one that happens to be
    followed by a dot. Same contract as :func:`count_boundary_refs`.
    """
    word_only, mixed = _partition(names)
    counts: dict[str, int] = dict.fromkeys(word_only, 0)
    if word_only:
        for match in _WORD_RUN.finditer(source):
            token = match.group()
            if token in counts and source.startswith(".", match.end()):
                counts[token] += 1
    if not mixed:
        return counts, []
    mixed_counts, uncounted = _scan_mixed(source, mixed, r"\.")
    counts.update(mixed_counts)
    return counts, uncounted
