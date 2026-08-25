"""Regression tests — the "Multiple versions detected" table must not be
breakable by an adversarial version string, and must not mangle a
legitimate one.

Version strings in that table come verbatim out of the analysed
project's manifest (``VersionedNode.declared_version``, or
``Dependency.version`` when the manifest left the entry unpinned). Before
the fix they were interpolated into the table row with no escaping at
all, so a ``|`` forged extra cells and a line break ended the row — and
with it the table, hiding every genuine conflict row below it from the
reviewer.

The fix folds line breaks to a space and then applies the existing
``_escape_md``. It must close that hole *without* the lossiness of
``sanitise_declared_version``: this cell exists to tell a reviewer which
versions conflict, so a legitimate Maven version range or qualifier has
to survive verbatim.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


# Every character a Markdown renderer (or ``str.splitlines``) may treat
# as a line ending. ``sanitise()`` removes CR / VT / FF / FS / GS / RS,
# but deliberately keeps LF and does not touch NEL, LINE SEPARATOR or
# PARAGRAPH SEPARATOR — so all of these must be handled here.
_LINE_BREAKS = ("\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e",
                "\x85", "\u2028", "\u2029")

_PAYLOAD = "1.0 |x|\n| evil | evil | evil |\n<b>tail</b>"


def _render(versioned_nodes, multi_version_coords, deps):
    from scarno.models import AnalysisResult
    from scarno.reporters.markdown_reporter import MarkdownReporter

    result = AnalysisResult(
        project_type="java",
        project_path="/tmp/x",
        dependencies=deps,
        dep_edges=[],
        versioned_nodes=versioned_nodes,
        multi_version_coords=multi_version_coords,
    )
    return MarkdownReporter().render(result)


def _table_rows(rendered: str) -> list[str]:
    """Return the lines of the multi-version section that a Markdown
    renderer would read as table rows (header, separator, data rows)."""
    lines = rendered.splitlines()
    start = lines.index("## Multiple versions detected")
    section = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        section.append(line)
    return [ln for ln in section if ln.startswith("|")]


@pytest.mark.requirement("FR-206")
def test_declared_version_cannot_break_out_of_the_table_cell():
    """A poisoned declared version must not forge cells, end its row, or
    swallow the genuine conflict row that follows it."""
    from scarno.models import Dependency, DependencyStatus, VersionedNode

    nodes = [
        # Coordinate "aaa" — attacker-controlled version, not the
        # resolved one, so it lands in the "Declared versions" cell.
        VersionedNode(
            canonical="aaa", declared_version=_PAYLOAD,
            status=DependencyStatus.SAFE, removable=True,
        ),
        VersionedNode(
            canonical="aaa", declared_version="2.0",
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        # Coordinate "zzz" — a genuine second conflict, sorted after
        # "aaa" so it renders below the poisoned row.
        VersionedNode(
            canonical="zzz", declared_version="3.0",
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        VersionedNode(
            canonical="zzz", declared_version="4.0",
            status=DependencyStatus.SAFE, removable=True,
        ),
    ]
    deps = [
        Dependency(name="aaa", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
        Dependency(name="zzz", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
    ]
    rendered = _render(nodes, ["aaa", "zzz"], deps)
    rows = _table_rows(rendered)

    # Header, separator, and exactly one row per coordinate. On the
    # unpatched reporter the poisoned row splits into several lines and
    # this count is wrong.
    assert len(rows) == 4, f"table structure broken: {rows}"
    assert rows[2].startswith("| `aaa`"), rows[2]
    assert rows[3].startswith("| `zzz`"), rows[3]

    # The whole payload stayed inside its own row.
    assert "evil" in rows[2]
    assert "evil" not in rows[3]

    # A 4-column row has exactly 5 unescaped pipes; every pipe the
    # attacker supplied is escaped.
    unescaped_pipes = rows[2].count("|") - rows[2].count("\\|")
    assert unescaped_pipes == 5, (
        f"forged cell delimiters in poisoned row: {rows[2]!r}"
    )

    # No raw HTML from the payload anywhere in the report.
    assert "<b>" not in rendered

    # The genuine second conflict is still a real, complete table row.
    assert rows[3].endswith("|")
    assert "3.0" in rows[3] and "4.0" in rows[3]


@pytest.mark.requirement("FR-206")
def test_unpinned_entry_version_cannot_break_out_of_the_table_cell():
    """Same guarantee for the fallback path: a node the manifest left
    unpinned takes its version straight from ``Dependency.version``."""
    from scarno.models import Dependency, DependencyStatus, VersionedNode

    nodes = [
        VersionedNode(
            canonical="aaa", declared_version=None,
            status=DependencyStatus.SAFE, removable=True,
        ),
        VersionedNode(
            canonical="aaa", declared_version="2.0",
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        VersionedNode(
            canonical="zzz", declared_version="3.0",
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        VersionedNode(
            canonical="zzz", declared_version="4.0",
            status=DependencyStatus.SAFE, removable=True,
        ),
    ]
    deps = [
        Dependency(name="aaa", version=_PAYLOAD,
                   status=DependencyStatus.IN_USE, reason=""),
        Dependency(name="zzz", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
    ]
    rendered = _render(nodes, ["aaa", "zzz"], deps)
    rows = _table_rows(rendered)

    assert len(rows) == 4, f"table structure broken: {rows}"
    assert rows[2].startswith("| `aaa`"), rows[2]
    assert rows[3].startswith("| `zzz`"), rows[3]
    assert "evil" in rows[2] and "evil" not in rows[3]
    assert (rows[2].count("|") - rows[2].count("\\|")) == 5, rows[2]
    assert "<b>" not in rendered


@pytest.mark.requirement("FR-206")
def test_resolved_version_cannot_break_out_of_the_table_cell():
    """The "Resolved" cell carries the same manifest-controlled string."""
    from scarno.models import Dependency, DependencyStatus, VersionedNode

    nodes = [
        VersionedNode(
            canonical="aaa", declared_version=_PAYLOAD,
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        VersionedNode(
            canonical="aaa", declared_version="2.0",
            status=DependencyStatus.SAFE, removable=True,
        ),
        VersionedNode(
            canonical="zzz", declared_version="3.0",
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        VersionedNode(
            canonical="zzz", declared_version="4.0",
            status=DependencyStatus.SAFE, removable=True,
        ),
    ]
    deps = [
        Dependency(name="aaa", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
        Dependency(name="zzz", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
    ]
    rendered = _render(nodes, ["aaa", "zzz"], deps)
    rows = _table_rows(rendered)

    assert len(rows) == 4, f"table structure broken: {rows}"
    assert rows[3].startswith("| `zzz`"), rows[3]
    assert (rows[2].count("|") - rows[2].count("\\|")) == 5, rows[2]


@pytest.mark.requirement("FR-206")
@pytest.mark.parametrize("break_char", _LINE_BREAKS)
def test_every_line_break_flavour_is_folded(break_char):
    """LF is not the only line ending that reaches the reporter: CR, VT,
    FF, the C0 separators, NEL, U+2028 and U+2029 all split a row in one
    renderer or another."""
    from scarno.models import Dependency, DependencyStatus, VersionedNode

    poisoned = f"1.0{break_char}| evil | evil | evil |"
    nodes = [
        VersionedNode(
            canonical="aaa", declared_version=poisoned,
            status=DependencyStatus.SAFE, removable=True,
        ),
        VersionedNode(
            canonical="aaa", declared_version="2.0",
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
    ]
    deps = [
        Dependency(name="aaa", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
    ]
    rendered = _render(nodes, ["aaa"], deps)
    rows = _table_rows(rendered)

    assert len(rows) == 3, f"{break_char!r} split the row: {rows}"
    assert (rows[2].count("|") - rows[2].count("\\|")) == 5, rows[2]
    assert not any(ch in rows[2] for ch in _LINE_BREAKS)


@pytest.mark.requirement("FR-206")
def test_legitimate_maven_versions_survive_verbatim():
    """The escaping must not be lossy. A Maven version RANGE and a
    qualifier containing a Mermaid reserved word are both legitimate and
    must reach the reviewer unchanged — ``sanitise_declared_version``
    would turn ``[1.0,2.0)`` into ``1.0,2.0)`` (which reads as two
    versions in a comma-joined cell) and ``1.0-clickhouse.1`` into the
    plausible-but-nonexistent ``1.0-house.1``.
    """
    from scarno.models import Dependency, DependencyStatus, VersionedNode

    version_range = "[1.0,2.0)"
    qualifier = "1.0-clickhouse.1"
    nodes = [
        VersionedNode(
            canonical="lib", declared_version=version_range,
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        VersionedNode(
            canonical="lib", declared_version=qualifier,
            status=DependencyStatus.SAFE, removable=True,
        ),
    ]
    deps = [
        Dependency(name="lib", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
    ]
    rendered = _render(nodes, ["lib"], deps)
    rows = _table_rows(rendered)
    assert len(rows) == 3, rows
    row = rows[2]

    # Nothing is dropped: unescaping the row recovers both versions
    # exactly as declared.
    plain = row.replace("\\", "")
    assert version_range in plain, row
    assert qualifier in plain, row

    # The range keeps its opening bracket (escaped, never deleted), so it
    # cannot be misread as two comma-separated versions.
    assert "\\[1.0,2.0)" in row, row
    # The qualifier is untouched — no reserved-word stripping, no cap.
    assert qualifier in row, row
    assert "1.0-house.1" not in rendered

    # The deliberate "resolved" bold marker still works around the
    # escaped version.
    assert "**\\[1.0,2.0)**" in row, row
    # …and the removable cell carries the qualifier verbatim.
    assert row.rstrip().endswith(f"{qualifier} |"), row


@pytest.mark.requirement("FR-206")
def test_long_version_is_not_truncated():
    """A 69-character qualifier is legitimate; the 64-byte
    ``DECLARED_VERSION_MAX_LEN`` cap belongs to the Mermaid-era
    sanitiser and must not silently trim this cell."""
    from scarno.models import Dependency, DependencyStatus, VersionedNode

    long_version = "1.0-" + ("a" * 65)
    assert len(long_version) > 64
    nodes = [
        VersionedNode(
            canonical="lib", declared_version=long_version,
            status=DependencyStatus.IN_USE, is_resolved=True,
        ),
        VersionedNode(
            canonical="lib", declared_version="2.0",
            status=DependencyStatus.SAFE, removable=True,
        ),
    ]
    deps = [
        Dependency(name="lib", version=None,
                   status=DependencyStatus.IN_USE, reason=""),
    ]
    rendered = _render(nodes, ["lib"], deps)
    assert long_version in rendered
