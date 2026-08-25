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

"""Markdown report — CI-pipeline friendly checklist format.

Designed for pasting into GitHub PR descriptions, issue bodies, or
release notes. Every **actionable** item (SAFE dep to remove, undeclared
import to resolve, finding to address) renders as an unticked checkbox;
confirmed-in-use deps render as a plain bulleted list.

REQ-17 adds an **ASCII dependency tree** at the top of every report
(``_render_ascii_tree``), an ``EntryPoint.usage_count`` suffix
(``used 23×``) on used entry points, and a dedicated *Transitive —
imported directly (promote to first-class)* subsection for transitive
deps that source imports directly. An earlier iteration emitted a
Mermaid diagram in the same slot; the helpers (``_render_mermaid``,
``_mermaid_label``, ``_mermaid_class_for``) are retained as
defence-in-depth utilities for any future renderer that surfaces dep
names inside a Mermaid fence, but are not called from the live render
path.

Safety:
  * User-derived strings pass through ``sanitise()`` (SEC-003, SEC-NEW-03).
  * Markdown-active characters (``|``, `` ` ``, ``*``, ``_``, ``[``,
    ``]``) in dep names / reasons / snippets are escaped so adversarial
    values cannot inject headings, tables, or code blocks; line
    separators (LF, NEL, U+2028, U+2029, …) are folded to spaces so a
    value cannot terminate the list item it is rendered in and emit
    markdown lines of its own.
  * Mermaid label text is hardened against injection: ``]``, ``[``, ``"``,
    newline, backslash, ANSI/control chars are escaped; reserved tokens
    (``subgraph``, ``classDef``, ``linkStyle``, ``style``, ``end``) are
    replaced with ``&lt;reserved&gt;``; the reporter never emits a
    ``click`` directive (SEC-NEW-32, T-17). This hardening protects the
    retained ``_render_mermaid`` helper described above.
"""
from __future__ import annotations

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    DepEdge,
    Finding,
    FindingSeverity,
    VersionedNode,
)
from scarno.reporters._remote_banner import compute_state, text_banner
from scarno.security import sanitise, sanitise_declared_version


# REQ-17 — Mermaid label hardening (kept as a defence-in-depth helper
# for any future renderer that surfaces dep names inside a Mermaid
# fenced block; the primary tree renderer is ASCII-based — see
# ``_render_ascii_tree``).
_MERMAID_RESERVED_TOKENS: frozenset[str] = frozenset({
    "subgraph", "classDef", "linkStyle", "style", "end",
    "---", "===", "graph", "flowchart",
})
_MERMAID_LABEL_MAX: int = 80
_MERMAID_NODE_CAP: int = 2000
_MERMAID_EDGE_CAP: int = 4000
_MERMAID_RESERVED_REPLACEMENT: str = "&lt;reserved&gt;"

# REQ-17 — ASCII tree caps + branch glyphs. Bumped 1000 → 2000 to
# match the wider Maven dep-graph traversal cap (the analyser can
# now surface up to 2000 transitives; the reporter shouldn't truncate
# them at half that).
_TREE_NODE_CAP: int = 2000
_TREE_LABEL_MAX: int = 200
_TREE_BRANCH_TEE: str = "├── "
_TREE_BRANCH_LAST: str = "└── "
_TREE_BRANCH_TRUNK: str = "│   "
_TREE_BRANCH_BLANK: str = "    "

_SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 4,
    FindingSeverity.HIGH: 3,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 1,
}


# Every character a markdown renderer (or a terminal) treats as a line
# break, folded to a single space so a user-derived value can never
# terminate the line it is rendered on. ``sanitise()`` already strips
# CR / VT / FF / FS / GS / RS, but LF, NEL (U+0085), U+2028 and U+2029
# survive it by design — they are listed here regardless so this helper
# stays correct independently of what ``sanitise()`` removes. TAB is
# deliberately absent: it is not a line break and is legitimate inside
# reason strings (SEC-NEW-03).
_LINE_BREAK_TRANSLATE = {
    ord(ch): " "
    for ch in (
        "\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e",
        "\x85", " ", " ",
    )
}


def _escape_md(text: str) -> str:
    """Escape the markdown-active characters that matter inside list items."""
    sanitised = sanitise(text)
    # Fold line separators to spaces — an embedded newline would otherwise
    # end the current list item and let the value emit arbitrary markdown
    # lines (forged headings, checklist entries) of its own.
    sanitised = sanitised.translate(_LINE_BREAK_TRANSLATE)
    # Backslash first — the rest of the replacements introduce backslashes.
    out = sanitised.replace("\\", "\\\\")
    for ch in ("|", "`", "*", "_", "[", "]", "<", ">"):
        out = out.replace(ch, f"\\{ch}")
    return out


def _dep_label(dep: Dependency) -> str:
    if dep.version:
        clean_version = sanitise_declared_version(dep.version) or ""
        return f"`{_escape_md(dep.name)}=={_escape_md(clean_version)}`"
    return f"`{_escape_md(dep.name)}`"


def _render_checklist(
    title: str, deps: list[Dependency], *, group_by_ecosystem: bool = False
) -> list[str]:
    lines = [f"## {title} ({len(deps)})", ""]

    # Sub-group into direct vs transitive when both are present.
    direct = [d for d in deps if not d.is_transitive]
    transitive = [d for d in deps if d.is_transitive]
    if direct and transitive:
        lines.append(f"### Direct ({len(direct)})")
        lines.append("")
        for dep in direct:
            reason = _escape_md(dep.reason) if dep.reason else ""
            lines.append(f"- [ ] {_dep_label(dep)} — {reason}")
        lines.append("")
        lines.append(f"### Transitive — orphaned ({len(transitive)})")
        lines.append("")
        for dep in transitive:
            reason = _escape_md(dep.reason) if dep.reason else ""
            lines.append(f"- [ ] {_dep_label(dep)} — {reason}")
        lines.append("")
        return lines

    if group_by_ecosystem:
        by_eco: dict[str, list[Dependency]] = {}
        for dep in deps:
            by_eco.setdefault(_escape_md(dep.ecosystem), []).append(dep)
        for eco in sorted(by_eco.keys()):
            eco_deps = by_eco[eco]
            lines.append(f"### [{eco}] ({len(eco_deps)})")
            lines.append("")
            for dep in eco_deps:
                reason = _escape_md(dep.reason) if dep.reason else ""
                lines.append(f"- [ ] {_dep_label(dep)} — {reason}")
            lines.append("")
        return lines
    for dep in deps:
        reason = _escape_md(dep.reason) if dep.reason else ""
        lines.append(f"- [ ] {_dep_label(dep)} — {reason}")
    lines.append("")
    return lines


# REQ-17 / FR-150 — entry-point ``kind`` legend rendered above the
# In use section. Surfaces the meaning of each kind so the user can
# tell wildcard imports from concrete classes from method calls etc.
_KIND_LEGEND: dict[str, str] = {
    "class":       "concrete `import com.x.Y;` line",
    "wildcard":    "`import com.x.*;` — package-level import",
    "import":      "import-path observation (no JAR available)",
    "method":      "`<receiver>.<method>(…)` call site",
    "constructor": "`new ClassName(…)` call site",
    "annotation":  "DI/framework activation (`@Autowired`, `@Service`, …)",
    "reflective":  "`Class.forName(\"…\")` / `ClassLoader.loadClass(…)`",
    "function":    "imported function (Python / Go / JS)",
    "namespace":   "`using` directive (C#)",
    "package":     "imported package (Go)",
    "export":      "`exports` entry (npm package.json)",
    "constant":    "module-level constant",
}


def _render_kind_legend(deps: list[Dependency]) -> list[str]:
    seen_kinds: set[str] = set()
    for dep in deps:
        for ep in dep.entry_points:
            if ep.used:
                seen_kinds.add(ep.kind)
    if not seen_kinds:
        return []
    out = ["### Entry-point kinds in this report", ""]
    for kind in sorted(seen_kinds):
        meaning = _KIND_LEGEND.get(kind, "(see ecosystem docs)")
        out.append(f"- `{_escape_md(kind)}` — {meaning}")
    out.append("")
    return out


def _render_in_use(
    deps: list[Dependency],
    *,
    title: str = "In use",
) -> list[str]:
    lines = [f"## {title} ({len(deps)})", ""]
    lines.extend(_render_kind_legend(deps))
    for dep in deps:
        ep_summary = ""
        if dep.entry_points:
            ep_summary = (
                f" — {dep.entry_points_used} / {dep.entry_points_total} "
                f"entry points used"
            )
        lines.append(f"- {_dep_label(dep)}{ep_summary}")
        used = [ep for ep in dep.entry_points if ep.used]
        for ep in used[:25]:  # cap per-dep noise
            # REQ-17 — append ``used N×`` suffix where applicable.
            count_suffix = (
                f" — used {ep.usage_count}×" if ep.usage_count > 0 else ""
            )
            lines.append(
                f"    - `{_escape_md(ep.name)}` "
                f"({_escape_md(ep.kind)}){count_suffix}"
            )
        if len(used) > 25:
            lines.append(f"    - … and {len(used) - 25} more")
    lines.append("")
    return lines


# ── REQ-17 Mermaid renderer ────────────────────────────────────────────────


def _mermaid_label(name: str) -> str:
    """Hardened label-escape for Mermaid node text (SEC-NEW-32, T-17)."""
    text = sanitise(name)
    if text in _MERMAID_RESERVED_TOKENS:
        text = _MERMAID_RESERVED_REPLACEMENT
    text = text.replace("\\", "\\\\")
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    text = text.replace("]", "&#93;")
    text = text.replace("[", "&#91;")
    # ` would re-open the surrounding markdown fenced code block.
    text = text.replace("`", "&#96;")
    text = text.replace("\n", " ")
    text = text.replace("\r", " ")
    if len(text) > _MERMAID_LABEL_MAX:
        text = text[: _MERMAID_LABEL_MAX - 1] + "…"
    return text


def _mermaid_class_for(dep: Dependency) -> str:
    """Map a dep to its Mermaid status classDef."""
    # REQ-17 — direct-use transitives stay black regardless of parent status.
    if dep.is_transitive and dep.imported_directly:
        return "status_used"
    if dep.status is DependencyStatus.SAFE:
        return "status_unused"
    if dep.status is DependencyStatus.UNCERTAIN:
        return "status_uncertain"
    # IN_USE and UNDECLARED render black.
    return "status_used"


def _ascii_label(name: str) -> str:
    """Hardened label-escape for an ASCII-tree row.

    The tree is rendered inside a ```diff fenced block so an
    attacker-controlled dep name must not be able to:
      * Inject backticks (``\\``\\``\\``) that would close the fence
        and execute arbitrary markdown / HTML.
      * Inject ANSI / control bytes that would corrupt terminal
        renderings of the same output.
      * Inject newlines that would split the row across two lines.
      * Inject literal HTML tags (``<script>`` etc.) — even though
        fenced code blocks typically render content as text, the
        markdown *source* should not contain literal tags in case
        downstream tooling concatenates it into a non-fenced context.
    """
    text = sanitise(name)
    text = text.replace("\\", "\\\\")
    text = text.replace("`", "'")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\n", " ")
    text = text.replace("\r", " ")
    if len(text) > _TREE_LABEL_MAX:
        text = text[: _TREE_LABEL_MAX - 1] + "…"
    return text


def _ascii_label_for_dep(dep: Dependency, *, at_top_level: bool) -> str:
    """Render a dep's display label for the tree (name@version + status hint).

    ``at_top_level`` is True only when the row is the dep's own entry
    in the project's direct-dep list (depth 1, the first row a dep
    appears on). When the same dep is rendered again as a child node
    deeper in the tree, ``at_top_level`` is False and the
    ``manifest_redundant`` annotation is suppressed — that recommendation
    only makes sense against the dep's own manifest line, not against
    the parent that pulls it in transitively.
    """
    label = _ascii_label(dep.name)
    if dep.version:
        clean_version = sanitise_declared_version(dep.version) or ""
        if clean_version:
            label += f"@{_ascii_label(clean_version)}"
    if dep.status is DependencyStatus.SAFE:
        label += "  (unused)"
    elif dep.status is DependencyStatus.UNCERTAIN:
        label += "  (uncertain)"
    elif dep.status is DependencyStatus.UNDECLARED:
        label += "  (undeclared)"
    elif dep.is_transitive and dep.imported_directly:
        label += "  (promote — imported directly)"
    elif dep.manifest_redundant and at_top_level:
        parent = (
            _ascii_label(dep.redundant_parent)
            if dep.redundant_parent
            else "an in-use dep"
        )
        label += f"  (manifest declaration redundant — kept alive by {parent})"
    return label


def _ascii_diff_marker(dep: Dependency, *, at_top_level: bool) -> str:
    """Return the leading two-character marker for diff colouring.

    GitHub / GitLab ``diff`` fenced blocks colour the line by its
    first character: ``-`` is red, ``+`` is green, ``!`` is plain in
    most renderers (orange in some). The user-facing colour scheme:

      * USED                                → black (neutral)  — leading ``  `` (space)
      * SAFE                                → red              — leading ``- ``
      * UNCERTAIN                           → orange           — leading ``! ``
      * UNDECLARED                          → orange           — leading ``! ``
      * manifest declaration redundant      → red              — leading ``- ``
        ONLY at top-level (the dep's own manifest line). When the
        same dep is rendered as a child node it shows neutral so the
        cleanup hint is not double-counted.
      * promote-needed transitive (used)    → neutral; suffix
        carries the message
    """
    if dep.status is DependencyStatus.SAFE:
        return "- "
    if dep.manifest_redundant and at_top_level:
        return "- "
    if dep.status in (
        DependencyStatus.UNCERTAIN,
        DependencyStatus.UNDECLARED,
    ):
        return "! "
    return "  "


def _render_ascii_tree(
    deps: list[Dependency],
    dep_graph: dict[str, set[str]],
    project_label: str,
    *,
    dep_edges: list["DepEdge"] | None = None,
    resolved_pairs: set[tuple[str, str | None]] | None = None,
) -> list[str]:
    """Render a vertical Unix-style ASCII dep tree.

    Wrapped in a ```diff fenced block so renderers that honour diff
    colouring (GitHub, GitLab, most IDEs) display the status colour
    scheme automatically. ``-`` lines are red (unused), ``!`` lines
    render orange in many viewers (uncertain / undeclared), and
    plain-prefixed lines are neutral (in use).

    Layout:
      * Project name on the left at depth 0.
      * Direct deps (``is_transitive=False``) listed below, depth 1.
      * Transitives nested under their parent at depth ≥ 2 via
        ``dep_graph`` (or ``dep_edges`` when REQ-19 is in effect).

    Caps:
      * 1000 nodes total (including the project root). On overflow,
        the remaining tree is truncated and a notice line is appended.

    Cycle detection: each recursion path tracks visited canonical
    names so a cyclic ``dep_graph`` cannot infinitely recurse.

    REQ-19 (FR-194): when ``dep_edges`` is populated, child nodes are
    rendered with the edge's declared version (``child@version``), and
    the same canonical at two declared versions renders as two distinct
    sibling nodes. The legacy canonical-only ``dep_graph`` rendering
    path is preserved when ``dep_edges`` is empty so REQ-17 acceptance
    criteria do not regress (TA-220).
    """
    if not deps:
        return []
    by_name: dict[str, Dependency] = {}
    for dep in deps:
        canonical = sanitise(dep.name).lower()
        # First-write-wins so ordering of duplicates doesn't surprise.
        by_name.setdefault(canonical, dep)

    # REQ-19 — group edges by parent canonical name (lower-cased to match
    # the by_name index). Each parent maps to a list of (child_canonical,
    # declared_version) pairs in stable sort order.
    edges_by_parent: dict[str, list[tuple[str, str | None]]] = {}
    if dep_edges:
        for edge in dep_edges:
            parent_key = sanitise(edge.parent).lower()
            child_key = sanitise(edge.child).lower()
            edges_by_parent.setdefault(parent_key, []).append(
                (child_key, edge.declared_version)
            )
        for parent_key in edges_by_parent:
            edges_by_parent[parent_key].sort(
                key=lambda pair: (pair[0], pair[1] or "")
            )

    direct_deps = [d for d in deps if not d.is_transitive]
    direct_deps.sort(key=lambda d: sanitise(d.name).lower())

    out: list[str] = ["```diff"]
    project_name = _ascii_label(project_label) or "(project)"
    # Project root row — neutral colour, no marker.
    out.append(f"  {project_name}")
    nodes_emitted = 1
    truncated = [False]

    resolved_set: set[tuple[str, str | None]] = (
        resolved_pairs if resolved_pairs is not None else set()
    )

    def _label_for_child(
        child_dep: Dependency,
        edge_version: str | None,
        *,
        at_top_level: bool,
    ) -> str:
        """REQ-19 — when an edge's declared_version is supplied, use it
        in the rendered label (overrides the Dependency.version label).
        This is what produces distinct ``x@1.1`` vs ``x@1.2`` rows for
        the same canonical name.

        REQ-20 (FR-206) — when this (canonical, version) is the
        resolved version per ``resolved_pairs``, append ``← resolved``
        so the user can see at a glance which version is on the
        classpath.
        """
        if edge_version is None:
            return _ascii_label_for_dep(child_dep, at_top_level=at_top_level)
        clean = sanitise_declared_version(edge_version) or ""
        base = _ascii_label(child_dep.name)
        label = f"{base}@{_ascii_label(clean)}" if clean else base
        if child_dep.status is DependencyStatus.SAFE:
            label += "  (unused)"
        elif child_dep.status is DependencyStatus.UNCERTAIN:
            label += "  (uncertain)"
        elif child_dep.status is DependencyStatus.UNDECLARED:
            label += "  (undeclared)"
        if (
            at_top_level
            and child_dep.manifest_redundant
            and child_dep.redundant_parent
        ):
            label += (
                f"  (manifest redundant — kept by "
                f"{_ascii_label(child_dep.redundant_parent)})"
            )
        if child_dep.is_transitive and child_dep.imported_directly:
            label += "  (promote — imported directly)"
        # REQ-20 / FR-206 resolved-version marker.
        canonical_lower = sanitise(child_dep.name).lower()
        if (canonical_lower, edge_version) in resolved_set or (
            canonical_lower,
            sanitise_declared_version(edge_version),
        ) in resolved_set:
            label += "  ← resolved"
        return label

    def nodes_emitted_capped() -> bool:
        if nodes_emitted >= _TREE_NODE_CAP:
            truncated[0] = True
            return True
        return False

    def bump_node() -> None:
        nonlocal nodes_emitted
        nodes_emitted += 1

    def _render_subtree(
        dep: Dependency,
        prefix: str,
        is_last: bool,
        path_visited: set[str],
        depth: int,
        edge_version: str | None = None,
    ) -> None:
        if nodes_emitted_capped():
            return
        elbow = _TREE_BRANCH_LAST if is_last else _TREE_BRANCH_TEE
        # Top-level == depth 1 (depth 0 is the project root, never a dep).
        # Manifest-redundancy hints render only here so child renderings
        # of the same dep stay neutral.
        at_top_level = depth == 1
        marker = _ascii_diff_marker(dep, at_top_level=at_top_level)
        if edge_version is not None:
            label = _label_for_child(
                dep, edge_version, at_top_level=at_top_level
            )
        else:
            label = _ascii_label_for_dep(dep, at_top_level=at_top_level)
        out.append(f"{marker}{prefix}{elbow}{label}")
        bump_node()
        canonical = sanitise(dep.name).lower()
        # Cycle: a node may legitimately appear twice in the tree under
        # different parents (diamond), but along a single ROOT→leaf path
        # we must not revisit.
        if canonical in path_visited:
            return
        new_visited = path_visited | {canonical}
        # REQ-19 path: prefer dep_edges-derived children when available
        # so distinct (child, declared_version) pairs render as siblings.
        new_prefix = prefix + (
            _TREE_BRANCH_BLANK if is_last else _TREE_BRANCH_TRUNK
        )
        if edges_by_parent:
            children_pairs = edges_by_parent.get(canonical, [])
            children = [
                (by_name[c], v) for c, v in children_pairs if c in by_name
            ]
            for i, (child_dep, child_ver) in enumerate(children):
                if nodes_emitted_capped():
                    break
                _render_subtree(
                    child_dep, new_prefix, i == len(children) - 1,
                    new_visited, depth + 1,
                    edge_version=child_ver,
                )
        else:
            children_canonical = sorted(dep_graph.get(canonical, set()))
            children = [
                (by_name[c], None) for c in children_canonical if c in by_name
            ]
            for i, (child_dep, _v) in enumerate(children):
                if nodes_emitted_capped():
                    break
                _render_subtree(
                    child_dep, new_prefix, i == len(children) - 1,
                    new_visited, depth + 1,
                )

    # REQ-19 — direct deps render with the version declared in the
    # project's own manifest (the synthetic root edges, parent ""),
    # consistent with how transitives render their parent-declared
    # version. Falls back to Dependency.version when no root edge is
    # present (the legacy dep_graph-only path, e.g. Python projects).
    root_version_by_child: dict[str, str | None] = {}
    for child_key, child_ver in edges_by_parent.get("", []):
        root_version_by_child.setdefault(child_key, child_ver)

    # ``_render_subtree`` recurses once per visited node along a
    # root→leaf chain. Worst-case depth is bounded by ``_TREE_NODE_CAP``
    # (a degenerate linear chain). When the cap was 500, Python's
    # default recursion limit (1000) absorbed it comfortably; the bump
    # to 1000 makes the worst case touch the limit. Defensively bump
    # the limit for the duration of the render, then restore.
    import sys as _sys
    _required_depth = _TREE_NODE_CAP + 200  # cap + frame overhead
    _prev_recursion_limit = _sys.getrecursionlimit()
    if _prev_recursion_limit < _required_depth:
        _sys.setrecursionlimit(_required_depth)
    try:
        for i, dep in enumerate(direct_deps):
            if nodes_emitted_capped():
                break
            _render_subtree(
                dep, "", i == len(direct_deps) - 1, set(),
                depth=1,
                edge_version=root_version_by_child.get(
                    sanitise(dep.name).lower()
                ),
            )
    finally:
        _sys.setrecursionlimit(_prev_recursion_limit)

    if truncated[0]:
        elided = max(0, len(deps) + 1 - nodes_emitted)
        out.append(
            f"  … tree truncated at {_TREE_NODE_CAP} nodes "
            f"({elided} more not shown)"
        )
    # Inline legend so the ``- ``/``! `` semantics and the version
    # annotations are self-describing even for readers whose markdown
    # viewer doesn't colour the diff.
    out.append("")
    out.append("  Legend:  (no marker) in use      - unused / manifest redundant      ! uncertain / undeclared")
    out.append("           name@version = declared version      ← resolved = effective version on the classpath")
    out.append("```")
    out.append("")
    return out


def _render_mermaid(
    deps: list[Dependency],
    dep_graph: dict[str, set[str]],
) -> list[str]:
    """Return the lines of a fenced ```mermaid block.

    Limits (SEC-NEW-32):
      * ≤ 1000 nodes (SAFE/UNCERTAIN/UNDECLARED first, then IN_USE).
      * ≤ 2000 edges.
      * 80-char labels.
      * No ``click`` directives, ever.
    """
    if not deps:
        return []
    # Stable canonical id per dep — sorted by (status priority, name).
    priority = {
        DependencyStatus.SAFE: 0,
        DependencyStatus.UNCERTAIN: 1,
        DependencyStatus.UNDECLARED: 2,
        DependencyStatus.IN_USE: 3,
    }
    sorted_deps = sorted(
        deps,
        key=lambda d: (priority.get(d.status, 9), sanitise(d.name).lower()),
    )
    truncated = len(sorted_deps) > _MERMAID_NODE_CAP
    visible = sorted_deps[:_MERMAID_NODE_CAP]
    name_to_id: dict[str, str] = {}
    # FR-152 — left→right orientation. ``flowchart LR`` lays parents
    # on the left and children flowing rightward; siblings stack
    # vertically within each rank, which keeps long sibling lists
    # readable as a column rather than a wide row. The rank/node
    # spacing init hints tighten the diagram for typical PR-comment
    # widths.
    out: list[str] = [
        "```mermaid",
        "%%{init: {'flowchart': {'rankSpacing': 60, 'nodeSpacing': 30}}}%%",
        "flowchart LR",
    ]
    for i, dep in enumerate(visible):
        nid = f"n_{i}"
        name_to_id[sanitise(dep.name).lower()] = nid
        label = _mermaid_label(dep.name)
        cls = _mermaid_class_for(dep)
        out.append(f'    {nid}["{label}"]:::{cls}')
    # Edges — only between visible nodes; cap at _MERMAID_EDGE_CAP.
    edge_count = 0
    edges_emitted = False
    cap_hit = False
    if dep_graph:
        for parent, children in dep_graph.items():
            if cap_hit:
                break
            p_id = name_to_id.get(sanitise(parent).lower())
            if p_id is None:
                continue
            for child in children:
                c_id = name_to_id.get(sanitise(child).lower())
                if c_id is None:
                    continue
                if edge_count >= _MERMAID_EDGE_CAP:
                    cap_hit = True
                    break
                out.append(f"    {p_id} --> {c_id}")
                edges_emitted = True
                edge_count += 1
    if cap_hit:
        out.append(
            f"    %% edge cap reached at "
            f"{_MERMAID_EDGE_CAP}; further edges elided"
        )
    if not edges_emitted:
        out.append("    %% no edge data available")
    out.append("    classDef status_used fill:#fff,stroke:#000,color:#000;")
    out.append("    classDef status_unused fill:#ffe5e5,stroke:#c00,color:#c00;")
    out.append(
        "    classDef status_uncertain fill:#fff5e0,"
        "stroke:#d97706,color:#d97706;"
    )
    if truncated:
        elided = len(sorted_deps) - _MERMAID_NODE_CAP
        out.append(
            f"    %% diagram truncated — {elided} additional nodes elided"
        )
    out.append("```")
    out.append("")
    return out


def _finding_sort_key(f: Finding) -> tuple[int, str, int]:
    return (-_SEVERITY_ORDER[f.severity], f.file_path, f.line)


def _render_multi_version_section(result: "AnalysisResult") -> list[str]:
    """REQ-20 / FR-206 — render the "Multiple versions detected" table.

    One row per coordinate in ``multi_version_coords``; columns:
    coordinate, declared versions (resolved bolded), resolved version,
    removable versions (or "—" when none).

    A node whose edge carried no declared version (the manifest left it
    unpinned) is shown with the resolver's effective version from the
    dependency list, tagged ``(resolved)`` — never a bare ``(none)``.
    """
    out: list[str] = []
    out.append("## Multiple versions detected")
    out.append("")
    out.append(
        "_**Bold** marks the resolved (effective) version — the one that "
        "actually lands on the classpath. `(resolved)` tags a version the "
        "resolver determined for an entry the manifest left unpinned._"
    )
    out.append("")
    out.append(
        "| Coordinate | Declared versions | Resolved | Removable |"
    )
    out.append("|---|---|---|---|")
    # Effective version per coordinate, from the dependency list — used
    # to fill in nodes whose edge carried no declared version.
    effective_version = {
        sanitise(d.name).lower(): d.version
        for d in result.dependencies
        if d.version
    }
    nodes_by_coord: dict[str, list[VersionedNode]] = {}
    for n in result.versioned_nodes:
        nodes_by_coord.setdefault(n.canonical, []).append(n)
    for coord in sorted(result.multi_version_coords):
        nodes = nodes_by_coord.get(coord, [])
        if not nodes:
            continue
        fallback = effective_version.get(sanitise(coord).lower())
        declared_parts: list[str] = []
        resolved_str = "?"
        removable_parts: list[str] = []
        for n in sorted(
            nodes,
            key=lambda v: (v.declared_version or ""),
        ):
            if n.declared_version:
                ver = shown = n.declared_version
            elif fallback:
                ver = fallback
                shown = f"{fallback} (resolved)"
            else:
                ver = shown = "(unresolved)"
            if n.is_resolved:
                declared_parts.append(f"**{shown}**")
                resolved_str = ver
            else:
                declared_parts.append(shown)
            if n.removable:
                removable_parts.append(ver)
        # No node carried is_resolved (e.g. the resolved version itself
        # was unpinned) — fall back to the dependency list.
        if resolved_str == "?" and fallback:
            resolved_str = fallback
        out.append(
            f"| `{_escape_md(coord)}` | "
            f"{', '.join(declared_parts)} | "
            f"`{_escape_md(resolved_str)}` | "
            f"{(', '.join(removable_parts)) or '—'} |"
        )
    out.append("")
    return out


def _render_pinning_overrides_section(
    pinned_deps: list[Dependency],
) -> list[str]:
    """REQ-21 / FR-215 — render the Maven (and later npm / Gradle)
    "Pinning overrides" section.

    Groups deps by ecosystem so each ecosystem's sub-table renders
    independently — PR-3 only emits the Maven sub-table; PR-5 / PR-6
    add npm / Gradle sub-tables that reuse this helper.
    """
    out: list[str] = []
    out.append("## Pinning overrides")
    out.append("")
    out.append(
        "These direct dependencies are kept on the classpath as "
        "substitutes for excluded or managed transitives. Removing "
        "them would silently re-introduce the substituted version."
    )
    out.append("")
    # Group by ecosystem.
    by_eco: dict[str, list[Dependency]] = {}
    for dep in pinned_deps:
        by_eco.setdefault(dep.ecosystem or "unknown", []).append(dep)
    for eco in sorted(by_eco.keys()):
        title = {
            "maven": "Maven", "npm": "npm", "gradle": "Gradle",
            "javascript": "npm", "java": "Maven",
        }.get(eco, eco)
        out.append(f"### {title}")
        out.append("")
        for dep in sorted(by_eco[eco], key=lambda d: d.name):
            kind = dep.pin_override_kind or "?"
            target = dep.pin_override_target or ""
            out.append(
                f"- `{_escape_md(dep.name)}` — **{_escape_md(kind)}**: "
                f"{_escape_md(target)}"
            )
        out.append("")
    return out


def _render_dynamic_pin_section(
    dynamic_pins: list[Dependency],
) -> list[str]:
    """REQ-21b / R-Phase9-02 — dedicated "DO NOT REMOVE — dynamic
    Gradle pin" section. Rendered ABOVE the generic pinning section so
    a user scanning for "removable" candidates never mistakes a
    dynamic pin for one.
    """
    out: list[str] = []
    out.append("## DO NOT REMOVE — dynamic Gradle pin")
    out.append("")
    out.append(
        "These dependencies are kept on the classpath by a Gradle "
        "resolution-strategy directive whose target version is computed "
        "**dynamically** (read from a properties file, computed by a "
        "closure, etc.). Scarno's static analysis cannot confirm "
        "the target; removing these will silently re-introduce "
        "whatever transitive version Gradle would otherwise resolve."
    )
    out.append("")
    for dep in sorted(dynamic_pins, key=lambda d: d.name):
        target = dep.pin_override_target or "dynamic pin"
        out.append(
            f"- `{_escape_md(dep.name)}` — {_escape_md(target)}"
        )
    out.append("")
    return out


def _render_findings(findings: list[Finding]) -> list[str]:
    visible = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    lines = [f"## Security findings ({len(visible)})", ""]
    for f in sorted(visible, key=_finding_sort_key):
        location = f"`{_escape_md(f.file_path)}:{f.line}`"
        lines.append(
            f"- [ ] **[{f.severity.value}]** `{f.rule_id}` {location} — "
            f"{_escape_md(f.message)}"
        )
        if f.remediation:
            lines.append(
                f"    - **Remediation:** {_escape_md(f.remediation)}"
            )
    lines.append("")
    if suppressed:
        lines.append(
            f"<details><summary>Suppressed findings ({len(suppressed)})</summary>"
        )
        lines.append("")
        for f in sorted(suppressed, key=_finding_sort_key):
            location = f"`{_escape_md(f.file_path)}:{f.line}`"
            lines.append(
                f"- _suppressed_ **[{f.severity.value}]** `{f.rule_id}` "
                f"{location}"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return lines


class MarkdownReporter:
    """Render an :class:`AnalysisResult` as a markdown checklist."""

    def render(
        self,
        result: AnalysisResult,
        *,
        dep_graph: dict[str, set[str]] | None = None,
    ) -> str:
        lines: list[str] = []
        lines.append(
            f"# Scarno analysis — `{_escape_md(result.project_path)}`"
        )
        lines.append("")
        lines.append(f"- **Project type:** {_escape_md(result.project_type)}")
        # REQ-24 / FR-266 — top-of-report banner. Rendered as a
        # blockquote so it stays visually distinct from the bullet
        # list of metadata.
        banner = text_banner(compute_state(result))
        if banner is not None:
            lines.append("")
            lines.append(f"> ⚠ **Remote-fetch active** — {_escape_md(banner)}")
        lines.append("")

        # REQ-17 — ASCII dependency tree immediately after the header.
        # Mermaid was replaced because real multi-hundred-dep projects
        # render as illegible spaghetti in most markdown viewers; the
        # ASCII form stays readable in any monospace renderer, and
        # ``diff`` colouring carries the status palette in GitHub /
        # GitLab / most IDEs.
        graph = dep_graph if dep_graph is not None else result.dep_graph
        # REQ-20 — pass the resolved (canonical, version) pairs so the
        # tree renderer can mark the resolved row with ``← resolved``.
        # Restricted to coordinates that actually have a version
        # conflict: on a single-version dep "← resolved" is just noise
        # (the only version is trivially the resolved one).
        _conflicted = {
            sanitise(c).lower()
            for c in (result.multi_version_coords or [])
        }
        resolved_pairs: set[tuple[str, str | None]] = {
            (sanitise(n.canonical).lower(), n.declared_version)
            for n in (result.versioned_nodes or [])
            if n.is_resolved
            and sanitise(n.canonical).lower() in _conflicted
        }
        lines.extend(
            _render_ascii_tree(
                result.dependencies, graph or {},
                project_label=result.project_path,
                dep_edges=result.dep_edges or None,
                resolved_pairs=resolved_pairs or None,
            )
        )

        # REQ-20 / FR-206 — "Multiple versions detected" section.
        # Inserted between the ASCII tree and the SAFE/UNCERTAIN/IN_USE
        # checklists when ``multi_version_coords`` is non-empty.
        if result.multi_version_coords and result.versioned_nodes:
            lines.extend(_render_multi_version_section(result))

        # REQ-21 / FR-215 — "Pinning overrides" section. Inserted
        # before the SAFE checklist so the user sees the load-bearing
        # pins before any removal recommendation.
        #
        # REQ-21b / R-Phase9-02 — GRADLE_DYNAMIC_PIN deps render in
        # their own dedicated "DO NOT REMOVE — dynamic Gradle pin"
        # section ABOVE the generic pinning section, so a user
        # reviewing the "Manual review required" list never mistakes
        # a dynamic-pin dep for a removable one.
        pinned_deps = [
            d for d in result.dependencies if d.pin_override
        ]
        dynamic_pinned = [
            d for d in pinned_deps
            if d.pin_override_kind == "GRADLE_DYNAMIC_PIN"
        ]
        static_pinned = [
            d for d in pinned_deps
            if d.pin_override_kind != "GRADLE_DYNAMIC_PIN"
        ]
        if dynamic_pinned:
            lines.extend(_render_dynamic_pin_section(dynamic_pinned))
        if static_pinned:
            lines.extend(_render_pinning_overrides_section(static_pinned))

        by_status: dict[DependencyStatus, list[Dependency]] = {
            DependencyStatus.SAFE: [],
            DependencyStatus.UNCERTAIN: [],
            DependencyStatus.UNDECLARED: [],
            DependencyStatus.IN_USE: [],
        }
        for dep in result.dependencies:
            bucket = by_status.get(dep.status)
            if bucket is not None:
                bucket.append(dep)

        distinct_ecosystems = {
            d.ecosystem for d in result.dependencies if d.ecosystem
        }
        group_by_eco = (
            len(result.languages) > 1 and len(distinct_ecosystems) > 1
        )

        if by_status[DependencyStatus.SAFE]:
            lines.extend(
                _render_checklist(
                    "Suggested removals (SAFE)",
                    by_status[DependencyStatus.SAFE],
                    group_by_ecosystem=group_by_eco,
                )
            )
        if by_status[DependencyStatus.UNDECLARED]:
            lines.extend(
                _render_checklist(
                    "Undeclared imports",
                    by_status[DependencyStatus.UNDECLARED],
                    group_by_ecosystem=group_by_eco,
                )
            )
        if by_status[DependencyStatus.UNCERTAIN]:
            lines.extend(
                _render_checklist(
                    "Manual review required (UNCERTAIN)",
                    by_status[DependencyStatus.UNCERTAIN],
                    group_by_ecosystem=group_by_eco,
                )
            )
        # REQ-17 — split the IN_USE bucket so directly-used transitives
        # render in their own promote-to-first-class subsection above the
        # regular "In use" list.
        # FR-150 — also split out direct deps whose explicit manifest
        # declaration is redundant (artifact stays alive transitively).
        # These render IN_USE (the artifact is needed) but in a
        # dedicated subsection so the developer sees the manifest
        # cleanup recommendation distinctly.
        in_use = by_status[DependencyStatus.IN_USE]
        promote = [
            d for d in in_use if d.is_transitive and d.imported_directly
        ]
        redundant = [
            d for d in in_use
            if d.manifest_redundant and d not in promote
        ]
        regular_in_use = [
            d for d in in_use if d not in promote and d not in redundant
        ]
        if promote:
            lines.extend(
                _render_in_use(
                    promote,
                    title="Transitive — imported directly (promote to first-class)",
                )
            )
        if redundant:
            lines.extend(
                _render_in_use(
                    redundant,
                    title=(
                        "Manifest declaration redundant "
                        "(safe to remove from manifest — kept alive transitively)"
                    ),
                )
            )
        if regular_in_use:
            lines.extend(_render_in_use(regular_in_use))
        if result.findings:
            lines.extend(_render_findings(result.findings))
        if result.errors:
            lines.append(f"## Warnings ({len(result.errors)})")
            lines.append("")
            for err in result.errors:
                lines.append(f"- {_escape_md(err)}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"
