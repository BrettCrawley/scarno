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

"""Human-readable text report.

The text reporter is deliberately ``print``-free: it builds and returns
a single string. The CLI decides where that string goes (stdout, file,
or nowhere).
"""
from __future__ import annotations

from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    Finding,
    FindingSeverity,
    VersionedNode,
)
from scarno.reporters._remote_banner import compute_state, text_banner
from scarno.security import sanitise

_SEVERITY_MARK: dict[FindingSeverity, str] = {
    FindingSeverity.LOW: " ! ",
    FindingSeverity.MEDIUM: " ! ",
    FindingSeverity.HIGH: "!! ",
    FindingSeverity.CRITICAL: "!! ",
}

_SECTION_ORDER: tuple[tuple[DependencyStatus, str], ...] = (
    (DependencyStatus.SAFE, "SAFE TO REMOVE"),
    (DependencyStatus.UNCERTAIN, "UNCERTAIN"),
    (DependencyStatus.UNDECLARED, "UNDECLARED"),
    (DependencyStatus.IN_USE, "IN USE"),
)


def _fmt_dep_header(dep: Dependency) -> str:
    name = sanitise(dep.name)
    if dep.version:
        return f"  - {name}=={sanitise(dep.version)}"
    return f"  - {name}"


def _fmt_entry_points(dep: Dependency) -> list[str]:
    if not dep.entry_points:
        return []
    lines = [f"    Entry points: {dep.entry_points_used} / {dep.entry_points_total} used"]
    for ep in dep.entry_points:
        if ep.used:
            # REQ-17 — append a ``used N×`` suffix when usage_count > 0.
            count_suffix = f"  used {ep.usage_count}×" if ep.usage_count > 0 else ""
            lines.append(
                f"      ✓ {sanitise(ep.name)}  ({sanitise(ep.kind)}){count_suffix}"
            )
    return lines


def _render_section(
    title: str,
    deps: list[Dependency],
    *,
    compact: bool,
    group_by_ecosystem: bool = False,
) -> list[str]:
    """Render a single status section.

    ``compact=True`` is used for IN USE, where we only want a flat list
    of names by default (full entry-point drill-down is still rendered
    for IN USE deps with populated ``entry_points``).

    ``group_by_ecosystem=True`` (REQ-9) inserts ``[<ecosystem>]``
    sub-headings inside the section when a polyglot result is rendered.

    For SAFE sections containing both direct and transitive deps, the
    output is sub-grouped into "Direct" and "Transitive (orphaned)".
    """
    lines: list[str] = [f"{title} ({len(deps)})"]

    # Sub-group SAFE into direct vs transitive when both are present.
    direct = [d for d in deps if not d.is_transitive]
    transitive = [d for d in deps if d.is_transitive]
    if direct and transitive:
        lines.append(f"  Direct ({len(direct)})")
        lines.extend(_render_dep_block(direct, compact=compact, indent=4))
        lines.append(f"  Transitive — orphaned ({len(transitive)})")
        lines.extend(_render_dep_block(transitive, compact=compact, indent=4))
        return lines

    if group_by_ecosystem:
        by_eco: dict[str, list[Dependency]] = {}
        for dep in deps:
            by_eco.setdefault(sanitise(dep.ecosystem), []).append(dep)
        for eco in sorted(by_eco.keys()):
            eco_deps = by_eco[eco]
            lines.append(f"  [{eco}] ({len(eco_deps)})")
            lines.extend(_render_dep_block(eco_deps, compact=compact, indent=4))
        return lines

    lines.extend(_render_dep_block(deps, compact=compact, indent=2))
    return lines


def _render_dep_block(
    deps: list[Dependency], *, compact: bool, indent: int
) -> list[str]:
    prefix = " " * indent
    lines: list[str] = []
    if compact and all(not d.entry_points for d in deps):
        names = ", ".join(sanitise(d.name) for d in deps)
        if names:
            lines.append(f"{prefix}{names}")
        return lines

    for dep in deps:
        header = _fmt_dep_header(dep)
        if indent != 2:
            # re-indent the dep-header leading "  - "
            header = prefix + header.lstrip(" ")
        lines.append(header)
        if dep.reason:
            lines.append(f"{prefix}  Reason: {sanitise(dep.reason)}")
        for ep_line in _fmt_entry_points(dep):
            lines.append(prefix + ep_line.lstrip(" "))
    return lines


def _render_multi_version(result: AnalysisResult) -> list[str]:
    """REQ-20 — render the "Multiple versions detected" block.

    One entry per coordinate in ``multi_version_coords``: the declared
    versions (the effective one tagged ``(resolved)``), and which of
    them the per-version classifier found removable. A version the
    manifest left unpinned is shown with the resolver's effective value
    rather than a bare ``(none)``. Empty ``versioned_nodes`` → no
    output (the analyser produced no version-keyed data).
    """
    coords = sorted(result.multi_version_coords)
    if not coords or not result.versioned_nodes:
        return []
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

    lines: list[str] = [
        f"MULTIPLE VERSIONS DETECTED ({len(coords)})",
        "  (resolved) = the effective version on the classpath; "
        "(unpinned) = no version declared in the manifest",
    ]
    for coord in coords:
        nodes = sorted(
            nodes_by_coord.get(coord, []),
            key=lambda v: (v.declared_version or ""),
        )
        if not nodes:
            continue
        fallback = effective_version.get(sanitise(coord).lower())
        lines.append(f"  - {sanitise(coord)}")
        declared_parts: list[str] = []
        removable_parts: list[str] = []
        for n in nodes:
            if n.declared_version:
                ver = sanitise(n.declared_version)
            elif fallback:
                ver = f"{sanitise(fallback)} (unpinned)"
            else:
                ver = "(unresolved)"
            declared_parts.append(
                f"{ver} (resolved)" if n.is_resolved else ver
            )
            if n.removable:
                removable_parts.append(ver)
        lines.append(f"      Declared: {', '.join(declared_parts)}")
        lines.append(
            f"      Removable: {', '.join(removable_parts) or '—'}"
        )
    lines.append("")
    return lines


class TextReporter:
    """Render an :class:`AnalysisResult` as a single text string."""

    def render(self, result: AnalysisResult) -> str:
        lines: list[str] = []
        lines.append(f"Scarno Analysis — {sanitise(result.project_path)}")
        lines.append(f"Project type: {sanitise(result.project_type)}")
        # REQ-24 / FR-266 — top-of-report banner when the analysis was
        # network-augmented. Shown immediately after the header so an
        # operator scanning the report cannot miss it.
        banner = text_banner(compute_state(result))
        if banner is not None:
            lines.append(f"⚠ {banner}")
        lines.append("")

        by_status: dict[DependencyStatus, list[Dependency]] = {
            status: [] for status, _ in _SECTION_ORDER
        }
        for dep in result.dependencies:
            if dep.status in by_status:
                by_status[dep.status].append(dep)

        # REQ-9 — when a polyglot result is rendered (two or more
        # distinct languages contributed), sub-section each status
        # block by ecosystem so mixed npm + pypi + go reports stay
        # scannable.
        distinct_ecosystems = {
            d.ecosystem for d in result.dependencies if d.ecosystem
        }
        group_by_eco = (
            len(result.languages) > 1 and len(distinct_ecosystems) > 1
        )

        for status, title in _SECTION_ORDER:
            deps = by_status[status]
            if not deps:
                continue
            compact = status is DependencyStatus.IN_USE
            lines.extend(
                _render_section(
                    title,
                    deps,
                    compact=compact,
                    group_by_ecosystem=group_by_eco,
                )
            )
            lines.append("")

        # REQ-20 — surface version conflicts between the status sections
        # and the security findings.
        lines.extend(_render_multi_version(result))

        visible_findings = [f for f in result.findings if not f.suppressed]
        if visible_findings:
            lines.append(f"SECURITY FINDINGS ({len(visible_findings)})")
            for finding in visible_findings:
                lines.extend(_format_finding(finding))
            lines.append("")

        if result.errors:
            lines.append(f"WARNINGS ({len(result.errors)})")
            for err in result.errors:
                lines.append(f"  ! {sanitise(err)}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"


def _format_finding(finding: Finding) -> list[str]:
    mark = _SEVERITY_MARK.get(finding.severity, " ! ")
    header = (
        f" {mark}[{finding.severity.value}] {finding.rule_id}  "
        f"{sanitise(finding.file_path)}:{finding.line}"
    )
    out: list[str] = [header]
    if finding.message:
        out.append(f"      {sanitise(finding.message)}")
    if finding.remediation:
        out.append(f"      Remediation: {sanitise(finding.remediation)}")
    return out
