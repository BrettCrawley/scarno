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

"""REQ-22 — cross-version ABI diff (deep-inspection only).

Detects ``NoSuchMethodError``-class runtime failures by comparing the
public ABI surface (extracted via ``javap``) of a transitive dep
between the *declared* version (in a parent's manifest) and the
*resolved* version that Maven actually puts on the classpath.

ARCHITECTURAL INVARIANTS:

* **NO subprocess imports** (NEW-ARCH-011 / SEC-NEW-51). ``javap`` is
  spawned via an injected callable — the hardened
  ``JvmSourceAnalyser._invoke_javap_safe`` — so SEC-NEW-09 (Java
  identifier validation), SEC-NEW-12 (``JAVA_HOME`` pinning), and the
  10-second per-call timeout always apply. The constructor REQUIRES
  ``invoke_javap`` as a keyword argument (no default) to make the
  injection structurally explicit.
* **No wholesale ``~/.m2`` enumeration** (SUC-52 / SAC-50). The differ
  reads JARs only for coordinates already present in
  ``result.dep_edges`` — never walks the cache to discover other
  coordinates. An AST scan in ``tests/security/`` rejects any
  directory-walking call site (see SUC-52 test).
* **Bounded thread pool + locked cap counter** (NEW-ARCH-010 / ADR-010).
  ``max_workers = min(8, os.cpu_count() or 1)``; the per-run jar cap
  (``_JAVAP_MAX_JARS_PER_RUN``) is enforced under
  ``threading.Lock`` so the cap is EXACT under concurrent execution.
* **Deterministic finding order** (R-Phase9-01). A stable sort
  applies BEFORE returning from :meth:`CrossVersionAbiDiffer.diff_all`
  so two runs against the same fixture produce byte-identical
  Finding ordering.
"""
from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from collections.abc import Sequence
from pathlib import Path
from typing import Callable

from scarno.analysers.java.maven import _validate_gav
from scarno.core.classifier import _safe_cpu_count
from scarno.models import (
    AnalysisResult,
    Finding,
    FindingKind,
    FindingSeverity,
    JavaSignature,
    VersionedNode,
)
from scarno.security import (
    PathEscapeError,
    resolve_and_confine,
    safe_jar_entries,
    sanitise,
)


# ── Caps (SEC-NEW-42 / SEC-NEW-43) ──────────────────────────────────────────


_JAVAP_PER_JAR_TIMEOUT_S: int = 30
_JAVAP_MAX_JARS_PER_RUN: int = 256
_JAVAP_MAX_SIGNATURES_PER_JAR: int = 50_000


def _compute_max_workers() -> int:
    """ADR-010 — ``min(8, os.cpu_count() or 1)`` with defensive fallback.

    Wrapped via :func:`scarno.core.classifier._safe_cpu_count` so
    platforms that raise on ``os.cpu_count()`` degrade to a single
    worker rather than crashing.
    """
    return min(8, _safe_cpu_count(default=1))


# ── javap output parsing (FR-232) ───────────────────────────────────────────


# Method / constructor:  public int utilityMethod(java.lang.String);
#                        public com.thirdparty.Helper(java.lang.String);
#                        void packagePrivate() throws java.io.IOException;
# Field:                 public static final java.lang.String VERSION;
#                        int packagePrivateField;
# Class header:          public class com.thirdparty.Helper {
_JAVAP_HEADER_RE = re.compile(
    r"^\s*(?:public\s+|protected\s+|abstract\s+|final\s+|static\s+)*"
    r"(?:class|interface|enum)\s+(?P<fqcn>[\w.$]+)",
)

# Modifiers are OPTIONAL (``*``, not ``+``) and include ``private``.
#
# A package-private member carries no access modifier at all — javap
# prints ``void foo();`` — so requiring at least one modifier dropped
# every one of them. ``private`` is accepted so the parser is correct
# for any javap access level, including ``-p``, even though the
# extraction runs at ``-package`` and never emits private members.
_JAVAP_MODIFIER = (
    r"(?:public|protected|private|static|final|abstract|synchronized"
    r"|native|strictfp|default|volatile|transient)"
)
_JAVAP_METHOD_RE = re.compile(
    rf"""
    ^\s*
    (?P<modifiers>(?:{_JAVAP_MODIFIER}\s+)*)
    (?:(?P<return>[\w.$<>\[\],\s?]+?)\s+)?     # optional return type (constructors omit it)
    (?P<name>[\w.$<>]+)                          # dots: javap prints constructors fully qualified
    \s*\((?P<args>[^)]*)\)
    (?:\s*throws\s+[\w.$,\s<>\[\]]+?)?         # optional throws clause
    \s*;\s*$
    """,
    re.VERBOSE,
)
_JAVAP_FIELD_RE = re.compile(
    rf"""
    ^\s*
    (?P<modifiers>(?:{_JAVAP_MODIFIER}\s+)*)
    (?P<type>[\w.$<>\[\],\s]+?)\s+
    (?P<name>[\w$]+)\s*;\s*$    # '$' is a legal identifier char: this$0,
    """,                        # val$x, $assertionsDisabled
    re.VERBOSE,
)


def javap_public_signatures(stdout: str) -> set[JavaSignature]:
    """Parse a ``javap -public`` stdout block into a frozen set of
    :class:`JavaSignature` records.

    Bounded by :data:`_JAVAP_MAX_SIGNATURES_PER_JAR`; an oversized
    output silently truncates at the cap (the diff is best-effort).
    """
    out: set[JavaSignature] = set()
    current_fqcn = "?"
    for line in stdout.splitlines():
        if len(out) >= _JAVAP_MAX_SIGNATURES_PER_JAR:
            break
        head = _JAVAP_HEADER_RE.match(line)
        if head:
            current_fqcn = head.group("fqcn")
            continue
        mm = _JAVAP_METHOD_RE.match(line)
        if mm:
            modifiers = frozenset(
                m.strip() for m in mm.group("modifiers").split() if m.strip()
            )
            name = mm.group("name")
            # javap prints a constructor fully qualified and with no
            # return type — ``public com.thirdparty.Helper(...)`` — so
            # match on the last segment and require the return group to
            # be absent. Comparing the whole printed name against the
            # class simple name never matched, which is why constructors
            # were dropped entirely rather than merely misclassified.
            simple_class = current_fqcn.rsplit(".", 1)[-1]
            is_constructor = (
                mm.group("return") is None
                and name.rsplit(".", 1)[-1] == simple_class
            )
            member_kind = "constructor" if is_constructor else "method"
            # Record a constructor under the simple name so its identity
            # does not carry the package twice (the FQCN is already the
            # first element of the identity tuple).
            if is_constructor:
                name = simple_class
            raw_return = mm.group("return")
            out.add(
                JavaSignature(
                    fqcn=current_fqcn,
                    member_kind=member_kind,
                    member_name=name,
                    descriptor=f"({mm.group('args').strip()})",
                    modifiers=modifiers,
                    # Constructors have none; a changed return type is a
                    # binary incompatibility the diff must see.
                    return_type=(
                        None if is_constructor or raw_return is None
                        else raw_return.strip()
                    ),
                )
            )
            continue
        fm = _JAVAP_FIELD_RE.match(line)
        if fm:
            modifiers = frozenset(
                m.strip() for m in fm.group("modifiers").split() if m.strip()
            )
            out.add(
                JavaSignature(
                    fqcn=current_fqcn,
                    member_kind="field",
                    member_name=fm.group("name"),
                    descriptor=fm.group("type").strip(),
                    modifiers=modifiers,
                )
            )
    return out


# ── Signature diff (FR-233) ─────────────────────────────────────────────────


@dataclass(frozen=True)
class AbiDiffResult:
    """Output of :func:`signature_diff` — three frozen sets describing
    the surface delta between a declared and resolved version of one
    coordinate."""

    added: frozenset[JavaSignature]
    removed: frozenset[JavaSignature]
    changed: frozenset[JavaSignature]


def _identity(sig: JavaSignature) -> tuple[str, str, str]:
    """Identity key for "is this the same member" matching: ignores
    descriptor + modifiers, so the sole overload of a method with a
    retyped parameter shows up as ``changed`` rather than as
    ``removed + added``.

    Identity is the FIRST of two matching levels — overloads share it,
    so it can never be the whole story. :func:`signature_diff` matches
    on ``descriptor`` WITHIN an identity (FR-272); collapsing an
    identity to one representative signature hides deleted overloads
    and makes the result depend on set-iteration order. See
    ``docs/SCARNO-BUG-signature-diff.md``.
    """
    return (sig.fqcn, sig.member_kind, sig.member_name)


def _signature_sort_key(
    sig: JavaSignature,
) -> tuple[str, str, str, str, tuple[str, ...], str]:
    """Total, hash-independent ordering over signatures — used to emit
    findings in a fixed order regardless of set-iteration order.

    Return type is the final component: covariant overrides share every
    other field, so without it two bridges would sort equal and fall back
    to set-iteration order.
    """
    return (
        sig.fqcn,
        sig.member_kind,
        sig.member_name,
        sig.descriptor,
        tuple(sorted(sig.modifiers)),
        sig.return_type or "",
    )


def _group_by_identity(
    signatures: set[JavaSignature],
) -> dict[tuple[str, str, str], dict[str, set[JavaSignature]]]:
    """``{identity: {descriptor: {signature, ...}}}``.

    The innermost value is a SET, not a single signature: within one
    identity a descriptor is unique in well-formed ``javap`` output
    (Java forbids two overloads sharing a parameter list), but a class
    header the parser failed to recognise can leave two members under
    the placeholder FQCN. Keeping the set means such a collision is
    handled by comparing everything, never by picking a winner.
    """
    grouped: dict[tuple[str, str, str], dict[str, set[JavaSignature]]] = {}
    for sig in signatures:
        grouped.setdefault(_identity(sig), {}).setdefault(
            sig.descriptor, set()
        ).add(sig)
    return grouped


def signature_diff(
    *,
    declared: set[JavaSignature],
    resolved: set[JavaSignature],
) -> AbiDiffResult:
    """Compute ADDED / REMOVED / CHANGED between two signature sets.

    Matching is identity-first, descriptor-second (FR-272). For an
    identity present on both sides, with ``gone`` the declared
    descriptors absent from the resolved side and ``new`` the resolved
    descriptors absent from the declared side:

    * the member is not overloaded on either side and its one
      descriptor differs — the FR-233 "retyped parameter" case:
      CHANGED, reported on the resolved side;
    * otherwise every ``gone`` descriptor is REMOVED (a symbol the JVM
      can no longer resolve — ``NoSuchMethodError`` — even when
      sibling overloads survive) and every ``new`` one is ADDED. Once
      a member IS overloaded, pairing a deletion with an unrelated
      addition is a guess; the deletion is a fact, and REMOVED is the
      bucket that names the descriptor the caller compiled against;
    * a descriptor on both sides whose modifiers shifted is CHANGED.

    The result is a pure function of the two input sets: no
    representative signature is selected anywhere, so the output does
    not vary with ``PYTHONHASHSEED`` (FR-273).
    """
    declared_by_id = _group_by_identity(declared)
    resolved_by_id = _group_by_identity(resolved)
    declared_ids = set(declared_by_id)
    resolved_ids = set(resolved_by_id)

    added: set[JavaSignature] = set()
    removed: set[JavaSignature] = set()
    changed: set[JavaSignature] = set()

    for i in resolved_ids - declared_ids:
        for sigs in resolved_by_id[i].values():
            added |= sigs
    for i in declared_ids - resolved_ids:
        for sigs in declared_by_id[i].values():
            removed |= sigs

    for i in declared_ids & resolved_ids:
        d_map = declared_by_id[i]
        r_map = resolved_by_id[i]
        gone = set(d_map) - set(r_map)
        new = set(r_map) - set(d_map)
        if len(d_map) == 1 and len(r_map) == 1 and gone and new:
            # The member is NOT overloaded on either side and its one
            # descriptor differs: the FR-233 retyped-parameter case.
            # Report the resolved side — that's what's on the
            # classpath today.
            changed |= r_map[next(iter(new))]
        else:
            for desc in gone:
                removed |= d_map[desc]
            for desc in new:
                added |= r_map[desc]
        for desc in set(d_map) & set(r_map):
            # Compare modifiers AND return type. The return type is not
            # part of the descriptor on purpose — folding it in would
            # split covariant overrides, and javap emits the synthetic
            # bridge beside the real method — but it IS part of what the
            # JVM resolves, so a change to it must surface. Comparing
            # sets means a bridge pair present on both sides matches,
            # while a genuine retype does not.
            d_shape = {(s.modifiers, s.return_type) for s in d_map[desc]}
            r_shape = {(s.modifiers, s.return_type) for s in r_map[desc]}
            if d_shape != r_shape:
                changed |= r_map[desc]

    return AbiDiffResult(
        added=frozenset(added),
        removed=frozenset(removed),
        changed=frozenset(changed),
    )


# ── JAR class enumeration (issue #2) ────────────────────────────────────────

# javap is handed this many class names per invocation. Batching matters
# because javap pays JVM startup per process; a batch also keeps a single
# argv from growing without bound on a large archive.
_JAVAP_CLASS_BATCH = 200
# Ceiling on classes inspected per JAR. Reached only by very large
# archives; when it bites the shortfall is REPORTED, never silent — a
# quiet truncation here would reintroduce exactly the class of false
# negative this enumeration exists to remove.
_MAX_CLASSES_PER_JAR = 4_000


def jar_class_names(jar_path: Path) -> list[str]:
    """Return the fully-qualified class names declared in ``jar_path``.

    Replaces guessing a single ``<group>.<Artifact>`` probe, which named
    a class that does not exist for most real coordinates, so ``javap``
    failed and the whole diff was skipped.

    Package-private and nested classes are INCLUDED. A consumer can
    declare its own class in the same package and reference a
    package-private type, so its removal is a ``NoClassDefFoundError``;
    and a public nested type such as ``Map.Entry`` is squarely part of
    the API. Neither is distinguishable from a class file's name, which
    is why the filter below is by role rather than by access.

    ``module-info`` / ``package-info`` are descriptors, not types. The
    ``META-INF/versions/N/`` prefixes of a multi-release JAR are skipped
    because the base-version class is already listed.

    Ordering is sorted so a run is reproducible.
    """
    try:
        entries = safe_jar_entries(jar_path)
    except (ValueError, OSError):
        return []
    names: set[str] = set()
    for entry in entries:
        if entry.startswith("META-INF/"):
            continue
        if not entry.endswith(".class"):
            continue
        stem = entry[: -len(".class")]
        tail = stem.rsplit("/", 1)[-1]
        if tail in ("module-info", "package-info"):
            continue
        names.add(stem.replace("/", "."))
    return sorted(names)


# ── Deterministic finding sort (R-Phase9-01) ────────────────────────────────


_SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
}


def _finding_sort_key(
    f: Finding,
) -> tuple[int, str, str, str, int, str, str, str, str]:
    """Stable sort key — severity DESC, then identity-bearing fields ASC
    for byte-identical output across runs of the same fixture.

    Every ABI finding carries ``file_path=""`` and ``line=0``, so
    ``message`` does nearly all the discriminating here — which is why
    it must name the overload (FR-274). ``remediation`` and
    ``provenance`` follow as tiebreaks so the key stays total for two
    findings that differ only in those.
    """
    return (
        _SEVERITY_ORDER.get(f.severity, 99),
        f.kind.value,
        f.package_hint or "",
        f.file_path,
        f.line,
        f.rule_id,
        f.message,
        f.remediation,
        f.provenance,
    )


# ── CrossVersionAbiDiffer ───────────────────────────────────────────────────


# Callable signature: (jar_path: Path, class_name: str) -> str | None.
# Returns javap stdout on success, None on timeout / parse error /
# binary missing. Caller must NEVER receive an exception from this.
# Accepts one class name or a batch of them. javap pays JVM startup per
# process, so enumerating a JAR's classes one process at a time is not
# affordable; the batch form is what the differ uses.
JavapCallable = Callable[[Path, "str | Sequence[str]"], str | None]


class CrossVersionAbiDiffer:
    """REQ-22 deep-inspection orchestrator.

    Construct ONLY when ``JvmSourceAnalyser(deep_inspection=True)``.
    The constructor REQUIRES ``invoke_javap`` (no default) so the
    hardened ``JvmSourceAnalyser._invoke_javap_safe`` MUST be wired
    in by the caller (NEW-ARCH-011).
    """

    def __init__(
        self,
        *,
        m2_root: Path,
        invoke_javap: JavapCallable,
        find_jar: Callable[[str, str], Path | None] | None = None,
    ) -> None:
        self._m2_root = Path(m2_root)
        self._invoke_javap = invoke_javap
        # REQ-24 — optional injection point. When supplied, jar lookup
        # consults the injected finder FIRST (typically the
        # quarantined cache populated by RemoteArtifactFetcher); falls
        # back to ``_m2_jar_path`` on miss. The orchestrator
        # (JavaAnalyser) wires this in only when --allow-remote-fetch
        # is set; otherwise pre-REQ-24 behaviour is preserved exactly.
        # When ``find_jar`` returns a path, that JAR is treated as
        # ``provenance="remote"`` for any finding it contributes to
        # (FR-265 / N-10 conservative tagging).
        self._find_jar = find_jar
        self._inspected_jar_count = 0
        self._cap_lock = threading.Lock()
        self._findings_lock = threading.Lock()

    # ── jar resolution: REQ-24 finder + m2 fallback ─────────────────────────

    def _resolve_jar(
        self, coordinate: str, version: str
    ) -> tuple[Path | None, str]:
        """Locate a JAR for ``coordinate@version`` and return
        ``(path, provenance)`` where ``provenance`` is ``"remote"`` for
        a JAR sourced via the REQ-24 injected finder, or ``"local"``
        for an m2-cache hit (or any miss).

        Order (H4 — cache-first):
          1. :meth:`_m2_jar_path` — provenance ``"local"`` on hit.
             m2 is the operator's pre-trusted cache; trying it first
             avoids spurious network calls for artefacts already
             resident.
          2. ``self._find_jar`` (REQ-24 quarantined cache / fetcher) if
             configured — provenance ``"remote"`` on hit.

        Earlier ordering (find_jar first) made sense when find_jar was
        a pre-populated dict — Option 2 made find_jar lazy, and a
        lazy find_jar that triggers a network fetch even when m2
        already has the artefact is wasteful.
        """
        local = self._m2_jar_path(coordinate, version)
        if local is not None and local.exists():
            return local, "local"
        if self._find_jar is not None:
            try:
                fetched = self._find_jar(coordinate, version)
            except Exception:  # pragma: no cover — defensive
                fetched = None
            if fetched is not None and fetched.exists():
                return fetched, "remote"
        # Both missed; return the (non-existent) local path so callers
        # can surface the standard "not cached in m2" audit line.
        return local, "local"

    # ── m2 cache lookup (SUC-51 / SEC-NEW-44) ───────────────────────────────

    def _m2_jar_path(
        self, coordinate: str, version: str
    ) -> Path | None:
        """Resolve ``group:artifact + version`` to a JAR path under
        the m2 root. Returns ``None`` when the coordinate is malformed
        (``_validate_gav`` rejects it) OR the resolved path would
        escape ``m2_root``.
        """
        parts = coordinate.split(":")
        if len(parts) != 2:
            return None
        group_id, artifact_id = parts
        if not _validate_gav((group_id, artifact_id, version)):
            return None
        candidate = (
            self._m2_root
            / group_id.replace(".", os.sep)
            / artifact_id
            / version
            / f"{artifact_id}-{version}.jar"
        )
        try:
            confined = resolve_and_confine(candidate, self._m2_root)
        except PathEscapeError:
            return None
        return confined

    # ── Cap counter (NEW-ARCH-010 / PERF-017) ───────────────────────────────

    def _try_consume_cap_slots(self, n: int) -> bool:
        """Atomically try to claim ``n`` cap slots. Returns True iff
        the claim succeeded (the cap had >= n slots free); False
        otherwise. NEVER mutates the counter outside the lock."""
        with self._cap_lock:
            if self._inspected_jar_count + n > _JAVAP_MAX_JARS_PER_RUN:
                return False
            self._inspected_jar_count += n
            return True

    # ── diff_all (FR-234 + R-Phase9-01) ─────────────────────────────────────

    def diff_all(
        self,
        result: AnalysisResult,
        source_symbols: dict[str, set[str]],
    ) -> list[Finding]:
        """Diff every multi-version coordinate in ``result`` against its
        resolved version. Returns a deterministically-sorted list of
        Findings (``ABI_RUNTIME_RISK`` for source-referenced symbols,
        ``ABI_DRIFT`` for the rest).

        ``source_symbols`` is ``{coordinate: {FQCN.member, ...}}`` — the
        set of symbols the project's source code references for each
        coordinate. The JVM source analyser already collects this via
        ``usage_count`` machinery; pass that map in.
        """
        # Build work items: one per (coord, declared_version) pair
        # whose declared_version differs from the resolved version.
        nodes_by_coord: dict[str, list[VersionedNode]] = {}
        for n in (result.versioned_nodes or []):
            nodes_by_coord.setdefault(n.canonical, []).append(n)

        work_items: list[tuple[str, str, str]] = []  # (coord, declared, resolved)
        for coord, nodes in nodes_by_coord.items():
            if coord not in (result.multi_version_coords or []):
                continue
            resolved_version: str | None = None
            for n in nodes:
                if n.is_resolved:
                    resolved_version = n.declared_version
                    break
            if resolved_version is None:
                continue
            for n in nodes:
                if n.declared_version == resolved_version:
                    continue
                if n.declared_version is None:
                    continue
                work_items.append((coord, n.declared_version, resolved_version))

        findings: list[Finding] = []
        # Issue #3 — a library split moves classes between artefacts. The
        # differ compares ONE coordinate across two versions, so a
        # relocated class reads as removed even though it is still on the
        # classpath via a sibling artefact. Index which classes the
        # RESOLVED graph provides, so a removal is judged against the whole
        # classpath rather than against one coordinate.
        provider_index = self._build_class_provider_index(result)

        def _process_one(item: tuple[str, str, str]) -> None:
            coord, declared_version, resolved_version = item
            # Cap check: each work item costs 2 slots (declared + resolved).
            if not self._try_consume_cap_slots(2):
                with self._findings_lock:
                    result.errors.append(
                        f"abi-diff: per-run jar cap "
                        f"({_JAVAP_MAX_JARS_PER_RUN}) reached; "
                        f"skipping {coord}@{declared_version} vs "
                        f"{resolved_version}."
                    )
                return
            declared_jar, declared_provenance = self._resolve_jar(
                coord, declared_version
            )
            resolved_jar, resolved_provenance = self._resolve_jar(
                coord, resolved_version
            )
            if declared_jar is None or not declared_jar.exists():
                with self._findings_lock:
                    result.errors.append(
                        f"abi-diff: declared version "
                        f"{sanitise(coord)}@{sanitise(declared_version)} "
                        f"not cached in m2; skipping diff."
                    )
                return
            if resolved_jar is None or not resolved_jar.exists():
                with self._findings_lock:
                    result.errors.append(
                        f"abi-diff: resolved version "
                        f"{sanitise(coord)}@{sanitise(resolved_version)} "
                        f"not cached in m2; skipping diff."
                    )
                return
            # FR-265 / N-10 — conservative tagging: if EITHER side of
            # the comparison was sourced via the REQ-24 finder
            # (quarantined cache), every finding from this comparison
            # is provenance="remote".
            comparison_provenance = (
                "remote"
                if "remote" in (declared_provenance, resolved_provenance)
                else "local"
            )
            # Inspect the classes the JARs actually declare. The old
            # ``<group>.<Artifact>`` probe was a guess that named no
            # real class for most coordinates, so javap failed and the
            # diff was skipped entirely (issue #2).
            declared_classes = jar_class_names(declared_jar)
            resolved_classes = jar_class_names(resolved_jar)
            if not declared_classes and not resolved_classes:
                with self._findings_lock:
                    result.errors.append(
                        f"abi-diff: no classes listed in either JAR for "
                        f"{sanitise(coord)}; skipping."
                    )
                return
            for label, names in (
                ("declared", declared_classes), ("resolved", resolved_classes),
            ):
                if len(names) > _MAX_CLASSES_PER_JAR:
                    with self._findings_lock:
                        result.errors.append(
                            f"abi-diff: {sanitise(coord)} {label} JAR "
                            f"declares {len(names)} classes; inspecting the "
                            f"first {_MAX_CLASSES_PER_JAR}. Removals in the "
                            f"remainder are NOT reported."
                        )
            declared_sigs = self._signatures_for(
                declared_jar, declared_classes[:_MAX_CLASSES_PER_JAR],
            )
            resolved_sigs = self._signatures_for(
                resolved_jar, resolved_classes[:_MAX_CLASSES_PER_JAR],
            )
            if not declared_sigs and not resolved_sigs:
                with self._findings_lock:
                    result.errors.append(
                        f"abi-diff: javap returned no output for "
                        f"{sanitise(coord)}; skipping."
                    )
                return
            diff = signature_diff(
                declared=declared_sigs, resolved=resolved_sigs,
            )
            produced = self._emit_findings(
                coord=coord,
                declared_version=declared_version,
                resolved_version=resolved_version,
                diff=diff,
                source_symbols=source_symbols.get(coord, set()),
                provenance=comparison_provenance,
                provider_index=provider_index,
            )
            with self._findings_lock:
                findings.extend(produced)

        with ThreadPoolExecutor(
            max_workers=_compute_max_workers()
        ) as pool:
            list(pool.map(_process_one, work_items))

        # R-Phase9-01 — deterministic sort before returning.
        findings.sort(key=_finding_sort_key)
        return findings

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _build_class_provider_index(
        self, result: AnalysisResult
    ) -> dict[str, str]:
        """``{FQCN: coordinate}`` over the RESOLVED version of every dep.

        When a library is split for modularity its classes move between
        artefacts. Diffing one coordinate across two versions then shows
        every relocated class as removed, and ``TS-ABI-RUNTIME-RISK``
        claims a NoSuchMethodError that cannot happen — the class is
        still on the classpath, just shipped by a sibling artefact.

        Only class-level presence is indexed. Listing an archive needs no
        ``javap``, so this is cheap; and it is deliberately treated as
        necessary-but-not-sufficient by the caller, because a class can
        move AND lose the member.

        Only resolved versions belong here: the declared side is what is
        being diffed against.
        """
        index: dict[str, str] = {}
        for node in (result.versioned_nodes or []):
            if not node.is_resolved or not node.declared_version:
                continue
            jar_path, _ = self._resolve_jar(
                node.canonical, node.declared_version
            )
            if jar_path is None or not jar_path.exists():
                continue
            for fqcn in jar_class_names(jar_path):
                # First writer wins: a class provided by two artefacts is
                # already ambiguous, and naming either is enough to show
                # the symbol has not left the classpath.
                index.setdefault(fqcn, node.canonical)
        return index

    def _signatures_for(
        self, jar_path: Path, class_names: list[str]
    ) -> set[JavaSignature]:
        """Parse the ABI surface of ``class_names`` out of ``jar_path``.

        javap is invoked in batches because it pays JVM startup per
        process; one process per class would make enumeration
        unaffordable on any real archive. A batch that fails — a class
        javap cannot read, say — costs only that batch, so one bad entry
        does not discard the whole JAR.
        """
        out: set[JavaSignature] = set()
        for start in range(0, len(class_names), _JAVAP_CLASS_BATCH):
            batch = class_names[start:start + _JAVAP_CLASS_BATCH]
            stdout = self._invoke_javap(jar_path, batch)
            if stdout is None:
                continue
            out |= javap_public_signatures(stdout)
        return out

    def _class_name_from_coord(self, coordinate: str) -> str:
        """Construct a probe FQCN for javap. We don't know which class
        in the JAR is "the" entry point; the injected javap helper
        accepts the artifact name and inspects every public symbol it
        finds. Convention: ``<group>.<Artifact>``."""
        parts = coordinate.split(":")
        if len(parts) != 2:
            return coordinate
        group_id, artifact_id = parts
        simple = "".join(
            piece[:1].upper() + piece[1:]
            for piece in artifact_id.replace("-", "_").split("_")
        )
        return f"{group_id}.{simple}"

    def _emit_findings(
        self,
        *,
        coord: str,
        declared_version: str,
        resolved_version: str,
        diff: AbiDiffResult,
        source_symbols: set[str],
        provenance: str = "local",
        provider_index: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Convert an :class:`AbiDiffResult` into Finding objects. For
        each REMOVED / CHANGED symbol that intersects ``source_symbols``
        emit ABI_RUNTIME_RISK (HIGH); for everything else emit
        ABI_DRIFT (MEDIUM).

        ``provenance`` (REQ-24 / FR-265) is set on every emitted
        :class:`Finding`. Callers pass ``"remote"`` when either side of
        the underlying comparison was sourced from the REQ-24
        quarantined cache.

        Messages name the OVERLOAD, not just the member (FR-274):
        ``signature_diff`` reports per-descriptor, so two overloads of
        one member reach this method together and a descriptor-less
        message would render them as two identical lines that
        :func:`_finding_sort_key` cannot order.
        """
        out: list[Finding] = []
        risk_classes = [
            *(("REMOVED", s) for s in sorted(diff.removed, key=_signature_sort_key)),
            *(("CHANGED", s) for s in sorted(diff.changed, key=_signature_sort_key)),
            *(("ADDED", s) for s in sorted(diff.added, key=_signature_sort_key)),
        ]
        providers = provider_index or {}
        for action, sig in risk_classes:
            # Issue #3 — a class absent from the resolved JAR but still
            # provided by another resolved artefact has been RELOCATED by
            # a library split, not removed. Claiming NoSuchMethodError for
            # it is a false positive, so it is reported as drift naming
            # where the class went.
            #
            # Class-level presence is necessary, not sufficient: the class
            # may have moved and dropped the member. So this downgrades
            # the finding rather than dropping it, and says so.
            relocated_to = (
                providers.get(sig.fqcn) if action == "REMOVED" else None
            )
            if relocated_to is not None and relocated_to == coord:
                # Same coordinate provides it — not a relocation.
                relocated_to = None
            symbol_id = f"{sig.fqcn}.{sig.member_name}"
            # Fields carry a type descriptor, members a parameter list.
            # A method's return type is prefixed when known: a change to
            # it alone is a binary incompatibility, and without it the
            # message would name text identical to the declared side and
            # read as though nothing had changed.
            if sig.member_kind == "field":
                symbol_display = f"{sig.descriptor} {symbol_id}"
            elif sig.return_type:
                symbol_display = (
                    f"{sig.return_type} {symbol_id}{sig.descriptor}"
                )
            else:
                symbol_display = f"{symbol_id}{sig.descriptor}"
            is_called = any(
                symbol_id == ref or ref.endswith("." + sig.member_name)
                for ref in source_symbols
            )
            if relocated_to is not None:
                out.append(
                    Finding(
                        rule_id="TS-ABI-DRIFT",
                        kind=FindingKind.ABI_DRIFT,
                        severity=FindingSeverity.MEDIUM,
                        file_path="",
                        line=0,
                        snippet="",
                        message=(
                            f"{sanitise(symbol_display)} is no longer in "
                            f"{sanitise(coord)} at resolved "
                            f"{sanitise(resolved_version)}, but "
                            f"{sanitise(sig.fqcn)} is still provided by "
                            f"{sanitise(relocated_to)} — the class moved "
                            f"between artefacts rather than being removed."
                        ),
                        remediation=(
                            "Usually a library split; the symbol is still "
                            "on the classpath. Confirm the member itself "
                            "still exists at the new location — a class "
                            "can move AND lose a member."
                        ),
                        package_hint=sanitise(coord),
                        provenance=provenance,
                    )
                )
            elif action == "REMOVED" and is_called:
                out.append(
                    Finding(
                        rule_id="TS-ABI-RUNTIME-RISK",
                        kind=FindingKind.ABI_RUNTIME_RISK,
                        severity=FindingSeverity.HIGH,
                        file_path="",
                        line=0,
                        snippet="",
                        message=(
                            f"{sanitise(symbol_display)} called by your "
                            f"source, exists in declared "
                            f"{sanitise(declared_version)} but "
                            f"REMOVED in resolved "
                            f"{sanitise(resolved_version)}."
                        ),
                        remediation=(
                            "Pin the dep to the declared version or "
                            "update call sites to the resolved-version "
                            "surface."
                        ),
                        package_hint=sanitise(coord),
                        provenance=provenance,
                    )
                )
            elif action == "CHANGED" and is_called:
                out.append(
                    Finding(
                        rule_id="TS-ABI-RUNTIME-RISK",
                        kind=FindingKind.ABI_RUNTIME_RISK,
                        severity=FindingSeverity.HIGH,
                        file_path="",
                        line=0,
                        snippet="",
                        message=(
                            f"{sanitise(symbol_display)} called by your "
                            f"source; signature CHANGED between declared "
                            f"{sanitise(declared_version)} and resolved "
                            f"{sanitise(resolved_version)}."
                        ),
                        remediation=(
                            "Confirm your call sites are compatible with "
                            "the resolved-version signature."
                        ),
                        package_hint=sanitise(coord),
                        provenance=provenance,
                    )
                )
            else:
                out.append(
                    Finding(
                        rule_id="TS-ABI-DRIFT",
                        kind=FindingKind.ABI_DRIFT,
                        severity=FindingSeverity.MEDIUM,
                        file_path="",
                        line=0,
                        snippet="",
                        message=(
                            f"{sanitise(symbol_display)} {action} between "
                            f"declared {sanitise(declared_version)} and "
                            f"resolved {sanitise(resolved_version)}."
                        ),
                        remediation=(
                            "Review the listed symbols; not currently "
                            "called by your source."
                        ),
                        package_hint=sanitise(coord),
                        provenance=provenance,
                    )
                )
        return out
