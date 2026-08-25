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

"""Shared security primitives for Scarno.

All security-critical behaviour lives here so it can be unit-tested in
one place and reused by every analyser, reporter, and the CLI. Nothing
in this module imports from other Scarno modules — it must stay at
the bottom of the dependency graph.
"""
from __future__ import annotations

import os
import re
import subprocess  # noqa: S404 — wrapped via safe_subprocess_run primitive
import sys
import zipfile
from pathlib import Path

# Resource ceilings (ARCH-PERF-001, SEC-NEW-02, SEC-NEW-04).
MAX_FILE_BYTES: int = 10 * 1024 * 1024
MAX_DEP_NAME_LEN: int = 256
MAX_JAR_ENTRIES: int = 10_000
MAX_JAR_ENTRY_BYTES: int = 50 * 1024 * 1024

# REQ-19 — Phase 9 lockfile + edge caps (SEC-NEW-37) and version-string
# sanitisation cap (SEC-NEW-38). Lockfile-byte cap is tighter than the
# generic MAX_FILE_BYTES so adversarial lockfiles are rejected early
# with a clear error rather than silently scraping into the JSON parser.
LOCKFILE_MAX_BYTES: int = 8 * 1024 * 1024
LOCKFILE_MAX_EDGES: int = 50_000
DECLARED_VERSION_MAX_LEN: int = 64


class PathEscapeError(ValueError):
    """A path resolved to a location outside its confinement root (SEC-002)."""


class FileTooLargeError(ValueError):
    """A file exceeded ``MAX_FILE_BYTES`` (SEC-NEW-04)."""


class BinaryNotConfinedError(ValueError):
    """A subprocess binary path resolved outside its declared ``binary_root``
    tree (NEW-ARCH-013 / FR-255). Mirrors the SEC-NEW-12 / SEC-NEW-28
    semantics for individual binaries (``javap`` / ``mvn``); the generic
    primitive ``safe_subprocess_run`` raises this when ``binary_root`` is
    supplied and ``argv[0]`` would resolve outside it.
    """


# REQ-24 / ARCH-SEC-005 — audit tag emitted when ``$XDG_CONFIG_HOME``
# resolves into the analysed project tree (or CWD) and the helper
# falls back to ``~/.config``. Stable string so callers can recognise
# the event in audit lines without parsing free-form prose.
USER_CONFIG_REJECTED_XDG: str = "USER_CONFIG_REJECTED_XDG"


# ── ANSI / control-char sanitisation ─────────────────────────────────────────
#
# Matches the four kinds of terminal escape sequences that commonly show up
# in package metadata:
#
#   * ESC + a single final byte (``\x1b@``..``\x1b_``)
#   * CSI — ``\x1b[`` + params + final byte
#   * OSC — ``\x1b]`` + payload + ``\x07`` (BEL) or ``\x1b\`` (ST)
#   * DCS / SOS / PM / APC — ``\x1bP|X|^|_`` + payload + ST
#
# Tests (test_security.py::TestStripAnsi) cover CSI, full-screen clear, and
# OSC 8 hyperlinks.
# Alternatives are ordered so longer/structured sequences match before
# single-byte escapes — a naive single-char ``\x1b]`` would otherwise
# swallow the opener of an OSC sequence and leave the payload (e.g.
# ``https://evil.com``) visible in the output.
_ANSI_RE = re.compile(
    r"\x1b"
    r"(?:"
    r"\][^\x07\x1b]*(?:\x07|\x1b\\)"       # OSC — terminated by BEL or ST
    r"|[PX^_][^\x07\x1b]*(?:\x07|\x1b\\)"  # DCS / SOS / PM / APC
    r"|\[[0-?]*[ -/]*[@-~]"                # CSI
    r"|[@-Z\\_]"                           # single-byte C1 (7-bit)
    r")"
)

# C0 controls (0x00..0x1F) + DEL (0x7F), except TAB (0x09) and LF (0x0A)
# which are legitimate in reason strings (SEC-NEW-03).
_CONTROL_CHARS = "".join(
    chr(c) for c in range(0, 32) if c not in (0x09, 0x0A)
) + chr(0x7F)
_CONTROL_TRANSLATE = str.maketrans("", "", _CONTROL_CHARS)


def strip_ansi(text: str) -> str:
    """Remove ANSI / OSC escape sequences from ``text`` (SEC-003)."""
    return _ANSI_RE.sub("", text)


def strip_control_chars(text: str) -> str:
    """Remove C0/C1 control bytes except TAB and LF (SEC-NEW-03)."""
    return text.translate(_CONTROL_TRANSLATE)


def sanitise(text: str) -> str:
    """Apply both escape and control-char stripping.

    The canonical sanitiser for any user-derived string bound for a
    terminal or structured output.
    """
    return strip_control_chars(strip_ansi(text))


# ── REQ-19a — generic subprocess primitive (NEW-ARCH-013 / FR-255) ──────────
#
# Per ADR-013: per-binary helpers (_invoke_mvn_safe / _invoke_gradle_safe /
# legacy _invoke_javap_safe) compose this primitive with binary-specific
# resolution and argv allowlists. The primitive enforces only the
# universal contract:
#   * shell=False
#   * mandatory positive timeout
#   * optional binary-root confinement (mirrors resolve_and_confine)
#
# It is the ONLY sanctioned subprocess call site in the codebase apart
# from the legacy _invoke_javap_safe helper (deferred-refactor per
# ADR-013). An AST-scan test (SEC-NEW-58) rejects new direct
# subprocess.run / Popen / os.exec* / os.spawn* / os.popen calls.


def safe_subprocess_run(
    argv: list[str],
    *,
    timeout_s: float,
    binary_root: Path | str | None = None,
    cwd: Path | str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with Scarno's mandatory hardening.

    Always uses ``shell=False``, ``check=False``, ``capture_output=True``,
    ``text=True``. ``timeout_s`` is required and must be > 0. When
    ``binary_root`` is supplied, the resolved ``argv[0]`` MUST sit
    inside that tree or :class:`BinaryNotConfinedError` is raised
    BEFORE spawning.

    ``cwd`` is the child's working directory; ``None`` (the default)
    inherits Scarno's own. Any caller spawning a tool that reads
    launcher / project configuration from its working directory (build
    tools such as ``mvn`` or ``gradle``) MUST pass an explicit neutral
    directory — the analysed tree is attacker-controlled input, and
    inheriting it turns repo content (``.mvn/jvm.config``,
    ``.mvn/extensions.xml``, ``pom.xml`` extensions) into executed code.

    Returns the :class:`subprocess.CompletedProcess`. Callers are
    responsible for inspecting returncode / stdout / stderr and
    recording sanitised errors.
    """
    if not argv:
        raise ValueError("safe_subprocess_run: argv must be non-empty")
    if timeout_s <= 0:
        raise ValueError("safe_subprocess_run: timeout_s must be > 0")
    if binary_root is not None:
        try:
            binary_path = Path(argv[0]).resolve()
            root_path = Path(binary_root).resolve()
            binary_path.relative_to(root_path)
        except ValueError as exc:
            raise BinaryNotConfinedError(
                f"Binary {argv[0]!s} resolves outside declared root "
                f"{binary_root!s}"
            ) from exc
    return subprocess.run(  # noqa: S603 — shell=False + caller-validated argv
        argv,
        capture_output=True,
        timeout=timeout_s,
        shell=False,
        check=False,
        text=True,
        cwd=cwd,
    )


# ── REQ-19 declared-version sanitisation (SEC-NEW-38 + SEC-NEW-54) ──────────
#
# Mermaid-active tokens stripped here even though the live render path is
# the ASCII tree (REQ-17). The Mermaid helpers in markdown_reporter.py are
# retained as defence-in-depth — versions must remain Mermaid-safe in case
# any future renderer wires them back in.
#
# Per-destination characters (``|`` for Markdown tables, backtick for
# inline code) added per Phase-3 T-Phase9-03 / SEC-NEW-54 so the same
# sanitised string can flow into Markdown / JSON / SARIF without further
# escaping.
_VERSION_STRIP_CHARS: frozenset[str] = frozenset(
    {"]", "[", '"', "\\", "|", "`", "\n", "\r", "\t"}
)
_VERSION_STRIP_TRANSLATE = str.maketrans(
    "", "", "".join(sorted(_VERSION_STRIP_CHARS))
)
# Mermaid keyword tokens that must never reach a label, even if a future
# renderer wires the Mermaid path back in. Stripping these losslessly
# turns adversarial directives into inert text. Trade-off: legitimate
# versions containing these substrings (e.g. ``1.0-clickhouse-driver``)
# lose the substring; treated as acceptable defence-in-depth per
# REQ-19 §SUC-40.
_VERSION_RESERVED_WORDS: tuple[str, ...] = (
    "click",
    "subgraph",
    "classDef",
    "linkStyle",
)


def sanitise_declared_version(value: str | None) -> str | None:
    """Bound a declared-version string and strip dangerous characters.

    Returns ``None`` when input is ``None`` or sanitises to empty.

    Mitigates SEC-NEW-38 (Mermaid + control-char injection) and the
    SEC-NEW-54 extension (per-destination escape coverage for Markdown
    tables, inline code, and JSON encoding).
    """
    if value is None:
        return None
    text = sanitise(value)  # strip ANSI + C0/C1 controls
    text = text.translate(_VERSION_STRIP_TRANSLATE)
    for word in _VERSION_RESERVED_WORDS:
        text = text.replace(word, "")
    text = text[:DECLARED_VERSION_MAX_LEN]
    return text or None


# ── Report-token sanitisation ───────────────────────────────────────────────
#
# For a short, user-derived token that a diagnostic message echoes back so
# the operator can tell which input caused it (e.g. a Maven ``<module>``
# name). Deliberately narrower than the two neighbouring helpers:
#
#   * NOT ``sanitise`` — that one preserves LF by design (it is used for
#     multi-line reason strings), so a token containing a newline could
#     forge extra lines in the text / Markdown warning lists.
#   * NOT ``sanitise_declared_version`` — that one also applies
#     Mermaid-label policy (dropping the reserved words ``click``,
#     ``subgraph``, ``classDef``, ``linkStyle``) and the 64-character
#     declared-version cap. Applied to a token, that policy rewrites
#     legitimate input: a directory named ``clickhouse-connector`` would
#     be echoed as ``house-connector``, naming something that does not
#     exist.
#
# Removed here: ANSI/OSC escape sequences, C0 controls and DEL, the 8-bit
# C1 range U+0080..U+009F (notably U+0085 NEL, which ``str.splitlines``
# treats as a line break and which ``strip_control_chars`` does not
# cover), TAB / LF / CR, and the same Markdown-active characters the
# declared-version sanitiser strips. Nothing else is touched and no
# length cap is applied, so a legitimate token is echoed verbatim.
#
# Not covered: the Unicode separators U+2028 / U+2029, which no sanitiser
# in this module strips today.
_C1_CONTROL_TRANSLATE = str.maketrans(
    "", "", "".join(chr(c) for c in range(0x80, 0xA0))
)


def sanitise_token(value: str) -> str:
    """Sanitise a short user-derived token for echoing into a message.

    Strips escape sequences, C0/C1 control characters (including
    U+0085 NEL), TAB / LF / CR, and the Markdown-active characters
    listed in ``_VERSION_STRIP_CHARS``. Applies no keyword substitution
    and no length cap, so the sanitised token still names the input the
    operator supplied.
    """
    text = sanitise(value)
    text = text.translate(_C1_CONTROL_TRANSLATE)
    return text.translate(_VERSION_STRIP_TRANSLATE)


# ── Path confinement ─────────────────────────────────────────────────────────


def resolve_and_confine(path: str | Path, root: str | Path) -> Path:
    """Resolve ``path`` and confirm it resolves inside ``root``.

    ``Path.resolve()`` follows symlinks and normalises ``..`` components,
    so this check catches both direct traversal (``../../etc/passwd``)
    and symlink escape (a link whose target is outside root).

    Returns the resolved absolute path. Raises :class:`PathEscapeError`
    if the resolution escapes ``root`` (SEC-002, SEC-NEW-05).
    """
    resolved_root = Path(root).resolve()
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise PathEscapeError(
            f"Path {path!s} resolves to {resolved!s}, which is outside "
            f"the confinement root {resolved_root!s}"
        ) from exc
    return resolved


# ── REQ-24 / ARCH-SEC-005 — sole user-config locator ────────────────────────
#
# The keystone control for REQ-24's "config-file indexes can never come
# from inside the analysed repo" guarantee. ANY scarno component
# that loads a user-level config file MUST go through this helper —
# direct ``open()`` of a config path is forbidden (enforced by the
# TS-003-style static-analysis lint to land alongside the resolver).
#
# Anchoring rules (in priority order):
#   1. ``$XDG_CONFIG_HOME/scarno/<name>`` if the env var is set
#      AND the resolved path is NOT under ``Path.cwd()`` and NOT under
#      ``project_root`` (when supplied). Fail-safe: if XDG resolves
#      into either, fall back to ``~/.config`` and emit a
#      ``USER_CONFIG_REJECTED_XDG`` warning so the operator can tell.
#   2. ``Path.home() / ".config" / "scarno" / <name>``.
#
# CWD-relative discovery, walking up from the project path, or any
# other repo-anchored heuristic is deliberately absent. A repo that
# ships ``.config/scarno/config.toml`` cannot influence the
# resolver — that's the whole point of REQ-24's E1 mitigation.
#
# Returns ``(path | None, warnings)``:
#   * ``path`` — the resolved file if it exists; else ``None``.
#   * ``warnings`` — audit lines describing any fallback (e.g. XDG
#     rejection). Caller is expected to forward these into the
#     ``result.errors`` channel so they appear in the persistent
#     report (PUC-006/007), not just stderr.

_SCARNO_USER_CONFIG_DIR: str = "scarno"


def _is_descendant(candidate: Path, ancestor: Path) -> bool:
    """Return True iff ``candidate`` is ``ancestor`` or a child of it.

    Both are pre-resolved before comparison so symlinks can't dodge
    the check. ``Path.is_relative_to`` is the conceptual equivalent
    but only landed in 3.9 — we run on 3.12+ but we keep the explicit
    try/relative_to form to match the rest of the module's idiom.
    """
    try:
        candidate.relative_to(ancestor)
    except ValueError:
        return False
    return True


def resolve_user_config_path(
    name: str,
    *,
    project_root: Path | str | None = None,
) -> tuple[Path | None, list[str]]:
    """Resolve a scarno user-config file path safely.

    Parameters
    ----------
    name:
        File name within the scarno config directory
        (e.g. ``"config.toml"``). MUST be a single path component
        (no separators); a ``ValueError`` is raised otherwise so a
        future caller cannot accidentally inject a traversal.
    project_root:
        Path of the analysed project, when known. The XDG fallback
        check uses it to detect a malicious environment that points
        ``$XDG_CONFIG_HOME`` into the analysed tree. Optional —
        when omitted, only ``Path.cwd()`` is checked.

    Returns
    -------
    ``(path, warnings)`` where ``path`` is the resolved config file
    if it exists on disk, else ``None``; ``warnings`` is a list of
    sanitised audit lines describing any fallback.

    Raises
    ------
    ValueError
        If ``name`` contains a path separator or is empty.
    """
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError(
            f"resolve_user_config_path: invalid name {name!r} "
            "(must be a single path component)"
        )

    warnings: list[str] = []
    cwd = Path.cwd().resolve()
    project_resolved: Path | None = (
        Path(project_root).resolve() if project_root is not None else None
    )

    xdg = os.environ.get("XDG_CONFIG_HOME")
    chosen_root: Path | None = None
    if xdg:
        try:
            xdg_resolved = Path(xdg).expanduser().resolve()
        except (OSError, RuntimeError):
            xdg_resolved = None
            warnings.append(
                f"req24: $XDG_CONFIG_HOME ({sanitise(xdg)}) could not be "
                f"resolved; falling back to ~/.config"
            )
        if xdg_resolved is not None:
            inside_cwd = _is_descendant(xdg_resolved, cwd)
            inside_project = (
                project_resolved is not None
                and _is_descendant(xdg_resolved, project_resolved)
            )
            if inside_cwd or inside_project:
                target = (
                    sanitise(str(project_resolved))
                    if inside_project
                    else sanitise(str(cwd))
                )
                warnings.append(
                    f"req24: $XDG_CONFIG_HOME ({sanitise(str(xdg_resolved))}) "
                    f"resolves under {target}; falling back to ~/.config "
                    f"({USER_CONFIG_REJECTED_XDG})"
                )
            else:
                chosen_root = xdg_resolved

    if chosen_root is None:
        chosen_root = (Path.home() / ".config").resolve()

    candidate = chosen_root / _SCARNO_USER_CONFIG_DIR / name
    # Defence-in-depth: confine the candidate inside chosen_root so a
    # symlink at <root>/scarno/<name> cannot escape. The scarno
    # subdirectory itself is the natural confinement boundary; we
    # confine against the chosen_root which strictly contains it.
    try:
        confined = resolve_and_confine(candidate, chosen_root)
    except PathEscapeError as exc:
        warnings.append(
            f"req24: user-config candidate {sanitise(str(candidate))} "
            f"escaped its root: {sanitise(str(exc))}"
        )
        return None, warnings

    if not confined.exists():
        return None, warnings
    return confined, warnings


def check_file_size(path: str | Path) -> None:
    """Raise :class:`FileTooLargeError` if ``path`` exceeds ``MAX_FILE_BYTES``.

    Called before opening any file for analysis (SEC-NEW-04, D-04).
    """
    size = Path(path).stat().st_size
    if size > MAX_FILE_BYTES:
        raise FileTooLargeError(
            f"File {path!s} is {size} bytes (limit {MAX_FILE_BYTES})"
        )


# ── Privilege check ──────────────────────────────────────────────────────────


def check_root_privilege() -> None:
    """Emit a stderr warning when running as root / uid 0 (SEC-005, E-01).

    ``os.getuid`` is not present on Windows, so the check is a no-op
    there. The message is a fixed string so tests can assert exact
    substrings.
    """
    if hasattr(os, "getuid") and os.getuid() == 0:
        print(
            "Warning: running as root is not recommended. Scarno only "
            "needs read access to the project directory.",
            file=sys.stderr,
        )


# ── JAR entry enumeration with ZIP-bomb guards ───────────────────────────────


def safe_jar_entries(jar_path: str | Path) -> list[str]:
    """Return the list of ``*.class`` entries in a JAR, with ZIP-bomb guards.

    Rejects archives that exceed ``MAX_JAR_ENTRIES`` or declare any entry
    whose uncompressed size exceeds ``MAX_JAR_ENTRY_BYTES`` (SEC-NEW-02).
    """
    with zipfile.ZipFile(str(jar_path), "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_JAR_ENTRIES:
            raise ValueError(
                f"JAR {jar_path!s} has {len(infos)} entries "
                f"(limit {MAX_JAR_ENTRIES})"
            )
        class_entries: list[str] = []
        for info in infos:
            if info.file_size > MAX_JAR_ENTRY_BYTES:
                raise ValueError(
                    f"JAR entry {info.filename} declares uncompressed size "
                    f"{info.file_size} (limit {MAX_JAR_ENTRY_BYTES})"
                )
            if info.filename.endswith(".class"):
                class_entries.append(info.filename)
        return class_entries
