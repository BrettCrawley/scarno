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

"""REQ-24 / SEC-NEW-59 — coordinate validation for the remote-fetch path.

Coordinates parsed from the analysed repo's manifests are
**attacker-controlled**. URL templating and cache-path construction
must never see a raw ``str`` — they accept :class:`ValidatedCoordinate`
exclusively.

Structural non-bypassability is enforced by two layers (N-1):

1. **Runtime** — ``ValidatedCoordinate.__init__`` requires a
   module-private constructor token. Any caller that holds the token
   (only :meth:`CoordinateValidator.validate` does) can construct;
   anything else raises ``TypeError``.
2. **Static-analysis** — :func:`tests.security.test_req24_validated_coord`
   AST-scans ``src/`` and rejects any ``ValidatedCoordinate(...)``
   construction outside this module.

Per-ecosystem validators are registered via :func:`register`.
Ecosystems without a registered validator are **fail-closed**: their
coordinates are not fetchable.
"""
from __future__ import annotations

import re
from typing import Callable, Final


# ── Construction token ──────────────────────────────────────────────────────
#
# A module-private sentinel. Every legitimate construction site is in
# this module and holds the token. ``object()`` would suffice; using a
# named class makes the intent explicit in tracebacks.


class _ConstructorToken:
    """Sentinel — opaque and module-private."""
    __slots__ = ()


_TOKEN: Final[_ConstructorToken] = _ConstructorToken()


_MAX_COMPONENT_LEN: Final[int] = 256


# ── ValidatedCoordinate ─────────────────────────────────────────────────────


class ValidatedCoordinate:
    """Opaque proof-of-validation. Construct ONLY via
    :meth:`CoordinateValidator.validate` — direct instantiation raises
    :class:`TypeError`.

    Equality + hash are derived from ``(ecosystem, components)`` so
    instances can be deduplicated and used as dict keys. ``raw`` is
    retained for audit-line rendering but does NOT participate in
    equality.
    """

    __slots__ = ("ecosystem", "components", "raw")

    # Class-level annotations so static analysers (mypy / pyright) can
    # see the attributes — the values themselves are written via
    # ``object.__setattr__`` in ``__init__`` because the class is
    # frozen-by-construction (``__setattr__`` raises post-init).
    ecosystem: str
    components: tuple[str, ...]
    raw: str

    def __init__(
        self,
        *,
        ecosystem: str,
        components: tuple[str, ...],
        raw: str,
        _token: object,
    ) -> None:
        if _token is not _TOKEN:
            raise TypeError(
                "ValidatedCoordinate must be constructed via "
                "CoordinateValidator.validate(...); direct instantiation "
                "is forbidden (REQ-24 / SEC-NEW-59)."
            )
        # ``object.__setattr__`` so the class can stay non-frozen-dataclass-y
        # (we keep __slots__ for memory + introspection clarity instead).
        object.__setattr__(self, "ecosystem", ecosystem)
        object.__setattr__(self, "components", tuple(components))
        object.__setattr__(self, "raw", raw)

    def __setattr__(self, name: str, value: object) -> None:
        # Frozen-by-construction. The constructor uses
        # ``object.__setattr__`` to bypass this guard.
        raise AttributeError(
            f"ValidatedCoordinate is immutable; cannot set {name!r}"
        )

    def __repr__(self) -> str:
        return (
            f"ValidatedCoordinate(ecosystem={self.ecosystem!r}, "
            f"components={self.components!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidatedCoordinate):
            return NotImplemented
        return (
            self.ecosystem == other.ecosystem
            and self.components == other.components
        )

    def __hash__(self) -> int:
        return hash((self.ecosystem, self.components))


# ── Per-ecosystem registry ──────────────────────────────────────────────────


_ValidatorFn = Callable[[str], tuple[str, ...]]
_REGISTRY: dict[str, _ValidatorFn] = {}


class UnknownEcosystemError(ValueError):
    """Raised when :meth:`CoordinateValidator.validate` is called for an
    ecosystem with no registered validator. Fail-closed: ecosystems
    without a validator are not fetchable (SEC-NEW-59)."""


def register(ecosystem: str) -> Callable[[_ValidatorFn], _ValidatorFn]:
    """Decorator: register an ecosystem's coordinate validator."""

    def _wrap(fn: _ValidatorFn) -> _ValidatorFn:
        _REGISTRY[ecosystem] = fn
        return fn

    return _wrap


class CoordinateValidator:
    """Sole entry point for constructing :class:`ValidatedCoordinate`.

    Stateless; static methods only. The class exists for namespacing —
    it makes the call site read ``CoordinateValidator.validate(...)``
    which is greppable and self-explanatory.
    """

    @staticmethod
    def validate(ecosystem: str, raw: str) -> ValidatedCoordinate:
        """Validate ``raw`` against the registered validator for
        ``ecosystem``. Returns a :class:`ValidatedCoordinate` on
        success; raises ``ValueError`` (or :class:`UnknownEcosystemError`)
        on rejection."""
        validator = _REGISTRY.get(ecosystem)
        if validator is None:
            raise UnknownEcosystemError(
                f"No coordinate validator registered for ecosystem "
                f"{ecosystem!r} — fail-closed (SEC-NEW-59)."
            )
        components = validator(raw)
        return ValidatedCoordinate(
            ecosystem=ecosystem,
            components=components,
            raw=raw,
            _token=_TOKEN,
        )

    @staticmethod
    def registered_ecosystems() -> frozenset[str]:
        """Return the set of ecosystems with a registered validator."""
        return frozenset(_REGISTRY)


# ── Generic component-level validation ──────────────────────────────────────
#
# The forbidden-character class is deliberately broad: every ASCII
# character that has special meaning in a URL, filesystem path, or
# shell quoting context is rejected. Per-ecosystem validators may
# layer additional constraints (the Maven and npm validators below
# do).


_FORBIDDEN_CHAR = re.compile(
    # control bytes + DEL + 0x80-0xFF
    r"[\x00-\x20\x7f-\xff"
    # path / URL / shell metacharacters. ``@`` is included because a
    # coord component containing ``@`` could synthesise URL userinfo
    # when concatenated into the index URL (``https://repo/g@evil/...``
    # would parse with ``g`` as username and ``evil`` as host). The
    # npm scope prefix is the only legitimate use of ``@`` in any
    # supported coord format and is handled before reaching this gate
    # (``_validate_npm`` matches ``_NPM_SCOPE`` directly without
    # passing through ``_validate_basic``).
    r"/\\?#&=%+:()\[\]\"';<>{}|^`~$*@]"
)


def _reject_traversal(component: str) -> None:
    if ".." in component:
        raise ValueError(f"component {component!r} contains '..'")


def _reject_overlong(component: str) -> None:
    if len(component) > _MAX_COMPONENT_LEN:
        raise ValueError(
            f"component length {len(component)} exceeds cap {_MAX_COMPONENT_LEN}"
        )


def _reject_forbidden_chars(component: str) -> None:
    if _FORBIDDEN_CHAR.search(component):
        raise ValueError(
            f"component {component!r} contains a forbidden character"
        )


def _validate_basic(component: str) -> None:
    """Length + traversal + forbidden-char + non-empty. The per-eco
    validators add format-specific regexes on top."""
    if not component:
        raise ValueError("empty component")
    _reject_overlong(component)
    _reject_forbidden_chars(component)
    _reject_traversal(component)


# ── Maven ───────────────────────────────────────────────────────────────────
#
# Maven coords have the form ``groupId:artifactId``. ``groupId`` is a
# dot-separated package path; each segment must be a Java-identifier-shape
# string. ``artifactId`` is a single segment with the same shape but
# allows hyphens (Maven convention).

_MAVEN_GROUP_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_MAVEN_ARTIFACT = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")


@register("maven")
def _validate_maven(raw: str) -> tuple[str, ...]:
    """Maven coord ``groupId:artifactId`` → ``(group, artifact)``.

    Versions are not part of the coordinate; they are validated
    separately at fetch time via :func:`is_valid_fetch_version`.
    """
    parts = raw.split(":")
    if len(parts) != 2:
        raise ValueError(
            f"Maven coord must be 'groupId:artifactId'; got {raw!r}"
        )
    group, artifact = parts[0], parts[1]
    if not group:
        raise ValueError("Maven coord: empty groupId")
    if not artifact:
        raise ValueError("Maven coord: empty artifactId")
    # Group is dot-separated; per-segment validation rejects '..' AND
    # individual segment shape.
    _validate_basic(group)
    for segment in group.split("."):
        if not _MAVEN_GROUP_SEGMENT.match(segment):
            raise ValueError(
                f"Maven groupId segment {segment!r} not a valid identifier"
            )
    _validate_basic(artifact)
    if not _MAVEN_ARTIFACT.match(artifact):
        raise ValueError(
            f"Maven artifactId {artifact!r} not a valid identifier"
        )
    return (group, artifact)


# ── npm ─────────────────────────────────────────────────────────────────────
#
# npm package names are lowercase, may contain ``[a-z0-9._-]`` after
# the first char, and may be scoped with ``@scope/name``.

_NPM_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_NPM_SCOPE = re.compile(r"^@[a-z0-9][a-z0-9._-]*$")


@register("npm")
def _validate_npm(raw: str) -> tuple[str, ...]:
    """npm coord ``name`` or ``@scope/name`` → ``(name,)`` or
    ``(scope, name)``."""
    if not raw:
        raise ValueError("npm coord: empty")
    _reject_overlong(raw)
    if "/" in raw:
        scope, _, name = raw.partition("/")
        if not _NPM_SCOPE.match(scope):
            raise ValueError(f"npm scope {scope!r} invalid")
        if not _NPM_NAME.match(name):
            raise ValueError(f"npm name {name!r} invalid")
        return (scope, name)
    if not _NPM_NAME.match(raw):
        raise ValueError(f"npm name {raw!r} invalid")
    return (raw,)


# ── Version validation (fetch-time) ─────────────────────────────────────────
#
# The version is not part of a :class:`ValidatedCoordinate` (it is
# chosen per fetch), but it is just as attacker-controlled — it comes
# from the analysed repo's manifest — and it is templated into the
# index URL and the quarantined-cache path exactly like a coordinate
# component. It therefore gets the same allow-list treatment.
#
# :func:`scarno.security.sanitise_declared_version` is NOT sufficient
# here: it is a report-rendering sanitiser and leaves ``/``, ``..``,
# ``?``, ``#``, ``%``, ``&`` and ``:`` intact, so a hostile
# ``<version>`` could otherwise steer scarno's outbound GET to an
# arbitrary path or query string on the configured (possibly
# internal) index host.
#
# The shape mirrors ``_is_valid_gav_component`` in the Maven analyser,
# widened by ``+`` for semver build metadata. It accepts every
# real-world published version shape — ``1.0``, ``2.0-SNAPSHOT``,
# ``1.0-20230101.120000-1``, ``5.3.20.RELEASE``, ``1.0.0.Final``,
# ``31.1-jre``, ``2.0.0-rc.1``, ``1.0.0+build.5``, ``20030203.000550``,
# ``r08``. Maven version RANGES (``[1.0,2.0)``) are rejected: an index
# never serves an artefact under a range as a path segment, and the
# bracket characters were already stripped upstream.

#
# ``~`` is admitted alongside the rest: RFC 3986 lists it in the
# unreserved set, so it is literal in a URL path segment and needs no
# encoding, and it is an ordinary filename character on every platform
# the cache targets (only a *leading* ``~`` means anything, and only to
# a shell, which never sees these paths). Debian-style pre-release
# versions such as ``1.0~beta`` do reach Maven repositories, so
# rejecting it would refuse to fetch a legitimate artefact.
_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$"
)


def is_valid_fetch_version(version: str) -> bool:
    """Return ``True`` if *version* is safe to template into an index
    URL path segment and a cache path.

    Fail-closed: everything outside the allow-list is rejected —
    path separators, ``..``, query/fragment introducers, percent
    escapes, userinfo ``@``, whitespace, control bytes and non-ASCII.
    """
    if not version or len(version) > _MAX_COMPONENT_LEN:
        return False
    if ".." in version:
        return False
    return _VERSION_RE.match(version) is not None
