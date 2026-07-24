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

"""Maven version range parser + range-membership test (REQ-24 G4).

Maven's version constraint syntax — distinct from semver and from
PEP 440 — is documented in the Maven docs under "Dependency Version
Requirement Specification". Scarno historically compared
declared/resolved versions as opaque strings, so a declared
``[1.0,2.0)`` and a resolved ``1.5.0`` looked like a multi-version
conflict even though they refer to the same artefact (Maven would
pick 1.5.0 for that range with no conflict).

Supported syntax:

* ``1.0`` — soft requirement; treated as a single allowed value.
  (Maven semantically allows other versions to override this; for
  scarno's "is the resolved version covered by this declared
  expression" question, equality is the right answer.)
* ``[1.0]`` — hard pin (equality).
* ``[1.0,2.0)`` — half-open: 1.0 ≤ v < 2.0.
* ``(1.0,2.0]`` — half-open: 1.0 < v ≤ 2.0.
* ``[1.0,2.0]`` — closed.
* ``(1.0,2.0)`` — open.
* ``[1.0,)`` — open-ended on the right (≥ 1.0).
* ``(,2.0]`` — open-ended on the left (≤ 2.0).
* ``[1.0,1.5),[1.6,2.0)`` — multiple ranges (logical OR).

Comparison uses ``packaging.version.Version`` — which is PEP 440
ordering, not strict Maven ordering, but the two agree on the
overwhelming majority of real-world Maven versions. Where parsing
fails we fall back to string equality so the function never raises
on adversarial input — the worst-case is a false multi-version
flag, never a missed one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from packaging.version import InvalidVersion, Version


# A single range "[1.0,2.0)" or "(1.0,2.0]" etc. Anchored on the
# whole string so adversarial input doesn't slip past via a partial
# match.
_RANGE_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    ^
    (?P<lopen>[\[(])
    \s*(?P<lo>[^,\s\[\]()]*)\s*
    ,
    \s*(?P<hi>[^,\s\[\]()]*)\s*
    (?P<ropen>[\])])
    $
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class _Bound:
    """One end of a range. ``version`` is ``None`` for an open end
    (``[1.0,)`` → high bound is ``_Bound(None, inclusive=False)``)."""

    version: Version | None
    inclusive: bool


@dataclass(frozen=True)
class _Range:
    """A single closed/open/half-open range."""

    low: _Bound
    high: _Bound

    def contains(self, candidate: Version) -> bool:
        if self.low.version is not None:
            if self.low.inclusive:
                if candidate < self.low.version:
                    return False
            else:
                if candidate <= self.low.version:
                    return False
        if self.high.version is not None:
            if self.high.inclusive:
                if candidate > self.high.version:
                    return False
            else:
                if candidate >= self.high.version:
                    return False
        return True


def _safe_version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _parse_one_range(spec: str) -> _Range | None:
    m = _RANGE_RE.match(spec)
    if m is None:
        return None
    lo_text = m.group("lo").strip()
    hi_text = m.group("hi").strip()
    lo_inclusive = m.group("lopen") == "["
    hi_inclusive = m.group("ropen") == "]"
    low = _Bound(
        version=_safe_version(lo_text) if lo_text else None,
        inclusive=lo_inclusive,
    )
    high = _Bound(
        version=_safe_version(hi_text) if hi_text else None,
        inclusive=hi_inclusive,
    )
    # Reject if any non-empty text failed to parse — that means
    # the spec is malformed; fall back to string-equality semantics.
    if lo_text and low.version is None:
        return None
    if hi_text and high.version is None:
        return None
    return _Range(low=low, high=high)


def _parse_pin(spec: str) -> Version | None:
    """``[1.0]`` — strict pin syntax. Returns the pinned ``Version``
    or ``None`` if the spec isn't a pin."""
    if not (spec.startswith("[") and spec.endswith("]")):
        return None
    inner = spec[1:-1].strip()
    if "," in inner or "[" in inner or "]" in inner:
        return None
    return _safe_version(inner)


def declared_covers_resolved(
    declared: str | None, resolved: str | None
) -> bool:
    """Return ``True`` iff ``declared`` is a Maven version expression
    that is satisfied by ``resolved``.

    Falls back to string equality when either side is ``None`` /
    fails to parse — preserves pre-G4 behaviour for non-range cases.
    """
    if declared is None or resolved is None:
        return False
    declared = declared.strip()
    resolved = resolved.strip()
    if declared == resolved:
        return True

    # Hard pin: ``[1.0]``.
    pinned = _parse_pin(declared)
    if pinned is not None:
        candidate = _safe_version(resolved)
        return candidate is not None and candidate == pinned

    # Multi-range: ``[1.0,1.5),[1.6,2.0)`` — logical OR.
    if declared.startswith(("[", "(")) and "," in declared:
        candidate = _safe_version(resolved)
        if candidate is None:
            return False
        for part in _split_range_list(declared):
            r = _parse_one_range(part)
            if r is not None and r.contains(candidate):
                return True
        return False

    # Anything else (including bare soft requirements like ``1.0``
    # and unparseable strings) → fall back to string equality.
    return False


def _split_range_list(text: str) -> list[str]:
    """Split ``[1.0,1.5),[1.6,2.0)`` into individual range strings.
    The naive ``text.split(",")`` would break each range in half;
    we walk the string and split only at commas at bracket-depth 0.
    """
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(text[start:i])
            start = i + 1
    out.append(text[start:])
    return [s.strip() for s in out if s.strip()]


def is_range_expression(text: str | None) -> bool:
    """Return True if ``text`` looks like a Maven range expression
    (starts with ``[`` or ``(``). Used by callers that want to
    distinguish "range" from "single version" for display purposes."""
    if not text:
        return False
    text = text.strip()
    return text.startswith(("[", "("))
