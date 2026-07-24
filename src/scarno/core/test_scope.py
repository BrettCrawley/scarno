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

"""Test-scope discovery helpers — REQ-17.

Two responsibilities:

1. :func:`sanitise_test_paths` — validates operator-supplied
   ``--test-paths`` glob patterns under the SEC-NEW-31 / SEC-NEW-33
   ceilings (count cap, length cap, no ``..``, no Windows separators,
   leading-``/`` stripped).

2. :class:`TestScopeMatcher` — given a language key, exposes
   :meth:`is_test_path` which returns ``True`` for paths the operator
   wants excluded under ``--exclude-tests``. The match runs only against
   *relative* paths (caller is responsible for ``Path.relative_to``).

The matcher is a no-op when ``exclude_tests=False`` so callers can wire
it unconditionally.
"""
from __future__ import annotations

import fnmatch
from typing import Final


# ── Per-ecosystem default test-path globs ────────────────────────────────


DEFAULT_TEST_PATTERNS: Final[dict[str, tuple[str, ...]]] = {
    "python": (
        "tests/*",
        "tests/**/*",
        "test/*",
        "test/**/*",
        "**/test_*.py",
        "**/*_test.py",
        "conftest.py",
        "**/conftest.py",
    ),
    "java": (
        "src/test/**/*.java",
        "src/test/**/*.kt",
        "**/*Test.java",
        "**/*Tests.java",
        "**/*IT.java",
        "**/*Test.kt",
        "**/*Tests.kt",
    ),
    "javascript": (
        "**/__tests__/**/*",
        "**/*.test.js",
        "**/*.test.jsx",
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/*.spec.js",
        "**/*.spec.jsx",
        "**/*.spec.ts",
        "**/*.spec.tsx",
        "tests/**/*",
        "test/**/*",
        "cypress/**/*",
        "playwright/**/*",
        "e2e/**/*",
    ),
    "go": (
        "**/*_test.go",
    ),
    "csharp": (
        "**/*Tests/**/*",
        "**/*Test/**/*",
    ),
    # CSS / HTML have no test convention; left empty so the matcher is a no-op.
    "css": (),
    "html": (),
}


# ── Operator-pattern caps (SEC-NEW-31) ───────────────────────────────────


MAX_USER_TEST_PATTERNS: Final[int] = 64
MAX_USER_TEST_PATTERN_BYTES: Final[int] = 256


def sanitise_test_paths(raw: tuple[str, ...]) -> tuple[str, ...]:
    """Validate operator-supplied ``--test-paths`` globs.

    Raises:
      ValueError: when the input violates SEC-NEW-31 / SEC-NEW-33.
        The message identifies the specific violation; the CLI maps
        :class:`ValueError` to a sanitised :class:`scarno.cli._CliError`
        and exits with code 2.

    Returns:
      A new tuple with leading ``/`` stripped from each entry.
    """
    if len(raw) > MAX_USER_TEST_PATTERNS:
        raise ValueError(
            f"--test-paths too many: {len(raw)} > "
            f"{MAX_USER_TEST_PATTERNS} max patterns"
        )
    cleaned: list[str] = []
    for pattern in raw:
        if not isinstance(pattern, str):
            raise ValueError(
                "--test-paths pattern must be a string"
            )
        if len(pattern.encode("utf-8")) > MAX_USER_TEST_PATTERN_BYTES:
            raise ValueError(
                f"--test-paths pattern too long: "
                f"{len(pattern.encode('utf-8'))} bytes > "
                f"{MAX_USER_TEST_PATTERN_BYTES} max"
            )
        if "\\" in pattern:
            raise ValueError(
                "--test-paths patterns must use POSIX `/` separators "
                "(backslash is not permitted)"
            )
        # Strip a single leading '/' (the CLI layer logs a verbose-mode warning).
        normalised = pattern.lstrip("/") if pattern.startswith("/") else pattern
        # Reject `..` segments (after stripping leading slash). We split on
        # `/` so a pattern like `tests/../etc` is caught even though the
        # leading char is not `..`.
        segments = normalised.split("/")
        if any(seg == ".." for seg in segments):
            raise ValueError(
                "--test-paths patterns must stay inside the project root "
                "(no '..' segments)"
            )
        if normalised:
            cleaned.append(normalised)
    return tuple(cleaned)


# ── Matcher ───────────────────────────────────────────────────────────────


class TestScopeMatcher:
    """Decide whether a relative path should be skipped under ``--exclude-tests``.

    The matcher combines per-language defaults with operator-supplied
    ``user_patterns``.  Both are matched via :func:`fnmatch.fnmatchcase`
    against the *relative* path; the caller must produce that path with
    :meth:`Path.relative_to` against the project root.

    When ``exclude_tests`` is False, the matcher always returns False.
    """

    __slots__ = ("_patterns", "_enabled")

    def __init__(
        self,
        language: str,
        *,
        exclude_tests: bool,
        user_patterns: tuple[str, ...] = (),
    ) -> None:
        self._enabled = bool(exclude_tests)
        defaults = DEFAULT_TEST_PATTERNS.get(language, ())
        self._patterns: tuple[str, ...] = (
            tuple(defaults) + tuple(user_patterns)
        )

    @property
    def patterns(self) -> tuple[str, ...]:
        """Compiled glob list (defaults + user). Useful for diagnostics."""
        return self._patterns

    def is_test_path(self, relative_path: str) -> bool:
        """Return True when ``relative_path`` matches any test pattern.

        Always False when the matcher was constructed with
        ``exclude_tests=False``.
        """
        if not self._enabled:
            return False
        # Normalise path separators — callers may pass `os.sep` paths on
        # Windows. We always match against forward-slash form.
        rel = relative_path.replace("\\", "/")
        for pat in self._patterns:
            if fnmatch.fnmatchcase(rel, pat):
                return True
        return False
