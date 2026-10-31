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

"""Shared source-file discovery (FR-279, ``docs/plans/gitignore-consistent-discovery.md``).

Every analyser used to walk the tree its own way. Only Python honoured
``.gitignore``, and it did so for the security rules as well as for
dependency classification. That let an analysed repository hide a payload
from the rule engine by listing it in its own ``.gitignore`` (Claude Security
finding F23). This module walks once and sorts every candidate file into
sets that each consumer then chooses from:

* ``tracked``: not gitignored, and not under one of the analyser's by-name
  classification exclusions. Used by classification and by the rules.
* ``ignored``: gitignored. The rules always scan these. Classification uses
  them according to the operator's :class:`GitignoreMode`.
* ``rule_only``: under a by-name classification exclusion (``build``,
  ``dist``, ``vendor`` …). Classification never uses them. The rules scan
  them, because a by-name list is as easy to hide behind as ``.gitignore``.

Two kinds of tree are never returned, for any consumer:

* **Installed environments, recognised by structure, not by name.** These
  are a directory holding ``pyvenv.cfg``, and any ``site-packages``,
  ``dist-packages``, ``__pypackages__`` or ``node_modules`` directory.
  Third-party code there trips the supply-chain rules (measured in step 1
  of the plan), and no name list can keep up with environment naming
  (``.direnv/``, ``env/``, ``.venv-3.12/`` …). A structural marker is
  visible in a pull request's diff, so planting one to hide code is
  reviewable. That is the documented residual risk.
* **Operator ``--exclude`` globs.** These are set from argv only, never
  from the analysed tree (SEC-NEW-76).

``.git`` is never entered. Symlinked directories are never entered, which
matches ``Path.rglob`` on every supported Python. Symlinked files are
returned only if they resolve inside the root (SEC-002), and no file over
``MAX_FILE_BYTES`` is returned.

Directories are pruned as the walk descends. An installed environment or an
excluded tree costs one check, not one per file inside it.
"""
from __future__ import annotations

import enum
import fnmatch
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from scarno.core.test_scope import TestScopeMatcher, sanitise_test_paths
from scarno.security import MAX_FILE_BYTES, PathEscapeError, resolve_and_confine


class GitignoreMode(str, enum.Enum):
    """How dependency classification treats gitignored files (FR-278).

    The security rules ignore this setting. They always scan gitignored
    files.
    """

    #: Usage found only in gitignored files makes a dep UNCERTAIN: never
    #: SAFE on that evidence, never confidently IN_USE either. The
    #: commonest gitignored code is generated (protobuf stubs, OpenAPI
    #: clients), and removing its dep breaks the build.
    UNCERTAIN = "uncertain"
    #: Gitignored files count like any other (``--no-gitignore``).
    INCLUDE = "include"
    #: Gitignored files are not read for classification at all.
    EXCLUDE = "exclude"


# Directory names whose presence marks an installed environment. Matched
# on the directory's own name; a ``pyvenv.cfg`` file marks its directory.
ENVIRONMENT_DIR_NAMES: frozenset[str] = frozenset(
    {"site-packages", "dist-packages", "__pypackages__", "node_modules"}
)
ENVIRONMENT_MARKER_FILES: frozenset[str] = frozenset({"pyvenv.cfg"})

_NEVER_ENTER: frozenset[str] = frozenset({".git"})


def sanitise_exclude_globs(raw: tuple[str, ...]) -> tuple[str, ...]:
    """Validate operator ``--exclude`` globs (SEC-NEW-76).

    Same contract as ``--test-paths``: a count cap and a byte cap, POSIX
    ``/`` only, no ``..`` segments, and a leading ``/`` stripped.
    Raises :class:`ValueError` naming ``--exclude``.
    """
    return sanitise_test_paths(raw, flag="--exclude")


@dataclass
class DiscoveredFiles:
    """The result of one :func:`discover` walk. Lists are sorted."""

    tracked: list[Path] = field(default_factory=list)
    ignored: list[Path] = field(default_factory=list)
    rule_only: list[Path] = field(default_factory=list)
    #: Installed-environment directories pruned (aggregate only: PRV-004).
    environment_dirs_skipped: int = 0
    #: Of those, how many the tree's own .gitignore does not cover. A
    #: gitignored virtualenv is the normal case. One that is not is either
    #: committed or relies on the operator's global excludes, and either
    #: way is worth surfacing: it is also what a planted marker looks like.
    environment_dirs_unignored: int = 0
    #: Files and directories removed by operator ``--exclude`` globs.
    operator_excluded: int = 0
    #: Files skipped by the ``--exclude-tests`` matcher.
    test_skipped: int = 0

    def for_rules(self) -> list[Path]:
        """Every file the security rules must scan, whatever the
        :class:`GitignoreMode`."""
        return sorted([*self.tracked, *self.ignored, *self.rule_only])

    def for_classification(self, mode: GitignoreMode) -> list[Path]:
        """Files whose usage counts with full weight for classification.

        Under ``UNCERTAIN`` the ignored files are *not* included here. The
        caller reads them separately, from :attr:`ignored`, and downgrades
        SAFE deps found only there to UNCERTAIN.
        """
        if mode is GitignoreMode.INCLUDE:
            return sorted([*self.tracked, *self.ignored])
        return list(self.tracked)


def load_gitignore_matcher(
    errors: list[str], label: str
) -> Callable[[str], bool] | None:
    """Return a matcher for the analysed tree's own ``.gitignore`` files,
    nested ones included, or ``None`` with a fixed error line if
    ``gitignorefile`` is unavailable.

    The matcher reads only ``.gitignore`` files found in the tree. The
    operator's global git excludes are deliberately not consulted, so
    results depend on the tree alone.
    """
    try:
        import gitignorefile  # type: ignore[import-untyped]
    except ImportError:
        errors.append(
            f"{label}: gitignorefile not installed — "
            "skipping .gitignore filtering (install with "
            "`pip install gitignorefile`)"
        )
        return None
    matcher: Callable[[str], bool] = gitignorefile.Cache()
    return matcher


def _matches_any(rel: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(rel, p) for p in patterns)


def is_operator_excluded(rel: str, patterns: tuple[str, ...]) -> bool:
    """True when an operator ``--exclude`` glob matches the root-relative
    POSIX path ``rel``, or the path of any directory above it. For callers
    that find candidates without :func:`discover` (Dockerfile and workflow
    scans)."""
    if not patterns:
        return False
    parts = rel.split("/")
    return any(
        _matches_any("/".join(parts[:i]), patterns)
        for i in range(1, len(parts) + 1)
    )


def _has_environment_marker(filenames: Iterable[str]) -> bool:
    return any(name in ENVIRONMENT_MARKER_FILES for name in filenames)


def _is_name_excluded(
    parts: tuple[str, ...], names: frozenset[str], suffixes: tuple[str, ...]
) -> bool:
    return any(
        part in names or (suffixes and part.endswith(suffixes))
        for part in parts
    )


def discover(
    root: Path,
    suffixes: Iterable[str],
    errors: list[str],
    *,
    label: str,
    classification_excluded_dirs: frozenset[str] = frozenset(),
    classification_excluded_dir_suffixes: tuple[str, ...] = (),
    operator_excludes: tuple[str, ...] = (),
    test_matcher: TestScopeMatcher | None = None,
    gitignore_matcher: Callable[[str], bool] | None = None,
    use_gitignore: bool = True,
) -> DiscoveredFiles:
    """Walk ``root`` once and classify every file whose lower-cased suffix
    is in ``suffixes``. Never raises: failures go to ``errors``, prefixed
    with ``label``.

    ``operator_excludes`` must already have passed
    :func:`sanitise_exclude_globs`. A pattern excludes a file when it
    matches the file's root-relative POSIX path, or the path of any
    directory above it.

    ``gitignore_matcher`` lets a caller share one matcher across several
    walks. When it is ``None`` and ``use_gitignore`` is true, one is
    loaded. When ``use_gitignore`` is false nothing is marked ignored.
    That is only the case when the caller has no use for the distinction:
    the rules scan ignored files either way.
    """
    out = DiscoveredFiles()
    wanted = frozenset(s.lower() for s in suffixes)
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        errors.append(f"{label}: could not resolve project path — {exc}")
        return out
    if not root.is_dir():
        return out

    matcher = gitignore_matcher
    if matcher is None and use_gitignore:
        matcher = load_gitignore_matcher(errors, label)

    def _on_error(exc: OSError) -> None:
        errors.append(f"{label}: tree walk failed — {exc}")

    def _count_environment(path: Path) -> None:
        out.environment_dirs_skipped += 1
        if matcher is None or not matcher(str(path)):
            out.environment_dirs_unignored += 1

    for dirpath, dirnames, filenames in os.walk(
        root, onerror=_on_error, followlinks=False
    ):
        here = Path(dirpath)
        rel_dir = here.relative_to(root)
        rel_dir_parts = rel_dir.parts
        # Deterministic order: os.walk yields filesystem order.
        dirnames.sort()
        filenames.sort()

        keep: list[str] = []
        for d in dirnames:
            if d in _NEVER_ENTER:
                continue
            rel = "/".join((*rel_dir_parts, d))
            if operator_excludes and _matches_any(rel, operator_excludes):
                out.operator_excluded += 1
                continue
            if d in ENVIRONMENT_DIR_NAMES:
                _count_environment(here / d)
                continue
            keep.append(d)
        dirnames[:] = keep

        # A pyvenv.cfg marks the directory it sits in. Count it and stop
        # descending. The root itself is never treated as an environment:
        # analysing a virtualenv directly is the operator's explicit choice.
        if rel_dir_parts and _has_environment_marker(filenames):
            _count_environment(here)
            dirnames[:] = []
            continue

        in_name_excluded = _is_name_excluded(
            rel_dir_parts,
            classification_excluded_dirs,
            classification_excluded_dir_suffixes,
        )

        for name in filenames:
            if Path(name).suffix.lower() not in wanted:
                continue
            raw_path = here / name
            rel_parts = (*rel_dir_parts, name)
            rel = "/".join(rel_parts)
            if operator_excludes and _matches_any(rel, operator_excludes):
                out.operator_excluded += 1
                continue
            is_ignored = (
                not in_name_excluded
                and matcher is not None
                and bool(matcher(str(raw_path)))
            )
            if test_matcher is not None and test_matcher.is_test_path(rel):
                # Counted only when classification would otherwise have
                # read the file. That keeps the --exclude-tests summary as
                # it was when Python discovery skipped ignored files first.
                if not in_name_excluded and not is_ignored:
                    out.test_skipped += 1
                continue
            try:
                resolved = resolve_and_confine(raw_path, root)
            except PathEscapeError:
                errors.append(f"{label}: symlink escape blocked: {rel}")
                continue
            try:
                size = resolved.stat().st_size
            except OSError as exc:
                errors.append(
                    f"{label}: stat failed for {resolved.name} — {exc}"
                )
                continue
            if size > MAX_FILE_BYTES:
                errors.append(
                    f"{label}: skipped {rel} — file too large "
                    f"({size} bytes > {MAX_FILE_BYTES})"
                )
                continue
            if in_name_excluded:
                out.rule_only.append(resolved)
            elif is_ignored:
                out.ignored.append(resolved)
            else:
                out.tracked.append(resolved)

    out.tracked.sort()
    out.ignored.sort()
    out.rule_only.sort()
    return out
