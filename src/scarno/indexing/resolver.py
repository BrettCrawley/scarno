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

"""REQ-24 / FR-256..259 — :func:`resolve_indexes`: merge CLI > user-config
> env into an ordered list of :class:`IndexEndpoint` for the fetcher.

Per-ecosystem **override** (not merge): the highest-precedence source
that mentions an ecosystem owns its whole list — simplest mental
model, matches ``PIP_INDEX_URL`` semantics. Avoids confusing
half-merged lists where two sources disagree on priority order.

When ``fetch_enabled`` is ``True``, env-sourced indexes are
**dropped with a warning** (SEC-NEW-62 / SUC-74) — env in CI is
shared mutable state, lower trust than CLI / user-config.

Every URL is HTTPS-validated at parse time AND will be re-validated
at request time by :class:`SafeHttpsClient` (defence in depth).

Returns ``(endpoints, warnings)``. ``warnings`` are sanitised audit
lines that the caller forwards into ``result.errors`` (the persistent
report channel) per PUC-006/007 — they must NOT go to stderr only.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from urllib.parse import urlparse

from scarno.indexing.endpoint import IndexConfigSource, IndexEndpoint
from scarno.security import resolve_user_config_path, sanitise


_ENV_PREFIX = "SCARNO_INDEX_"


def _validate_url(url: str) -> None:
    """SEC-NEW-66 + N-2 envelope — HTTPS-only, no userinfo, must have
    a host, well-formed URL.

    Raises ``ValueError`` on rejection. The fetcher's
    :class:`SafeHttpsClient` re-runs equivalent checks at request time
    so a bug here cannot bypass the network controls — this is the
    *parse-time* gate that ensures bad URLs never reach the resolver
    output.
    """
    try:
        parsed = urlparse(url)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"unparseable URL: {exc}") from exc
    if parsed.scheme != "https":
        raise ValueError(
            f"index URL must use https:// (got {parsed.scheme!r}); {url!r}"
        )
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            f"index URL must not contain userinfo (user:pass@): {url!r}"
        )
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"index URL missing host: {url!r}")


# ── per-source parsers ──────────────────────────────────────────────────────


def _parse_cli_indexes(
    raw: list[str] | None,
) -> tuple[dict[str, list[str]], list[str]]:
    out: dict[str, list[str]] = {}
    warnings: list[str] = []
    for entry in (raw or ()):
        if "=" not in entry:
            warnings.append(
                f"req24: --index {sanitise(entry)!r} missing '=' "
                "(expected ECOSYSTEM=URL); ignored"
            )
            continue
        eco, _, url = entry.partition("=")
        eco = eco.strip().lower()
        url = url.strip()
        if not eco:
            warnings.append(
                f"req24: --index {sanitise(entry)!r} has empty ecosystem; "
                "ignored"
            )
            continue
        try:
            _validate_url(url)
        except ValueError as exc:
            warnings.append(
                f"req24: --index {sanitise(entry)!r} rejected: "
                f"{sanitise(str(exc))}"
            )
            continue
        out.setdefault(eco, []).append(url)
    return out, warnings


def _parse_env_indexes() -> tuple[dict[str, list[str]], list[str]]:
    out: dict[str, list[str]] = {}
    warnings: list[str] = []
    for key, value in os.environ.items():
        if not key.startswith(_ENV_PREFIX):
            continue
        eco = key[len(_ENV_PREFIX):].lower()
        if not eco:
            continue
        for url in value.split():
            try:
                _validate_url(url)
            except ValueError as exc:
                warnings.append(
                    f"req24: env {sanitise(key)} URL rejected: "
                    f"{sanitise(str(exc))}"
                )
                continue
            out.setdefault(eco, []).append(url)
    return out, warnings


def _parse_user_config_indexes(
    project_root: Path | None = None,
) -> tuple[dict[str, list[str]], list[str]]:
    """Read ``[indexes]`` from the user-config file via the SOLE locator.

    The locator (``security.resolve_user_config_path``) is the keystone
    control: it cannot resolve to a file inside the analysed project
    tree (ARCH-SEC-005). Any code that bypasses the locator violates
    REQ-24's E1 mitigation.
    """
    out: dict[str, list[str]] = {}
    warnings: list[str] = []
    config_path, locator_warnings = resolve_user_config_path(
        "config.toml", project_root=project_root
    )
    warnings.extend(locator_warnings)
    if config_path is None:
        return out, warnings
    try:
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        warnings.append(
            f"req24: user-config {sanitise(str(config_path))} could not be "
            f"parsed: {sanitise(str(exc))}"
        )
        return out, warnings
    indexes = data.get("indexes")
    if not isinstance(indexes, dict):
        return out, warnings
    for eco_raw, urls in indexes.items():
        if not isinstance(eco_raw, str):
            continue
        eco = eco_raw.strip().lower()
        if not eco:
            continue
        if not isinstance(urls, list):
            warnings.append(
                f"req24: user-config [indexes].{sanitise(eco)} must be a "
                "list of URL strings; ignored"
            )
            continue
        for url in urls:
            if not isinstance(url, str):
                warnings.append(
                    f"req24: user-config [indexes].{sanitise(eco)} contains "
                    "a non-string entry; skipped"
                )
                continue
            try:
                _validate_url(url)
            except ValueError as exc:
                warnings.append(
                    f"req24: user-config [indexes].{sanitise(eco)} URL "
                    f"rejected: {sanitise(str(exc))}"
                )
                continue
            out.setdefault(eco, []).append(url)
    return out, warnings


# ── merge ───────────────────────────────────────────────────────────────────


def resolve_indexes(
    *,
    cli_indexes: list[str] | None,
    fetch_enabled: bool,
    project_root: Path | None = None,
) -> tuple[list[IndexEndpoint], list[str]]:
    """Merge index sources by precedence and return ordered endpoints.

    Parameters
    ----------
    cli_indexes:
        Raw values from repeatable ``--index ECO=URL`` argv (the typer
        list). ``None`` and ``[]`` are equivalent.
    fetch_enabled:
        ``True`` when ``--allow-remote-fetch`` is set on argv. When
        true, env-sourced indexes are dropped with a warning
        (SEC-NEW-62).
    project_root:
        Analysed project root — passed to the user-config locator so
        the ARCH-SEC-005 XDG-confinement check has a project to
        compare against.

    Returns
    -------
    ``(endpoints, warnings)``: endpoints sorted by ``(ecosystem,
    priority)``; warnings are sanitised audit lines (one per rejected
    URL or fallback event).
    """
    cli_eco, w_cli = _parse_cli_indexes(cli_indexes)
    user_eco, w_user = _parse_user_config_indexes(project_root=project_root)
    env_eco, w_env = _parse_env_indexes()
    warnings: list[str] = w_cli + w_user + w_env

    if fetch_enabled and env_eco:
        # SEC-NEW-62 / SUC-74 — env is CI-shared mutable state; drop it
        # in dangerous mode. The ergonomic case (interactive
        # `scarno .` without fetch) keeps env support for free
        # because this branch only fires when fetch is on.
        for eco in sorted(env_eco):
            urls = env_eco[eco]
            warnings.append(
                f"req24: env-sourced indexes for ecosystem {sanitise(eco)} "
                f"({len(urls)} entr{'y' if len(urls) == 1 else 'ies'}) "
                f"dropped because --allow-remote-fetch is set; pass --index "
                f"on argv or list in ~/.config/scarno/config.toml for "
                f"auditable provenance (SEC-NEW-62)."
            )
        env_eco = {}

    # Per-ecosystem OVERRIDE (FR-259). Walk sources in precedence
    # order; the first source that mentions an ecosystem owns its
    # whole list. Subsequent sources contribute nothing for that
    # ecosystem.
    final: list[IndexEndpoint] = []
    seen_ecos: set[str] = set()
    for source, source_eco in (
        (IndexConfigSource.CLI, cli_eco),
        (IndexConfigSource.USER_CONFIG, user_eco),
        (IndexConfigSource.ENV, env_eco),
    ):
        for eco in sorted(source_eco):
            if eco in seen_ecos:
                continue
            seen_ecos.add(eco)
            for priority, url in enumerate(source_eco[eco]):
                final.append(IndexEndpoint(
                    ecosystem=eco,
                    url=url,
                    priority=priority,
                    source=source,
                ))
    return final, warnings
