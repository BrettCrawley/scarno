"""TA-325 — REQ-24 / ARCH-SEC-005 — user-config locator is the SOLE
discovery path; home-anchored; XDG-confined; never CWD- or
project-relative.

Closes design-flaw E1 (Critical) from the REQ-24 threat model: a
malicious repo planting ``.config/scarno/config.toml`` inside its
own tree must not influence scarno's resolved index list.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from scarno.security import (
    USER_CONFIG_REJECTED_XDG,
    resolve_user_config_path,
)

pytestmark = pytest.mark.security


# ── invalid names rejected at the boundary ──────────────────────────────────


@pytest.mark.requirement("ARCH-SEC-005")
def test_invalid_name_with_separator_raises():
    """A future caller cannot accidentally inject a traversal via
    ``name``. Single-component validation is the structural guard."""
    for bad in ("../config.toml", "subdir/config.toml", "a\\b", "..", ".", ""):
        with pytest.raises(ValueError, match="invalid name"):
            resolve_user_config_path(bad)


# ── repo-local config files cannot influence the resolver ───────────────────


@pytest.mark.requirement("ARCH-SEC-005")
def test_repo_local_dot_config_is_ignored(tmp_path, monkeypatch):
    """Plant ``.config/scarno/config.toml`` inside a tmp project tree
    and assert that ``resolve_user_config_path`` does NOT discover it.

    This is the load-bearing E1 mitigation. The resolver is anchored to
    ``Path.home()`` / ``$XDG_CONFIG_HOME``; CWD-relative or
    project-relative discovery must NEVER occur.
    """
    project = tmp_path / "victim_project"
    project.mkdir()
    hostile = project / ".config" / "scarno" / "config.toml"
    hostile.parent.mkdir(parents=True)
    hostile.write_text('[indexes]\nmaven = ["https://attacker.example/repo"]\n')

    # Strip any pre-existing XDG so we exercise the home-fallback path.
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    # Anchor cwd at the project so a buggy CWD-relative discovery would
    # find the planted file.
    monkeypatch.chdir(project)
    # Anchor "home" away from the project so the genuine home path
    # never overlaps the planted file.
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    path, warnings = resolve_user_config_path(
        "config.toml", project_root=project
    )

    assert path is None, (
        f"resolver discovered a path: {path}. The repo-local config at "
        f"{hostile} must not be findable. This is E1 (Critical)."
    )
    # No XDG was set, so no XDG warnings expected.
    assert not warnings


# ── XDG_CONFIG_HOME pointing into the project tree falls back ──────────────


@pytest.mark.requirement("ARCH-SEC-005")
def test_xdg_pointing_into_project_falls_back(tmp_path, monkeypatch):
    """When ``$XDG_CONFIG_HOME`` resolves under the analysed project root,
    the resolver MUST fall back to ``~/.config`` and emit a
    ``USER_CONFIG_REJECTED_XDG`` warning. This closes E2: env-var
    injection (CI shared mutable state) cannot subvert the home-anchor.
    """
    project = tmp_path / "analysed_project"
    project.mkdir()
    hostile_xdg = project / "fake_xdg"
    (hostile_xdg / "scarno").mkdir(parents=True)
    (hostile_xdg / "scarno" / "config.toml").write_text(
        '[indexes]\nmaven = ["https://attacker.example/repo"]\n'
    )

    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(hostile_xdg))

    path, warnings = resolve_user_config_path(
        "config.toml", project_root=project
    )

    assert path is None, (
        f"resolver returned {path}; XDG fallback should have skipped "
        f"the planted file under the project root."
    )
    assert any(USER_CONFIG_REJECTED_XDG in w for w in warnings), (
        f"missing {USER_CONFIG_REJECTED_XDG} audit; warnings: {warnings}"
    )


@pytest.mark.requirement("ARCH-SEC-005")
def test_xdg_pointing_into_cwd_falls_back(tmp_path, monkeypatch):
    """Same protection when ``$XDG_CONFIG_HOME`` resolves under
    ``Path.cwd()`` even without an explicit ``project_root``."""
    cwd_xdg = tmp_path / "cwd_xdg"
    (cwd_xdg / "scarno").mkdir(parents=True)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cwd_xdg))
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    _path, warnings = resolve_user_config_path("config.toml")

    assert any(USER_CONFIG_REJECTED_XDG in w for w in warnings), (
        f"missing {USER_CONFIG_REJECTED_XDG} when XDG resolves under CWD; "
        f"warnings: {warnings}"
    )


# ── happy paths ─────────────────────────────────────────────────────────────


@pytest.mark.requirement("ARCH-SEC-005")
def test_xdg_safe_path_resolves(tmp_path, monkeypatch):
    """When XDG points outside CWD and the project, resolve to it."""
    safe_xdg = tmp_path / "safe_xdg"
    (safe_xdg / "scarno").mkdir(parents=True)
    cfg = safe_xdg / "scarno" / "config.toml"
    cfg.write_text("[indexes]\n")

    project = tmp_path / "project"
    project.mkdir()
    other_cwd = tmp_path / "other_cwd"
    other_cwd.mkdir()

    monkeypatch.chdir(other_cwd)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(safe_xdg))

    path, warnings = resolve_user_config_path(
        "config.toml", project_root=project
    )
    assert path == cfg.resolve()
    assert not warnings


@pytest.mark.requirement("ARCH-SEC-005")
def test_home_fallback_when_no_xdg(tmp_path, monkeypatch):
    """No ``$XDG_CONFIG_HOME`` set → resolves under ``~/.config``."""
    fake_home = tmp_path / "fake_home"
    (fake_home / ".config" / "scarno").mkdir(parents=True)
    cfg = fake_home / ".config" / "scarno" / "config.toml"
    cfg.write_text("[indexes]\n")

    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(fake_home))

    path, warnings = resolve_user_config_path("config.toml")
    assert path == cfg.resolve()
    assert not warnings


@pytest.mark.requirement("ARCH-SEC-005")
def test_returns_none_when_file_absent(tmp_path, monkeypatch):
    """No config file present at the resolved root → returns ``None``;
    no exception."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(fake_home))

    path, warnings = resolve_user_config_path("absent.toml")
    assert path is None
    assert not warnings


# ── audit-tag stability ─────────────────────────────────────────────────────


@pytest.mark.requirement("ARCH-SEC-005")
def test_audit_tag_constant_is_stable():
    """Other components (IndexConfigResolver, audit emitters) match on
    the literal ``USER_CONFIG_REJECTED_XDG`` tag — guard the value."""
    assert USER_CONFIG_REJECTED_XDG == "USER_CONFIG_REJECTED_XDG"
