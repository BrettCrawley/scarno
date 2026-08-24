"""``mvn`` must never be spawned with the analysed tree as its CWD.

Maven's launcher reads ``.mvn/jvm.config`` (folded into the JVM command
line — a ``-javaagent:`` there runs attacker code before any goal),
``.mvn/maven.config``, ``.mvn/extensions.xml`` and the local ``pom.xml``
from the directory it starts in. Scarno's own working directory is the
analysed repository for ``scarno .`` and for the shipped GitHub Action,
so inheriting it would let untrusted repository content execute as the
scanning user. ``_invoke_mvn_safe`` therefore spawns from a private
empty scratch directory carrying an empty ``.mvn`` marker (which also
halts Maven's upward search for a project base directory inside a
directory Scarno owns).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("SEC-NEW-55")
def test_invoke_mvn_safe_spawns_from_neutral_scratch_dir(monkeypatch, tmp_path):
    """The cwd handed to the subprocess is an existing directory that is
    neither the process CWD nor anywhere inside the analysed tree, holds
    no Maven launcher configuration, and carries an empty ``.mvn``
    marker.
    """
    from scarno import security as _security
    from scarno.analysers.java import maven as _maven

    # Stand in for the attacker-controlled analysed repository and make
    # it the process CWD, exactly as `scarno .` / the composite action do.
    analysed_repo = tmp_path / "analysed-repo"
    (analysed_repo / ".mvn").mkdir(parents=True)
    (analysed_repo / ".mvn" / "jvm.config").write_text(
        "-javaagent:/tmp/evil.jar\n", encoding="utf-8"
    )
    (analysed_repo / "pom.xml").write_text("<project/>", encoding="utf-8")
    monkeypatch.chdir(analysed_repo)

    captured: dict[str, object] = {}

    def _capturing_run(argv, *, timeout_s, binary_root=None, cwd=None):
        captured["cwd"] = cwd
        # The scratch directory must still exist while mvn would be running.
        assert cwd is not None, "mvn inherited Scarno's working directory"
        captured["contents"] = sorted(os.listdir(cwd))
        captured["mvn_dir_contents"] = sorted(os.listdir(Path(cwd) / ".mvn"))
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(_security, "safe_subprocess_run", _capturing_run)
    monkeypatch.setattr(_maven, "_resolve_mvn_binary", lambda: "/usr/bin/mvn")

    _maven._invoke_mvn_safe(
        ["dependency:get",
         "-Dartifact=com.example:thing:1.0:pom",
         "-Dtransitive=false"],
    )

    cwd = captured.get("cwd")
    assert cwd is not None, "mvn was not invoked"
    resolved = Path(str(cwd)).resolve()
    assert resolved != Path(analysed_repo).resolve()
    assert not resolved.is_relative_to(Path(analysed_repo).resolve()), (
        f"mvn spawned inside the analysed tree: {resolved}"
    )
    # No pom.xml and no launcher config reachable from the scratch dir.
    assert captured["contents"] == [".mvn"]
    assert captured["mvn_dir_contents"] == []


@pytest.mark.requirement("SEC-NEW-55")
def test_neutral_mvn_working_dir_is_cleaned_up():
    """The scratch directory is removed once the invocation completes."""
    from scarno.analysers.java import maven as _maven

    with _maven._neutral_mvn_working_dir() as scratch:
        path = Path(scratch)
        assert path.is_dir()
        assert (path / ".mvn").is_dir()
    assert not path.exists()
