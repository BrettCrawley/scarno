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

"""REQ-24 acceptance — a run WITHOUT ``--allow-remote-fetch`` emits
zero outbound traffic *by any mechanism*.

REQ-24's acceptance criterion was written as "verified via mock
``SafeHttpsClient`` instance counter — must remain at zero". That
counter alone is not sufficient: Scarno's Maven POM resolver has a
third tier that shells out to ``mvn dependency:get``, which performs
outbound requests from a subprocess and writes what it downloads into
the operator's real ``~/.m2/repository``. Egress through that tier is
invisible to a ``SafeHttpsClient`` counter.

These tests therefore assert BOTH:

  * no ``SafeHttpsClient`` is ever constructed, and
  * no subprocess is spawned and no ``mvn`` binary is even resolved,

for a project whose parent, BOM import and dependencies are all absent
from the local cache — i.e. exactly the shape of repository that would
otherwise drive one ``mvn`` invocation per missing coordinate
(UC-081 "analysis completes with zero outbound packets"; README
"Without it, configured indexes are validated but zero network calls
happen").

The final test is a positive control: with the flag ON, the same
counters DO fire. Without it, the tests above could pass vacuously.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scarno.analysers.java import JavaAnalyser
from scarno.analysers.java import maven as mvn_mod

pytestmark = pytest.mark.security


# A pom.xml whose parent, BOM import and direct dependency are all
# attacker-chosen coordinates that miss the local cache — the finding's
# exploit shape (a hostile repo choosing what the scanner asks for).
_HOSTILE_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.attacker.internal</groupId>
    <artifactId>beacon-parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.victim</groupId>
  <artifactId>app</artifactId>
  <version>0.1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.attacker.internal</groupId>
        <artifactId>beacon-bom</artifactId>
        <version>2.0.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.attacker.internal</groupId>
      <artifactId>beacon-lib</artifactId>
      <version>3.0.0</version>
    </dependency>
  </dependencies>
</project>
"""


class _EgressProbe:
    """Records every egress-capable event the analysis triggers."""

    def __init__(self) -> None:
        self.https_clients: list[object] = []
        self.spawns: list[list[str]] = []
        self.mvn_lookups: int = 0


@pytest.fixture
def probe(monkeypatch, tmp_path) -> _EgressProbe:
    """Instrument every outbound path and empty the local cache."""
    p = _EgressProbe()

    # 1. SafeHttpsClient instance counter — the original REQ-24
    #    acceptance mechanism. Patch the name JavaAnalyser binds.
    class _CountingSafeHttpsClient:
        def __init__(self, *args, **kwargs) -> None:
            p.https_clients.append(self)

    monkeypatch.setattr(
        "scarno.analysers.java.SafeHttpsClient", _CountingSafeHttpsClient
    )

    # 2. Subprocess counter — catches egress that never touches
    #    SafeHttpsClient (``mvn dependency:get``).
    def _fake_run(*args, **kwargs):
        argv = list(args[0]) if args else list(kwargs.get("args") or [])
        p.spawns.append(argv)
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)

    # 3. Make ``mvn`` look installed — the precondition the exploit
    #    needs. Records lookups so we can assert the gate fails closed
    #    BEFORE binary resolution, not just before the spawn.
    def _fake_resolve_mvn() -> str:
        p.mvn_lookups += 1
        return "/usr/bin/mvn"

    monkeypatch.setattr(mvn_mod, "_resolve_mvn_binary", _fake_resolve_mvn)

    # 4. Point the "local cache" at an empty directory so every
    #    coordinate in the hostile POM misses tier 1.
    empty_m2 = tmp_path / "empty-m2" / "repository"
    empty_m2.mkdir(parents=True)
    monkeypatch.setattr(mvn_mod, "_m2_repo_path", lambda: empty_m2)

    return p


def _hostile_project(tmp_path: Path) -> Path:
    project = tmp_path / "cloned-repo"
    project.mkdir()
    (project / "pom.xml").write_text(_HOSTILE_POM, encoding="utf-8")
    return project


def _run(project: Path, **flags):
    analyser = JavaAnalyser()
    for name, value in flags.items():
        setattr(analyser, name, value)
    return analyser.analyse(str(project))


# ── The acceptance criterion, both halves ───────────────────────────────────


@pytest.mark.requirement("FR-260")
@pytest.mark.requirement("SEC-NEW-72")
def test_default_run_makes_no_outbound_call_of_any_kind(probe, tmp_path):
    """Plain ``scarno <path>``: no HTTPS client, no subprocess, not
    even an ``mvn`` binary lookup — regardless of how many indexes are
    configured."""
    project = _hostile_project(tmp_path)

    result = _run(
        project,
        # Indexes configured but NOT consented to — REQ-24 requires
        # they stay inert.
        cli_indexes=("maven=https://repo1.maven.org/maven2",),
    )

    assert probe.https_clients == [], (
        "SafeHttpsClient constructed without --allow-remote-fetch"
    )
    assert probe.spawns == [], (
        "subprocess spawned without --allow-remote-fetch — outbound "
        f"egress bypassing the capability gate: {probe.spawns}"
    )
    assert probe.mvn_lookups == 0, (
        "mvn binary resolved without --allow-remote-fetch — the CLI "
        "fetch tier was entered"
    )
    # The operator is told why the cache misses were not resolved
    # (UC-081: misses surface as warnings), exactly once.
    gate_notes = [
        e for e in result.errors
        if "--allow-remote-fetch" in e and "NOT" in e
    ]
    assert len(gate_notes) == 1, result.errors
    assert not any("REMOTE FETCH ENABLED" in e for e in result.errors)


@pytest.mark.requirement("FR-260")
@pytest.mark.requirement("SEC-NEW-72")
def test_no_egress_even_when_mvn_and_deep_inspection_are_available(
    probe, tmp_path,
):
    """``--deep-inspection`` alone is NOT consent to reach the network.

    It is the flag that makes the JVM analyser resolve more coordinates
    (and therefore miss the cache more often), so it is the most likely
    way to trip an ungated fetch tier.
    """
    project = _hostile_project(tmp_path)

    _run(project, deep_inspection=True)

    assert probe.https_clients == []
    assert probe.mvn_lookups == 0
    assert [s for s in probe.spawns if any("mvn" in tok for tok in s)] == [], (
        f"mvn spawned under --deep-inspection alone: {probe.spawns}"
    )


# ── Positive control — the counters above are not vacuous ──────────────────


@pytest.mark.requirement("FR-260")
@pytest.mark.requirement("FR-263")
@pytest.mark.requirement("PRV-006")
def test_with_consent_the_cli_tier_runs_and_is_disclosed_first(
    probe, tmp_path, monkeypatch,
):
    """With ``--allow-remote-fetch`` (and no indexes configured, so the
    SafeHttpsClient tier is unavailable) the Maven CLI tier DOES run —
    proving the probes above would have caught a regression — and the
    FR-263 pre-fetch disclosure lands in the persistent report channel
    before the first spawn, naming IP exposure and the ``~/.m2`` write.
    """
    project = _hostile_project(tmp_path)
    # Deterministic: no indexes resolve, whatever the host machine's
    # ~/.config/scarno/config.toml says, so tier 2 is unavailable and
    # tier 3 is the tier under test.
    monkeypatch.setattr(
        "scarno.analysers.java.resolve_indexes",
        lambda **kwargs: ([], []),
    )

    result = _run(project, allow_remote_fetch=True)

    mvn_spawns = [s for s in probe.spawns if s and "mvn" in s[0]]
    assert mvn_spawns, (
        "Maven CLI tier did not run with --allow-remote-fetch — the "
        "probe cannot distinguish gated from broken"
    )
    assert probe.mvn_lookups >= 1
    assert any("dependency:get" in tok for s in mvn_spawns for tok in s)

    disclosures = [e for e in result.errors if "REMOTE FETCH ENABLED" in e]
    assert len(disclosures) == 1, (
        f"expected exactly one FR-263 disclosure, got {len(disclosures)}"
    )
    disclosure = disclosures[0]
    assert "IP address will be visible" in disclosure
    assert "~/.m2/repository" in disclosure
    assert "SafeHttpsClient" in disclosure
    # (Ordering — disclosure strictly before the first spawn — is
    # asserted in tests/integration/test_req24_option2_pom_and_jar_fetch.py
    # where the fetch tier itself can inspect the report channel.)


@pytest.mark.requirement("FR-260")
def test_module_level_fetch_helper_fails_closed(tmp_path, monkeypatch):
    """``_fetch_pom_via_maven`` refuses to act without explicit consent
    even when called directly — the gate is not only at the call site.
    """
    monkeypatch.setattr(
        mvn_mod,
        "_resolve_mvn_binary",
        lambda: pytest.fail("binary resolved without consent"),
    )
    errors: list[str] = []
    assert mvn_mod._fetch_pom_via_maven(
        ("com.example", "lib", "1.0"), errors, allow_remote_fetch=False
    ) is None

    # ...and the parameter is keyword-only with no default, so a future
    # call site cannot re-open the egress path by simply omitting it.
    with pytest.raises(TypeError):
        mvn_mod._fetch_pom_via_maven(("com.example", "lib", "1.0"), errors)
