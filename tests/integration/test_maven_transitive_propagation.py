"""Maven dependency-classification rules (FR-150).

The model has three rules, all unified by one principle:

  **We cannot prove a third-party library does not need its declared
  transitives without reading its bytecode. So when an IN_USE dep
  pulls another dep in via its POM, the pulled dep is also IN_USE.**

  Rule 1 — A direct manifest declaration whose artifact is also
  reachable as a transitive of an IN_USE dep is *redundant*: the
  artifact stays on the classpath without the explicit declaration.
  The dep classifies IN_USE (we can't prove the parent doesn't need
  it) but is flagged ``manifest_redundant=True`` and reporters
  surface a "remove this manifest line" recommendation.

  Rule 2 — A transitive that's directly imported by project code is
  IN_USE even when its declared parent is SAFE
  (``imported_directly=True``). The developer is told to promote it
  before removing the parent.

  Rule 3 — A pure lockfile/POM transitive (``is_transitive=True``,
  not declared in the manifest) inherits its parent's status: an
  IN_USE direct parent lifts the transitive to IN_USE. (Maven does
  not enumerate pure transitives into the dep list today; this
  rule applies to Python lockfiles and any future Maven extension
  that adds pure transitives to the dep list.)

These tests pin Rule 1 specifically with the dep_graph populated
from cached POMs in ``~/.m2/repository`` so the propagation pathway
is fully exercised.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app


def _w(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _run(tmp: Path) -> dict:
    result = CliRunner().invoke(app, [str(tmp), "--format", "json"])
    assert result.exit_code in (0, 1, 3), result.output
    return json.loads(result.output)


def _dep(data: dict, name: str) -> dict:
    matches = [d for d in data["dependencies"] if d["name"] == name]
    assert matches, (
        f"dep {name} missing; got "
        f"{[d['name'] for d in data['dependencies']]}"
    )
    return matches[0]


def _populate_fake_m2_alpha_requires_beta(m2: Path) -> None:
    """``com.alpha:core:1.0`` declares a runtime dep on
    ``org.beta:utils:2.0``. Used so dep_graph carries alpha → beta."""
    pom = m2 / "com" / "alpha" / "core" / "1.0" / "core-1.0.pom"
    pom.parent.mkdir(parents=True)
    pom.write_text("""\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.alpha</groupId>
  <artifactId>core</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>org.beta</groupId>
      <artifactId>utils</artifactId>
      <version>2.0</version>
    </dependency>
  </dependencies>
</project>
""")


# ── Rule 1 ───────────────────────────────────────────────────────────────


class TestRedundantDirectDeclarationLiftsToInUse:
    @pytest.mark.requirement("FR-150")
    def test_redundant_direct_dep_lifts_to_in_use_and_flags_manifest_redundant(
        self, tmp_path, monkeypatch,
    ):
        """alpha is imported (IN_USE). beta is declared in pom.xml AND
        appears as alpha's transitive in dep_graph. Project source
        never imports beta directly. We cannot prove alpha does NOT
        need beta at runtime without reading alpha's bytecode, so
        beta MUST classify IN_USE. The explicit manifest declaration
        is however redundant — alpha already pulls beta in
        transitively — so beta is flagged ``manifest_redundant=True``
        with ``redundant_parent`` naming alpha."""
        fake_m2 = tmp_path / "fake-m2" / "repository"
        fake_m2.mkdir(parents=True)
        _populate_fake_m2_alpha_requires_beta(fake_m2)
        from scarno.analysers.java import maven as _maven
        monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

        project = tmp_path / "project"
        _w(project / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.alpha</groupId>
      <artifactId>core</artifactId>
      <version>1.0</version>
    </dependency>
    <dependency>
      <groupId>org.beta</groupId>
      <artifactId>utils</artifactId>
      <version>2.0</version>
    </dependency>
  </dependencies>
</project>
""")
        # Source imports alpha only — never beta directly.
        _w(project / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.alpha.core.Util;
public class App { public Util u() { return new Util(); } }
""")
        data = _run(project)
        alpha = _dep(data, "com.alpha:core")
        beta = _dep(data, "org.beta:utils")
        assert alpha["status"] == "IN_USE"
        assert alpha.get("manifest_redundant") is False, (
            "alpha is imported directly, manifest declaration is NOT redundant"
        )
        assert beta["status"] == "IN_USE", (
            "beta must classify IN_USE — alpha pulls it in transitively "
            "and we cannot prove alpha does not need it at runtime "
            "without reading alpha's bytecode"
        )
        assert beta.get("manifest_redundant") is True, (
            f"beta's direct manifest declaration is redundant — alpha "
            f"would still pull beta in via the transitive path. Expected "
            f"manifest_redundant=True; got {beta.get('manifest_redundant')!r}"
        )
        assert beta.get("redundant_parent") == "com.alpha:core", (
            f"redundant_parent must name the IN_USE parent that keeps "
            f"beta alive; got {beta.get('redundant_parent')!r}"
        )
        assert "com.alpha:core" in beta["reason"]

    @pytest.mark.requirement("FR-150")
    def test_in_use_child_does_not_lift_safe_parent(
        self, tmp_path, monkeypatch,
    ):
        """alpha is the GRAPH-PARENT of beta. The user imports beta
        directly but never uses alpha. beta is IN_USE on its own
        merit; alpha must stay SAFE — propagation flows parent→child
        only, never child→parent."""
        fake_m2 = tmp_path / "fake-m2" / "repository"
        fake_m2.mkdir(parents=True)
        _populate_fake_m2_alpha_requires_beta(fake_m2)
        from scarno.analysers.java import maven as _maven
        monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

        project = tmp_path / "project"
        _w(project / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>com.alpha</groupId><artifactId>core</artifactId><version>1.0</version></dependency>
    <dependency><groupId>org.beta</groupId><artifactId>utils</artifactId><version>2.0</version></dependency>
  </dependencies>
</project>
""")
        # Import beta only — NOT alpha.
        _w(project / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import org.beta.utils.Helper;
public class App { public Helper h() { return new Helper(); } }
""")
        data = _run(project)
        alpha = _dep(data, "com.alpha:core")
        beta = _dep(data, "org.beta:utils")
        assert beta["status"] == "IN_USE"
        assert beta.get("manifest_redundant") is False, (
            "beta is imported directly — its declaration is the genuine "
            "source of truth, not redundant"
        )
        assert alpha["status"] == "SAFE", (
            "alpha is not imported and is not a transitive of any IN_USE "
            "dep, so it must stay SAFE"
        )

    @pytest.mark.requirement("FR-150")
    def test_neither_imported_both_safe(self, tmp_path, monkeypatch):
        fake_m2 = tmp_path / "fake-m2" / "repository"
        fake_m2.mkdir(parents=True)
        _populate_fake_m2_alpha_requires_beta(fake_m2)
        from scarno.analysers.java import maven as _maven
        monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

        project = tmp_path / "project"
        _w(project / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>com.alpha</groupId><artifactId>core</artifactId><version>1.0</version></dependency>
    <dependency><groupId>org.beta</groupId><artifactId>utils</artifactId><version>2.0</version></dependency>
  </dependencies>
</project>
""")
        _w(project / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
public class App {}
""")
        data = _run(project)
        # Neither dep is IN_USE so the propagator finds no roots — both
        # stay SAFE; nothing is flagged manifest_redundant.
        assert _dep(data, "com.alpha:core")["status"] == "SAFE"
        assert _dep(data, "org.beta:utils")["status"] == "SAFE"

    @pytest.mark.requirement("FR-150")
    def test_both_imported_both_in_use_neither_redundant(
        self, tmp_path, monkeypatch,
    ):
        """Sanity: both imported → both IN_USE on their own merit;
        neither flagged manifest_redundant — both manifest lines are
        the genuine source of truth for their direct usage."""
        fake_m2 = tmp_path / "fake-m2" / "repository"
        fake_m2.mkdir(parents=True)
        _populate_fake_m2_alpha_requires_beta(fake_m2)
        from scarno.analysers.java import maven as _maven
        monkeypatch.setattr(_maven, "_m2_repo_path", lambda: fake_m2)

        project = tmp_path / "project"
        _w(project / "pom.xml", """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>com.alpha</groupId><artifactId>core</artifactId><version>1.0</version></dependency>
    <dependency><groupId>org.beta</groupId><artifactId>utils</artifactId><version>2.0</version></dependency>
  </dependencies>
</project>
""")
        _w(project / "src" / "main" / "java" / "demo" / "App.java", """\
package demo;
import com.alpha.core.Util;
import org.beta.utils.Helper;
public class App {
    public Util u() { return new Util(); }
    public Helper h() { return new Helper(); }
}
""")
        data = _run(project)
        alpha = _dep(data, "com.alpha:core")
        beta = _dep(data, "org.beta:utils")
        assert alpha["status"] == "IN_USE"
        assert beta["status"] == "IN_USE"
        assert alpha.get("manifest_redundant") is False
        assert beta.get("manifest_redundant") is False
