"""CLI auto-name + markdown-default-format contract.

Markdown is now the default ``--format``. When ``--output`` is omitted
AND the format is markdown, the CLI auto-derives a path of the form
``<project-name>-analysis-report.md`` in CWD.

Tested contracts:

1. Project name is read from pyproject.toml / package.json / pom.xml /
   go.mod / Gradle settings / *.csproj, in that priority order.
2. Spaces and other unsafe characters collapse to ``-``.
3. No manifest → ``analysis-report.md`` fallback.
4. Non-markdown formats keep the old stdout-default behaviour (no
   auto-write) so piped tooling is unaffected.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from scarno.cli import (
    _derive_default_output_path,
    _derive_project_name,
    _sanitise_project_name_for_filename,
)


class TestSanitiseProjectNameForFilename:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("simple", "simple"),
            ("with space", "with-space"),
            ("multiple  spaces", "multiple-spaces"),
            ("path/like", "path-like"),
            ("colon:case", "colon-case"),
            ("dots.are.fine", "dots.are.fine"),
            ("hyphen-kept", "hyphen-kept"),
            ("under_score_kept", "under_score_kept"),
            ("  trim me  ", "trim-me"),
            ("--leading-and-trailing--", "leading-and-trailing"),
            ("..leading.dots", "leading.dots"),
        ],
    )
    def test_sanitisation(self, raw, expected):
        assert _sanitise_project_name_for_filename(raw) == expected

    def test_empty_input_returns_empty(self):
        assert _sanitise_project_name_for_filename("") == ""
        assert _sanitise_project_name_for_filename("   ") == ""


class TestDeriveProjectName:
    def test_pyproject_wins(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "from-pyproject"\nversion = "1.0"\n',
        )
        (tmp_path / "package.json").write_text(
            '{"name": "from-package-json"}',
        )
        assert _derive_project_name(tmp_path) == "from-pyproject"

    def test_package_json_when_no_pyproject(self, tmp_path):
        (tmp_path / "package.json").write_text(
            '{"name": "from-npm"}',
        )
        assert _derive_project_name(tmp_path) == "from-npm"

    def test_pom_xml_name_preferred_over_artifact_id(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            "<project>"
            "<artifactId>my-art</artifactId>"
            "<name>My Human Readable Name</name>"
            "</project>",
        )
        assert _derive_project_name(tmp_path) == "My Human Readable Name"

    def test_pom_xml_falls_back_to_artifact_id(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            "<project><artifactId>my-art</artifactId></project>",
        )
        assert _derive_project_name(tmp_path) == "my-art"

    def test_go_mod_uses_last_segment(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module github.com/example/myproj\n\ngo 1.21\n",
        )
        assert _derive_project_name(tmp_path) == "myproj"

    def test_gradle_settings_kts(self, tmp_path):
        (tmp_path / "settings.gradle.kts").write_text(
            'rootProject.name = "gradle-app"\n',
        )
        assert _derive_project_name(tmp_path) == "gradle-app"

    def test_gradle_settings_groovy(self, tmp_path):
        (tmp_path / "settings.gradle").write_text(
            "rootProject.name = 'gradle-app-groovy'\n",
        )
        assert _derive_project_name(tmp_path) == "gradle-app-groovy"

    def test_csproj_stem(self, tmp_path):
        (tmp_path / "MyApp.csproj").write_text("<Project></Project>")
        assert _derive_project_name(tmp_path) == "MyApp"

    def test_returns_none_when_no_manifest(self, tmp_path):
        assert _derive_project_name(tmp_path) is None

    def test_returns_none_for_non_directory(self, tmp_path):
        bogus = tmp_path / "does-not-exist"
        assert _derive_project_name(bogus) is None

    def test_oversize_manifest_treated_as_missing(self, tmp_path):
        # 2 MiB pyproject.toml — over the 1 MiB safety cap.
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\n' + "# " + "a" * (2 * 1024 * 1024),
        )
        # Falls through to None (no other manifests).
        assert _derive_project_name(tmp_path) is None

    def test_malformed_pyproject_falls_through(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("not = valid = toml\n")
        (tmp_path / "package.json").write_text('{"name": "fallback"}')
        # Pyproject parses fail → next manifest tried.
        assert _derive_project_name(tmp_path) == "fallback"


class TestDeriveDefaultOutputPath:
    def test_uses_sanitised_project_name(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "Hello World"\n',
        )
        # Pin CWD so the test asserts against a known prefix.
        monkeypatch.chdir(tmp_path)
        result = _derive_default_output_path(tmp_path)
        assert result == tmp_path / "Hello-World-analysis-report.md"

    def test_fallback_when_no_name(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = _derive_default_output_path(tmp_path)
        assert result == tmp_path / "analysis-report.md"

    def test_anchored_at_cwd_not_project(self, tmp_path, monkeypatch):
        """The report lands in CWD, never inside the analysed project."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\nname = "scoped"\n',
        )
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        result = _derive_default_output_path(project)
        assert result == elsewhere / "scoped-analysis-report.md"
        # Critically NOT under the project directory.
        assert project not in result.parents


class TestMarkdownDefaultEndToEnd:
    """The headline contract: omitting both --format and --output writes
    a markdown report to ``<project-name>-analysis-report.md`` in CWD."""

    def test_omit_everything_writes_md_with_project_name(
        self, tmp_path, monkeypatch
    ):
        from typer.testing import CliRunner
        from scarno.cli import app

        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["boto3"]\n',
        )
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [str(tmp_path)])
        assert result.exit_code in (0, 1)
        # The auto-written file should exist with the derived name.
        written = tmp_path / "demo-analysis-report.md"
        assert written.exists(), (
            f"expected {written} to be auto-written; "
            f"stdout={result.output!r}"
        )
        assert "# Scarno analysis" in written.read_text(encoding="utf-8")

    def test_non_markdown_format_still_writes_stdout(
        self, tmp_path, monkeypatch
    ):
        """Sanity — JSON / SARIF / text default behaviour is unchanged
        (omitted --output → stdout, no auto-file)."""
        from typer.testing import CliRunner
        from scarno.cli import app

        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["boto3"]\n',
        )
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(
            app, [str(tmp_path), "--format", "json"],
        )
        assert result.exit_code in (0, 1)
        # No auto-file should exist for non-markdown formats.
        assert not (tmp_path / "demo-analysis-report.md").exists()
        # JSON content lands on stdout as before.
        assert result.output.lstrip().startswith("{")


@pytest.mark.security
@pytest.mark.performance
class TestPomNameRedosRegression:
    """``_read_pom_xml_name`` must stay linear on hostile pom.xml text.

    The name/artifactId patterns used to be ``<tag>\\s*([^<]+?)\\s*</tag>``,
    where the leading ``\\s*``, the lazy ``[^<]+?`` and the trailing
    ``\\s*`` could all match the same whitespace characters. A ``<name>``
    token that never closes — trivially achieved inside an XML comment,
    which keeps the document well-formed so the Maven analyser still
    parses it — made the search backtrack cubically over an
    attacker-controlled whitespace run and the scan never finished.
    """

    # Comfortably under the 1 MiB _MANIFEST_MAX_BYTES read cap, so these
    # tests exercise the matcher itself rather than the size guard.
    PAYLOAD_WHITESPACE_BYTES = 200_000

    def _write_hostile_pom(self, tmp_path: Path) -> Path:
        from scarno.cli import _MANIFEST_MAX_BYTES

        pom = tmp_path / "pom.xml"
        # Well-formed XML: the <name> token lives inside a comment, so it
        # is never closed by a real </name>.
        pom.write_text(
            "<project><artifactId>safe-art</artifactId>"
            "<!-- <name>" + " " * self.PAYLOAD_WHITESPACE_BYTES
            + "--></project>",
        )
        assert pom.stat().st_size < _MANIFEST_MAX_BYTES, (
            "payload must stay under the read cap or the cap, not the "
            "regex fix, is what makes this test pass"
        )
        return pom

    def test_unclosed_name_token_does_not_hang(self, tmp_path):
        """The headline regression.

        Against the old ambiguous pattern this payload needs on the
        order of 1e11 backtracking steps (measured: 400 whitespace
        bytes already cost 30 ms and the cost is cubic, so 200 KB is
        many hours). With the possessive ``[^<]++`` capture the whole
        derivation completes in well under a millisecond.
        """
        self._write_hostile_pom(tmp_path)
        start = time.monotonic()
        name = _derive_project_name(tmp_path)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"pom name derivation took {elapsed:.2f}s — the <name> "
            f"pattern is backtracking again"
        )
        # And it still produces the right answer: no usable <name>, so
        # the <artifactId> fallback wins.
        assert name == "safe-art"

    def test_unclosed_artifact_id_token_does_not_hang(self, tmp_path):
        """Same shape on the ``<artifactId>`` fallback pattern, which is
        only reached when no ``<name>`` matched."""
        pom = tmp_path / "pom.xml"
        pom.write_text(
            "<project><!-- <artifactId>"
            + " " * self.PAYLOAD_WHITESPACE_BYTES
            + "--></project>",
        )
        start = time.monotonic()
        name = _derive_project_name(tmp_path)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"pom artifactId derivation took {elapsed:.2f}s — the "
            f"<artifactId> pattern is backtracking again"
        )
        # Nothing derivable from this pom and no other manifest.
        assert name is None

    def test_surrounding_whitespace_is_still_trimmed(self, tmp_path):
        """Behaviour guard for the rewrite.

        The old pattern trimmed padding via its edge ``\\s*`` groups; the
        new one captures the raw run and relies on the existing
        ``.strip()``. Both must yield the same name.
        """
        (tmp_path / "pom.xml").write_text(
            "<project><artifactId>my-art</artifactId>"
            "<name>\n    My Human Readable Name  \t\n</name>"
            "</project>",
        )
        assert _derive_project_name(tmp_path) == "My Human Readable Name"

    def test_blank_name_element_falls_back_to_artifact_id(self, tmp_path):
        """A whitespace-only <name> strips to empty and must not win."""
        (tmp_path / "pom.xml").write_text(
            "<project><artifactId>my-art</artifactId>"
            "<name>   </name></project>",
        )
        assert _derive_project_name(tmp_path) == "my-art"
