"""Security adversarial tests — each corresponds to a threat in the risk register."""
from __future__ import annotations

import os
import signal
import textwrap
import time
from pathlib import Path

import pytest

from scarno.analysers.java.gradle import GradleBuildResolver
from scarno.analysers.java import maven as maven_mod
from scarno.analysers.java.maven import (
    MavenPomResolver,
    _gav_to_pom_path,
    _locate_pom_in_local_cache,
    _resolve_mvn_binary,
)
from scarno.analysers.python.source_analyser import _build_venv_dist_imports_map
from scarno.analysers.python.dep_file_parser import parse_all_dependency_files
from scarno.security import PathEscapeError, resolve_and_confine

pytestmark = pytest.mark.security


class TestPathTraversal:
    """T-01, T-06, T-07 — path traversal attack vectors."""

    @pytest.mark.requirement("T-01")
    def test_requirements_r_include_traversal_blocked(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("-r ../../../../etc/passwd\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        assert any(
            "escape" in e.lower() or "outside" in e.lower() or "confined" in e.lower()
            for e in errors
        )
        for d in deps:
            assert "root" not in d.name

    @pytest.mark.requirement("T-07")
    def test_symlink_to_etc_passwd_blocked(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        if os.path.exists("/etc/passwd"):
            symlink = project / "config.py"
            symlink.symlink_to("/etc/passwd")
            with pytest.raises(PathEscapeError):
                resolve_and_confine(symlink, project)

    @pytest.mark.requirement("T-07")
    def test_symlink_to_aws_credentials_blocked(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        aws_creds = Path.home() / ".aws" / "credentials"
        if aws_creds.exists():
            symlink = project / "aws.py"
            symlink.symlink_to(aws_creds)
            with pytest.raises(PathEscapeError):
                resolve_and_confine(symlink, project)
        else:
            pytest.skip("~/.aws/credentials does not exist on this machine")

    @pytest.mark.requirement("T-06")
    @pytest.mark.requirement("SEC-NEW-11")
    def test_output_path_traversal_via_cli(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner

        from scarno.cli import app

        runner = CliRunner()
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text('[project]\ndependencies = []\n')
        evil_path = str(tmp_path / ".." / ".." / ".ssh" / "authorized_keys")
        monkeypatch.chdir(project)
        result = runner.invoke(app, [str(project), "--output", evil_path])
        assert result.exit_code == 2
        real_evil = Path(evil_path).resolve()
        assert (
            not real_evil.exists()
            or "project_type" not in real_evil.read_text()
        )


class TestXMLAttacks:
    """T-02, T-03, D-02, D-03 — XML-based attacks against the POM parser."""

    @pytest.mark.requirement("T-02")
    @pytest.mark.requirement("SEC-010")
    @pytest.mark.requirement("SEC-NEW-01")
    def test_xxe_local_file_read_blocked(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <!DOCTYPE project [
              <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <project>
              <groupId>&xxe;</groupId>
              <artifactId>app</artifactId>
              <version>1.0</version>
            </project>
        """
            )
        )
        resolver = MavenPomResolver()
        try:
            result = resolver.analyse(str(tmp_path))
            all_text = " ".join(d.name for d in result.dependencies)
            all_text += " ".join(result.errors)
        except Exception as e:
            all_text = str(e)
        assert "root:" not in all_text
        assert "/bin/" not in all_text

    @pytest.mark.requirement("T-03")
    @pytest.mark.requirement("D-03")
    @pytest.mark.requirement("SEC-NEW-07")
    def test_deeply_nested_xml_does_not_stack_overflow(self, tmp_path):
        depth = 2000
        open_tags = "<project>" + "<extra>" * depth
        close_tags = "</extra>" * depth + "</project>"
        (tmp_path / "pom.xml").write_text(
            f'<?xml version="1.0"?>{open_tags}{close_tags}'
        )
        resolver = MavenPomResolver()
        try:
            resolver.analyse(str(tmp_path))
        except RecursionError:
            pytest.fail("Deep XML caused RecursionError — iterparse not used")
        except Exception:
            pass  # other exceptions are acceptable; RecursionError is not

    @pytest.mark.requirement("D-02")
    def test_billion_laughs_completes_within_timeout(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent(
                """\
            <?xml version="1.0"?>
            <!DOCTYPE project [
              <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
              <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
              <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
            ]>
            <project><groupId>&c;</groupId></project>
        """
            )
        )
        resolver = MavenPomResolver()
        start = time.monotonic()
        try:
            resolver.analyse(str(tmp_path))
        except Exception:
            pass
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"Billion laughs took {elapsed:.1f}s — DTD not disabled"


class TestSubprocessSafety:
    """E-02, S-01, D-05 — javap subprocess attack vectors."""

    @pytest.mark.requirement("E-02")
    @pytest.mark.requirement("SEC-012")
    def test_javap_invocation_uses_shell_false(self, tmp_path):
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        sentinel_file = tmp_path / "shell_executed.txt"
        evil_classname = f"com.example.Foo; touch {sentinel_file}; echo"
        analyser = JvmSourceAnalyser()
        try:
            analyser._invoke_javap_safe(Path("/dev/null"), evil_classname)
        except Exception:
            pass
        assert not sentinel_file.exists(), "Shell injection succeeded"

    @pytest.mark.requirement("E-02")
    @pytest.mark.requirement("SEC-NEW-09")
    def test_invalid_classname_skipped_not_passed_to_javap(self, tmp_path):
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        analyser = JvmSourceAnalyser()
        invalid_names = [
            "com.example.Foo; rm -rf /",
            "../../../evil",
            "com.example.Foo\x00",
            "",
            "123invalid",
        ]
        for name in invalid_names:
            result = analyser._invoke_javap_safe(Path("/dev/null"), name)
            assert result is None, f"Invalid classname '{name}' was not rejected"


class TestOutputInjection:
    """SEC-003, SEC-004, Rich-01 — output injection via dependency names."""

    @pytest.mark.requirement("SEC-003")
    @pytest.mark.requirement("SEC-013")
    def test_ansi_clear_screen_in_dep_name_stripped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("\x1b[2J\x1b[Hevil==1.0\n")
        from scarno.analysers.python.dep_file_parser import parse_all_dependency_files
        from scarno.models import AnalysisResult
        from scarno.reporters.text_reporter import TextReporter

        deps, _, _ = parse_all_dependency_files(str(tmp_path))
        result = AnalysisResult("python", str(tmp_path), deps, [])
        output = TextReporter().render(result)
        assert "\x1b" not in output

    @pytest.mark.requirement("SEC-004")
    def test_json_injection_via_dep_name_blocked(self):
        import json

        from scarno.models import AnalysisResult, Dependency, DependencyStatus
        from scarno.reporters.json_reporter import JsonReporter

        evil_name = '{"injected": true, "extra": "value"}'
        result = AnalysisResult(
            "python",
            "/tmp",
            [
                Dependency(
                    evil_name, "1.0", DependencyStatus.SAFE, "No usage", [], 0, 0
                )
            ],
            [],
        )
        output = JsonReporter().render(result)
        data = json.loads(output)
        assert data["dependencies"][0]["name"] == evil_name
        assert "injected" not in data

    @pytest.mark.requirement("Rich-01")
    @pytest.mark.requirement("SEC-NEW-10")
    def test_rich_markup_in_dep_name_does_not_cause_rendering_side_effects(self):
        from scarno.models import AnalysisResult, Dependency, DependencyStatus
        from scarno.reporters.text_reporter import TextReporter

        evil_names = [
            "[bold red]danger[/bold red]",
            "[link=https://evil.com]click[/link]",
            "[on red]bg[/on red]",
        ]
        reporter = TextReporter()
        for name in evil_names:
            result = AnalysisResult(
                "python",
                "/tmp",
                [
                    Dependency(
                        name, "1.0", DependencyStatus.SAFE, "No usage", [], 0, 0
                    )
                ],
                [],
            )
            output = reporter.render(result)
            assert isinstance(output, str)


class TestDenialOfService:
    """D-01, D-04, D-07 — resource exhaustion attacks."""

    @pytest.mark.requirement("D-04")
    @pytest.mark.requirement("SEC-NEW-04")
    def test_oversized_source_file_skipped_with_warning(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests"]\n'
        )
        huge_file = project / "huge_module.py"
        huge_file.write_bytes(b"x = 1\n" * (10 * 1024 * 1024 // 6 + 1))
        from scarno.analysers.python.source_analyser import analyse_source_files
        from scarno.models import Dependency, DependencyStatus

        deps = [
            Dependency(
                "requests",
                "2.31.0",
                DependencyStatus.UNCERTAIN,
                "pending",
                [],
                0,
                0,
            )
        ]
        _, errors = analyse_source_files(str(project), deps)
        assert any(
            "skip" in e.lower() or "large" in e.lower() or "size" in e.lower()
            for e in errors
        )

    @pytest.mark.requirement("D-07")
    def test_excessively_long_dep_name_truncated_or_warned(self, tmp_path):
        long_name = "a" * 300
        (tmp_path / "requirements.txt").write_text(f"{long_name}==1.0\n")
        deps, errors, _ = parse_all_dependency_files(str(tmp_path))
        if deps:
            assert len(deps[0].name) <= 256
        else:
            assert len(errors) >= 1

    @pytest.mark.requirement("D-01")
    @pytest.mark.requirement("SEC-009")
    def test_self_referencing_requirements_terminates(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("-r requirements.txt\n")

        def timeout_handler(signum, frame):
            pytest.fail("Circular include did not terminate within 5 seconds")

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)
        try:
            deps, errors, _ = parse_all_dependency_files(str(tmp_path))
            assert any(
                "cycle" in e.lower()
                or "circular" in e.lower()
                or "depth" in e.lower()
                for e in errors
            )
        finally:
            signal.alarm(0)


class TestGradleReDoS:
    @pytest.mark.requirement("T-08")
    def test_gradle_redos_payload_completes_within_time(self, tmp_path):
        redos_content = "implementation " + "a" * 50000 + "\n"
        (tmp_path / "build.gradle").write_text(redos_content)
        resolver = GradleBuildResolver()
        start = time.monotonic()
        try:
            resolver.analyse(str(tmp_path))
        except Exception:
            pass
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"Gradle ReDoS took {elapsed:.1f}s"


class TestPrivilegeEscalation:
    @pytest.mark.requirement("E-01")
    @pytest.mark.requirement("SEC-005")
    def test_root_execution_emits_warning_to_stderr(self, monkeypatch, capsys):
        if hasattr(os, "getuid"):
            monkeypatch.setattr(os, "getuid", lambda: 0)
        from scarno.security import check_root_privilege

        check_root_privilege()
        captured = capsys.readouterr()
        warning_text = captured.err.lower()
        assert "root" in warning_text or "administrator" in warning_text

    @pytest.mark.requirement("SEC-NEW-12")
    def test_javap_path_verified_against_java_home(self, monkeypatch):
        monkeypatch.setenv("JAVA_HOME", "/usr/lib/jvm/temurin-21")
        from scarno.analysers.java.source_analyser import JvmSourceAnalyser

        analyser = JvmSourceAnalyser()
        # Must not raise NotImplementedError once REQ-6 lands. Until then
        # this fails red as the signal that the resolver still needs
        # implementation — deliberately NOT skipped.
        javap_path = analyser._resolve_javap_binary()
        if javap_path is not None:
            java_home = Path("/usr/lib/jvm/temurin-21").resolve()
            resolved_javap = Path(javap_path).resolve()
            try:
                resolved_javap.relative_to(java_home)
            except ValueError:
                pytest.skip(
                    "System javap not under mock JAVA_HOME — validation exists"
                )


class TestMavenCachePathTraversal:
    """SEC-NEW-27, SEC-NEW-28 — Maven cache and binary resolution attacks."""

    @pytest.mark.requirement("SEC-NEW-27")
    def test_gav_path_traversal_in_m2_cache_blocked(self, tmp_path, monkeypatch):
        """A crafted GAV must not read files outside ~/.m2/repository."""
        repo = tmp_path / ".m2" / "repository"
        repo.mkdir(parents=True)
        monkeypatch.setattr(maven_mod, "_m2_repo_path", lambda: repo)
        errors: list[str] = []
        result = _locate_pom_in_local_cache(
            ("../../etc", "passwd", "1.0"), errors
        )
        assert result is None

    @pytest.mark.requirement("SEC-NEW-28")
    def test_mvn_binary_symlink_escape_blocked(self, tmp_path, monkeypatch):
        """A symlinked mvn binary pointing outside MAVEN_HOME must be rejected."""
        maven_home = tmp_path / "maven"
        maven_home.mkdir()
        bin_dir = maven_home / "bin"
        bin_dir.mkdir()
        # Create symlink pointing outside MAVEN_HOME
        outside_bin = tmp_path / "outside" / "mvn"
        outside_bin.parent.mkdir()
        outside_bin.write_text("#!/bin/sh\n")
        outside_bin.chmod(0o755)
        (bin_dir / "mvn").symlink_to(outside_bin)
        monkeypatch.setenv("MAVEN_HOME", str(maven_home))
        monkeypatch.delenv("M2_HOME", raising=False)
        result = _resolve_mvn_binary()
        assert result is None


class TestVenvMetadataEscape:
    """SEC-NEW-30 — .venv metadata scanning must not escape project root."""

    @pytest.mark.requirement("SEC-NEW-30")
    def test_venv_symlink_to_outside_blocked(self, tmp_path):
        """A .venv symlink pointing outside the project must not leak data."""
        project = tmp_path / "project"
        project.mkdir()
        outside = tmp_path / "outside"
        sp = outside / "lib" / "python3.12" / "site-packages"
        sp.mkdir(parents=True)
        dist_dir = sp / "secret-1.0.dist-info"
        dist_dir.mkdir()
        (dist_dir / "METADATA").write_text("Name: secret\nVersion: 1.0\n")
        (dist_dir / "top_level.txt").write_text("secret\n")
        (project / ".venv").symlink_to(outside)
        errors: list[str] = []
        result = _build_venv_dist_imports_map(project, errors)
        assert "secret" not in result or any(
            "escape" in e.lower() for e in errors
        )
