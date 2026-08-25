"""Tests for the Gradle build resolver — REQ-5.

Placeholder test bodies derived from REQ-5 acceptance criteria. Each test
carries an SRTM marker so coverage is tracked even while the resolver is
unimplemented.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scarno.analysers.java.gradle import GradleBuildResolver


@pytest.fixture
def resolver() -> GradleBuildResolver:
    return GradleBuildResolver()


class TestGroovyDSL:
    @pytest.mark.requirement("FR-018")
    def test_implementation_dep_parsed(self, tmp_path, resolver):
        (tmp_path / "build.gradle").write_text(
            textwrap.dedent(
                """\
            dependencies {
                implementation 'com.google.guava:guava:32.1.2-jre'
            }
        """
            )
        )
        result = resolver.analyse(str(tmp_path))
        assert any("guava" in d.name for d in result.dependencies)

    @pytest.mark.requirement("FR-018")
    def test_test_implementation_parsed(self, tmp_path, resolver):
        (tmp_path / "build.gradle").write_text(
            textwrap.dedent(
                """\
            dependencies {
                testImplementation 'junit:junit:4.13.2'
            }
        """
            )
        )
        result = resolver.analyse(str(tmp_path))
        assert any("junit" in d.name for d in result.dependencies)


class TestKotlinDSL:
    @pytest.mark.requirement("FR-018")
    def test_implementation_dep_parsed_kotlin(self, tmp_path, resolver):
        (tmp_path / "build.gradle.kts").write_text(
            textwrap.dedent(
                """\
            dependencies {
                implementation("com.google.guava:guava:32.1.2-jre")
            }
        """
            )
        )
        result = resolver.analyse(str(tmp_path))
        assert any("guava" in d.name for d in result.dependencies)


class TestVersionResolution:
    @pytest.mark.requirement("FR-018")
    def test_ext_variable_resolved(self, tmp_path, resolver):
        (tmp_path / "build.gradle").write_text(
            textwrap.dedent(
                """\
            ext.guavaVersion = '32.1.2-jre'
            dependencies {
                implementation "com.google.guava:guava:${guavaVersion}"
            }
        """
            )
        )
        result = resolver.analyse(str(tmp_path))
        guava = next((d for d in result.dependencies if "guava" in d.name), None)
        assert guava is not None
        assert guava.version == "32.1.2-jre"

    @pytest.mark.requirement("FR-018")
    def test_unresolvable_version_warns(self, tmp_path, resolver):
        (tmp_path / "build.gradle").write_text(
            textwrap.dedent(
                """\
            dependencies {
                implementation "com.example:foo:${unknownVersion}"
            }
        """
            )
        )
        result = resolver.analyse(str(tmp_path))
        assert any("resolve" in e.lower() or "version" in e.lower() for e in result.errors)


class TestVersionCatalog:
    @pytest.mark.requirement("FR-018")
    def test_libs_versions_toml_alias_resolved(self, tmp_path, resolver):
        catalog_dir = tmp_path / "gradle"
        catalog_dir.mkdir()
        (catalog_dir / "libs.versions.toml").write_text(
            textwrap.dedent(
                """\
            [versions]
            guava = "32.1.2-jre"

            [libraries]
            guava = { group = "com.google.guava", name = "guava", version.ref = "guava" }
        """
            )
        )
        (tmp_path / "build.gradle.kts").write_text(
            textwrap.dedent(
                """\
            dependencies {
                implementation(libs.guava)
            }
        """
            )
        )
        result = resolver.analyse(str(tmp_path))
        guava = next((d for d in result.dependencies if "guava" in d.name), None)
        assert guava is not None
        assert guava.version == "32.1.2-jre"


class TestMultiModule:
    @pytest.mark.requirement("FR-018")
    def test_settings_include_discovers_submodule(self, tmp_path, resolver):
        (tmp_path / "settings.gradle").write_text("include 'module-a'\n")
        (tmp_path / "build.gradle").write_text("dependencies {}\n")
        module_a = tmp_path / "module-a"
        module_a.mkdir()
        (module_a / "build.gradle").write_text(
            "dependencies {\n  implementation 'com.google.guava:guava:32.1.2-jre'\n}\n"
        )
        result = resolver.analyse(str(tmp_path))
        assert any("guava" in d.name for d in result.dependencies)

    @pytest.mark.requirement("FR-018")
    def test_in_tree_symlinked_build_file_keeps_module_source(
        self, tmp_path, resolver
    ):
        """A submodule build file symlinked *inside* the project keeps its
        module-relative provenance in ``Dependency.source``."""
        (tmp_path / "settings.gradle").write_text("include 'module-a'\n")
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "common.gradle").write_text(
            "dependencies {\n  implementation 'com.google.guava:guava:32.1.2-jre'\n}\n"
        )
        module_a = tmp_path / "module-a"
        module_a.mkdir()
        (module_a / "build.gradle").symlink_to(shared / "common.gradle")

        result = resolver.analyse(str(tmp_path))

        guava = next((d for d in result.dependencies if "guava" in d.name), None)
        assert guava is not None
        assert guava.source == f"{Path('module-a') / 'build.gradle'}:implementation"


class TestSecurity:
    @pytest.mark.requirement("SEC-011")
    @pytest.mark.security
    def test_gradle_parsing_uses_no_subprocess(self, tmp_path, resolver, monkeypatch):
        """Gradle parsing must never shell out to gradle/groovy/kotlin."""
        import subprocess

        called: list[str] = []

        def _record(*args, **kwargs):
            called.append("subprocess.run called")
            raise AssertionError("subprocess.run must not be invoked by Gradle parser")

        monkeypatch.setattr(subprocess, "run", _record)
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n  implementation 'com.google.guava:guava:32.1.2-jre'\n}\n"
        )
        try:
            resolver.analyse(str(tmp_path))
        except AssertionError:
            raise
        except Exception:
            pass
        assert called == []

    @pytest.mark.requirement("SEC-002")
    @pytest.mark.security
    @pytest.mark.parametrize("relative_link", [False, True])
    def test_symlinked_submodule_build_file_outside_root_skipped(
        self, tmp_path, resolver, relative_link
    ):
        """`<included-dir>/build.gradle` symlinked out of the tree is not read.

        Confining the included *directory* is not enough — the build file
        inside it is a separate path that the untrusted settings file can
        point anywhere.
        """
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.gradle"
        secret.write_text(
            "dependencies {\n"
            "  implementation 'com.evil:leaked-secret:6.6.6'\n"
            "  implementation 'not-a-valid-coordinate'\n"
            "}\n"
        )
        project = tmp_path / "project"
        project.mkdir()
        (project / "settings.gradle").write_text("include 'module-a'\n")
        (project / "build.gradle").write_text("dependencies {}\n")
        module_a = project / "module-a"
        module_a.mkdir()
        target = (
            Path("..") / ".." / "outside" / "secret.gradle"
            if relative_link
            else secret
        )
        (module_a / "build.gradle").symlink_to(target)

        result = resolver.analyse(str(project))

        assert not any("leaked-secret" in d.name for d in result.dependencies)
        joined = " ".join(result.errors)
        # No content from the out-of-tree file, and no absolute path to it.
        assert "leaked-secret" not in joined
        assert "not-a-valid-coordinate" not in joined
        assert str(secret) not in joined
        assert str(outside) not in joined
        assert any("escapes project root" in e for e in result.errors)

    @pytest.mark.requirement("T-08")
    @pytest.mark.security
    def test_malformed_gradle_file_does_not_crash(self, tmp_path, resolver):
        (tmp_path / "build.gradle").write_text("dependencies { { { { { {\n")
        result = resolver.analyse(str(tmp_path))
        assert hasattr(result, "errors")
