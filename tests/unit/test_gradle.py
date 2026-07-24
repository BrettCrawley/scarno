"""Tests for the Gradle build resolver — REQ-5.

Placeholder test bodies derived from REQ-5 acceptance criteria. Each test
carries an SRTM marker so coverage is tracked even while the resolver is
unimplemented.
"""
from __future__ import annotations

import textwrap

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

    @pytest.mark.requirement("T-08")
    @pytest.mark.security
    def test_malformed_gradle_file_does_not_crash(self, tmp_path, resolver):
        (tmp_path / "build.gradle").write_text("dependencies { { { { { {\n")
        result = resolver.analyse(str(tmp_path))
        assert hasattr(result, "errors")
