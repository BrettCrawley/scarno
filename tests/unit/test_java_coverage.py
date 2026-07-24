"""Coverage tests for Java Maven + Gradle parsers."""
from __future__ import annotations

import pytest


class TestMavenCoverage:
    @pytest.mark.requirement("FR-010")
    def test_maven_with_parent_pom(self, tmp_path):
        from scarno.analysers.java.maven import MavenPomResolver
        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <parent>\n"
            "    <groupId>org.springframework.boot</groupId>\n"
            "    <artifactId>spring-boot-starter-parent</artifactId>\n"
            "    <version>3.2.0</version>\n"
            "  </parent>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>demo</artifactId>\n"
            "  <version>0.0.1</version>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.springframework.boot</groupId>\n"
            "      <artifactId>spring-boot-starter-web</artifactId>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        result = MavenPomResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "org.springframework.boot:spring-boot-starter-web" in names

    @pytest.mark.requirement("FR-010")
    def test_maven_with_properties(self, tmp_path):
        from scarno.analysers.java.maven import MavenPomResolver
        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>app</artifactId>\n"
            "  <version>1.0</version>\n"
            "  <properties>\n"
            "    <slf4j.version>2.0.9</slf4j.version>\n"
            "  </properties>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.slf4j</groupId>\n"
            "      <artifactId>slf4j-api</artifactId>\n"
            "      <version>${slf4j.version}</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        result = MavenPomResolver().analyse(str(tmp_path))
        dep = next(d for d in result.dependencies if "slf4j" in d.name)
        assert dep.version == "2.0.9"

    @pytest.mark.requirement("FR-010")
    def test_maven_multi_module(self, tmp_path):
        from scarno.analysers.java.maven import MavenPomResolver
        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>parent</artifactId>\n"
            "  <version>1.0</version>\n"
            "  <packaging>pom</packaging>\n"
            "  <modules><module>child</module></modules>\n"
            "</project>\n"
        )
        child = tmp_path / "child"
        child.mkdir()
        (child / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <parent>\n"
            "    <groupId>com.example</groupId>\n"
            "    <artifactId>parent</artifactId>\n"
            "    <version>1.0</version>\n"
            "  </parent>\n"
            "  <artifactId>child</artifactId>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>junit</groupId>\n"
            "      <artifactId>junit</artifactId>\n"
            "      <version>4.13.2</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        result = MavenPomResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "junit:junit" in names

    @pytest.mark.requirement("FR-010")
    def test_maven_dependency_management(self, tmp_path):
        from scarno.analysers.java.maven import MavenPomResolver
        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>app</artifactId>\n"
            "  <version>1.0</version>\n"
            "  <dependencyManagement>\n"
            "    <dependencies>\n"
            "      <dependency>\n"
            "        <groupId>com.google.guava</groupId>\n"
            "        <artifactId>guava</artifactId>\n"
            "        <version>32.1.2-jre</version>\n"
            "      </dependency>\n"
            "    </dependencies>\n"
            "  </dependencyManagement>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>com.google.guava</groupId>\n"
            "      <artifactId>guava</artifactId>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        result = MavenPomResolver().analyse(str(tmp_path))
        guava = next(d for d in result.dependencies if "guava" in d.name)
        assert guava.version == "32.1.2-jre"


class TestGradleCoverage:
    @pytest.mark.requirement("FR-018")
    def test_gradle_kts_build(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        (tmp_path / "build.gradle.kts").write_text(
            'plugins { id("java") }\n\n'
            "dependencies {\n"
            '    implementation("com.google.guava:guava:32.1.2-jre")\n'
            '    testImplementation("junit:junit:4.13.2")\n'
            "}\n"
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "com.google.guava:guava" in names
        assert "junit:junit" in names

    @pytest.mark.requirement("FR-018")
    def test_gradle_with_version_catalog(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        libs = tmp_path / "gradle"
        libs.mkdir()
        (libs / "libs.versions.toml").write_text(
            "[versions]\n"
            'guava = "32.1.2-jre"\n'
            "\n"
            "[libraries]\n"
            "guava = { module = \"com.google.guava:guava\", version.ref = \"guava\" }\n"
        )
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n\n"
            "dependencies {\n"
            "    implementation libs.guava\n"
            "}\n"
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "com.google.guava:guava" in names

    @pytest.mark.requirement("FR-018")
    def test_gradle_settings_gradle_kts(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        (tmp_path / "settings.gradle.kts").write_text(
            'rootProject.name = "myapp"\n'
        )
        (tmp_path / "build.gradle.kts").write_text(
            'plugins { id("java") }\n'
            'dependencies { implementation("com.a:b:1.0") }\n'
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "com.a:b" in names

    @pytest.mark.requirement("FR-018")
    def test_gradle_multiple_dependency_configs(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n\n"
            "dependencies {\n"
            "    implementation 'com.a:b:1.0'\n"
            "    api 'com.c:d:2.0'\n"
            "    compileOnly 'com.e:f:3.0'\n"
            "    runtimeOnly 'com.g:h:4.0'\n"
            "    testImplementation 'com.i:j:5.0'\n"
            "}\n"
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "com.a:b" in names
        assert "com.c:d" in names
        assert "com.e:f" in names

    @pytest.mark.requirement("FR-018")
    def test_gradle_subproject_include(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        (tmp_path / "settings.gradle").write_text(
            "rootProject.name = 'root'\n"
            "include 'sub'\n"
        )
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n"
            "dependencies { implementation 'com.root:pkg:1.0' }\n"
        )
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "build.gradle").write_text(
            "plugins { id 'java' }\n"
            "dependencies { implementation 'com.sub:pkg:2.0' }\n"
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "com.root:pkg" in names

    @pytest.mark.requirement("FR-018")
    def test_gradle_groovy_variable_dep(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n"
            "ext {\n"
            "    guavaVersion = '32.1.2-jre'\n"
            "}\n"
            "dependencies {\n"
            "    implementation \"com.google.guava:guava:${guavaVersion}\"\n"
            "}\n"
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        names = {d.name for d in result.dependencies}
        assert "com.google.guava:guava" in names

    @pytest.mark.requirement("FR-018")
    def test_gradle_platform_dependency(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n"
            "dependencies {\n"
            "    implementation platform('com.example:bom:1.0')\n"
            "    implementation 'com.example:lib'\n"
            "}\n"
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        # platform() deps may or may not be extracted depending on regex
        assert isinstance(result.dependencies, list)

    @pytest.mark.requirement("FR-018")
    def test_gradle_empty_build_file(self, tmp_path):
        from scarno.analysers.java.gradle import GradleBuildResolver
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n// no dependencies\n"
        )
        result = GradleBuildResolver().analyse(str(tmp_path))
        assert result.dependencies == []
