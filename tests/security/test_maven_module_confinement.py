"""Adversarial tests — Maven ``<module>`` confinement before filesystem access.

The ``<module>`` text in a POM is attacker-controlled. It must be
confined to the project root BEFORE it is joined and probed, otherwise
an adversarial POM gets a filesystem existence oracle for arbitrary
absolute paths on the operator's host, and the resolved out-of-root path
is rendered into the shared report.

The token echoed back into the warning must be sanitised (no escape
sequences, control characters, or line breaks that could forge report
lines) but otherwise left intact, so the warning still names the module
the operator actually wrote.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scarno.analysers.java.maven import MavenPomResolver
from scarno.security import sanitise_token


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _root_pom(*modules: str) -> str:
    module_lines = "\n".join(f"    <module>{m}</module>" for m in modules)
    return (
        '<?xml version="1.0"?>\n'
        "<project>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>root</artifactId>\n"
        "  <version>1.0</version>\n"
        "  <modules>\n"
        f"{module_lines}\n"
        "  </modules>\n"
        "</project>\n"
    )


class TestModuleEscapeNotProbed:
    @pytest.mark.requirement("SEC-002")
    @pytest.mark.requirement("SEC-NEW-05")
    @pytest.mark.security
    def test_out_of_root_module_is_no_existence_oracle(self, tmp_path):
        """An escaping <module> must not leak whether its target exists.

        The same POM is analysed twice against the same absolute paths —
        once with the out-of-root ``pom.xml`` present, once with it
        absent. If the module is joined and stat()ed before confinement,
        the two runs report different warnings and the analysed host's
        filesystem layout leaks into the report.
        """
        project = tmp_path / "project"
        outside = tmp_path / "outside" / "target"
        _write(project / "pom.xml", _root_pom("../outside/target"))
        _write(
            outside / "pom.xml",
            textwrap.dedent(
                """\
                <?xml version="1.0"?>
                <project>
                  <groupId>com.example</groupId>
                  <artifactId>outside</artifactId>
                  <version>1.0</version>
                </project>
                """
            ),
        )

        resolver = MavenPomResolver()
        errors_present = list(resolver.analyse(str(project)).errors)

        (outside / "pom.xml").unlink()
        outside.rmdir()
        errors_absent = list(MavenPomResolver().analyse(str(project)).errors)

        assert errors_present == errors_absent, (
            "existence oracle: the report differs depending on whether an "
            "out-of-root path exists on the operator's host — "
            f"present={errors_present!r} absent={errors_absent!r}"
        )
        joined = " ".join(errors_present)
        assert str(tmp_path / "outside") not in joined, (
            f"out-of-root absolute path leaked into the report: {joined!r}"
        )

    @pytest.mark.requirement("SEC-002")
    @pytest.mark.requirement("SEC-NEW-05")
    @pytest.mark.security
    def test_absolute_module_path_is_not_probed(self, tmp_path):
        """An absolute <module> must not be resolved against the filesystem.

        The token itself is whatever the POM author wrote, so echoing it
        back reveals nothing new; what must never appear is a path this
        process derived by resolving it, and the outcome must not depend
        on what is on disk.
        """
        project = tmp_path / "project"
        outside = tmp_path / "outside"
        _write(project / "pom.xml", _root_pom(str(outside)))
        _write(outside / "pom.xml", "<project/>\n")

        errors_present = list(MavenPomResolver().analyse(str(project)).errors)

        (outside / "pom.xml").unlink()
        outside.rmdir()
        errors_absent = list(MavenPomResolver().analyse(str(project)).errors)

        assert errors_present == errors_absent, (
            "existence oracle: the report differs depending on whether an "
            "out-of-root path exists on the operator's host — "
            f"present={errors_present!r} absent={errors_absent!r}"
        )
        joined = " ".join(errors_present)
        assert str(outside / "pom.xml") not in joined, (
            f"resolved out-of-root path leaked into the report: {joined!r}"
        )


class TestModuleTokenEchoedFaithfully:
    @pytest.mark.requirement("SEC-NEW-03")
    @pytest.mark.requirement("SEC-003")
    @pytest.mark.security
    def test_module_token_is_sanitised_but_not_rewritten(self, tmp_path):
        """The echoed token loses control characters, nothing else.

        ``clickhouse-connector`` is the regression guard: sanitising the
        token with the declared-version helper would strip the reserved
        word ``click`` and report a directory that does not exist.
        """
        project = tmp_path / "project"
        _write(
            project / "pom.xml",
            _root_pom(
                "clickhouse-connector",
                "subgraph-svc",
                "my_module",
                "forged\nWARNINGS (1)",
            ),
        )
        # A legitimate module that DOES have a pom.xml must still be
        # traversed and its dependency collected.
        _write(
            project / "clickhouse-connector" / "pom.xml",
            textwrap.dedent(
                """\
                <?xml version="1.0"?>
                <project>
                  <groupId>com.example</groupId>
                  <artifactId>clickhouse-connector</artifactId>
                  <version>1.0</version>
                  <dependencies>
                    <dependency>
                      <groupId>com.acme</groupId>
                      <artifactId>widget</artifactId>
                      <version>2.3.4</version>
                    </dependency>
                  </dependencies>
                </project>
                """
            ),
        )

        result = MavenPomResolver().analyse(str(project))

        assert any(d.name == "com.acme:widget" for d in result.dependencies), (
            "in-tree module 'clickhouse-connector' was no longer traversed"
        )
        # Modules without a pom.xml are named exactly as written.
        assert "Module 'subgraph-svc' has no pom.xml" in result.errors
        assert "Module 'my_module' has no pom.xml" in result.errors
        # The forged token cannot break out of its warning line.
        assert not any("\n" in e or "\r" in e for e in result.errors), (
            f"module token forged a report line: {result.errors!r}"
        )
        assert "Module 'forgedWARNINGS (1)' has no pom.xml" in result.errors


class TestSanitiseToken:
    @pytest.mark.requirement("SEC-NEW-03")
    @pytest.mark.requirement("SEC-003")
    @pytest.mark.security
    def test_strips_escapes_controls_and_markdown_actives(self):
        assert sanitise_token("\x1b[31mred\x1b[0m") == "red"
        assert sanitise_token("a\nb\rc\td") == "abcd"
        assert sanitise_token("a\x00b\x7fc") == "abc"
        # U+0085 (NEL) is a line break to str.splitlines and is not
        # covered by strip_control_chars; sanitise_token removes it.
        assert sanitise_token("a\x85b") == "ab"
        assert sanitise_token('a[b]c"d\\e|f`g') == "abcdefg"

    @pytest.mark.requirement("SEC-NEW-03")
    @pytest.mark.security
    def test_preserves_legitimate_tokens_verbatim(self):
        for token in (
            "clickhouse-connector",
            "subgraph-svc",
            "classDef-mod",
            "linkStyle-x",
            "my_module",
            "services/api",
            "a" * 80,
        ):
            assert sanitise_token(token) == token
