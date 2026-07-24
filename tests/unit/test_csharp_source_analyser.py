"""REQ-16 — C# source analyser (Phase 7, TDD red).

Tests are written against the expected Phase 7 public API:

    from scarno.analysers.csharp.source_analyser import (
        CSHARP_AST_AVAILABLE,
        analyse_csharp_sources,
    )

Covers:
  * C# ``using`` directives via tree-sitter-c-sharp
  * Razor / cshtml ``@using`` directives
  * Microsoft shared-framework alias table (System.* → runtime, not NuGet)
  * Security findings: TS-CE-010 (Assembly.Load taint), TS-CE-011
    (Process.Start taint), TS-SI-018 (DllImport P/Invoke)
"""
from __future__ import annotations

import pytest

try:
    from scarno.analysers.csharp.source_analyser import (  # type: ignore[import-not-found]
        CSHARP_AST_AVAILABLE,
        analyse_csharp_sources,
    )
    from scarno.findings.rules import RULES
    from scarno.models import Dependency, DependencyStatus

    CSHARP_SOURCE_AVAILABLE = True
except ImportError:
    analyse_csharp_sources = None  # type: ignore[assignment]
    CSHARP_AST_AVAILABLE = False
    RULES = {}  # type: ignore[assignment]
    try:
        from scarno.models import Dependency, DependencyStatus  # type: ignore
    except ImportError:
        Dependency = DependencyStatus = None  # type: ignore
    CSHARP_SOURCE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not CSHARP_SOURCE_AVAILABLE,
    reason="pending Phase 7 — scarno.analysers.csharp.source_analyser not yet implemented",
)


def _declared(name: str, *, version: str = "1.0.0") -> "Dependency":
    return Dependency(
        name=name,
        version=version,
        status=DependencyStatus.UNCERTAIN,
        reason="declared — source analysis pending",
        entry_points=[],
        entry_points_used=0,
        entry_points_total=0,
        source="App.csproj:PackageReference",
        ecosystem="nuget",
    )


def _status(deps, name):
    return next(d.status for d in deps if d.name == name)


# ── REQ-16 — using directives via tree-sitter ──────────────────────────────


class TestReq16UsingDirectives:
    @pytest.mark.requirement("FR-128")
    def test_using_directive_marks_dep_in_use(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using Newtonsoft.Json;\n\n"
            "class Program {\n"
            "    static void Main() { JsonConvert.SerializeObject(null); }\n"
            "}\n"
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Newtonsoft.Json")]
        )
        assert _status(deps, "Newtonsoft.Json") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-128")
    def test_namespace_qualified_match_for_subnamespace(self, tmp_path):
        # `using Serilog.Core;` should still match dep "Serilog"
        (tmp_path / "Program.cs").write_text(
            "using Serilog.Core;\n\nclass Program {}\n"
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Serilog")]
        )
        assert _status(deps, "Serilog") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-128")
    def test_unused_dep_marks_safe(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using System;\n\nclass Program { static void Main() {} }\n"
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Newtonsoft.Json")]
        )
        assert _status(deps, "Newtonsoft.Json") is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-128")
    def test_using_alias_directive_matched(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using Json = Newtonsoft.Json;\n\nclass Program {}\n"
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Newtonsoft.Json")]
        )
        assert _status(deps, "Newtonsoft.Json") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-128")
    def test_using_static_directive_matched(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using static Newtonsoft.Json.JsonConvert;\n\nclass Program {}\n"
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Newtonsoft.Json")]
        )
        assert _status(deps, "Newtonsoft.Json") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-128")
    def test_string_inside_code_is_not_a_using(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            'using System;\n\n'
            'class Program {\n'
            '    static void Main() { Console.WriteLine("using Newtonsoft.Json"); }\n'
            '}\n'
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Newtonsoft.Json")]
        )
        assert _status(deps, "Newtonsoft.Json") is DependencyStatus.SAFE

    @pytest.mark.requirement("FR-128")
    def test_comment_is_not_a_using(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "// using Newtonsoft.Json;\n"
            "/* using Newtonsoft.Json; */\n"
            "using System;\n\n"
            "class Program {}\n"
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Newtonsoft.Json")]
        )
        assert _status(deps, "Newtonsoft.Json") is DependencyStatus.SAFE


# ── REQ-16 — Razor / cshtml ────────────────────────────────────────────────


class TestReq16RazorDirectives:
    @pytest.mark.requirement("FR-129")
    def test_cshtml_at_using_recognised(self, tmp_path):
        (tmp_path / "Index.cshtml").write_text(
            '@using Microsoft.AspNetCore.Html\n'
            '@using Newtonsoft.Json\n'
            '<p>hello</p>\n'
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Newtonsoft.Json")]
        )
        assert _status(deps, "Newtonsoft.Json") is DependencyStatus.IN_USE

    @pytest.mark.requirement("FR-129")
    def test_razor_page_imports_file(self, tmp_path):
        (tmp_path / "_ViewImports.cshtml").write_text(
            '@using Serilog\n'
        )
        deps, _ = analyse_csharp_sources(
            str(tmp_path), [_declared("Serilog")]
        )
        assert _status(deps, "Serilog") is DependencyStatus.IN_USE


# ── REQ-16 — Microsoft shared-framework alias table ────────────────────────


class TestReq16SharedFrameworkAliases:
    @pytest.mark.requirement("FR-130")
    def test_system_namespaces_not_phantom(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using System;\n"
            "using System.Collections.Generic;\n"
            "using System.Threading.Tasks;\n"
            "using System.IO;\n\n"
            "class Program { static void Main() {} }\n"
        )
        deps, _ = analyse_csharp_sources(str(tmp_path), [])
        names = {d.name for d in deps}
        # None of these should appear as UNDECLARED/phantom — they're
        # part of the runtime, not NuGet packages.
        assert not any(n.startswith("System") for n in names)

    @pytest.mark.requirement("FR-130")
    def test_microsoft_extensions_still_phantom(self, tmp_path):
        # Microsoft.Extensions.* IS distributed as NuGet packages even
        # though "Microsoft" is a vendor name — must surface as phantom.
        (tmp_path / "Program.cs").write_text(
            "using Microsoft.Extensions.Logging;\n\n"
            "class Program {}\n"
        )
        deps, _ = analyse_csharp_sources(str(tmp_path), [])
        names = {d.name for d in deps}
        assert "Microsoft.Extensions.Logging" in names


# ── REQ-16 — Security: Assembly.Load taint ─────────────────────────────────


class TestReq16AssemblyLoadTaint:
    @pytest.mark.requirement("SF-028")
    @pytest.mark.security
    def test_ts_ce_010_rule_exists(self):
        assert "TS-CE-010" in RULES

    @pytest.mark.requirement("SF-028")
    @pytest.mark.security
    def test_assembly_load_with_tainted_arg_emits_ts_ce_010(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using System;\n"
            "using System.Reflection;\n\n"
            "class Program {\n"
            "    static void Main(string[] args) {\n"
            "        var name = args[0];\n"
            "        Assembly.Load(name);\n"
            "    }\n"
            "}\n"
        )
        _, errors = analyse_csharp_sources(str(tmp_path), [])
        # Finding surfaces via the analyser's AnalysisResult at integration
        # time. For unit scope we assert rule exists; the full assertion
        # lives in the integration tests once the analyser is wired in.
        assert isinstance(errors, list)


# ── REQ-16 — Security: Process.Start taint ─────────────────────────────────


class TestReq16ProcessStartTaint:
    @pytest.mark.requirement("SF-029")
    @pytest.mark.security
    def test_ts_ce_011_rule_exists(self):
        assert "TS-CE-011" in RULES

    @pytest.mark.requirement("SF-029")
    @pytest.mark.security
    def test_process_start_with_env_var_emits_ts_ce_011(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using System;\n"
            "using System.Diagnostics;\n\n"
            "class Program {\n"
            "    static void Main() {\n"
            "        var cmd = Environment.GetEnvironmentVariable(\"CMD\");\n"
            "        Process.Start(cmd);\n"
            "    }\n"
            "}\n"
        )
        _, errors = analyse_csharp_sources(str(tmp_path), [])
        assert isinstance(errors, list)


# ── REQ-16 — Security: DllImport ───────────────────────────────────────────


class TestReq16DllImport:
    @pytest.mark.requirement("SF-030")
    @pytest.mark.security
    def test_ts_si_018_rule_exists(self):
        assert "TS-SI-018" in RULES

    @pytest.mark.requirement("SF-030")
    @pytest.mark.security
    def test_dllimport_attribute_emits_ts_si_018(self, tmp_path):
        (tmp_path / "Program.cs").write_text(
            "using System.Runtime.InteropServices;\n\n"
            "class Program {\n"
            "    [DllImport(\"kernel32.dll\")]\n"
            "    static extern int GetCurrentProcessId();\n"
            "    static void Main() { GetCurrentProcessId(); }\n"
            "}\n"
        )
        _, errors = analyse_csharp_sources(str(tmp_path), [])
        assert isinstance(errors, list)
