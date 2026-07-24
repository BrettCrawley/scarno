"""Adversarial path-traversal tests — dep-name and project-reference paths.

These tests assert that Scarno never reads files outside the project
root just because an attacker placed a `..`-prefixed dep name or `.sln`
project reference in an in-tree file. Both attack surfaces deviate from
the codebase's SEC-002 confinement standard.

The fixtures use a sentinel marker injected into an out-of-tree file;
each test asserts the marker does NOT appear anywhere in the analyser's
output (deps, errors, findings).
"""
from __future__ import annotations

from pathlib import Path

import pytest


SENTINEL = "SCARNO-LEAK-MARKER-DO-NOT-INDEX"


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# ── C# .sln Project("...") = "...", "<rel>" ──────────────────────────────


class TestSlnProjectTraversal:
    @pytest.mark.requirement("SEC-002")
    @pytest.mark.requirement("SEC-NEW-35")
    @pytest.mark.security
    def test_sln_project_path_with_dotdot_does_not_read_out_of_tree(
        self, tmp_path
    ):
        """SEC-002 — `.sln` Project paths must be confined to project root."""
        outside_dir = tmp_path / "outside"
        project_dir = tmp_path / "project"

        # The attacker-controlled out-of-tree file. If Scarno reads it,
        # SENTINEL will surface as a Dependency.name in the result.
        _write(
            outside_dir / "leaked.csproj",
            f"""\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="{SENTINEL}" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
        )

        # In-tree files: a .sln with a Project line escaping the root.
        _write(
            project_dir / "App.sln",
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
            '"Foo", "..\\outside\\leaked.csproj", '
            '"{11111111-1111-1111-1111-111111111111}"\nEndProject\n',
        )

        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )

        deps, errors, _findings = parse_all_csharp_dependency_files(
            str(project_dir)
        )

        # The sentinel from the out-of-tree file must NOT have leaked.
        names = {d.name for d in deps}
        assert SENTINEL not in names, (
            f"out-of-tree leak: {SENTINEL} surfaced as a dep — the .sln "
            f"reference escaped the project root and was read"
        )
        # Errors should explain that the reference was rejected.
        joined_errors = " ".join(errors)
        assert SENTINEL not in joined_errors, (
            "out-of-tree filename leaked into errors output"
        )
        assert any(
            "escape" in e.lower() or "outside" in e.lower()
            or "root" in e.lower()
            for e in errors
        ), (
            f"expected an 'outside root' / 'escape' diagnostic in errors; "
            f"got {errors!r}"
        )

    @pytest.mark.requirement("SEC-002")
    @pytest.mark.security
    def test_sln_project_path_absolute_does_not_read(self, tmp_path):
        """An absolute path in a .sln must not be followed."""
        outside_dir = tmp_path / "outside"
        project_dir = tmp_path / "project"
        _write(
            outside_dir / "absolute.csproj",
            f"""\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="{SENTINEL}" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
        )
        absolute = (outside_dir / "absolute.csproj").resolve()
        _write(
            project_dir / "App.sln",
            f'Project("{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}") = '
            f'"Foo", "{absolute}", '
            f'"{{11111111-1111-1111-1111-111111111111}}"\nEndProject\n',
        )

        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )

        deps, _errors, _findings = parse_all_csharp_dependency_files(
            str(project_dir)
        )
        names = {d.name for d in deps}
        assert SENTINEL not in names

    @pytest.mark.requirement("FR-126")
    def test_sln_legitimate_relative_reference_still_works(self, tmp_path):
        """A normal relative .sln reference (no traversal) must still resolve."""
        project_dir = tmp_path / "project"
        _write(
            project_dir / "src" / "App" / "App.csproj",
            """\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LegitDep" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
        )
        _write(
            project_dir / "App.sln",
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = '
            '"App", "src\\App\\App.csproj", '
            '"{11111111-1111-1111-1111-111111111111}"\nEndProject\n',
        )

        from scarno.analysers.csharp.dep_file_parser import (
            parse_all_csharp_dependency_files,
        )

        deps, _errors, _findings = parse_all_csharp_dependency_files(
            str(project_dir)
        )
        names = {d.name for d in deps}
        assert "LegitDep" in names, (
            "regression: legitimate in-tree project reference was rejected"
        )


# ── npm dep name ─────────────────────────────────────────────────────────


class TestNpmDepNameTraversal:
    @pytest.mark.requirement("SEC-002")
    @pytest.mark.requirement("SEC-NEW-34")
    @pytest.mark.security
    def test_npm_dep_name_with_dotdot_does_not_read_out_of_tree(
        self, tmp_path
    ):
        """SEC-002 — adversarial npm dep names must not escape the project root.

        Mechanism: ``_resolve_entry_points`` builds
        ``root / "node_modules" / package_name / "package.json"`` from the
        attacker-controlled dep name. If ``package_name`` contains ``..``
        segments the OS resolves the path outside the project root.
        """
        # Out-of-tree package.json that would be reached via ../../leaked
        # from the project's node_modules dir.
        outside_dir = tmp_path / "outside-pkg"
        outside_pkg = outside_dir / "package.json"
        import json

        outside_pkg.parent.mkdir(parents=True, exist_ok=True)
        outside_pkg.write_text(json.dumps({
            "name": "leaked",
            "version": "1.0.0",
            # Sentinel placed where _resolve_entry_points would harvest it.
            "exports": {f"./{SENTINEL}": "./index.js"},
        }))

        project_dir = tmp_path / "project"
        # node_modules so the relative resolution actually exists on disk.
        (project_dir / "node_modules").mkdir(parents=True)
        # The dep name is the traversal payload. The number of ../ segments
        # is calibrated to land on outside-pkg/package.json from
        # project/node_modules/.
        traversal = "../../outside-pkg"
        _write(
            project_dir / "package.json",
            json.dumps({
                "name": "victim",
                "version": "1.0.0",
                "dependencies": {traversal: "1.0.0"},
            }),
        )
        # An import in source that, after canonicalisation, names the dep —
        # ensures _resolve_entry_points is actually invoked for it.
        _write(
            project_dir / "src" / "index.ts",
            f'import x from "{traversal}";\n',
        )

        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        from scarno.analysers.javascript.source_analyser import (
            analyse_npm_sources,
        )

        deps, errors, _findings = parse_all_npm_dependency_files(
            str(project_dir)
        )
        deps, src_errors = analyse_npm_sources(str(project_dir), deps)

        # The sentinel from the out-of-tree package.json must NOT appear in
        # any output field.
        all_text_blobs: list[str] = []
        for d in deps:
            all_text_blobs.append(d.name)
            for ep in d.entry_points:
                all_text_blobs.append(ep.name)
                all_text_blobs.append(ep.kind)
            all_text_blobs.append(d.reason or "")
        all_text_blobs.extend(errors + src_errors)
        joined = "||".join(all_text_blobs)
        assert SENTINEL not in joined, (
            f"out-of-tree leak: {SENTINEL} surfaced via dep-name traversal"
        )

    @pytest.mark.requirement("SEC-002")
    @pytest.mark.security
    def test_npm_dep_name_with_backslash_dotdot_rejected(self, tmp_path):
        """Windows-style separators in dep names must not bypass validation."""
        import json

        outside = tmp_path / "outside-bs" / "package.json"
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.write_text(json.dumps({
            "name": "leaked",
            "version": "1.0.0",
            "exports": {f"./{SENTINEL}": "./index.js"},
        }))

        project_dir = tmp_path / "project"
        (project_dir / "node_modules").mkdir(parents=True)
        _write(
            project_dir / "package.json",
            json.dumps({
                "name": "victim",
                "version": "1.0.0",
                "dependencies": {"..\\..\\outside-bs": "1.0.0"},
            }),
        )

        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )
        from scarno.analysers.javascript.source_analyser import (
            analyse_npm_sources,
        )

        deps, _errors, _findings = parse_all_npm_dependency_files(
            str(project_dir)
        )
        deps, _src_errors = analyse_npm_sources(str(project_dir), deps)

        for d in deps:
            for ep in d.entry_points:
                assert SENTINEL not in ep.name, (
                    "backslash traversal in dep name escaped the root"
                )

    @pytest.mark.requirement("FR-103")
    def test_legitimate_npm_scoped_name_still_accepted(self, tmp_path):
        """Regression: scoped names like @scope/pkg must still pass."""
        import json

        project_dir = tmp_path / "project"
        _write(
            project_dir / "package.json",
            json.dumps({
                "name": "victim",
                "version": "1.0.0",
                "dependencies": {"@types/node": "20.0.0", "lodash": "4.0.0"},
            }),
        )

        from scarno.analysers.javascript.dep_file_parser import (
            parse_all_npm_dependency_files,
        )

        deps, _errors, _findings = parse_all_npm_dependency_files(
            str(project_dir)
        )
        names = {d.name for d in deps}
        assert "@types/node" in names
        assert "lodash" in names
