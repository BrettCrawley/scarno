# csharp_malicious/ — adversarial C# / .NET fixtures (REQ-15 / REQ-16)

| Directory | Payload |
|-----------|---------|
| `csproj_xxe/` | `*.csproj` with `<!DOCTYPE Project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` → rejected pre-parse (SEC-NEW-25) |
| `directory_build_props_escape/` | `Directory.Build.props` walked up from csproj with parent-POM-style traversal attempt → confined to project root (SEC-NEW-26) |
| `sln_circular/` | `.sln` with project A → project B → project A → cycle detection by resolved `.csproj` path |
| `hintpath_escape/` | `<PackageReference>` with `<HintPath>..\..\..\outside\dll</HintPath>` → blocked via path confinement |
| `nuget_rogue_registry/` | `nuget.config` with `<add key="internal" value="https://evil.example.com/" />` → Finding `TS-SI-015` |
| `usingtask_unknown_dll/` | `*.csproj` with `<UsingTask AssemblyFile="...\\unknown.dll" />` → Finding `TS-SI-017` |

Built in-test via `tmp_path`.
