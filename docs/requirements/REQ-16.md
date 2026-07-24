# C# / .NET Source Analyser

## Overview
Scan `.cs`, `.fs`, `.vb`, `.cshtml`, `.razor` files via **tree-sitter-c-sharp** (plus lightweight Razor preprocessing). Update each NuGet dep from REQ-15 to `IN_USE` / `UNCERTAIN` / `SAFE`. Honours C# 10+ `global using`, using aliases, reflection patterns, ASP.NET / MEF DI conventions, and P/Invoke.

## Problem Statement
.NET's source syntax has several traps for a naive parser:

- `using` has four meanings: namespace import, static-member import (`using static X.Y`), alias (`using Alias = X.Y;`), and disposable-scope block.
- C# 10 introduced `global using` — a single file's `global using X;` applies to every file in the project.
- Namespaces don't map 1:1 to NuGet packages. `Microsoft.Extensions.Logging` namespace → `Microsoft.Extensions.Logging` package (1:1), but `Microsoft.AspNetCore.*` namespaces → `Microsoft.AspNetCore.App` shared framework (1:many).
- Reflection is culturally common: `Type.GetType("Foo, MyAssembly")`, `Assembly.Load(...)`, `Assembly.LoadFrom(...)`.
- ASP.NET uses attribute-based routing / filtering (`[ApiController]`, `[Route("api/[controller]")]`, `[HttpGet]`) that implicitly references the MVC package even without an explicit `using`.
- Razor / Blazor (`*.cshtml`, `*.razor`) mix C# with HTML — `@using` directives are inside those files too.

## Solution
`analyse_source_files(project_path, dependencies) -> (list[Dependency], list[str], list[Finding])` in `src/scarno/analysers/csharp/source_analyser.py`. Uses `tree-sitter-c-sharp`. Razor / Blazor files pre-processed to extract `@using` / `@inject` / `@inherits` directives as C# statements.

## Scope

### Using directive discovery

AST node types to walk:

| Node type | Example | Extracted |
|---|---|---|
| `using_directive` (regular) | `using Microsoft.Extensions.Logging;` | `Microsoft.Extensions.Logging` |
| `using_directive` with `static` | `using static System.Math;` | `System.Math` (namespace, for match) |
| `using_directive` with alias | `using ILog = log4net.ILog;` | `log4net` (top-level namespace) |
| **`global_using_directive`** (C# 10+) | `global using Serilog;` in a single file | `Serilog` — applies project-wide |
| `attribute_list` | `[ApiController]` on a class | `ApiController` — resolved via DI annotation table |

Relative namespaces and nested-class references use the fully-qualified form.

### Razor / Blazor preprocessing

`.cshtml` / `.razor` files contain directives prefixed with `@`:

```razor
@using Microsoft.AspNetCore.Components
@inject ILogger<MyComponent> Logger
@inherits LayoutComponentBase
```

Extract these lines with a bounded, anchored regex (`^\s*@(using|inject|inherits|page|model|namespace)\b`) and feed the `@using` lines into the using-directive set. Everything else is ignored.

### Namespace → NuGet alias table

Many .NET namespaces map 1:1 to their NuGet ID, but several shared frameworks require an alias table (like REQ-6's Java Guava → common mapping):

```python
DOTNET_NAMESPACE_ALIASES: dict[str, tuple[str, ...]] = {
    # Microsoft shared frameworks
    "Microsoft.AspNetCore.App": (
        "Microsoft.AspNetCore",
        "Microsoft.AspNetCore.Mvc",
        "Microsoft.AspNetCore.Http",
        "Microsoft.AspNetCore.Routing",
        "Microsoft.AspNetCore.Authentication",
        # ... full list from MS docs
    ),
    "Microsoft.NETCore.App": (
        "System",
        "System.Collections",
        "System.IO",
        "System.Net",
        "System.Text",
        # ... .NET BCL
    ),
    # Common community packages where namespace ≠ package id
    "AutoMapper": ("AutoMapper",),
    "Newtonsoft.Json": ("Newtonsoft.Json",),  # 1:1 but listed for clarity
    "Serilog": ("Serilog", "Serilog.Core", "Serilog.Events"),
}
```

Matching logic: a using directive resolves to IN_USE if the declared NuGet dep's ID equals a prefix of the namespace OR any alias entry for a configured package includes the used namespace.

### `Microsoft.NETCore.App` / BCL exclusion

Like Python's stdlib exclusion and Node's core modules. `System.*` namespaces are part of the runtime; never flagged as UNDECLARED. The BCL list is bundled in a constant alongside the alias table.

### Reflection heuristics

| Pattern | Example | Classification |
|---|---|---|
| `Type.GetType("Foo, MyAssembly")` with literal | Literal namespace matched via prefix → `UNCERTAIN` |
| `Type.GetType(dynamic)` | non-literal arg → overall project marked as having dynamic reflection, affects all deps |
| `Assembly.Load(bytes)` | always `Finding` `TS-CE-010` (CRITICAL) if bytes source is tainted |
| `Assembly.LoadFrom("path")` with literal | Recorded as reflective usage |
| `Activator.CreateInstance(Type.GetType("Foo.Bar"))` | Same as `Type.GetType` above |

### Attribute-based DI detection

Attributes that imply framework wiring:

| Attribute | Implies (package) |
|---|---|
| `[ApiController]`, `[Controller]`, `[Route]`, `[HttpGet]`, `[HttpPost]`, `[FromBody]`, `[FromRoute]`, `[FromQuery]`, `[Authorize]` | `Microsoft.AspNetCore.Mvc` → `Microsoft.AspNetCore.App` |
| `[Inject]` (Blazor) | `Microsoft.AspNetCore.Components` → `Microsoft.AspNetCore.App` |
| `[Export]`, `[Import]` (MEF) | `System.ComponentModel.Composition` |
| `[TestMethod]` (MSTest), `[Fact]` (xUnit), `[Test]` (NUnit) | Respective packages — `IN_USE` but marked as test-only (similar to Go's `_test.go` segregation) |

### Multi-target framework handling

Projects with `<TargetFrameworks>net8.0;netstandard2.0</TargetFrameworks>` produce one source set that's compiled against multiple TFMs. We analyse **all** source files regardless of `#if NET8_0_OR_GREATER` preprocessor directives — conservative IN_USE (like Go's build-tag policy).

### Security findings

Additions to the REQ-3c rule catalogue:

| Rule ID | Kind | Severity |
|---|---|---|
| `TS-CE-010` | `ASSEMBLY_LOAD_TAINTED` | CRITICAL — `Assembly.Load(bytes)` where bytes trace to network / env |
| `TS-CE-011` | `PROCESS_START_TAINT` | CRITICAL — `Process.Start(userInput)` |
| `TS-SI-016` | `MSBUILD_EXEC_TASK` | MEDIUM — `<Target><Exec Command="..." /></Target>` in csproj (raised by REQ-15 too) |
| `TS-SI-017` | `MSBUILD_CUSTOM_TASK` | MEDIUM — `<UsingTask>` loading an unknown DLL |
| `TS-SI-018` | `PINVOKE_DLLIMPORT` | MEDIUM — `[DllImport(...)]` with a path-like string |

### Entry-point enumeration

When a dep is IN_USE and the NuGet restore cache is present (`~/.nuget/packages/<pkg>/<ver>/lib/<tfm>/<Name>.dll`):
- Enumerate public types via a lightweight .NET metadata reader (`System.Reflection.Metadata` doesn't have a pure-Python equivalent)
- Alternative: use `dotnet-metadata-dumper` if present, or skip enumeration and leave `entry_points=[]`
- Phase 7 acceptable floor: entry-point enumeration skipped; IN_USE is classified correctly without it

### Safety

- tree-sitter-c-sharp parse bounded by `MAX_FILE_BYTES` + 10 s timeout
- `.cshtml` / `.razor` preprocessor extracts only anchored `@using` / `@inject` / etc. — no HTML parsing
- All paths confined via `resolve_and_confine`

## SRTM

| ID | Description |
|---|---|
| FR-128 | `using` directives (regular / static / alias / global) extracted via tree-sitter |
| FR-129 | Razor / Blazor `@using` / `@inject` directives recognised |
| FR-130 | `Microsoft.AspNetCore.App` / `Microsoft.NETCore.App` shared-framework alias table |
| SF-028 | `Assembly.Load(tainted)` → `TS-CE-010` |
| SF-029 | `Process.Start(tainted)` → `TS-CE-011` |
| SF-030 | `[DllImport]` → `TS-SI-018` |

## Acceptance Criteria
- [] Given `using Serilog;` in a C# file and `Serilog` declared in `*.csproj`, When analysed, Then `Serilog` → IN_USE
- [] Given `global using System.Linq;` in `GlobalUsings.cs`, When analysed, Then every file in the project is treated as having imported `System.Linq` (BCL; not a NuGet dep — so no UNDECLARED either)
- [] Given `using ILog = log4net.ILog;`, When analysed, Then the `log4net` namespace is marked as used (alias form)
- [] Given a Razor file with `@using Microsoft.AspNetCore.Components;`, When analysed, Then `Microsoft.AspNetCore.App` → IN_USE via the alias table
- [] Given `[ApiController]` attribute on a class, When analysed, Then `Microsoft.AspNetCore.App` → IN_USE via DI attribute table
- [] Given `Type.GetType("Foo.Bar, MyAssembly")` with literal, When analysed, Then the `Foo.Bar` prefix is matched and the dep → UNCERTAIN
- [] Given `Assembly.Load(await httpClient.GetByteArrayAsync(url))`, When analysed, Then `TS-CE-010` fires at CRITICAL
- [] Given `Process.Start(userInput)`, When analysed, Then `TS-CE-011` fires at CRITICAL
- [] Given `[DllImport("kernel32.dll")] static extern ...`, When analysed, Then `TS-SI-018` fires at MEDIUM
- [] Given `[TestMethod]` on a method, When analysed, Then `MSTest.TestFramework` → IN_USE but reason notes "test-only usage"
- [] Given a comment `// using Secret.Package;`, When analysed, Then no import fires (tree-sitter comment exclusion)
