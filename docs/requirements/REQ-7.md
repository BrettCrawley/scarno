# Confidence-scored Report Engine (Text & JSON Formatters + CLI Wiring)

## Overview
Format `AnalysisResult` into human-readable text and machine-readable JSON, and wire both formats into the `scarno` CLI with output path and exit code support.

## Problem Statement
The analysers (REQ-3, REQ-6) produce `AnalysisResult` objects but there is no way to present findings to a developer or consume them in a CI pipeline.

## Solution
Implement `TextReporter` and `JsonReporter` in `src/scarno/reporters/`, update `cli.py` to accept `--format` and `--output` flags, and return structured exit codes.

## File Layout

```
src/scarno/
├── reporters/
│   ├── __init__.py          # exports TextReporter, JsonReporter
│   ├── text_reporter.py     # TextReporter
│   └── json_reporter.py     # JsonReporter
└── cli.py                   # updated — adds --format, --output, exit codes

tests/
├── test_text_reporter.py
├── test_json_reporter.py
├── test_cli_reporter.py
└── fixtures/
    └── report/
        ├── all_statuses/     # mix of SAFE, UNCERTAIN, IN_USE deps + warnings
        ├── empty_result/     # AnalysisResult with no deps and no errors
        ├── entry_points/     # IN_USE dep with populated entry_points list
        └── ansi_input/       # dep names/reasons containing ANSI escape sequences
```

## Reporter Interface

Both reporters are **pure** — they accept an `AnalysisResult` and return a `str`. No file I/O, no `print()`, no `sys.stdout` access inside reporter classes.

```python
class TextReporter:
    def render(self, result: AnalysisResult) -> str: ...

class JsonReporter:
    def render(self, result: AnalysisResult) -> str: ...
```

## Text Format

### Section Order (fixed)
1. `SAFE TO REMOVE`
2. `UNCERTAIN`
3. `IN USE`
4. `WARNINGS`

Omit a section entirely if it has no items.

### Layout Rules

| Element              | Rule                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------ |
| Section header       | `## SAFE TO REMOVE` (two `#`, uppercase)                                                   |
| Section separator    | `─` (U+2500) repeated 60 characters, printed after each section                            |
| Dependency line      | `{name} {version}  [{status}]  {reason}`                                                   |
| Entry point (used)   | `  ✓ {entry_point.name}` — indented 2 spaces, `✓` prefix                                   |
| Entry point (unused) | omitted from text output                                                                   |
| Warnings header      | `## WARNINGS`                                                                              |
| Warning line         | `  {error_string}` — indented 2 spaces                                                     |
| ANSI stripping       | Strip all ANSI escape sequences (`\x1b\[[0-9;]*m`) from all string fields before rendering |

Entry points are only printed for `IN_USE` dependencies. If `entry_points` is empty for an `IN_USE` dep, no entry point lines are printed for that dep.

### Example (illustrative, not pixel-perfect)
```
## SAFE TO REMOVE
────────────────────────────────────────────────────────────
commons-lang3 3.12.0  [SAFE]  no import or usage found

## IN USE
────────────────────────────────────────────────────────────
requests 2.31.0  [IN_USE]  imported in main.py:4
  ✓ requests.get
  ✓ requests.Session

## WARNINGS
────────────────────────────────────────────────────────────
  source_analyser: could not read vendor/lib.py — PermissionError
```

## JSON Format

Serialise with `json.dumps(indent=2, ensure_ascii=True)`.

### Schema

```
{
  "project_type": string,
  "dependencies": [
    {
      "name": string,
      "version": string | null,
      "status": "SAFE" | "UNCERTAIN" | "IN_USE",
      "reason": string,
      "is_type_stub": boolean,
      "entry_points": [
        {
          "name": string,
          "kind": string,
          "used": boolean
        }
      ],
      "entry_points_used": integer,
      "entry_points_total": integer
    }
  ],
  "errors": [string]
}
```

**Control character sanitisation:** Replace any control character (`\x00`–`\x1f`, excluding `\t`, `\n`, `\r`) in string fields with `?` before serialisation. This applies to `name`, `version`, `reason`, `errors`, and entry point `name` fields.

The full `entry_points` array is always included (used and unused). `version` is `null` when not resolved.

## CLI Wiring (`cli.py`)

### New Flags

| Flag       | Type                   | Default         | Description                            |
| ---------- | ---------------------- | --------------- | -------------------------------------- |
| `--format` | choice: `text`, `json` | `text`          | Output format                          |
| `--output` | path string            | `None` (stdout) | Write output to file instead of stdout |

### Exit Codes

| Code | Condition                                                                                  |
| ---- | ------------------------------------------------------------------------------------------ |
| `0`  | Analysis complete, no errors, no UNCERTAIN or SAFE deps                                    |
| `1`  | Analysis complete but has UNCERTAIN or SAFE deps (actionable findings)                     |
| `2`  | Analysis failed (unhandled exception, unreadable project path, or `errors` list non-empty) |

Exit code `2` takes precedence over `1`. If `errors` is non-empty but deps were also classified, exit `2`.

### I/O Behaviour
- If `--output` is provided, write the rendered string to that path (UTF-8, overwrite if exists). Print nothing to stdout.
- If `--output` is omitted, write the rendered string to stdout.
- Errors during file write (e.g. permission denied) are printed to stderr and exit with code `2`.

## Data Models (reference — defined in REQ-1)

`AnalysisResult`:
- `project_type` (str)
- `dependencies` (list[Dependency])
- `errors` (list[str])

`Dependency`:
- `name` (str), `version` (str | None), `status` (DependencyStatus), `reason` (str)
- `is_type_stub` (bool)
- `entry_points` (list[EntryPoint])
- `entry_points_used` (int), `entry_points_total` (int)

`EntryPoint`: `name` (str), `kind` (str), `used` (bool)

## Test Fixtures

### `all_statuses/`
`AnalysisResult` with one dep per status (`SAFE`, `UNCERTAIN`, `IN_USE`) plus one entry in `errors`. Validates section order, separators, and warnings section in text output; validates full JSON schema.

### `empty_result/`
`AnalysisResult` with `dependencies=[]` and `errors=[]`. Text output is empty string or contains no sections. JSON output is valid with empty arrays.

### `entry_points/`
`IN_USE` dep with `entry_points` containing 3 items: 2 `used=True`, 1 `used=False`. Text output shows exactly 2 `✓` lines. JSON output includes all 3 entry point objects.

### `ansi_input/`
Dep with `name` and `reason` containing `\x1b[32m` ANSI codes. Text output contains no ANSI sequences. JSON output contains no ANSI sequences.

## Acceptance Criteria
- [] Given `all_statuses/` result, When `TextReporter.render()` is called, Then sections appear in order: `SAFE TO REMOVE`, `UNCERTAIN`, `IN USE`, `WARNINGS`
- [] Given `all_statuses/` result, When `TextReporter.render()` is called, Then each section is followed by a `─` separator line of exactly 60 characters
- [] Given `all_statuses/` result, When `TextReporter.render()` is called, Then each dependency line contains name, version, status in brackets, and reason
- [] Given a result with no `UNCERTAIN` deps, When `TextReporter.render()` is called, Then the `UNCERTAIN` section is absent from the output
- [] Given a result with no `errors`, When `TextReporter.render()` is called, Then the `WARNINGS` section is absent from the output
- [] Given `entry_points/` result, When `TextReporter.render()` is called, Then exactly 2 lines prefixed with `  ✓` appear under the `IN_USE` dep
- [] Given `entry_points/` result, When `TextReporter.render()` is called, Then the unused entry point does not appear in the output
- [] Given `ansi_input/` result, When `TextReporter.render()` is called, Then the output contains no `\x1b[` sequences
- [] Given `empty_result/` result, When `TextReporter.render()` is called, Then the output contains no section headers
- [] Given a result with warnings, When `TextReporter.render()` is called, Then each warning line is indented 2 spaces under `## WARNINGS`
- [] Given `all_statuses/` result, When `JsonReporter.render()` is called, Then the output is valid JSON parseable by `json.loads`
- [] Given `all_statuses/` result, When `JsonReporter.render()` is called, Then the JSON contains `project_type`, `dependencies`, and `errors` keys at the top level
- [] Given `entry_points/` result, When `JsonReporter.render()` is called, Then the `entry_points` array contains all 3 entry point objects (used and unused)
- [] Given a dep with `version=None`, When `JsonReporter.render()` is called, Then the JSON field `version` is `null`
- [] Given a dep with a control character (`\x01`) in its `reason`, When `JsonReporter.render()` is called, Then the character is replaced with `?` in the JSON output
- [] Given `ansi_input/` result, When `JsonReporter.render()` is called, Then the JSON string fields contain no ANSI escape sequences
- [] Given `empty_result/` result, When `JsonReporter.render()` is called, Then `dependencies` and `errors` are empty arrays
- [] Given `JsonReporter.render()` is called, Then the output uses 2-space indentation and `ensure_ascii=True`
- [] Given `TextReporter.render()` is called, Then the method makes no calls to `print()`, `sys.stdout`, or any file I/O
- [] Given `JsonReporter.render()` is called, Then the method makes no calls to `print()`, `sys.stdout`, or any file I/O
- [] Given `scarno <path> --format json`, When analysis completes with no errors and no SAFE/UNCERTAIN deps, Then exit code is `0`
- [] Given `scarno <path> --format text`, When analysis produces at least one `SAFE` or `UNCERTAIN` dep, Then exit code is `1`
- [] Given `scarno <path>`, When `AnalysisResult.errors` is non-empty, Then exit code is `2`
- [] Given `scarno <path> --output report.txt`, When analysis completes, Then output is written to `report.txt` and nothing is printed to stdout
- [] Given `scarno <path>` with no `--output` flag, When analysis completes, Then rendered output is written to stdout
- [] Given `scarno <path> --output /nonexistent/dir/report.txt`, When the write fails, Then an error is printed to stderr and the process exits with code `2`
