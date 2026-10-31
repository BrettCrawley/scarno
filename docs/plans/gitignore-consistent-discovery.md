# Plan: Consistent `.gitignore` handling across every analyser, and closing F23

**Status:** Proposed (2026-10-31). Supersedes workstream 4 of
`roadmap-closeout.md`.

## Context

Two defects share one root cause: each analyser walks the tree its own
way.

1. **`.gitignore` is a Python-only feature that every analyser claims to
   support.**
   - `use_gitignore` lives on `BaseAnalyser`, so every analyser
     inherits it, and `--no-gitignore` is a global CLI flag.
   - Only Python `.py` discovery applies it
     (`_discover_py_files`, `src/scarno/analysers/python/source_analyser.py:485`).
   - The Java analyser forwards the flag to its Maven, Gradle and
     source sub-analysers (`analysers/java/__init__.py:122,145,171`),
     which drop it.
   - Go, JS/TS, C#, CSS and the HTML scanner never read it. Python
     notebooks don't either.

   So `--no-gitignore` does nothing outside Python `.py` files, and the
   results for a gitignored file depend on which language it's in.
2. **F23 (Claude Security scan of `a4cc442`, LOW).** The analysed
   repository's `.gitignore` is attacker-authored in the pull-request
   scenario. A PR can add `evil.py` with a `TS-CE-001` payload, add
   `evil.py` to `.gitignore` and `git add -f` it. Python discovery then
   skips it, the rule engine never sees it, and the run exits 0. It is
   the only finding from that scan still open.

The defects have to be fixed together. Teaching the other analysers to
honour `.gitignore` the way Python does today would spread F23's blind
spot to every language.

The scan's own patch for F23 was declined twice. Lessons to keep:

- Counting skipped files alone doesn't help: the payload is still
  unscanned and the run still exits 0.
- Scanning *everything* ignored parses installed environments (`env/`,
  `__pypackages__/`, unlisted virtualenvs). Third-party code there
  trips the supply-chain rules, which floods the report and forces
  exit 3 with no way to narrow the scan.
- Any cap on *how many* ignored files are scanned is itself a detection
  bypass. Exclusion must be by *kind* of directory, never by count.
- The audit line must be a fixed literal plus an integer, so no path
  can leak (PRV-004).

## Where the work lands

| Analyser | Discovery today | Source-code rules? | Change needed |
|---|---|---|---|
| Python `.py` | `_discover_py_files`, honours `.gitignore` | yes (`apply_rules`) | classification mode + F23 rules pass |
| Python notebooks | `_parse_notebooks`, `_collect_notebook_findings` | yes (magics) | classification mode; rules already see everything |
| Dockerfile / workflows | `container_ci_parser._scan_dockerfiles`, `_collect_shell_findings` | yes | none (rules only; already ignore `.gitignore`) |
| HTML / templates | `html_scanner._iter_template_files` | yes (`TS-CE-012`) | classification mode + rules pass |
| CSS | `css/__init__.py` walk | yes (`TS-CE-007`) | classification mode + rules pass |
| Java / Kotlin | `JvmSourceAnalyser._gather_source_files` | no | classification mode |
| JS / TS | `javascript/source_analyser._scan_tree` | no | classification mode |
| Go | `go/source_analyser._scan_tree` | no | classification mode |
| C# | `csharp/source_analyser._scan_tree` | no | classification mode |

Project-type detection (each analyser's `supports()`) is unchanged. A
gitignored file still counts toward "this is a Go project".

## Design

### Default: gitignored usage is UNCERTAIN, not SAFE and not IN_USE

Ignoring gitignored files can only *remove* usages, so it can only push
deps toward SAFE. The commonest gitignored code that really uses a dep
is generated code:

- protobuf `_pb2.py` stubs
- OpenAPI clients
- Java `target/generated-sources`
- C# `obj/` source generators

Honouring `.gitignore` there tells the user to remove `protobuf`, and
the build breaks. That is the false SAFE scarno exists to prevent.
Treating them as ordinary files errs the safe way but lets a dirty local
tree mask real removals.

So classification is three-way, selected by a CLI-only option,
`--gitignore`:

| `--gitignore` | A dep whose only usages are in gitignored files is… |
|---|---|
| `uncertain` (**default**) | `UNCERTAIN`, reason: "used only in files excluded by .gitignore (e.g. generated code); verify before removing" |
| `include` | `IN_USE`, as if the files were tracked. `--no-gitignore` stays as an alias. |
| `exclude` | not counted, so `SAFE` if unused elsewhere. Today's Python behaviour, now opt-in. |

Rules for the mode:

- A dep with usages in tracked files is `IN_USE` whatever the mode.
- The reason string is a fixed literal and names no file.
- **CLI only.** It is never read from the analysed tree's
  `pyproject.toml` or `scarno.json` (F15 precedent: the policed tree
  must not configure its own policing).

### Security rules never honour `.gitignore`

The rule pass sees every candidate file, gitignored or not, *except*:

- **Installed-environment trees, recognised by structure:**
  - a directory containing `pyvenv.cfg`
  - any `site-packages` / `dist-packages` segment
  - `__pypackages__/<ver>/lib`
  - `node_modules`

  A structural marker is visible in the PR diff, so planting one to
  hide a payload (for example a fake `pyvenv.cfg`) is reviewable. That
  residual risk goes into `docs/THREAT-MODEL.md`.
- **Operator `--exclude` globs** (below).
- `resolve_and_confine` failures and `MAX_FILE_BYTES` overruns, exactly
  as today.

**The per-analyser name lists** (`_EXCLUDED_DIRS`,
`_EXCLUDED_DIR_NAMES`: `build`, `dist`, `vendor`, `target`, …) are an
F23-shaped gap too: a PR can drop `build/evil.py`. These lists keep
applying to classification unchanged. For the rule pass they are
replaced by the structural check, so a committed `build/` directory is
scanned.

The rule pass gets a measurement step first (step 1) on the repo's own
fixtures and a sample of real repos. If scanning `build`/`dist`/`target`
proves too noisy, the fallback is to scan those directories only when
they are *not* also gitignored. That still closes the "commit it and
ignore it" path.

`.git/` is always skipped, by both passes.

### Operator-side `--exclude <glob>` (repeatable, CLI only)

`--exclude` narrows both passes in every analyser, so an operator can
silence a noisy tree.

- Validated exactly like `--test-paths`, reusing the
  `core/test_scope.sanitise_test_paths` checks (count cap, byte cap, no
  backslashes, no absolute paths, no `..`).
- Matched with `fnmatch.fnmatchcase` on the root-relative POSIX path.
- Never read from the analysed tree.
- Findings excluded this way are not counted. The operator asked for
  it, and the flag's value is in the run's own command line.

### One shared discovery helper

Add `src/scarno/core/discovery.py`:

```python
@dataclass(frozen=True)
class DiscoveredFiles:
    tracked: list[Path]          # classification + rules
    ignored: list[Path]          # gitignored; rules always, classification per mode
    environment_skipped: int     # aggregate only
    operator_excluded: int       # aggregate only

def discover(
    root: Path,
    patterns: tuple[str, ...],                 # e.g. ("*.py",)
    errors: list[str],
    *,
    classification_excluded_dirs: frozenset[str],
    gitignore: GitignoreMode,
    operator_excludes: tuple[str, ...],
    test_matcher: TestScopeMatcher | None = None,
) -> DiscoveredFiles
```

What the helper does:

- **Walks the tree once.** It applies `resolve_and_confine` and the
  `MAX_FILE_BYTES` check in one place. Each analyser currently does both
  separately, with slightly different error messages.
- **Reuses the existing gitignore matcher.** That is
  `_load_gitignore_matcher` (moved from the Python analyser), built on
  `gitignorefile.Cache`, which handles nested `.gitignore` files. Only
  the analysed tree's own ignore files are read; the operator's global
  git excludes are not, so results depend on the tree alone.
- **Uses fixed `errors` messages.** If `gitignorefile` is missing, the
  helper emits the existing "not installed" line, and every candidate
  is `tracked`. That fails safe for the rules.
- **Decides by directory.** It prunes directories as it descends
  instead of matching every file under them, so a `node_modules` with
  100k files costs one check, not 100k.

Each analyser keeps its own patterns and classification exclusion list,
and passes them in. `BaseAnalyser` grows `gitignore: GitignoreMode` and
`operator_excludes: tuple[str, ...]`. These are threaded by the CLI the
same way `exclude_tests` and `test_paths` are (`cli.py:667-679`,
`:847`, `:872`). `use_gitignore` becomes a derived property for one
release, so external callers don't break.

### Classification plumbing

Each analyser builds its usage maps from `tracked`, and builds a second,
`ignored_only`, map from `ignored`.

- When the mode is `uncertain`, a dep found only in `ignored_only` is
  downgraded from SAFE to UNCERTAIN with the fixed reason.
- When the mode is `include`, the two maps are merged.
- When the mode is `exclude`, `ignored` is never parsed for
  classification.

The status decision itself goes through `core/classifier.py`, so every
analyser uses one function rather than re-deriving the rule. Add
`ignored_only_usage: bool` to the classifier input. The classifier
already centralises status for every ecosystem (NEW-ARCH-006).

### Reporting

- **One aggregate line per run** in `errors`, emitted only when nonzero,
  in the `--exclude-tests` style (`source_analyser.py:1215`):
  `"<n> finding(s) came from files the project's .gitignore excludes"`.
  The literal is fixed and only the integer varies.
- **A second line** when installed-environment trees were skipped:
  `"<n> installed-environment file(s) not rule-scanned"`. It tells the
  operator why a tree is silent, without paths.
- **Findings from ignored files are ordinary findings.** They gate exit
  3 like any other. Nothing in the `Finding` model changes, so SARIF,
  JSON, Markdown and text need no reporter change beyond the existing
  errors rendering.

## Steps

One commit per step. Run the full gate before each:
`uv run pytest --srtm-fail-on-gap && uv run mypy src`. New requirement
IDs are registered in `tests/srtm.py`:

- FR for the classification mode
- SEC-NEW for "rules ignore `.gitignore`"
- SEC-NEW for "operator excludes are CLI-only"
- PRV for the aggregate lines

1. **Measure before changing.**
   - Run today's scarno on `tests/fixtures/` and three or four real
     polyglot repos.
   - Record, per analyser, the files `.gitignore` drops, and how many
     extra findings the new rule pass would produce, including inside
     `build`/`dist`/`target`/`vendor`.
   - Decide the name-list question above from data. Record the numbers
     in this plan.
2. **`core/discovery.py` + `GitignoreMode` + CLI options.**
   - Add `--gitignore {uncertain,include,exclude}`, `--exclude`, and
     `--no-gitignore` as an alias of `include`.
   - Unit-test the helper directly:
     - nested `.gitignore`
     - pruning
     - structural environment markers
     - a planted `pyvenv.cfg`, recorded as the documented residual
     - symlink escape
     - oversized file
     - `--exclude` validation, reusing the `--test-paths` adversarial
       cases
     - no `gitignorefile` installed
   - No analyser uses the helper yet.
3. **Python `.py` + notebooks (closes F23).**
   - Port `_discover_py_files` and the notebook walks onto the helper.
   - Rule pass over `tracked + ignored`. Classification per mode.
   - Security tests (`tests/security/test_gitignore_not_a_detection_gate.py`):
     - a gitignored `TS-CE-001` payload yields the finding and exit 3
       in all three modes
     - `env/` holding `pyvenv.cfg` plus a rule-tripping third-party
       file yields no finding, and the environment-skipped line
     - `[tool.scarno]` in the analysed `pyproject.toml` cannot set
       `--exclude` or `--gitignore`
   - Classification tests:
     - a protobuf-style `_pb2.py` that is gitignored and is the only
       importer gives UNCERTAIN (default), IN_USE (`include`) and
       SAFE (`exclude`)
     - a dep used in tracked code is IN_USE in every mode
   - Back-compat: a snapshot under `--gitignore exclude` is
     byte-identical to today's output on every fixture.
4. **HTML scanner + CSS.** These are the other two rule-bearing
   analysers. Same pattern and the same test shape, using `TS-CE-012`
   and `TS-CE-007` payloads.
5. **Java/Kotlin.** Wire the flag the analyser already forwards into
   `_gather_source_files`. Test: gitignored
   `target/generated-sources/...` as the only user gives UNCERTAIN.
6. **JS/TS.** `_scan_tree`. Test: a gitignored generated client as the
   only importer.
7. **Go.** `_scan_tree`. Keep `vendor/` and `testdata/` excluded from
   classification as today. Test the gitignored-only case.
8. **C#.** `_scan_tree`. Test: gitignored `obj/` generated source.
9. **Docs and records.**
   - README: CLI table and the `.gitignore` section.
   - `docs/LIMITATIONS.md`: structural detection residual, and
     detection ignores the mode.
   - `docs/THREAT-MODEL.md`: F23 closed, planted-marker residual.
   - Add a CHANGELOG entry, **flagged as a behaviour change.**
   - Mark F23 resolved in the scan resolution table
     (`roadmap-closeout.md` workstream 7).

## Behaviour changes users will see

- **Python:**
  - Deps used only in gitignored files go from SAFE to UNCERTAIN.
  - Findings in gitignored files now appear and can gate exit 3.
  - `--gitignore exclude` restores the old classification exactly.
- **Every other language:**
  - Deps used only in gitignored files go from IN_USE to UNCERTAIN.
  - `--no-gitignore` starts working there.
- **HTML/CSS:** findings in gitignored templates and stylesheets now
  appear, as before (they were never filtered), and are counted in the
  new line.
- **Rule pass:** committed `build/`, `dist/`, `target/` and `vendor/`
  trees may be scanned, subject to step 1.

Exit 1 (SAFE deps present) can only become *less* frequent, because
SAFE becomes UNCERTAIN, never the reverse. Exit 3 can become *more*
frequent, which is the point of F23.

## Risks

- **Rule-pass noise from committed generated trees.** Step 1 exists to
  measure it before the design commits to it. `--exclude` is the
  operator's lever either way.
- **Structural markers are a heuristic.** A planted `pyvenv.cfg` hides
  its directory from the rules. It is visible in review, and it is
  written down as a residual rather than left implicit.
- **The walk cost moves into one place.** A pruning bug would affect
  every analyser at once. The helper gets the most direct tests, and
  steps 3–8 each keep their analyser's existing fixtures green.
- **More UNCERTAIN results.** Generated-code users see deps move to
  UNCERTAIN with a reason that tells them why and how to opt out.

## Out of scope

- Reading git's index to tell committed files from untracked ones.
  scarno does not run `git`, and parsing `.git/index` is a separate
  piece of work. It would sharpen the fallback in the rule-pass design.
- The operator's global git excludes (`core.excludesFile`,
  `.git/info/exclude`). Results should depend on the analysed tree
  alone.
- Changing `supports()` detection.
