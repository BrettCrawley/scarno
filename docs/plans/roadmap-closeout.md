# Plan: Roadmap close-out — open issues, unfixed security finding, Phase 9 follow-ups, doc drift

## Context

All the delivery plans are implemented. Phases 0a–7 (`docs/PLAN.md`) and
Phase 9 (`docs/plans/phase-9-version-aware-classification.md`) have
landed, as have Maven parent/BOM resolution, matching Python import
names to distribution names, PEP 562 enumeration, artifact-based package
discovery and the ABI-diff overload fix. GAP-A/B/C from
`docs/gap-remediation-plan.md` are implemented and tested in
`tests/unit/test_gap_remediation.py`.

24 of the 25 findings from the Claude Security scan of `a4cc442`
(`CLAUDE-SECURITY-20260802-085339/`) are closed by commits
`cf946cc`…`912b90c`. This includes the eight where the scan produced no
patch (F5, F6, F11, F12, F13, F15, F18). F12's capability-gate half is
closed by `7d939d6`. The `-Dmaven.repo.local` allowlist widening that
sank its patch was never adopted.

The remaining work, verified against the tree at `36aaf6f` plus the
working copy (full suite: 1759 passed; mypy clean, 54 files):

1. **Uncommitted work.** `JavaSignature.return_type` and its use in
   `signature_diff` / finding display (`src/scarno/models.py`,
   `src/scarno/analysers/java/abi_diff.py`) have no test. There is also
   an unrelated `uv.lock` refresh with major bumps (one package goes
   3.32.0 → 4.2.5, another 0.6.0 → 0.13.1).
2. **Unpushed commits.** `8f838b5` and `36aaf6f` close GitHub issues #2
   and #3, but they are not on `origin/main`, so both issues are still
   open.
3. **Security finding F23 is not fixed.** The analysed repository's own
   `.gitignore` is honoured by default during source discovery
   (`src/scarno/cli.py:112`, `base_analyser.py:26`). A payload in a
   gitignored file is never seen by the rule engine, and the run exits 0.
4. **GitHub issue #1.** `_invoke_gradle_safe` spawned without `cwd`.
   It had no production caller, so the problem was latent. **Done:**
   the helper was removed (workstream 5).
5. **Phase 9 deferred follow-ups**, still open:
   - the `_invoke_javap_safe` refactor
   - pin-detector placeholders
   - `parent_dep_coord` on Gradle exclusions
   - the Gradle `force(...)` named-argument form
   - npm `target_constraint`
6. **Doc drift.**
   - `PLAN.md` stops at Phase 7, and its status line still reads
     "Phase 4 … 333 tests".
   - `AGENTS.md` says 773 tests.
   - `gap-remediation-plan.md` still says "Open" three times.
   - The plans in `docs/plans/` carry no status.
   - `docs/SCARNO-BUG-signature-diff.md` duplicates
     `docs/issues/SCARNO-BUG-signature-diff.md`.

The code the scan reviewed is not the code that ships now. A lot has
landed since `a4cc442`: JAR enumeration, the bounded ZIP listing, the
`javap -package` switch and the relocation handling. That is why
workstream 8 re-scans.

## Steps

Each workstream is one commit or a short series. Run the full gate
before every commit:
`uv run pytest --srtm-fail-on-gap && uv run mypy src`.

### 1. Land the return-type ABI change (FR-233)

Add tests in `tests/unit/` next to the existing `signature_diff` tests,
marked `@pytest.mark.requirement("FR-233")`:

- `javap_public_signatures` captures `return_type` for methods, and
  leaves it `None` for constructors and fields.
- **Retype only:** `int foo(String)` → `long foo(String)` lands in
  `changed`, and the finding message names the new return type.
- **Covariant bridge pair present on both sides** (e.g.
  `StringBuilder append(int)` + `AbstractStringBuilder append(int)`):
  produces no `changed` entry.
- **Bridge pair → single method:** reports `changed`. Assert this
  explicitly, because it is the behaviour the set comparison implies,
  and record it as intended or fix it.
- **Determinism:** two signatures differing only in `return_type` sort
  stably. Run the diff under two `PYTHONHASHSEED` values in a
  subprocess-free way (compare `_signature_sort_key` order) and get the
  same order.

Commit with a CHANGELOG `[Unreleased] → Fixed` entry: a changed return
type is now reported as `TS-ABI-*` drift/risk.

### 2. Land the lockfile refresh separately

- Review the `uv.lock` diff for every major bump. Check each against its
  release notes: is it a runtime dependency or dev-only?
- Run the full gate under `uv sync --locked`, which is what CI runs.
- One commit, "Refresh uv.lock", listing the major bumps in the body.
- If a bump breaks anything, pin it back in `pyproject.toml` and do not
  weaken tests.

### 3. Push and close issues #2 and #3

- Push `main`. Confirm CI is green on the pushed SHA.
- Close #2 and #3, each with a comment linking `8f838b5` / `36aaf6f`.

### 4. Fix F23: don't let the analysed repository's `.gitignore` blind the rule engine

**Problem.** `.gitignore` is attacker-authored in the PR scenario.
Honouring it is right for *dependency classification*: ignored build
output should not count as usage. It is wrong for the *security rule
engine*: it lets a PR hide a CRITICAL `TS-CE-001` payload by also adding
its path to `.gitignore`.

**Why the scan's patch was declined.** Scanning everything ignored also
pulls in `env/`, `__pypackages__/` and other unlisted virtualenvs. Third-
party code there trips the supply-chain rules, which floods the report,
forces exit 3, and leaves the operator no way to narrow the scan.

**Design (needs sign-off):**

- Split discovery into two file sets:
  - *Classification* keeps honouring `.gitignore`, so its output is
    unchanged byte for byte.
  - *Rule engine* ignores `.gitignore` but still applies the hard-coded
    exclusion set.
- Recognise environment trees **structurally** rather than by name, and
  exclude them from the rule engine:
  - a directory containing `pyvenv.cfg`
  - `__pypackages__/<ver>/lib`
  - `site-packages` / `dist-packages`
  - `node_modules`

  Structure is much harder for an attacker to fake into a hiding place
  than a name. Hiding a payload in a fake venv requires a `pyvenv.cfg`
  that a reviewer can see in the diff. Record this as a residual risk in
  `docs/THREAT-MODEL.md`.
- Add an **operator-side** exclusion: `--exclude <glob>`, repeatable,
  CLI only. Never read it from the analysed tree, so the operator can
  narrow a noisy scan. The analysed tree's `pyproject.toml` must not be
  able to set it; F15 is the precedent.
- Count findings from files classification ignored. Surface the count in
  the summary for all four formats, so operators can see why a finding
  appeared.

**Tests** (`tests/security/`, new SEC-NEW ID registered in
`tests/srtm.py`):

- A gitignored file with a `TS-CE-001` payload yields the finding and
  exit 3.
- `env/` containing `pyvenv.cfg` and a third-party file that trips a
  rule produces no finding.
- `[tool.scarno]` in the analysed `pyproject.toml` cannot add exclusions.
- Dependency classification is identical with and without the change
  (snapshot over `tests/fixtures/`).

### 5. Issue #1: Gradle subprocess working directory — DONE

**Decision (2026-10-31): remove the subprocess path.** No production
code called it, and running `gradle dependencies` executes the analysed
build script by design, so no `cwd` choice makes it safe on untrusted
input.

Correction to the earlier draft of this plan: `gradle.lockfile` is
**not** parsed during analysis. The lockfile parser,
`_resolve_versions_with_lockfile_priority`, exists but is not wired in.
Production Gradle analysis is DSL + `libs.versions.toml` only. Wiring
the lockfile parser in is follow-up 6.6.

What was done:

- Deleted from `src/scarno/analysers/java/gradle.py` only the code that
  runs Gradle, along with the imports that became unused (`os`,
  `shutil`, `subprocess`, `sys`):
  - `_invoke_gradle_safe` and its argv allowlist
  - `_resolve_gradle_binary` and `_warn_path_fallback_once` (Maven
    keeps its own copy)
- Kept the text parsers, which spawn nothing, with their tests and
  SRTM IDs:
  - `_emit_dep_edges_from_output` (FR-192)
  - `_check_lockfile_consistency` (SEC-NEW-53)
  - `_resolve_versions_from_dependencies_output` and
    `_resolve_versions_with_lockfile_priority` (FR-204)
- Deleted the spawn tests: TA-229/230 in `test_req20_argv_allowlist.py`
  and TA-231a–c in `test_mvn_gradle_binary_pinning.py`. SEC-NEW-52 and
  SEC-NEW-55 keep their Maven coverage, and their Gradle halves are
  noted as withdrawn.
- Added `tests/security/test_no_gradle_spawn.py` (SEC-011). It runs
  static AST checks over `src/scarno`:
  - no spawn API is imported into `gradle.py`
  - `gradle.py` has no `GRADLE_HOME` literal
  - nothing hands `gradle`/`gradlew` to a spawn primitive or
    `shutil.which`
  - a self-check runs the matcher on known-bad input

  Run against the pre-change `gradle.py`, all three checks fail.
- Updated `docs/LIMITATIONS.md` and the CHANGELOG, plus the comments in
  `security.py` and the `gradle.py` docstring.
- Still to do: update the historical design docs that list
  `_invoke_gradle_safe` as a sanctioned helper (Security architecture
  §11.15 / ADR-013, `REQ-19a.md`, the Phase 9 plan and test plan). Each
  gets a "withdrawn, see issue #1" note, not a rewrite. Fold this into
  workstream 7.

If Gradle invocation is ever wanted, use the issue's option 2 and make
it a separate plan: require explicit opt-in consent
(`--allow-build-execution`), and run with `--offline --no-daemon
-g <scratch>` and a scarno-owned `--init-script`. The static guard test
must then be relaxed deliberately, in the same change.

### 6. Phase 9 deferred follow-ups

1. **`_invoke_javap_safe` → `safe_subprocess_run`**
   (`src/scarno/analysers/java/source_analyser.py:698`). Route it
   through the wrapper with a neutral `cwd` like Maven's, keeping the
   identifier validation and the multi-class argv. Remove the
   `_GRANDFATHERED` entry from
   `tests/security/test_arch_subprocess_call_sites.py`, so the AST scan
   now enforces it.
2. **Pin-detector placeholders → real registration.** The Maven and npm
   detectors now emit `pin_override`, and the Gradle DSL walker exists.
   - Reword the "placeholder" comments in
     `analysers/java/__init__.py:460` and
     `analysers/javascript/__init__.py:87`.
   - Add a test confirming every registered ecosystem has a detector
     that can set `pin_override`.
   - Add a test confirming that an ecosystem registered *without* one
     gets the ADR-012 downgrade to UNCERTAIN.
   - Update Drift §1 of the Phase 9 plan.
3. **`GradleExclusion.parent_dep_coord`.** Track the enclosing
   `implementation(...) { exclude(...) }` block in the bounded walker
   (`gradle_dsl.py:357`). Surface it in the reporter narrative.
4. **Gradle `force(group: 'g', name: 'a', version: 'v')`** and the
   Kotlin `force(group = …)` form. Add a bounded regex next to the GAV-
   string one (`gradle_dsl.py:102`). Give it a ReDoS timing test like
   the F6/F7 ones.
5. **npm `target_constraint` matching.** Make the matcher honour `**/x`
   versus `parent/x` from `resolutions` keys
   (`javascript/dep_file_parser.py:1316`). Unknown constraint shapes
   must fall back to the current conservative exact-name match.
6. **Wire `gradle.lockfile` reading into analysis.** The parser
   (`_resolve_versions_with_lockfile_priority`, FR-204) exists, but
   nothing calls it, so Gradle has no resolved-version source.
   - Read `gradle.lockfile` under `resolve_and_confine` and
     `MAX_FILE_BYTES`, with the `_MAX_LINE_BYTES` cap the parsers use.
   - Feed it to `classify_versioned` as Gradle's `resolved_versions`.
   - Add an end-to-end test over a fixture with a lockfile.

Each item gets its own commit, its own requirement-marked tests and a
CHANGELOG line.

### 7. Documentation pass

- `docs/PLAN.md`:
  - Fix the status line.
  - Add a Phase 9 section that points to its plan.
  - Say what happened to Phase 8; it is referenced from
    `Specification.md` and the test-suite doc.
  - Add a "Post-Phase-9 hardening" section covering the security-scan
    remediation and this plan.
- `AGENTS.md` §7: update the test count, SRTM count and mypy file count
  from a fresh run. Do the same for the layout tree (`indexing/`,
  `core/classifier.py`).
- `docs/gap-remediation-plan.md`: mark GAP-A/B/C done with commit
  references. For GAP-B, record that `uv.lock` + `uv sync --locked` in
  CI is the hash-pinning mechanism instead of `requirements-lock.txt`.
- Add a `**Status:**` line to every file in `docs/plans/`.
- Delete `docs/SCARNO-BUG-signature-diff.md`. The copy in
  `docs/issues/` remains. Mark both `docs/issues/` reports as fixed,
  with commit refs.
- Add a resolution table to `CLAUDE-SECURITY-20260802-085339/` or
  `docs/THREAT-MODEL.md`, mapping each F-id to its commit and F23 to
  workstream 4.

### 8. Re-scan

After workstreams 1–6 land, run a Claude Security scan of the changes
since `a4cc442`, or a full scan. Triage any new findings into a follow-
up plan rather than widening this one.

## Order and dependencies

```
1 → 2 → 3          (clean tree, push, close #2/#3)
4, 5, 6.1          (security-relevant; independent of each other)
6.2–6.5            (feature follow-ups; any order)
7                  (after code lands, so counts are final)
8                  (last)
```

## Risks

- **F23 changes CI outcomes.** Repositories that ignore vendored or
  generated code with unusual layouts may start seeing findings and
  exit 3. `--exclude` is the operator's lever. The CHANGELOG must say so
  explicitly.
- **Removing the Gradle subprocess helpers** gives up per-version
  Gradle resolution before it ever shipped. That is the intended trade.
  It is reversible behind a consent flag later.
- **Lockfile major bumps** may change tree-sitter or HTTP behaviour.
  Workstream 2 is a separate commit so it can be reverted alone.
- **The structural environment detection in F23** is a heuristic. The
  residual risk (a planted `pyvenv.cfg`) must be written into the threat
  model, not left implicit.

## Out of scope

- Grouping `TS-ABI-DRIFT` per identity in the reporter (deferred in
  `abi-diff-overload-collapse.md`).
- Descriptor-level `is_called` matching in `_emit_findings`.
- New ecosystems or rules beyond those listed above.
