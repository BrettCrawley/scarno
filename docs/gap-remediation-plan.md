# Gap Remediation Plan

Gaps identified during the security architecture and privacy analysis
update (v2.0, 2026-04-19). Each gap follows the TDD workflow:
write the test first, watch it fail, implement the fix, watch it pass.

---

## GAP-A: HTML scanner should emit security Findings for remote CDN scripts

**Source:** SAC-26, SUC-26, GAP-18 (partial)
**Risk:** MEDIUM
**Status:** Open

**Problem:** The HTML scanner discovers `<script src="https://cdn...">` and
`<link rel="stylesheet" href="https://cdn...">` and adds them to the dep
list, but never emits a `Finding` object. A malicious CDN URL is silently
inventoried without a security warning. CSS already emits TS-CE-007 for
remote `@import` — HTML should do the same for remote `<script>` and
`<link>` tags.

**New rules needed:**
- `TS-CE-009` is taken (Go exec.Command). Use `TS-CE-012`: remote `<script src>` in HTML/template
- `TS-CE-013`: remote `<link stylesheet>` in HTML/template (or reuse TS-CE-007 since it's the same class of risk)

**TDD approach:**
1. Add rule `TS-CE-012` to `findings/rules.py` (kind: `DOWNLOAD_AND_EXEC`, severity: MEDIUM)
2. Write test: `test_html_scanner.py::test_remote_script_src_emits_finding` — assert a Finding with rule_id TS-CE-012 is returned
3. Write test: `test_html_scanner.py::test_local_script_src_does_not_emit_finding`
4. Update `html_scanner.py` to return `list[Finding]` alongside deps
5. Wire findings into the CLI orchestrator merge
6. Run gate

**Files to modify:**
- `src/scarno/models.py` — no change (FindingKind.DOWNLOAD_AND_EXEC already exists)
- `src/scarno/findings/rules.py` — add TS-CE-012
- `src/scarno/analysers/html_scanner.py` — add `findings: list[Finding]` to `HtmlScanResult`, emit findings for remote URLs
- `src/scarno/cli.py` — merge HTML findings into the result
- `tests/unit/test_html_scanner.py` — add finding assertion tests
- `tests/srtm.py` — add new requirement IDs if needed

---

## GAP-B: Tree-sitter grammar wheel hash pinning

**Source:** GAP-17, SUC-27, SAC-27
**Risk:** MEDIUM
**Status:** Open

**Problem:** `pyproject.toml` pins tree-sitter grammar versions
(`tree-sitter-java>=0.23.5`) but does not use hash verification. A
compromised PyPI release of any grammar wheel would load native code
directly into the Scarno process. `uv` supports `--require-hashes`
but `pyproject.toml` does not natively support hash constraints.

**TDD approach:**
1. Write test: `test_coverage_configured.py::test_tree_sitter_deps_have_exact_pins` — assert every `tree-sitter-*` dependency in pyproject.toml uses `==` exact pins (not `>=` ranges)
2. Update `pyproject.toml` to use exact version pins for all tree-sitter deps
3. Generate `requirements-lock.txt` with `uv pip compile --generate-hashes` for CI use
4. Write test: `test_coverage_configured.py::test_requirements_lock_has_hashes` — assert the lock file exists and every tree-sitter entry has a sha256 hash
5. Document in `AGENTS.md`: tree-sitter deps must use exact pins

**Files to modify:**
- `pyproject.toml` — change `>=` to `==` for all tree-sitter deps
- `requirements-lock.txt` — new file with hashes (CI uses this)
- `tests/unit/test_coverage_configured.py` — add pin/hash tests
- `AGENTS.md` — document the policy

---

## GAP-C: CDN URLs should not appear in error messages

**Source:** GAP-18, SEC-NEW-29, PAC-07
**Risk:** LOW
**Status:** Open

**Problem:** If the HTML scanner encounters an error reading a template
file, the error message may include the file path but should never
include the CDN URLs extracted from that file. Currently the scanner
does not embed CDN URLs in error strings, but there is no test
enforcing this invariant.

**TDD approach:**
1. Write test: `test_html_scanner.py::test_error_messages_do_not_contain_cdn_urls` — create a template with a CDN URL that also triggers a read error (e.g. via permissions); assert no error string contains `cdn.jsdelivr.net` or similar
2. Review all `errors.append()` calls in `html_scanner.py` for URL leakage
3. No code change expected (the scanner already only appends file paths in errors), but the test locks the invariant

**Files to modify:**
- `tests/unit/test_html_scanner.py` — add invariant test

---

## Accepted risks (no implementation needed)

| ID | Item | Decision |
|----|------|----------|
| PAC-08 | Internal package names in SARIF | **Accept.** SARIF is designed to contain dependency names. Users control whether to upload SARIF to GitHub. Document in README. |
| PUC-08 | SARIF snippet contains source lines | **Accept.** This is standard SARIF behaviour (snippet.text). Snippets are sanitised and truncated to 200 chars. The privacy use case description should be updated to say "sanitised source snippets only, not full source files." |

---

## Implementation order

1. **GAP-A** (HTML findings) — highest value; aligns with existing CSS finding pattern
2. **GAP-C** (CDN URL error invariant) — quick win; test-only
3. **GAP-B** (hash pinning) — build/CI change; no runtime code change

## Estimated scope

- GAP-A: 2 new rules, ~30 lines of scanner code, ~10 test assertions
- GAP-B: pyproject.toml pin changes, 1 new CI file, 2 test assertions
- GAP-C: 1 test assertion, 0 code changes
