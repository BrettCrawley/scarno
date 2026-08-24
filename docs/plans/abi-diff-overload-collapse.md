# Plan: Fix overload collapse in `signature_diff()` (REQ-22 / FR-233)

## Context

`docs/SCARNO-BUG-signature-diff.md` reports a High-severity defect in
`scarno.analysers.java.abi_diff`, confirmed against the published
1.0.4 wheel. `signature_diff()` keys both sides of the diff on
`_identity(sig) = (fqcn, member_kind, member_name)` — descriptor
deliberately excluded so a retyped parameter reads as CHANGED rather
than REMOVED + ADDED — but it then materialises that keying as a dict
comprehension **over a `set`**:

```python
declared_by_id = {_identity(s): s for s in declared}   # src/scarno/analysers/java/abi_diff.py:208
```

Overloads share an identity, so the comprehension keeps whichever
overload the set happened to yield last. Two failures follow:

1. **Non-reproducible output.** The representative chosen per identity
   varies with per-process string hash randomisation; the reporter
   measured `changed` swinging between 50 and 58 across
   `PYTHONHASHSEED` values on the same jar pair, with `removed` /
   `added` stable (they are set differences over identities). SARIF
   fed to GitHub Code Scanning gains and loses findings between
   identical CI runs, and `--fail-on-severity` can gate a build on the
   hash seed.
2. **Deleted overloads are invisible.** If `foo(String)` is deleted and
   `foo(int)` survives, the identity exists on both sides, so the
   deletion enters neither `removed` nor `changed` unless the two
   arbitrary representatives happen to differ. Measured on
   `jetty-util` 9.4.51 → 12.0.22: 20 of 20 identities carrying a
   deleted overload were missed (100%), including
   `URIUtil#encodePath(StringBuilder, String)` — a path-encoding API
   whose removal is a live `NoSuchMethodError` at any call site
   compiled against 9.4.x. That is precisely the failure
   `TS-ABI-RUNTIME-RISK` exists to catch, so the bug is a false
   negative in the core detection, not a cosmetic one. Roughly a
   quarter of the public surface of the sample jar is overloaded
   (124 identities covering 351 of 1533 signatures).

`javap_public_signatures()` is not implicated — the reporter verified
it deterministic across seeds, and our reading agrees (it iterates
`stdout.splitlines()` in order and truncates at a fixed cap).

Blast radius is small: `signature_diff`, `AbiDiffResult` and
`javap_public_signatures` have no call sites outside `abi_diff.py`.

## Second defect found while tracing the fix

The bug report stops at `signature_diff`. Fixing only that function
leaves the run **still non-deterministic**, for a different reason.

`_emit_findings` (`abi_diff.py:541`) builds `risk_classes` as a *set*
of `(action, sig)` tuples and iterates it, so Finding order is
hash-dependent. `diff_all` compensates with a stable sort
(`_finding_sort_key`, R-Phase9-01) — but that key is
`(severity, kind, package_hint, file_path, line, rule_id, message)`,
and every ABI finding carries `file_path=""`, `line=0`. The only
discriminating field left is `message`, which is built from
`f"{sig.fqcn}.{sig.member_name}"` — **the descriptor is not in it**.

Today that is masked, because identity collapse guarantees at most one
signature per identity. The moment we fix `signature_diff` to report
per-overload, two overloads of the same member produce two Findings
with byte-identical messages and therefore identical sort keys, and
`list.sort` falls back to input order — which is the hash-ordered set
iteration. The reproducibility bug would survive the fix in a new
place, and the report would show duplicate-looking lines with no way
to tell which overload each refers to.

So the fix is two-part: descriptor-granular diffing **and**
descriptor-bearing, totally-ordered findings.

## Design

### Bucketing rule

Group each side by identity into the full set of signatures, then
compare at descriptor granularity. Within one identity in one version,
`descriptor` is unique (Java forbids two overloads with the same
parameter list; `javap` renders the parameter list only), so
`(identity, descriptor)` is a sound full key.

Per identity present on both sides, with
`gone` = declared descriptors absent from resolved,
`new` = resolved descriptors absent from declared,
`shifted` = descriptors on both sides whose `modifiers` differ:

| Case | Bucket | Rationale |
|---|---|---|
| identity only in declared | all its sigs → `removed` | unchanged from today |
| identity only in resolved | all its sigs → `added` | unchanged from today |
| member not overloaded on either side, its one descriptor differs | the resolved-side sig → `changed` | the FR-233 "retyped parameter" case; preserves documented semantics and the existing test |
| otherwise, `gone` non-empty | each → `removed` | a descriptor the JVM can no longer resolve — `NoSuchMethodError` |
| otherwise, `new` non-empty | each → `added` | a widened surface is not a hazard |
| `shifted` | resolved-side sig → `changed` | e.g. became `abstract` / lost `static` |

The bug report leaves removed-vs-changed for a deleted overload as a
judgement call. The not-overloaded rule above is the one place that
judgement lives, and it is deliberately low-stakes: `_emit_findings` maps
**both** REMOVED-and-called and CHANGED-and-called to
`TS-ABI-RUNTIME-RISK` at HIGH, so a misclassification between those
two buckets changes wording and remediation text, not severity or
gating. The classification that would actually be dangerous — a
deleted overload landing in `added`, which only ever emits MEDIUM
`TS-ABI-DRIFT` — cannot happen under this rule. If we later decide the
heuristic is still too clever, changing it to "every `gone` is
`removed`" is a one-line edit plus the FR-233 test's expectation.

**Narrowed during implementation.** The rule was first written as
`len(gone) == 1 and len(new) == 1`, i.e. any one-in-one-out swap
within an identity. The TA-363 fixture showed why that is wrong: a
member with four overloads that loses `(StringBuilder, String)` and
gains `(CharSequence)` would be reported as CHANGED *naming
`(CharSequence)`* — the signature the caller never used — while the
descriptor they actually compiled against disappears from the report.
Pairing a deletion with an unrelated addition is a guess as soon as
the member is overloaded; the deletion is a fact. The rule now
applies only when the member has exactly one descriptor on each side,
which is the case FR-233's reasoning actually covers.

Determinism follows by construction: the output sets are a pure
function of the input sets, with no representative selection anywhere.

### Findings

- Put the descriptor in the Finding message, e.g.
  `org.eclipse.jetty.util.URIUtil.encodePath(java.lang.StringBuilder, java.lang.String)`,
  through `sanitise()` like every other interpolated value.
- Iterate `sorted(...)` over the diff sets in `_emit_findings` instead
  of a set of tuples, so ordering is fixed before the stable sort ever
  runs.
- Add `descriptor` (or the full symbol string) as a trailing
  `_finding_sort_key` component so the key is total for ABI findings
  even if two messages ever coincide again.

## Steps

Red-test-first, matching the Phase-9 convention (tests committed
before implementation). Single PR; the parts are too coupled to split
usefully.

1. **Register the requirement IDs first**, or CI rejects the new
   markers — `tests/srtm_plugin.py` fails the session on any
   `@pytest.mark.requirement` ID absent from `tests/srtm.py`. Add to
   `FUNCTIONAL_REQUIREMENTS`:
   - `FR-272` — `signature_diff` diffs at descriptor granularity; a
     deleted overload of a surviving member is reported.
   - `FR-273` — `signature_diff` output is invariant under
     `PYTHONHASHSEED`.
   - `FR-274` — ABI findings identify the overload (descriptor in the
     message) and sort totally.
   Add the matching rows to the SRTM table in `docs/requirements/REQ-22.md`
   and TA rows (`TA-357`+, next free) to
   `docs/scarno-test-plan-phase9.md`.

2. **Red tests** in `tests/unit/test_req22_diff.py` (extend; keep the
   existing `test_signature_diff_added_removed_changed` untouched as
   the FR-233 back-compat guard):
   - `foo(String)` + `foo(int)` → `foo(int)`: assert the `String`
     overload appears in `removed`, keyed on descriptor, and that the
     surviving overload appears in none of the three sets. **FR-272**
   - Mirror: `foo(int)` → `foo(int)` + `foo(String)`; assert exactly
     one entry in `added` and nothing in `removed` / `changed`
     (guards against over-reporting).
   - Sole overload retyped `(I)V` → `(II)V` → `changed`, not
     `removed`+`added` (the 1:1 rule, and FR-233 semantics).
   - Modifier-only shift on an unchanged descriptor → `changed`.
   - Constructor and field identities behave the same (fields cannot
     overload — assert they still round-trip).
   - A `URIUtil#encodePath`-shaped fixture drawn from the bug report,
     asserted by name, so the regression has a named witness.
3. **Determinism test**, `tests/unit/test_req22_diff_determinism.py`
   — **FR-273**. Two layers:
   - Exact-set assertions on an overload-heavy fixture. A correct
     implementation is order-free by construction, so this pins the
     behaviour and runs in-process.
   - The report's actual reproduction: re-run the diff in child
     interpreters under `PYTHONHASHSEED` in `{0, 1, 2, 3, 42}` via
     `subprocess.run([sys.executable, "-c", ...])`, comparing a
     canonical serialisation of the three sets. Note in the docstring
     that the NEW-ARCH-011 "no subprocess imports" invariant binds
     `src/scarno/analysers/**`, not tests — confirm the
     `tests/security/test_arch_*.py` AST scans are scoped to `src/`
     before writing this, and if any scan covers `tests/`, fall back
     to the in-process layer plus a permuted-insertion-order check.
4. **Finding-level test** — **FR-274**. Drive `_emit_findings` with a
   diff containing two removed overloads of one member and assert:
   two distinct Findings, each message carrying its own descriptor,
   and `sorted(findings, key=_finding_sort_key)` stable across a
   shuffled input list.
5. **Implement** in `abi_diff.py`:
   - Rewrite `signature_diff` per the bucketing table, using a
     `defaultdict(set)` grouping helper. Keep the signature, the
     keyword-only parameters and the `AbiDiffResult` shape exactly as
     they are — this is an internal-behaviour fix, not an API change.
   - Update the `signature_diff` docstring and the `_identity`
     docstring (which currently states the collapse as intended
     behaviour) to describe identity-then-descriptor matching.
   - Extend `_emit_findings` messages with the descriptor; iterate
     `sorted()` over each bucket.
   - Extend `_finding_sort_key` with a final tiebreak component.
   - Correct the `JavaSignature` docstring in `src/scarno/models.py:180`,
     which describes diffing as "set operations on
     `(fqcn, member_kind, member_name, descriptor)` tuples" — that is
     what the fix makes true, and was not true before.
6. **Full suite** — `uv run pytest` with `--srtm-fail-on-gap`. Pay
   particular attention to:
   - `tests/performance/test_req22_perf.py` (PERF-015, "no quadratic
     blowup"): the new implementation is one pass to group plus one
     pass over the identity intersection, so it stays linear in
     signature count, but the constant factor rises — check the
     assertion's headroom rather than assuming.
   - `tests/unit/test_req22_runtime_risk.py` and
     `tests/unit/test_req22_cli.py` — message-text assertions are the
     likely breakage from the descriptor change.
   - `tests/fixtures/back_compat/pre_phase9.*` should be unaffected
     (deep inspection is off in that baseline); confirm rather than
     assume.
7. **CHANGELOG** under a new `## [Unreleased]` → `### Fixed` heading,
   in the existing prose style: state the false negative plainly, name
   the affected rule IDs, and say that reported counts will rise on
   overload-heavy dependencies after upgrading. Reference the bug
   report path.

## Risks

- **Finding volume rises.** Overload-heavy jars now yield one finding
  per deleted overload rather than one per member. On the reporter's
  sample that is ~351 signatures where 124 identities were considered
  before. Existing runs already emit hundreds of ABI_DRIFT findings,
  so this is a change of degree, and the extra findings are the true
  positives the tool was missing — but `TS-ABI-DRIFT` (MEDIUM,
  not-called symbols) is where the noise lands. If the increase proves
  unusable in practice, the follow-up is to group DRIFT per identity
  in the reporter, not to re-collapse the diff. Out of scope here.
- **`--fail-on-severity` behaviour changes for existing users.** Builds
  that passed on a false negative will start failing. That is the
  point of the fix, and the CHANGELOG must say so explicitly so an
  upgrade is not mistaken for a regression.
- **The 1:1 replacement heuristic** is the one judgement call; see
  the design note above for why it is contained and how to reverse it.

## Out of scope

- `_emit_findings`'s `is_called` matching
  (`ref.endswith("." + sig.member_name)`) flags every overload of a
  called member, not the specific overload — over-reporting rather
  than under-reporting, so it is conservative in the safe direction,
  and narrowing it requires descriptor-level call-site extraction from
  the source analyser. Separate piece of work.
- `_class_name_from_coord`'s probe-FQCN convention, and the
  `_JAVAP_MAX_SIGNATURES_PER_JAR` silent truncation.
- The reporter's own `abi_diff_pairs.py` workaround is theirs to
  retire once this ships.