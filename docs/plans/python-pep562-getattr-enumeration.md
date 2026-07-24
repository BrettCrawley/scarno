# Plan: PEP 562 Module-Level `__getattr__` in Python Entry-Point Enumeration

## Context

The Python entry-point enumerator (`src/scarno/analysers/python/source_analyser.py:663-758`)
lists a dependency's public surface from `__all__` (if present) or `dir(module)`.
Module-level `__getattr__` (PEP 562) — used by numpy, scipy, tensorflow and others
for lazy submodule/attribute loading — is **not** explicitly considered.

The current code already handles the common cases by accident:

- **Module defines `__all__`** (numpy, scipy mostly do): enumeration uses `__all__`,
  and `getattr(module, sym)` at `:720` triggers `__getattr__`, resolving each lazy
  attribute so `_classify_symbol` sees the real type. ✅
- **Module defines `__getattr__` *and* `__dir__`**: `dir(module)` at `:697` honours
  the PEP 562 `__dir__` hook, so lazy names appear. ✅

Two real gaps remain:

1. **Under-reporting of *used* symbols** — a lazy symbol the user actually imports
   (`from pkg import lazy_thing`) that isn't in `dir()`/`__all__` never becomes an
   entry point. Worse, if `getattr` raises, `:721` silently drops a symbol we *know*
   was used. (Generic — not limited to PEP 562.)
2. **Unused, lazy-only surface** — a module with `__getattr__` but no `__all__` and
   no `__dir__` exposes names that are fundamentally non-enumerable from the module
   object. We cannot list what we cannot see; we can only be honest about it.

This change is tagged **FR-271** — the next free FR across the repo's SRTM
(`tests/srtm.py`); the prior maximum was FR-270 (REQ-24). Note FR-160 is already
assigned (Java method-invocation entry points), so it must not be reused here.

---

## Feature 1: Surface observed-used symbols regardless of `dir()`/`__all__`

### Current state
`_enumerate_entry_points()` builds `symbol_names` solely from `__all__` or
`dir(module)` (`source_analyser.py:693-697`), then emits one `EntryPoint` per name.
Symbols the user demonstrably used but that don't appear there are lost; a `getattr`
failure at `:721` drops the symbol entirely via `continue`.

### Implementation

**File:** `src/scarno/analysers/python/source_analyser.py`

In `_enumerate_entry_points()`:

- After computing `symbol_names` (`:693-697`), union in symbols observed in source:
  `used_symbols.get(import_name, set())` plus any `sym` where `(import_name, sym)`
  is a key in `usage_counts`. Dedupe while preserving the existing `__all__`/`dir()`
  ordering, then appending the extra used names.
- In the emit loop (`:718-738`), when `getattr(module, sym)` raises **and the symbol
  is known-used**, do not `continue`. Emit
  `EntryPoint(name=f"{import_name}.{sym}", kind="unknown", used=True, usage_count=count)`
  instead of dropping it.

This fixes gap #1 and generalises beyond PEP 562 (also covers re-exports and
conditionally-hidden names).

---

## Feature 2: Detect `__getattr__` and emit an honest diagnostic

### Problem
A module with module-level `__getattr__` but no `__dir__` has an unused lazy surface
we cannot enumerate. Silently returning an incomplete list misrepresents coverage.

### Implementation

**File:** `src/scarno/analysers/python/source_analyser.py`

Before the emit loop, inspect the module statically (no execution beyond what already
happens):

```python
module_getattr = vars(module).get("__getattr__")
has_dir_override = "__dir__" in vars(module)
if callable(module_getattr) and not has_dir_override:
    errors.append(
        f"entry_point_enumerator: {dep_canonical} uses module-level "
        "__getattr__ (PEP 562) without __dir__; unused lazy attributes "
        "may be under-enumerated."
    )
```

`vars()` introspection only — **no new code-execution surface** (SEC-001 unaffected).
The `getattr` calls that trigger lazy code already exist today at `:720`.

---

## Feature 3: Documentation

- **`docs/LIMITATIONS.md`** (Python section, `:71-85`): add a bullet noting that
  unused, lazy-only (`__getattr__`-without-`__dir__`) attributes are not enumerable;
  *used* lazy attributes now are surfaced.
- **`docs/requirements/REQ-3.md`** and **`docs/requirements/REQ-17b.md`**: short note
  referencing PEP 562 lazy loading and the FR-271 behaviour.
- **SRTM / tests**: register **FR-271** and tag new tests with
  `@pytest.mark.requirement("FR-271")` to match repo convention.

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/scarno/analysers/python/source_analyser.py` | Union observed-used symbols into enumeration; keep known-used symbols on `getattr` failure; emit PEP 562 diagnostic |
| `docs/LIMITATIONS.md` | New Python bullet for lazy-only attribute limitation |
| `docs/requirements/REQ-3.md`, `docs/requirements/REQ-17b.md` | PEP 562 / FR-271 note |
| `tests/unit/test_source_analyser.py` | New `TestPep562LazyEnumeration` class |

---

## Verification

Inject synthetic packages on `sys.path` via `tmp_path` + `monkeypatch.syspath_prepend`
(mirrors the `.venv`/dist-info fixture style at `test_source_analyser.py:157-173`):

1. **Used lazy symbol surfaced** — package with module-level `__getattr__`, no
   `__all__`/`__dir__`; fixture source does `from pkg import lazy_thing`. Assert
   `pkg.lazy_thing` appears as a `used=True` entry point.
2. **Diagnostic emitted** — same package shape; assert the PEP 562 note appears in the
   returned `errors`.
3. **`__dir__` regression** — package with `__getattr__` *and* `__dir__`; assert lazy
   names enumerate normally (documents existing-good behaviour).
4. **`__all__` regression** — existing `requests`/`pytest` enumeration tests still pass.
5. **Full suite** — all existing tests pass.

---

## Out of scope

No brute-forcing or speculative probing of `__getattr__` names — impossible in general
and an unbounded-execution risk.
