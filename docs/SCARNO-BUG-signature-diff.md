# scarno bug: `signature_diff()` collapses overloads — non-deterministic output and missed removals

**Component:** `scarno.analysers.java.abi_diff`
**Version confirmed:** scarno **1.0.4** (PyPI, `py3-none-any`)
**Severity:** High — produces non-reproducible output and **false negatives in the core
`TS-ABI-RUNTIME-RISK` detection**
**Found:** 2026-08-24, during ASF diamond-dependency research
**Reproduced on:** macOS arm64, CPython 3.14.2, JDK 21 (Corretto 21.0.10)

---

## Summary

`signature_diff()` keys both sides of the diff on
`_identity(sig) = (fqcn, member_kind, member_name)`, which deliberately ignores the
descriptor. It then builds a **dict keyed on that identity from a `set` of signatures**:

```python
# scarno/analysers/java/abi_diff.py:197
def signature_diff(*, declared: set[JavaSignature], resolved: set[JavaSignature]) -> AbiDiffResult:
    declared_by_id: dict[tuple[str, str, str], JavaSignature] = {
        _identity(s): s for s in declared          # <-- lossy
    }
    resolved_by_id: dict[tuple[str, str, str], JavaSignature] = {
        _identity(s): s for s in resolved          # <-- lossy
    }
```

Overloaded methods share an identity. The dict comprehension keeps only the
**last-iterated** signature per identity, and iteration order of a `set` of frozen
dataclasses depends on per-process string hash randomisation. Two consequences follow.

### 1. Output is not reproducible across processes

Same two jars, same code, only `PYTHONHASHSEED` varying:

```
PYTHONHASHSEED=0   removed=422 added=437 changed=51
PYTHONHASHSEED=1   removed=422 added=437 changed=53
PYTHONHASHSEED=2   removed=422 added=437 changed=58
PYTHONHASHSEED=3   removed=422 added=437 changed=50
PYTHONHASHSEED=42  removed=422 added=437 changed=52
```

`removed` and `added` are stable (they are set differences over identities), but
`changed` swings by ±8 because *which* overload becomes the representative for an
identity is arbitrary, and the descriptor/modifier comparison is done against that
arbitrary representative.

This matters beyond tidiness: an ABI finding used as vulnerability-disclosure evidence
has to be stable. "We found N breaking symbols" cannot vary run to run.

### 2. Deleted overloads are silently missed — a false negative for `NoSuchMethodError`

This is the more serious half. If `foo(String)` is deleted but `foo(int)` survives, the
*identity* `(Cls, method, foo)` exists on both sides, so it never enters `removed` and
never enters `changed` unless the arbitrarily-chosen representatives happen to differ.

Measured on one real pair (`org.eclipse.jetty:jetty-util` 9.4.51.v20230217 → 12.0.22):

```
identities present in both versions but with >=1 DELETED overload : 20
  of those, NOT reported in signature_diff().removed              : 20   (100%)
```

Concrete examples, all invisible to the current diff:

| Class#member | Deleted overload | Still present in 12.x |
|---|---|---|
| `ContainerLifeCycle#addEventListener` | `(Container$Listener)` | `(java.util.EventListener)` |
| `ContainerLifeCycle#removeEventListener` | `(Container$Listener)` | `(java.util.EventListener)` |
| **`URIUtil#encodePath`** | `(StringBuilder, String)` | `(String)` |
| `CompressionPool#release` | `(T)` | `(CompressionPool<T>.Entry)` |
| `ArrayTernaryTrie#getBest` | `(String)` | `(byte[], int, int)`, `(String, int, int)` |

A call site compiled against `URIUtil.encodePath(StringBuilder, String)` throws
`NoSuchMethodError` at runtime under 12.x. That is exactly the failure
`TS-ABI-RUNTIME-RISK` is documented to catch — "a symbol your source calls is removed or
signature-changed between the declared and resolved version of a transitive —
`NoSuchMethodError` imminent" — and it is missed. `URIUtil#encodePath` is a path-encoding
routine, so this is a security-relevant API, not an incidental one.

Scale: in the 9.4.51 jar alone, **124 identities cover 351 of 1533 signatures** — roughly
a quarter of the public surface is overloaded and therefore exposed to this.

---

## Reproduction

```python
from scarno.analysers.java.abi_diff import javap_public_signatures, signature_diff
import subprocess, zipfile

def sigs(jar):
    with zipfile.ZipFile(jar) as zf:
        cls = [n[:-6].replace("/", ".") for n in zf.namelist()
               if n.endswith(".class") and "$" not in n
               and not n.endswith("module-info.class") and not n.startswith("META-INF/")]
    out = set()
    for i in range(0, len(cls), 200):
        p = subprocess.run(["javap", "-public", "-classpath", jar, *cls[i:i+200]],
                           capture_output=True, text=True)
        out |= javap_public_signatures(p.stdout)
    return out

A = sigs("jetty-util-9.4.51.v20230217.jar")
B = sigs("jetty-util-12.0.22.jar")
print(len(signature_diff(declared=A, resolved=B).changed))
```

Run it several times under different `PYTHONHASHSEED` values; `changed` differs.

---

## Suggested fix

Group by identity into the **set of descriptors**, rather than collapsing to one
representative. This is deterministic and detects overload-level deletions:

```python
from collections import defaultdict

def signature_diff(*, declared, resolved):
    def by_id(sigs):
        m = defaultdict(set)
        for s in sigs:
            m[_identity(s)].add(s)
        return m

    d_by, r_by = by_id(declared), by_id(resolved)
    d_ids, r_ids = set(d_by), set(r_by)

    added   = {s for i in (r_ids - d_ids) for s in r_by[i]}
    removed = {s for i in (d_ids - r_ids) for s in d_by[i]}
    changed = set()

    for i in d_ids & r_ids:
        d_desc = {(s.descriptor, s.modifiers) for s in d_by[i]}
        r_desc = {(s.descriptor, s.modifiers) for s in r_by[i]}
        if d_desc == r_desc:
            continue
        # overloads deleted outright -> genuinely removed, not merely "changed"
        gone = {s for s in d_by[i] if (s.descriptor, s.modifiers) not in r_desc}
        still = {s for s in r_by[i] if (s.descriptor, s.modifiers) not in d_desc}
        if gone and not still:
            removed |= gone           # pure deletion of one or more overloads
        else:
            changed |= still or gone  # signature/modifier change
    return AbiDiffResult(added=frozenset(added), removed=frozenset(removed),
                         changed=frozenset(changed))
```

Whether a deleted overload belongs in `removed` or `changed` is a judgement call — but it
must appear in one of them, and the result must not depend on iteration order.

### Regression tests worth adding

1. **Determinism.** Run `signature_diff` over a fixture with overloads under several
   `PYTHONHASHSEED` values; assert identical results. A plain round-trip test will pass
   today and still miss this.
2. **Overload deletion.** `foo(String)` + `foo(int)` → `foo(int)`; assert `foo(String)`
   is reported.
3. **Overload addition.** The mirror case, so the fix does not over-report.

---

## Impact on downstream users

- `CrossVersionAbiDiffer.diff_all()` feeds `signature_diff` output into the
  `TS-ABI-RUNTIME-RISK` / `TS-ABI-DRIFT` split, so both findings inherit the false
  negatives and the instability.
- SARIF/JSON output is used for GitHub Code Scanning, where non-deterministic results
  cause findings to appear and disappear between otherwise identical CI runs.
- `--fail-on-severity` gates builds on this, so a build can pass or fail on hash seed.

## Workaround used in this research

`javap_public_signatures()` is **not affected** — verified deterministic across repeated
calls and across hash seeds — so this project keeps using it as the parser and performs
the diff itself at full-signature granularity (`(fqcn, kind, name, descriptor)`),
classifying an identity that survives with a deleted overload as breaking. See
`abi_diff_pairs.py`.