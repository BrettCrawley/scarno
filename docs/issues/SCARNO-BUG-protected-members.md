# scarno bug 2: `javap -public` hides protected members, so protected-member removals are never reported

**Component:** `scarno.analysers.java.source_analyser` (javap invocation) +
`scarno.analysers.java.abi_diff.javap_public_signatures` (parser)
**Version confirmed:** scarno **1.0.4**
**Severity:** High — **false negative in `TS-ABI-RUNTIME-RISK`**, the core detection
**Found:** 2026-08-25, ASF diamond-dependency research
**Relationship to the first report:** independent. `SCARNO-BUG-signature-diff.md` concerns
the diff *algorithm* collapsing overloads. This concerns the *input* never containing the
members in the first place. Fixing either does not fix the other.

---

## Summary

`source_analyser.py:691` extracts the ABI surface with:

```python
completed = subprocess.run(  # noqa: S603 — shell=False + validated argv
    [javap, "-public", "-classpath", str(jar_path), class_name],
```

`javap -public` emits **only public members**. Protected and package-private members never
appear, so `CrossVersionAbiDiffer` cannot see them change or disappear.

But a protected member removed between the declared and resolved version of a dependency
raises `NoSuchMethodError` at runtime exactly like a public one. Any subclass of a library
class that calls an inherited protected method is exposed — and subclassing library base
classes is the idiomatic way to use precisely the libraries most affected:

* Jackson — `StdDeserializer`, `BeanDeserializerModifier`
* Netty — `ChannelHandlerAdapter`, `ByteToMessageDecoder`
* Jetty — handler and `AbstractConnection` hierarchies
* SnakeYAML — `Constructor`, `Composer`, `SafeConstructor`

So the failure mode `TS-ABI-RUNTIME-RISK` exists to catch — *"a symbol your source calls is
removed or signature-changed between the declared and resolved version of a transitive —
`NoSuchMethodError` imminent"* — is undetectable for the entire protected surface.

## Scale

Non-private API surface by access level, measured with `javap -package` over the shipped
jars (these are the members a caller outside the class can legally reference):

| Artifact | public | protected | package-private | hidden from `-public` |
|---|---:|---:|---:|---:|
| `io.netty:netty-common@4.1.131.Final` | 2741 | 168 | 4810 | **64.5%** |
| `org.yaml:snakeyaml@2.5` | 901 | 146 | 225 | **29.2%** |
| `com.fasterxml.jackson.core:jackson-databind@2.21.1` | 7329 | **2484** | 365 | **28.0%** |
| `org.eclipse.jetty:jetty-util@12.0.22` | 2682 | 143 | 241 | 12.5% |
| `org.apache.commons:commons-lang3@3.18.0` | 4274 | 182 | 317 | 10.5% |

`jackson-databind` alone has **2,484 protected members** invisible to the current
extraction. Per-class the ratio can invert entirely: `org.yaml.snakeyaml.composer.Composer`
declares **4 public and 8 protected** members — twice as much protected surface as public.

## Scope: this affects classes, NOT interfaces

Interface members are implicitly `public`, so `javap -public` already emits all of them.
Verified by comparing member counts across access levels over whole interface sets:

| Sample | `-public` | `-package` | `-p` |
|---|---:|---:|---:|
| 57 interfaces from `netty-transport@4.1.131.Final` | 506 | 506 | 506 |
| 60 interfaces from `jackson-databind@2.21.1` | 251 | 251 | 251 |

Identical at every level. Java 9+ *private* interface methods are the only exception, and
they cannot be referenced by an external caller, so their removal is not a linkage risk.

The interface-side linkage risks that **are** real remain visible to `-public` and are
therefore detectable today — provided the diff algorithm itself is sound (see bug 1):

* removing an `abstract` interface method -> `NoSuchMethodError` for callers
* removing a `default` method -> `AbstractMethodError` for implementors relying on it
* removing an interface constant -> `NoSuchFieldError`

All three forms parse correctly with the reference implementation
(`java.util.function.Function` 4/4 incl. 2 default + 1 static; `java.util.Comparator`
18/18 incl. 7 default + 9 static; `java.util.Map` 39/39; `javax.xml.XMLConstants` 16/16
constants — the last being directly security-relevant, e.g.
`FEATURE_SECURE_PROCESSING`).

**So the defect is confined to class hierarchies** — which is where it bites hardest
anyway, because the affected pattern is subclassing a library base class and calling
inherited protected methods.

## Reproduction

```bash
JAR=~/.m2/repository/org/yaml/snakeyaml/2.5/snakeyaml-2.5.jar
javap -public  -classpath $JAR org.yaml.snakeyaml.composer.Composer | grep -c ';'   # 4
javap -package -classpath $JAR org.yaml.snakeyaml.composer.Composer | grep -c ';'   # 12
```

The 8 protected members in the difference are the ones a subclass calls, and the ones
whose removal would raise `NoSuchMethodError`.

---

## Suggested fix

**Two changes are needed — the flag alone is insufficient.**

**1. Extract at the right access level.** Replace `-public` with `-package` (public +
protected + package-private, excluding private) at `source_analyser.py:691`. Private
members cannot be referenced from outside the class, so including them would only add
noise; everything else is reachable by some legal caller.

**2. The parser cannot handle the extra output.** `javap_public_signatures` will silently
drop most of the newly-visible members, because its regexes enumerate the modifiers they
accept and require at least one:

```python
_JAVAP_METHOD_RE = ... (?:public|protected|static|final|abstract|synchronized|native)\s+ ... 
_JAVAP_FIELD_RE  = ... (?:public|protected|static|final|volatile|transient)\s+ ...
```

`private` appears in neither alternation, and a package-private member carries **no access
modifier at all** (`void foo();`), so the `+` quantifier fails outright. Measured on
`javap -p` output for `org.yaml.snakeyaml.LoaderOptions`: **34 declarations emitted, 22
parsed**. For `Composer`: **25 emitted, 11 parsed**, losing all 8 protected members.

The regexes need the access modifier to be optional and to include `private`:

```python
_ACCESS = r"(?:public|protected|private)"
_OTHER  = r"(?:static|final|abstract|synchronized|native|strictfp|default|volatile|transient)"
_MODS   = rf"(?:(?:{_ACCESS}|{_OTHER})\s+)*"     # note: * not +, modifiers optional
```

A working reference implementation covering all access levels is in this project's
`javap_parse.py` (validated at 34/34 and 25/25 against the counts above).

**3. Related, same file.** Constructors are printed **fully qualified** by javap
(`public org.yaml.snakeyaml.LoaderOptions();`), so any name group of the form `[\w$<>]+`
drops every constructor. Constructor removal is also a `NoSuchMethodError` source.

### Regression tests worth adding

1. Fixture class with a protected method; remove it between two versions; assert it is
   reported. Passes trivially today only because the member is invisible in both.
2. Fixture with a package-private method, same shape.
3. Assert parsed-declaration count equals the `;`-terminated line count of the javap
   output, so a silent parser drop fails the build.

## Impact summary

| | Bug 1 (`signature_diff`) | Bug 2 (this) |
|---|---|---|
| Mechanism | overloads collapsed to one representative | protected/package-private never extracted |
| Symptom | non-deterministic `changed`; deleted overloads missed | entire access levels invisible |
| Fix site | `abi_diff.signature_diff` | `source_analyser` javap argv + `abi_diff` regexes |
| Shared consequence | false negative in `TS-ABI-RUNTIME-RISK` | false negative in `TS-ABI-RUNTIME-RISK` |
