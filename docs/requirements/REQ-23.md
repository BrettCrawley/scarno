# REQ-23 — npm `overrides` / `resolutions` / `pnpm.overrides` Pinning Detection

## Overview

npm and its sibling package managers (yarn, pnpm) provide three
mechanisms for forcing a package to a specific version, regardless
of what transitive declarations would otherwise resolve:

- **`overrides`** in `package.json` (npm 8+).
- **`resolutions`** in `package.json` (yarn classic + Berry; pnpm
  also reads it).
- **`pnpm.overrides`** under `package.json#pnpm` (pnpm-specific).

A direct dependency that *appears* unused at the source level must
NOT be flagged for removal when it is itself the **target** of one
of these mechanisms, OR when a non-direct package becomes the
declared version because of one. The semantic mirrors REQ-21 (Maven
pinning): the pin exists for a reason and silently removing it
causes the original (often vulnerable) version to resolve.

Like REQ-21, REQ-23 surfaces these as `pin_override` with a
`pin_override_kind` that names the mechanism so the developer can
trace the why.

---

## Problem Statement

Common npm pin patterns we must NOT misclassify as removable:

```jsonc
// 1. npm overrides — pin transitive lodash to a CVE-patched version
{
  "name": "app",
  "dependencies": { "some-lib": "^3" },
  "overrides": { "lodash": "4.17.21" }
}

// 2. yarn resolutions — same intent, different field
{
  "name": "app",
  "dependencies": { "some-lib": "^3" },
  "resolutions": { "**/lodash": "4.17.21" }
}

// 3. pnpm.overrides
{
  "name": "app",
  "pnpm": { "overrides": { "lodash": "4.17.21" } }
}

// 4. Targeted overrides (npm syntax) — pin only when reached via X
{
  "overrides": {
    "some-lib": { "lodash": "4.17.21" }
  }
}

// 5. yarn pattern with package range — "x@<5"
{
  "resolutions": { "lodash@<5": "4.17.21" }
}
```

Scarno has no awareness of these today. Without REQ-23:

- A direct `lodash` declaration that exists only to *carry* the
  pinned version (when `overrides` references the direct version)
  could be flagged SAFE / removable.
- A user removes the direct dep + the override → vulnerable lodash
  reappears at the next `npm install`.

---

## Solution

### 1. Override extraction

```python
@dataclass
class NpmOverride:
    target_name: str            # "lodash"
    target_constraint: str | None  # "<5", "^4", or None for plain target
    forced_version: str         # "4.17.21"
    mechanism: str              # "npm-overrides" | "yarn-resolutions" | "pnpm-overrides"
    nested_under: str | None    # parent path for npm targeted overrides; None for top-level
    raw_key: str                # original key for diagnostics
```

Extracted at `package.json` parse time:

| File field | Mechanism |
|---|---|
| `overrides` | `npm-overrides` |
| `resolutions` | `yarn-resolutions` |
| `pnpm.overrides` | `pnpm-overrides` |

Targeted overrides (`overrides.some-lib.lodash`) recurse one level:
the `nested_under` field carries `"some-lib"`. Deeper nesting is
flattened with caps (see SEC-NEW-45).

### 2. Detection

```
For each direct dep X with no source-level usage:
    matching_overrides = [o for o in overrides if o.target_name == X.canonical]
    if matching_overrides:
        X.pin_override = True
        X.pin_override_kind = matching_overrides[0].mechanism.upper().replace("-", "_")
                              # e.g. "NPM_OVERRIDES"
        X.pin_override_target = (
            f"pinned via {mech} to {o.forced_version}"
            if not o.nested_under else
            f"pinned via {mech} under {o.nested_under} to {o.forced_version}"
        )
        X.status = IN_USE
```

Two edge cases:

- **Override target is NOT a direct dep**: that's normal (most
  overrides target transitives). REQ-23 *also* surfaces this as
  metadata on the affected `(canonical, version)` node in REQ-20's
  `versioned_nodes`, so users see why a non-direct version is
  resolved differently.
- **Override target is a direct dep with source usage**: no change
  to classification; the dep was already IN_USE. REQ-23 still
  records the `pin_override` flag for transparency.

### 3. Report integration

Markdown reporter "Pinning overrides" section (introduced in REQ-21)
gains an npm sub-table:

```markdown
### Pinning overrides (npm)

These dependencies (or override targets) are kept in place by an
override mechanism. Removing them silently re-allows the previous
version.

- `lodash` — pinned via `overrides` to 4.17.21
- `axios` — pinned via `pnpm.overrides` under `some-lib` to 1.6.7
```

JSON: same `pin_override` / `pin_override_kind` /
`pin_override_target` fields as REQ-21.
SARIF: rule `TS-DEP-PIN-OVERRIDE-NPM`, severity `note`.

### 4. Interaction with REQ-19 / REQ-20

- **REQ-19**: when an npm lockfile records the version forced by an
  override, that version is the declared version on the relevant
  edges (the override propagates through `package-lock.json`).
- **REQ-20**: the override's forced version is the resolved version
  for that coordinate; the multi-version table annotates it as
  `(pinned via npm-overrides)`.

### 5. Caps and recursion limits (`SEC-NEW-45`)

| Cap | Value | Justification |
|---|---|---|
| `_NPM_OVERRIDES_MAX_ENTRIES` | **2048** | Far above real-world usage. |
| `_NPM_OVERRIDES_MAX_NESTING` | **8** | npm allows nested targeted overrides; 8 is well above any sane usage. |

A targeted overrides tree that exceeds the nesting cap stops at the
cap with a sanitised note; entries already extracted are kept so a
partial pin-override report is still produced.

---

## Use Cases

```
UC-23a: npm overrides pinning a direct dep
Actor: Frontend developer.
Goal: Scarno keeps a direct dep that exists only as the override anchor.
Preconditions: package.json has `dependencies.lodash: "^4"` AND
  `overrides.lodash: "4.17.21"`. Source code does not import lodash
  directly (it's used only by transitive code paths).
Main flow:
  1. dep_file_parser extracts the npm-overrides entry.
  2. Source-usage check shows lodash unused at top level.
  3. REQ-23 matches the override target → pin_override=True.
  4. Status forced to IN_USE; report explains the pin.
Postcondition: no false-positive removal recommendation.

UC-23b: yarn resolutions with constraint
Actor: yarn-Berry developer.
Goal: Scarno recognises `**/lodash` patterns.
Preconditions: package.json has `resolutions: {"**/lodash": "4.17.21"}`.
Main flow:
  1. Parser extracts the resolution entry; target_name="lodash";
     target_constraint="**" (path glob, not version).
  2. Match logic strips path-glob prefixes and matches lodash by name.
Postcondition: lodash carries pin_override=True with
  kind="YARN_RESOLUTIONS".

UC-23c: pnpm.overrides nested under a parent
Actor: pnpm developer.
Goal: Scarno honours nested overrides.
Preconditions: package.json has
  `pnpm.overrides: { "some-lib>lodash": "4.17.21" }` (pnpm syntax for
  "lodash but only when reached via some-lib").
Main flow:
  1. Parser extracts the entry, target_name="lodash",
     nested_under="some-lib".
  2. The override applies whenever a some-lib branch resolves lodash.
  3. REQ-20 marks the resulting (lodash, 4.17.21) node as resolved.
Postcondition: tree row + "Multiple versions detected" annotation.
```

---

## Abuse Cases

```
SAC-51: Adversarial overrides tree triggers parser explosion
Linked threat: T-34
Attacker: External (commits a poisoned package.json with deeply
  nested targeted overrides).
Goal: Cause O(N) memory consumption / parse-time blowup on the
  override extractor.
Mitigated by: SEC-NEW-45 (entry + nesting caps).
OWASP: A05:2021.

SAC-52: Misleading override target name
Linked threat: T-35
Attacker: External (publishes a package whose name shadows a real
  dep, e.g. `lodash` capitalised differently or with a homoglyph).
Goal: Cause REQ-23 to attribute a pin to the wrong dep, hiding a
  real removable dep.
Mitigated by: SUC-54 — npm dep-name validator (SEC-NEW-34) plus
  exact-match-only logic (REQ-23 does NOT do fuzzy matching).
OWASP: A04:2021.
```

---

## Privacy

No new data category. Override target names are project metadata
already exposed in the SBOM. PUC-10 (REQ-19) sanitisation applies.

---

## Performance

```
PERF-016: npm pin-detection scaling
- Per package.json: O(overrides) bounded by _NPM_OVERRIDES_MAX_ENTRIES=2048.
- Targeted overrides tree walk: O(nodes × nesting), nesting capped
  at 8.
- Real-world budget: typical project (< 10 overrides): < 5 ms.
- Adversarial budget: 2048 overrides × 8 nesting = ~16k entries,
  parse + match < 100 ms.
```

---

## Security Use Cases

```
SUC-54: Exact-match override target validation
Mitigates: SAC-52
Control: NpmOverride.target_name passes through the existing
  _is_valid_npm_name validator (SEC-NEW-34) before being used as a
  match key. Match logic is exact equality (after path-glob prefix
  strip for yarn resolutions) — no fuzzy / case-insensitive match.
Implementation: src/scarno/analysers/javascript/dep_file_parser.py.
OWASP ASVS: §5.1.4.

SUC-55: SEC-NEW-45 caps
Mitigates: SAC-51
Control: Per SEC-NEW-45 above.
Implementation: src/scarno/analysers/javascript/dep_file_parser.py.
OWASP ASVS: §11.1.4.

SUC-56: Defer to REQ-20 classifier
Mitigates: SAC-44 npm variant (silent vulnerability reintroduction)
Control: REQ-20's SUC-42 already defers to pin_override flags. REQ-23
  populates the same flag, so the classifier protection is the same.
Implementation: src/scarno/core/detector.py.
```

---

## Threat Model

| ID | Threat | Mitigation |
|---|---|---|
| T-34 | Adversarial overrides JSON consumes parse / memory budget. | SEC-NEW-45 caps. |
| T-35 | Override target name does not match any real dep, leading to misclassification. | SUC-54 (exact match only) + SEC-NEW-34 npm-name validator. |

---

## SRTM (REQ-23)

| Req ID | Description | Test File |
|---|---|---|
| FR-240 | NpmOverride dataclass + extraction from `overrides` | `tests/unit/test_req23_overrides.py` |
| FR-241 | Extraction from `resolutions` (yarn) | `tests/unit/test_req23_resolutions.py` |
| FR-242 | Extraction from `pnpm.overrides` | `tests/unit/test_req23_pnpm.py` |
| FR-243 | Targeted overrides nesting (one level) | `tests/unit/test_req23_targeted.py` |
| FR-244 | Pin-override flagging on direct dep matches | `tests/unit/test_req23_match.py` |
| FR-245 | REQ-20 classifier defers to npm pin flags | `tests/unit/test_req23_classifier_integration.py` |
| FR-246 | Markdown / JSON / SARIF reporter integration | `tests/unit/test_req23_reporters.py` |
| SEC-NEW-45 | Override entry + nesting caps | `tests/security/test_req23_caps.py` |
| PERF-016 | Adversarial 2048 × 8 overrides parse < 100 ms | `tests/performance/test_req23_perf.py` |

---

## Acceptance Criteria

- [ ] Given `package.json` with `dependencies.lodash` and
  `overrides.lodash: "4.17.21"`, source not importing lodash, when
  analysis runs, then lodash has `pin_override=True`,
  `pin_override_kind="NPM_OVERRIDES"`, status=IN_USE.
- [ ] Given `package.json` with `resolutions: {"**/lodash": "4.17.21"}`
  and direct lodash dep unused at source, when analysis runs, then
  lodash has `pin_override_kind="YARN_RESOLUTIONS"`.
- [ ] Given `pnpm.overrides: {"some-lib>lodash": "4.17.21"}`, when
  analysis runs, then NpmOverride.nested_under="some-lib" is recorded.
- [ ] Given an override target name `lodash..` (invalid), when
  parsing runs, then it is rejected by SEC-NEW-34 and not added to
  the override list.
- [ ] Given 5000 overrides entries in package.json, when parsing
  runs, then exactly 2048 are retained and errors[] contains the
  truncation note.
- [ ] Given a targeted overrides tree nested 12 deep, when parsing
  runs, then 8 levels are retained and errors[] contains the
  nesting-cap note.
- [ ] Given an override target that does NOT match any direct dep,
  when classification runs, then no Dependency is incorrectly
  flagged pin_override; the override still appears in the
  multi-version annotation if a transitive matches.
- [ ] Given the SARIF reporter, when npm pin-overrides exist, then
  rule `TS-DEP-PIN-OVERRIDE-NPM` results are emitted per pinned dep.

---

## Out of Scope (REQ-23)

- **Detection of inappropriate overrides** (e.g. an override that
  pins to a still-vulnerable version) — out of scope.
- **Bun's lockfile and `bun.lockb`** — REQ-23 does not parse Bun's
  binary lockfile. Bun's `package.json` overrides field follows the
  npm convention and IS handled.
- **Workspaces / monorepo nesting** — REQ-23 evaluates the root
  `package.json` only. Per-workspace overrides are a future REQ.
- **Polyrepo overrides** — `npm-shrinkwrap.json` is treated like
  `package-lock.json` for resolved-version detection (REQ-19), but
  doesn't itself carry override directives.

---

## Limitations

- **Yarn Berry `protocols`** (`portal:`, `link:`, `patch:`) declared
  inside `resolutions` are recognised as overrides for classification
  purposes but the protocol-specific fetch behaviour is opaque.
- **`overrides` with a glob pattern that uses `*` cross-segment**
  (e.g. `*lodash*`) is not matched fuzzily; we look up exact targets
  only. Users who rely on glob overrides should treat the report as
  a starting point.
- **`pnpm.peerDependencyRules`** is similar in spirit but does NOT
  pin a version — REQ-23 ignores it.
- **The interaction of multiple mechanisms** (e.g. both `overrides`
  and `pnpm.overrides` in the same file) is reported as multiple
  pin records on the same dep; the report explains both. The
  package manager's actual precedence rules are documented but not
  encoded in REQ-23.
