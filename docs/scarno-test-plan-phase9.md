# Scarno — Phase-9 Test Plan (REQ-19..REQ-23 + REQ-19a)

Date: 2026-05-11
Version: 1.0
Framework: pytest 8.x · Python 3.12+
Input artifacts:
- `docs/THREAT-MODEL.md` §9 (Phase-9 threat model) + §9.11 (re-validation closure)
- `docs/scarno-security-architecture.md` §11 + §11.15 (post-threat-model revisions)
- `docs/scarno-security-privacy-analysis.md` §13..§21
- `docs/requirements/REQ-19.md`, REQ-20.md, REQ-21.md, REQ-21b.md, REQ-22.md, REQ-23.md, REQ-19a.md

This document is the Phase-9 companion to `docs/scarno-test-suite.md`
(which covers REQ-1..REQ-18). Pre-existing TAs continue at their
established IDs; Phase-9 starts at **TA-200** and runs through
**TA-3xx** depending on per-PR allocation.

---

## Conventions

- **TA-XXX** identifier per test or test-group.
- **Markers**: `@pytest.mark.REQ_NN` (REQ_19, REQ_20, REQ_21, REQ_21b, REQ_22, REQ_23, REQ_19a). NEW-ARCH-NNN markers fold under `@pytest.mark.REQ_19a` (per analysis-doc §20.3 convention) — the underlying SUC / SEC-NEW marker rides as a second pytest marker for SRTM-plugin discovery.
- **Test categories**: Functional Security · Security Attack · Performance · Regression · TDD red-then-green · Penetration (manual).
- **TDD discipline**: every test in this plan is intended to **fail** in the current pre-Phase-9 codebase. The implementation in PR-1..PR-6 makes them green.
- **Fixtures**: per-PR fixtures live under `tests/fixtures/phase9/<req>/`. Existing fixtures (e.g. `tests/fixtures/req17/`) are not touched.
- **SRTM gate**: `tests/srtm_plugin.py` baseline rises from 195/195 to 256/256 once Phase 9 lands across all six PRs (per analysis §21.5).

The single highest-priority test in the entire plan is **TA-228** (PR-2's SEC-NEW-55 fixed-argv contract verification). It is what closes Phase-3 finding T-Phase9-04 from "Open / Escalated" to "Closed".

---

## PR-1 — REQ-19 (per-edge version labels)

Lands: `DepEdge` dataclass, `AnalysisResult.dep_edges`, `sanitise_declared_version`, per-ecosystem edge emitters (Maven / Gradle / npm), markdown reporter rendering distinct (canonical, version) nodes, gradle.lockfile cross-check (SEC-NEW-53), pre-Phase-9 back-compat fixture establishment (NEW-ARCH-009).

### Functional security

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-200 | `test_depedge_dataclass_is_frozen` | `tests/unit/test_req19_models.py` | `REQ_19` + `FR-190` | Construct `DepEdge`; mutate `declared_version` after construction. | `dataclasses.FrozenInstanceError`. |
| TA-201 | `test_depedge_default_scope_runtime` | same | `REQ_19` + `FR-190` | Construct without scope. | `scope == "runtime"`. |
| TA-202 | `test_dep_graph_derived_from_dep_edges` | `tests/unit/test_req19_compat.py` | `REQ_19` + `FR-195` | Pass `dep_edges` only, leave `dep_graph` empty. | After `__post_init__`, `dep_graph` mirrors `{e.parent: {e.child for e in dep_edges if e.parent==p}}`. |
| TA-203 | `test_maven_emits_dep_edges_with_declared_version` | `tests/unit/test_req19_maven_edges.py` | `REQ_19` + `FR-191` | Fixture: `pom.xml` with `alpha 2.0` → transitive `x 1.1`; `beta 3.0` → transitive `x 1.2` (via cached POMs in fake `~/.m2`). | `result.dep_edges` contains both edges with distinct `declared_version`. |
| TA-204 | `test_maven_property_resolution_precedes_edge_emission` | same | `REQ_19` + `FR-191` | Fixture: `<version>${some.prop}</version>` with property defined locally. | Edge emitted with the resolved version, not the literal `${...}`. |
| TA-205 | `test_maven_unresolvable_version_emits_edge_with_None` | same | `REQ_19` + `FR-191` | Fixture: `<version>${undefined.prop}</version>`. | `DepEdge.declared_version is None` (NOT skipped). |
| TA-206 | `test_gradle_emits_edge_with_requested_version_not_resolved` | `tests/unit/test_req19_gradle_edges.py` | `REQ_19` + `FR-192` | `gradle dependencies` output line `a:b:1.0 -> 1.5`. | `DepEdge.declared_version == "1.0"`. |
| TA-207 | `test_npm_package_lock_v3_emits_distinct_versions` | `tests/unit/test_req19_npm_edges.py` | `REQ_19` + `FR-193` | `package-lock.json v3` with two paths declaring `scheduler` at 0.23.0 and 0.23.2. | Both edges in `dep_edges`. |
| TA-208 | `test_yarn_lock_v1_partial_parse_skips_malformed` | same | `REQ_19` + `FR-193` | `yarn.lock` v1 with one valid entry + one malformed. | Valid entry emitted; malformed dropped with sanitised `errors[]` note. |
| TA-209 | `test_pnpm_lockfile_v6_emits_edges` | same | `REQ_19` + `FR-193` | `pnpm-lock.yaml` v6 fixture. | Edges emitted. |
| TA-210 | `test_markdown_renders_distinct_versions_as_two_nodes` | `tests/unit/test_req19_tree_render.py` | `REQ_19` + `FR-194` | `dep_edges` with `x@1.1` and `x@1.2`. | Rendered tree has TWO `x` nodes, not one. |

### Security attack

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-211 | `test_version_string_strips_control_chars` | `tests/security/test_req19_version_sanitise.py` | `REQ_19` + `SEC-NEW-38` | Version string `1.0\x1b[31mEVIL\x1b[0m`. | Output stripped to `1.0EVIL` (control bytes gone, payload kept as inert text). |
| TA-212 | `test_version_string_strips_mermaid_active_chars` | same | `REQ_19` + `SEC-NEW-38` | Version `1.0]; click n_0 "javascript:alert(1)"`. | Output contains no `]`, no `click`. |
| TA-213 | `test_version_string_capped_at_64_chars` | same | `REQ_19` + `SEC-NEW-38` | 200-char version string. | Length ≤ 64. |
| TA-214 | `test_version_string_safe_for_markdown_table` | same | `REQ_19` + `SEC-NEW-38` (extended per SEC-NEW-54) | Version `1.0\|alpha`. | `\|` stripped or escaped so the rendered "Multiple versions detected" markdown table parses correctly. |
| TA-215 | `test_version_string_safe_for_markdown_inline_code` | same | `REQ_19` + `SEC-NEW-54` | Version with backtick. | Backtick stripped/escaped. |
| TA-216 | `test_version_string_json_encodeable` | same | `REQ_19` + `SEC-NEW-54` | Adversarial version string round-tripped through `json.dumps` → `json.loads`. | No exception, output stable. |
| TA-217 | `test_lockfile_size_cap_rejects_9MiB` | `tests/security/test_req19_lockfile_caps.py` | `REQ_19` + `SEC-NEW-37` | 9 MiB synthetic `package-lock.json`. | Lockfile rejected with sanitised `errors[]` note; rest of analysis still produces a partial result. |
| TA-218 | `test_lockfile_edge_cap_rejects_60k_edges` | same | `REQ_19` + `SEC-NEW-37` | Synthetic lockfile within byte cap but with 60 000 edges. | Edge emission stops at 50 000 with truncation note. |
| TA-219 | `test_pom_xml_with_adversarial_version_no_breakage` | same | `REQ_19` + `SEC-NEW-38` | Fixture: `<version>1.0\n[click n_0 ...]</version>`. | Rendered tree row has no newline, no `click` substring; markdown still parses. |

### Regression / back-compat

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-220 | `test_dep_graph_only_path_preserves_REQ17_render` | `tests/unit/test_req19_compat.py` | `REQ_19` + `REQ_17` | Build `AnalysisResult` with `dep_graph` populated, `dep_edges` empty. | Markdown reporter renders identically to the pre-Phase-9 output (REQ-17 acceptance criteria do not regress). |
| TA-221 | `test_back_compat_fixture_present` | `tests/integration/test_back_compat.py` | `REQ_19a` + `NEW-ARCH-009` | `tests/fixtures/back_compat/pre_phase9.{json,sarif,md,txt}` exist. | Files present and non-empty. |
| TA-222 | `test_back_compat_strict_inclusion_json` | same | `REQ_19a` + `NEW-ARCH-009` + `SEC-NEW-49` | Run JSON reporter against the saved `AnalysisResult` and compare keys to the saved JSON fixture. | Every fixture key present in current output. New keys allowed; removed keys fail with PR-description-required message. |
| TA-223 | `test_back_compat_strict_inclusion_sarif` | same | `REQ_19a` + `NEW-ARCH-009` | Same as TA-222 for SARIF rule IDs. | Every fixture rule-id present. |

### gradle.lockfile cross-check (SEC-NEW-53)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-224 | `test_gradle_lockfile_strict_subset_warns` | `tests/unit/test_req19_gradle_lockfile_crosscheck.py` | `REQ_19` + `SEC-NEW-53` | Both `gradle.lockfile` and `gradle dependencies` output present; lockfile is a strict subset of the gradle-output coordinate set. | `result.errors[]` contains the lockfile-divergence warning. |
| TA-225 | `test_gradle_lockfile_equal_set_no_warning` | same | `REQ_19` + `SEC-NEW-53` | Both sources present, equal coordinate sets. | No warning emitted. |

### Performance

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-226 | `test_tree_render_1000_deps_5000_edges_under_25pct_baseline` | `tests/performance/test_req19_tree_render_perf.py` | `REQ_19` + `PERF-010` | Synthetic 1000-dep / 5000-edge graph. | Tree render time ≤ 1.25 × the REQ-17 baseline (captured by `tests/performance/test_req17_perf.py`). |
| TA-227 | `test_npm_lockfile_8MiB_parse_under_500ms` | same | `REQ_19` + `PERF-010` | 8 MiB realistic `package-lock.json`. | Parse + edge emission under 500 ms wall clock. |

### PR-1 landing checklist

Required to merge PR-1: TA-200, TA-202, TA-203, TA-206, TA-207, TA-210, TA-211–TA-219 (all security), TA-220, TA-221, TA-222, TA-223, TA-224. Performance tests (TA-226, TA-227) are advisory but blocking for the release tag, not for merge.

NEW-ARCH-009 is established here even though its statement applies to every subsequent PR — TA-221..223 set up the fixture framework that PR-2..PR-6 inherit.

---

## PR-2 — REQ-20 (per-version classification + classifier extraction + subprocess hardening)

Lands the largest PR by far. Architecture §11.15 expanded PR-2 to own:
- `core/classifier.py` (new module) with `classify_versioned`, `classify_canonical`, `apply_pin_override_safety`, the pin-detector registry (ADR-012), and `_safe_cpu_count`.
- `Dependency.pin_override*` field allocation (moved from PR-3).
- `security.safe_subprocess_run` primitive (ADR-013) + `BinaryNotConfinedError`.
- `_invoke_mvn_safe` + `_invoke_gradle_safe` per-binary helpers.
- `_resolve_gradle_binary` mirroring `_resolve_mvn_binary` (SEC-NEW-52).
- REQ-20 resolved-version detection using fixed argv (SEC-NEW-55).
- `register_no_pin_mechanism` calls in pypi / go / nuget / css analyser modules.
- `VersionedNode` dataclass + `multi_version_coords` reporting.

### Functional security — classifier core

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-220a | `test_classify_versioned_diamond_partial_safe` | `tests/unit/test_req20_classify.py` | `REQ_20` + `FR-201` | alpha (IN_USE) → x@1.1 + beta (SAFE) → x@1.2; resolved 1.1. | `versioned_nodes` has x@1.1 IN_USE, x@1.2 SAFE removable. |
| TA-220b | `test_classify_versioned_any_in_use_promotes` | same | `REQ_20` + `FR-202` | Both alpha (IN_USE) → x@1.1 and beta (IN_USE) → x@1.2. | Both x versions IN_USE; multi_version_coords lists x; "Removable" = "—". |
| TA-220c | `test_classify_canonical_legacy_path_unchanged` | same | `REQ_20` + `FR-195` | Analyser supplies dep_graph but no dep_edges. | `classify_canonical` invoked; output matches pre-Phase-9 Python-analyser behaviour exactly. |
| TA-220d | `test_dependency_status_rollup_any_version_in_use` | same | `REQ_20` + `FR-200` | After `classify_versioned`, `Dependency.status` reflects "any version IN_USE" rollup of `versioned_nodes`. | Rollup matches expected. |

### Functional security — pin-override safety (the load-bearing one)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-221a | `test_apply_pin_override_safety_forces_in_use` | `tests/unit/test_req20_pin_override_safety.py` | `REQ_20` + `SUC-42` | `Dependency(pin_override=True, pin_override_kind="EXCLUSION")` + `VersionedNode(status=SAFE)`. | After `apply_pin_override_safety`, `VersionedNode.status == IN_USE`, `removable == False`, reason names the trigger. |
| TA-221b | `test_apply_pin_override_safety_dynamic_downgrades` | same | `REQ_20` + `SUC-42` + `SUC-48` | `pin_override_kind == GRADLE_DYNAMIC_PIN`. | `VersionedNode.status == UNCERTAIN`, reason = "manual review required". |
| TA-221c | `test_apply_pin_override_safety_manifest_redundant_forces_in_use` | same | `REQ_20` + `SUC-42` | `Dependency(manifest_redundant=True)`. | Status forced IN_USE. |
| TA-221d | `test_apply_pin_override_safety_resolved_version_forces_in_use` | same | `REQ_20` + `SUC-42` | `VersionedNode(is_resolved=True)`. | Status IN_USE; removable False. |

### Functional security — pin-detector registry (NEW-ARCH-012)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-222a | `test_pin_detector_registry_api_register_pin_detector` | `tests/unit/test_arch_pin_detector_registry.py` | `REQ_19a` + `NEW-ARCH-012` + `FR-254` | Call `register_pin_detector("foo")`. | `"foo" in _PIN_DETECTOR_REGISTRY`. |
| TA-222b | `test_pin_detector_registry_api_register_no_pin_mechanism` | same | `REQ_19a` + `NEW-ARCH-012` + `FR-254` | Call `register_no_pin_mechanism("bar")`. | `"bar" in _NO_PIN_MECHANISM_REGISTRY`. |
| TA-222c | `test_symmetric_coverage_after_all_imports` | same | `REQ_19a` + `NEW-ARCH-012` + `SEC-NEW-57` + `SUC-63` | Force-import every analyser module under `src/scarno/analysers/`. | `set(core.registry.registered_languages()) == _PIN_DETECTOR_REGISTRY \| _NO_PIN_MECHANISM_REGISTRY`. |
| TA-222d | `test_pin_detector_and_no_pin_mechanism_disjoint` | same | `REQ_19a` + `NEW-ARCH-012` + `SEC-NEW-57` | Same fixture as TA-222c. | `_PIN_DETECTOR_REGISTRY & _NO_PIN_MECHANISM_REGISTRY == set()`. |
| TA-222e | `test_unregistered_ecosystem_classifier_downgrades_to_uncertain` | same | `REQ_20` + `REQ_19a` + `NEW-ARCH-012` | Classifier sees direct dep with no source usage in an unregistered ecosystem. | `Dependency.status == UNCERTAIN` with reason naming the missing detector. |

### Functional security — `Dependency` post-init invariant (NEW-ARCH-007)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-223a | `test_post_init_rejects_pin_override_and_manifest_redundant` | `tests/unit/test_arch_pin_redundant_mutex.py` | `REQ_19a` + `NEW-ARCH-007` + `FR-251` + `SUC-58` | Construct `Dependency(pin_override=True, manifest_redundant=True)`. | `ValueError` raised. |
| TA-223b | `test_classifier_asserts_mutex_on_entry` | same | `REQ_19a` + `NEW-ARCH-007` + `SEC-NEW-47` | Pre-existing `Dependency` mutated post-construction to set both flags, then passed to `apply_pin_override_safety`. | `AssertionError` raised. |

### Resolved-version detection (REQ-20 §3)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-224a | `test_maven_resolved_version_via_dependency_tree` | `tests/unit/test_req20_resolved_maven.py` | `REQ_20` + `FR-203` | Mocked `mvn dependency:tree` output. | `versioned_nodes[i].is_resolved == True` for the picked version. |
| TA-224b | `test_maven_resolved_version_fallback_nearest_wins` | same | `REQ_20` + `FR-203` | mvn unavailable; fall through to dep_edges-shortest-path heuristic. | Resolved version picked correctly; `errors[]` notes the fallback. |
| TA-225a | `test_gradle_resolved_version_via_dependencies_output` | `tests/unit/test_req20_resolved_gradle.py` | `REQ_20` + `FR-204` | Mocked `gradle dependencies` output with `requested -> resolved`. | Resolved-version flag set. |
| TA-225b | `test_gradle_lockfile_overrides_dependencies_output` | same | `REQ_20` + `FR-204` | Both gradle.lockfile + dependencies output present. | Lockfile wins for resolved-version detection. |
| TA-226a | `test_npm_resolved_version_from_lockfile_root_install` | `tests/unit/test_req20_resolved_npm.py` | `REQ_20` + `FR-205` | package-lock.json with overrides forcing lodash to 4.17.21. | Resolved version 4.17.21 marked. |

### Subprocess primitive + per-binary helpers (ADR-013)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-227a | `test_safe_subprocess_run_enforces_shell_false` | `tests/unit/test_safe_subprocess_run.py` | `REQ_19a` + `FR-255` | Call `safe_subprocess_run(["echo", "hi"], timeout_s=1)`. | Returns `CompletedProcess`; subprocess monitor confirms `shell=False`. |
| TA-227b | `test_safe_subprocess_run_timeout_required` | same | `REQ_19a` + `FR-255` | Call without `timeout_s`. | `TypeError` (kwarg-only, required). |
| TA-227c | `test_safe_subprocess_run_binary_root_confined` | same | `REQ_19a` + `FR-255` + `SEC-NEW-52` | argv[0] resolves outside `binary_root`. | `BinaryNotConfinedError` raised before spawn. |
| TA-227d | `test_safe_subprocess_run_no_binary_root_unconfined` | same | `REQ_19a` + `FR-255` | Same call, `binary_root=None`. | No confinement check. |
| **TA-228** | **`test_invoke_mvn_safe_uses_fixed_argv_no_project_flags`** | **`tests/security/test_req20_argv_allowlist.py`** | **`REQ_20` + `SEC-NEW-55`** | **Mock `safe_subprocess_run`; invoke REQ-20's resolved-version detection against a fixture pom.xml with `<profiles>` and `<properties>` containing `<argLine>`-style values.** | **Captured argv contains ONLY the fixed flags (`mvn dependency:tree -DoutputType=text -DoutputFile=... --batch-mode --no-transfer-progress -f <pom-path>`). NO `-P`, NO `-D` from project source.** **THIS IS THE T-Phase9-04 CLOSURE GATE.** |
| TA-229 | `test_invoke_gradle_safe_uses_fixed_argv` | same | `REQ_20` + `SEC-NEW-55` | Analogous for Gradle: `gradle dependencies --configuration runtimeClasspath --console=plain --no-daemon --quiet`. | Captured argv matches; configuration name validated against allowlist. |
| TA-230 | `test_invoke_gradle_safe_rejects_unknown_configuration` | same | `REQ_20` + `SEC-NEW-55` | Caller passes `configuration="evil-config"`. | `ValueError`; no spawn. |

### Binary pinning (SEC-NEW-52, S-Phase9-01)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-231a | `test_resolve_gradle_binary_pins_under_GRADLE_HOME` | `tests/security/test_mvn_gradle_binary_pinning.py` | `REQ_20` + `SEC-NEW-52` | `GRADLE_HOME=/opt/gradle` set; `gradle` candidate resolves to `/opt/gradle/bin/gradle`. | Binary returned; resolved path inside GRADLE_HOME tree. |
| TA-231b | `test_resolve_gradle_binary_rejects_path_when_env_set_but_missing` | same | `REQ_20` + `SEC-NEW-52` | GRADLE_HOME set to dir containing no `bin/gradle`. | Returns None; PATH fallback NOT used. |
| TA-231c | `test_resolve_gradle_binary_path_fallback_warns` | same | `REQ_20` + `SEC-NEW-52` | Neither GRADLE_HOME nor M2_HOME-style env set; mock `shutil.which` to return a valid path. | Warning emitted via `_warn_path_fallback_once("gradle")`; only once per process. |
| TA-231d | `test_resolve_mvn_binary_path_fallback_warns` | same | `REQ_20` + `SEC-NEW-52` | Analogous for `mvn` (extends existing SEC-NEW-28 behaviour with the new warning). | Warning emitted. |

### Per-coordinate version cap (SEC-NEW-39)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-232a | `test_per_coord_version_cap_truncates_at_64` | `tests/security/test_req20_version_cap.py` | `REQ_20` + `SUC-43` + `SEC-NEW-39` | Synthetic dep_edges with 100 declared versions of one coordinate. | `versioned_nodes` for that coord has exactly 64 entries; resolved version retained; `errors[]` contains truncation note. |
| TA-232b | `test_per_coord_version_cap_resolved_never_dropped` | same | `REQ_20` + `SEC-NEW-39` | Same as TA-232a but the resolved version is ranked 80th by version order. | After truncation, the resolved version is one of the kept 64. |

### Reporters

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-233 | `test_multi_version_section_rendered` | `tests/unit/test_req20_multi_version_section.py` | `REQ_20` + `FR-206` | `multi_version_coords` non-empty. | Markdown reporter emits the "Multiple versions detected" table with declared versions + resolved + per-version removable. |
| TA-234 | `test_sarif_TS_DEP_MULTI_VERSION_emitted` | `tests/unit/test_req20_sarif.py` | `REQ_20` + `FR-207` | Same fixture. | Exactly one `TS-DEP-MULTI-VERSION` SARIF result per coordinate, severity `note`. |
| TA-235 | `test_resolved_version_marker_in_tree` | `tests/unit/test_req20_tree_render_marker.py` | `REQ_20` + `FR-194` (extended) | Two declared versions; one is resolved. | Tree row for the resolved version carries the `← resolved` marker (or `+` diff prefix per spec). |

### Classifier centralisation enforcement (NEW-ARCH-006)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-236a | `test_every_analyser_routes_through_classifier` | `tests/unit/test_arch_classifier_centralisation.py` | `REQ_19a` + `NEW-ARCH-006` + `SEC-NEW-46` + `SUC-57` | Import every registered analyser; run `analyse()` against a tiny fixture that produces deterministic deps. | Each result has a non-empty `versioned_nodes` (proves classifier ran) OR registers as `no_pin_mechanism` and uses `classify_canonical`. |
| TA-236b | `test_no_inline_transitive_propagation_outside_classifier` | same | `REQ_19a` + `NEW-ARCH-006` + `SUC-57` | Static-grep for `_resolve_transitive_statuses` symbol outside `core/classifier.py`. | Zero matches (the legacy Python-analyser definition has been moved). |

### Subprocess AST scan (NEW-ARCH-013)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-237 | `test_subprocess_call_sites_only_safe_run` | `tests/security/test_arch_subprocess_call_sites.py` | `REQ_19a` + `NEW-ARCH-013` + `SEC-NEW-58` + `SUC-64` | Walk every `*.py` under `src/scarno/`; parse via `ast.parse`; collect `Call` nodes whose `.func` references `subprocess.run` / `subprocess.Popen` / `os.execvp` / `os.execve` / `os.spawn*` / `os.popen` / `os.posix_spawn*` / `asyncio.subprocess.*`. | The only matches are in `analysers/java/source_analyser.py` at the line range enclosing `_invoke_javap_safe` (grandfathered). Any other match fails with file:line. |

### `_safe_cpu_count` helper (D-Phase9-01 partial)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-238 | `test_safe_cpu_count_handles_None` | `tests/unit/test_safe_cpu_count.py` | `REQ_19a` + `NEW-ARCH-010` | Mock `os.cpu_count` to return `None`. | Returns `default` (1 by default). |
| TA-239 | `test_safe_cpu_count_handles_exception` | same | `REQ_19a` + `NEW-ARCH-010` | Mock `os.cpu_count` to raise `OSError`. | Returns `default`. |
| TA-240 | `test_safe_cpu_count_returns_value` | same | `REQ_19a` + `NEW-ARCH-010` | Mock to return 4. | Returns 4. |

### PR-2 landing checklist

Required to merge PR-2: TA-220a..d, TA-221a..d, TA-222a..e, TA-223a..b, TA-224a, TA-225a, TA-226a, TA-227a..d, **TA-228 (T-Phase9-04 closure — single highest-priority gate)**, TA-229, TA-230, TA-231a..d, TA-232a..b, TA-233, TA-234, TA-235, TA-236a..b, TA-237, TA-238, TA-239, TA-240.

If TA-228 fails or is skipped, **PR-2 must not merge** — it leaves the codebase with a HIGH-severity unmitigated finding (T-Phase9-04 §9.5 register).

PR-2's scope expanded substantially per architecture §11.15.8. The 38 tests above are the minimum gating set; additional integration tests (TA-241..245 envisaged below) cover end-to-end classifier flow per ecosystem.

### End-to-end classifier integration (advisory; gate for the release tag)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-241 | `test_classifier_e2e_maven_no_pin_detector_yet` | `tests/integration/test_req20_classifier_e2e.py` | `REQ_20` + `REQ_19a` + `NEW-ARCH-012` | Maven project analysed with PR-2 only (Maven detector not yet shipped). | Direct deps with no source-use classify UNCERTAIN with explicit reason; "no pin-detector for ecosystem 'maven' yet" warning emitted. |
| TA-242 | `test_classifier_e2e_pypi_classifies_safe_normally` | same | `REQ_20` + `REQ_19a` + `NEW-ARCH-012` | Pure Python project (pypi → registered as no_pin_mechanism). | Direct deps with no source-use classify SAFE per existing rules (REQ-17 acceptance preserved). |

---

## PR-3 — REQ-21 (Maven pinning detection)

Lands: Maven `_collect_exclusions`, `_collect_dependency_management`, `_detect_pin_overrides`. Calls `register_pin_detector("maven")`. Adds SARIF `TS-DEP-PIN-OVERRIDE-MAVEN`. Removes the per-ecosystem-warning fallback for Maven (PR-2's TA-241 inverts).

### Functional security

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-250 | `test_collect_exclusions_indexes_by_ga` | `tests/unit/test_req21_exclusions_index.py` | `REQ_21` + `FR-210` | Walked POMs containing `<exclusion>` blocks. | Index keyed on `(group, artifact)` of every excluded coord. |
| TA-251 | `test_pattern_a_direct_dep_substituting_excluded_transitive` | `tests/unit/test_req21_pattern_a.py` | `REQ_21` + `FR-211` + `SUC-45` | pom.xml: lib-y declares `<exclusion>vulnerable-x</exclusion>`; direct dep `patched-x` at same GA. Source never imports x. | `patched-x.pin_override == True`, `pin_override_kind == "EXCLUSION"`, status IN_USE. Reason includes the "manual review recommended — coincidental GA match is possible" phrase per T-Phase9-02. |
| TA-252 | `test_pattern_b_dependency_management_pin` | `tests/unit/test_req21_pattern_b.py` | `REQ_21` + `FR-213` + `SUC-46` | Root POM `<dependencyManagement>` pins jackson-databind; jackson-databind reached transitively; source never imports it. | `pin_override == True`, `pin_override_kind == "DEPENDENCY_MANAGEMENT"`, status IN_USE. |
| TA-253 | `test_pattern_b_dm_not_reached_no_pin` | same | `REQ_21` + `FR-213` | DM pins jackson-databind but no transitive reaches it. | `pin_override == False` (no false flag). |
| TA-254 | `test_dm_parsed_after_property_resolution` | `tests/unit/test_req21_dm_parse.py` | `REQ_21` + `FR-212` | Root POM DM uses `<version>${jackson.version}</version>`. | Property resolved to literal version before DM index lookup. |
| TA-255 | `test_classifier_defers_to_pin_override` | `tests/unit/test_req21_classifier_integration.py` | `REQ_21` + `REQ_20` + `FR-214` + `SUC-42` | Direct dep flagged `pin_override`, classifier runs. | `versioned_nodes` row IN_USE, removable False, reason mentions the pin. |

### Reporter integration

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-256 | `test_pinning_overrides_section_rendered` | `tests/unit/test_req21_reporters.py` | `REQ_21` + `FR-215` | At least one Maven pin_override exists. | Markdown "Pinning overrides (Maven)" sub-table renders with the substitution narrative. |
| TA-257 | `test_sarif_TS_DEP_PIN_OVERRIDE_MAVEN` | same | `REQ_21` + `FR-215` | Same fixture. | Exactly one TS-DEP-PIN-OVERRIDE-MAVEN result per pinned dep, severity note. |

### Security attack

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-258 | `test_max_exclusions_per_dep_cap_128` | `tests/security/test_req21_caps.py` | `REQ_21` + `SEC-NEW-40` + `SUC-47` | pom.xml with 200 `<exclusion>` entries on one transitive. | Exactly 128 retained; `errors[]` contains truncation note; analysis completes. |
| TA-259 | `test_max_dm_entries_cap_2048` | same | `REQ_21` + `SEC-NEW-40` | Synthetic DM block with 3000 entries. | 2048 retained; truncation note. |
| TA-260 | `test_pin_override_pattern_a_reason_mentions_coincidence` | same | `REQ_21` + T-Phase9-02 | Pattern (a) flagged dep. | Reason text contains "coincidental GA match is possible". |

### Pin-override / manifest-redundant invariant (cross-PR with NEW-ARCH-007)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-261 | `test_pin_override_and_manifest_redundant_never_both_set_by_detectors` | `tests/integration/test_req21_invariants.py` | `REQ_21` + `REQ_19a` + `NEW-ARCH-007` | Run Maven detector + the existing FR-150 manifest-redundant detector against a fixture where both COULD apply. | Detectors coordinate; only one flag is True per dep. No `ValueError` raised by `Dependency.__post_init__`. |

### Enum-coverage initial slice (NEW-ARCH-008)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-262 | `test_pin_override_kind_enum_includes_maven_kinds` | `tests/unit/test_arch_pin_kind_enum.py` | `REQ_19a` + `NEW-ARCH-008` + `FR-252` | Inspect `PinOverrideKind` enum. | `EXCLUSION` and `DEPENDENCY_MANAGEMENT` values present. |
| TA-263 | `test_safety_function_branch_for_maven_kinds` | same | `REQ_19a` + `NEW-ARCH-008` + `SEC-NEW-48` + `SUC-59` | Construct synthetic Dependency for each Maven kind; run `apply_pin_override_safety`. | Each triggers a recognised branch (status forced IN_USE). |

### Performance

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-264 | `test_pin_detection_perf_spring_boot_style` | `tests/performance/test_req21_perf.py` | `REQ_21` + `PERF-012` | spring-boot-dependencies-style fixture: ~1500 DM entries, ~30 direct deps. | `_detect_pin_overrides` total time < 50 ms. |

### PR-3 landing checklist

Required: TA-250..255, TA-256, TA-257, TA-258, TA-259, TA-260, TA-261, TA-262, TA-263. TA-264 is the perf gate, advisory.

PR-3 closes the X-Phase9-02 partial-population window for Maven (`register_pin_detector("maven")` lifts the UNCERTAIN-fallback warning emitted by PR-2). Verify TA-241 (PR-2 e2e Maven warning) is INVERTED post-PR-3 — Maven projects no longer get the warning.

---

## PR-4 — REQ-22 (cross-version ABI diff, --deep-inspection)

Lands: `--deep-inspection` CLI flag, `analysers/java/abi_diff.py` (with `CrossVersionAbiDiffer`, deterministic finding sort, dependency-injected `_invoke_javap_safe`), `JavaSignature` dataclass, `FindingKind.ABI_RUNTIME_RISK` + `FindingKind.ABI_DRIFT`, SARIF rules `TS-ABI-RUNTIME-RISK` (severity error) and `TS-ABI-DRIFT` (severity note).

### Functional security — module shape

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-265 | `test_deep_inspection_off_by_default` | `tests/unit/test_req22_cli.py` | `REQ_22` + `FR-230` | Construct `_RunOptions()` with no flag. | `deep_inspection == False`. |
| TA-266 | `test_deep_inspection_set_only_by_argv_flag` | `tests/security/test_req22_deep_inspection_argv_only.py` | `REQ_22` + `SEC-NEW-56` + E-Phase9-01 | Static-AST parse `cli.py`; collect every assignment to `deep_inspection`. | The only assignment site is in the argparse handler. NO env-var fallback, NO config-file fallback. |
| TA-267 | `test_javap_NOT_spawned_when_flag_off` | `tests/security/test_req22_no_javap_default.py` | `REQ_22` + `FR-230` | Run analyser without `--deep-inspection`; mock `subprocess.run`. | Zero subprocess calls for ABI-diff purposes. |

### ABI diff — happy path

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-268 | `test_javap_public_signatures_parses_method` | `tests/unit/test_req22_javap_parse.py` | `REQ_22` + `FR-232` | Mock javap stdout for a class with one public method. | Parses to `JavaSignature(member_kind="method", member_name="utilityMethod", descriptor=...)`. |
| TA-269 | `test_signature_diff_added_removed_changed` | `tests/unit/test_req22_diff.py` | `REQ_22` + `FR-233` | Two synthetic signature sets. | Diff yields ADDED / REMOVED / CHANGED frozensets. |
| TA-270 | `test_runtime_risk_finding_for_source_referenced_removed_method` | `tests/unit/test_req22_runtime_risk.py` | `REQ_22` + `FR-234` + COMP-004 | helper 1.2.0 has `utilityMethod`; helper 1.5.0 (resolved) does not; source calls it. | Exactly one `Finding(severity=HIGH, kind=ABI_RUNTIME_RISK)` referencing the call site, symbol, declared 1.2.0, resolved 1.5.0. |
| TA-271 | `test_abi_drift_finding_for_unreferenced_change` | same | `REQ_22` + `FR-234` | Same fixture but symbol NOT in source call set. | `Finding(severity=MEDIUM, kind=ABI_DRIFT)`. |

### Overload-aware diff (`docs/SCARNO-BUG-signature-diff.md`)

Post-1.0.4 defect: `signature_diff` collapsed each identity to one
arbitrary overload, so deleted overloads of a surviving member were
invisible to `TS-ABI-RUNTIME-RISK` and `changed` varied by hash seed.

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-357 | `test_deleted_overload_of_surviving_member_is_removed` | `tests/unit/test_req22_diff.py` | `REQ_22` + `FR-272` | `foo(String)` + `foo(int)` → `foo(int)`. | `foo(String)` in `removed`; surviving `foo(int)` in none of the three sets. |
| TA-358 | `test_added_overload_is_added_not_removed` | same | `REQ_22` + `FR-272` | `foo(int)` → `foo(int)` + `foo(String)`. | Exactly one entry in `added`; `removed` and `changed` empty (no over-reporting). |
| TA-359 | `test_sole_overload_retype_is_changed` | same | `REQ_22` + `FR-272` + `FR-233` | Single overload `(I)V` → `(II)V`, member not overloaded on either side. | Resolved-side sig in `changed`; `removed` / `added` empty. |
| TA-360 | `test_modifier_only_shift_is_changed` | same | `REQ_22` + `FR-272` | Same descriptor, `modifiers` gains `static`. | Resolved-side sig in `changed`. |
| TA-361 | `test_field_and_constructor_identities_round_trip` | same | `REQ_22` + `FR-272` | Field removed; one of two constructor overloads removed. | Field in `removed`; deleted constructor overload in `removed`. |
| TA-362 | `test_uriutil_encodepath_regression` | same | `REQ_22` + `FR-272` | The bug report's witness: `encodePath(StringBuilder, String)` deleted, `encodePath(String)` survives. | Deleted overload reported; named regression guard. |
| TA-363 | `test_overload_heavy_diff_exact_sets` | `tests/unit/test_req22_diff_determinism.py` | `REQ_22` + `FR-273` | Overload-heavy fixture; assert the three sets exactly. | Output is a pure function of the inputs — no representative selection. |
| TA-364 | `test_signature_diff_invariant_under_hash_seed` | same | `REQ_22` + `FR-273` | Re-run the diff in child interpreters under `PYTHONHASHSEED` ∈ {0,1,2,3,42} (the bug report's reproduction). | Canonical serialisation of `added` / `removed` / `changed` identical across every seed. |
| TA-365 | `test_findings_name_the_overload` | `tests/unit/test_req22_finding_sort.py` | `REQ_22` + `FR-274` | Two removed overloads of one member. | Two Findings; each message carries its own descriptor. |
| TA-366 | `test_finding_sort_total_for_overloads` | same | `REQ_22` + `FR-274` | Shuffled Finding list from overloads of one member. | `_finding_sort_key` orders them identically regardless of input order. |

### M2 cache reads (SEC-NEW-44 + SUC-51 + SUC-52)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-272 | `test_m2_jar_path_confined` | `tests/security/test_req22_traversal.py` | `REQ_22` + `SEC-NEW-44` + `SUC-51` | Coordinate `<groupId>../../etc</groupId>`. | Path rejected by `_validate_gav` before any FS access. |
| TA-273 | `test_m2_jar_path_resolves_under_m2_root` | same | `REQ_22` + `SEC-NEW-44` | Valid coord. | Resolved path is under `~/.m2/repository`; `resolve_and_confine` succeeds. |
| TA-274 | `test_no_wholesale_m2_enumeration` | same | `REQ_22` + `SUC-52` + I-Phase9-01 | Static-grep `analysers/java/abi_diff.py` for `os.scandir`, `Path.iterdir`, `glob.glob` rooted at m2. | Zero matches. |
| TA-275 | `test_jar_not_cached_graceful_skip` | `tests/unit/test_req22_missing_jar.py` | `REQ_22` + `FR-236` | Resolved JAR not in m2. | `errors[]` contains "resolved version not cached for <coord>; skipping ABI diff" note (sanitised — no raw path); analysis completes. |

### Subprocess timeout + dependency-injection (SUC-50, SUC-53, NEW-ARCH-011)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-276 | `test_javap_per_jar_timeout_30s` | `tests/security/test_req22_timeout.py` | `REQ_22` + `SEC-NEW-42` + `SUC-50` | Mock `_invoke_javap_safe` to sleep 35s. | After 30s, sanitised error recorded; analysis continues. |
| TA-277 | `test_javap_max_jars_per_run` | `tests/security/test_req22_jar_cap.py` | `REQ_22` + `SEC-NEW-43` + `SUC-53` | Construct work list of 100 multi-version coords (× 2 jars each = 200). | Exactly 128 jars inspected; 72 skipped with "cap reached" note. |
| TA-278 | `test_abi_diff_module_no_subprocess_imports` | `tests/security/test_arch_javap_dependency_injection.py` | `REQ_19a` + `NEW-ARCH-011` + `SEC-NEW-51` + `SUC-62` | AST-parse `analysers/java/abi_diff.py`. | Zero `Import` / `ImportFrom` nodes referencing `subprocess` / `os.execvp` / `os.execve` / `os.spawnv` / `os.spawnve` / `os.posix_spawn` / `popen` / `asyncio.subprocess`. |
| TA-279 | `test_cross_version_abi_differ_init_requires_invoke_javap` | same | `REQ_19a` + `NEW-ARCH-011` | Construct `CrossVersionAbiDiffer(m2_root=Path(...))` — no `invoke_javap` kwarg. | `TypeError` (kwarg required, no default). |

### Concurrency (NEW-ARCH-010, ADR-010)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-280 | `test_threadpool_max_workers_capped_at_8` | `tests/security/test_arch_threadpool_cap.py` | `REQ_19a` + `NEW-ARCH-010` + `SUC-61` + `SEC-NEW-50` | Mock `_safe_cpu_count` to return 16. | Constructed `ThreadPoolExecutor._max_workers == 8`. |
| TA-281 | `test_threadpool_max_workers_min_with_cpu_count` | same | `REQ_19a` + `NEW-ARCH-010` | Mock to return 4. | `_max_workers == 4`. |
| TA-282 | `test_threadpool_max_workers_None_falls_back_to_1` | same | `REQ_19a` + `NEW-ARCH-010` + D-Phase9-01 | Mock `os.cpu_count` to return None. | `_max_workers == 1`. |
| TA-283 | `test_cap_counter_atomic_under_concurrency` | same | `REQ_19a` + `NEW-ARCH-010` + `PERF-017` + D-Phase9-02 | Concurrent `_try_consume_cap_slots(2)` invocations exceeding the cap (probes `_JAVAP_MAX_JARS_PER_RUN` directly so test survives future bumps). | Exactly `_JAVAP_MAX_JARS_PER_RUN / 2` cap-passes; remainder cap-rejects. Counter mutated only inside `with cap_lock:`. |
| TA-284 | `test_findings_list_locked_under_concurrency` | same | `REQ_19a` + `NEW-ARCH-010` | 100 concurrent finding-emit calls. | All findings present (no lost writes); list integrity preserved. |

### Deterministic finding sort (R-Phase9-01)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-285 | `test_findings_sorted_after_diff_all` | `tests/unit/test_req22_finding_sort.py` | `REQ_22` + R-Phase9-01 | Run `diff_all` 100 times against the same fixture. | Each run produces byte-identical Finding ordering (verified via `repr(findings)` equality across runs). |
| TA-286 | `test_finding_sort_key_severity_desc` | same | `REQ_22` + R-Phase9-01 | Mixed-severity findings list. | After sort, all CRITICAL precede HIGH precede MEDIUM precede LOW. |
| TA-287 | `test_sarif_output_byte_identical_across_runs` | `tests/integration/test_req22_sarif_determinism.py` | `REQ_22` + R-Phase9-01 | Run full deep-inspection pipeline 100 times against the same project + cache fixture. | SARIF output bytes-identical across all runs. |

### Reporters

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-288 | `test_cross_version_abi_section_rendered` | `tests/unit/test_req22_reporters.py` | `REQ_22` + `FR-235` | At least one ABI_RUNTIME_RISK Finding. | "Cross-version ABI risks (deep inspection)" markdown section rendered. |
| TA-289 | `test_sarif_TS_ABI_RUNTIME_RISK_severity_error` | same | `REQ_22` + `FR-235` | Same. | TS-ABI-RUNTIME-RISK rule result, SARIF severity `error`. |

### Performance

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-290 | `test_deep_inspection_5x2_jars_under_60s` | `tests/performance/test_req22_perf.py` | `REQ_22` + `PERF-014` | Project with 5 multi-version coordinates × 2 versions each = 10 cached jars. | `--deep-inspection` total time < 60s wall clock. |
| TA-291 | `test_signature_diff_no_quadratic_blowup` | same | `REQ_22` + `PERF-015` | Synthetic 50 000-signature jar diffed against another 50 000-sig jar. | Diff completes within bounded time; relative scaling matches O(n log n). |

### PR-4 landing checklist

Required: TA-265..267, TA-268..271, TA-272..275, TA-276..279, TA-280..284, TA-285..287, TA-288, TA-289. TA-290 / TA-291 are advisory.

TA-278 + TA-279 (NEW-ARCH-011 enforcement) and TA-266 (SEC-NEW-56 argv-only) are critical because they keep the deep-inspection feature from leaking into default behaviour.

---

## PR-5 — REQ-23 (npm overrides / resolutions / pnpm.overrides)

Lands: npm `_extract_overrides`, `_detect_pin_overrides`, `register_pin_detector("npm")`. SARIF `TS-DEP-PIN-OVERRIDE-NPM`. Removes the per-ecosystem-warning fallback for npm (PR-2's TA-241-equivalent for npm now silenced).

### Functional security

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-295 | `test_extract_overrides_npm` | `tests/unit/test_req23_overrides.py` | `REQ_23` + `FR-240` | package.json with `overrides.lodash: "4.17.21"`. | NpmOverride extracted; mechanism="npm-overrides". |
| TA-296 | `test_extract_resolutions_yarn` | `tests/unit/test_req23_resolutions.py` | `REQ_23` + `FR-241` | `resolutions: {"**/lodash": "4.17.21"}`. | NpmOverride extracted; target_constraint preserves the pattern; matched on lodash. |
| TA-297 | `test_extract_pnpm_overrides` | `tests/unit/test_req23_pnpm.py` | `REQ_23` + `FR-242` | `pnpm.overrides: {"some-lib>lodash": "4.17.21"}`. | nested_under="some-lib", target_name="lodash". |
| TA-298 | `test_pin_override_flag_set_for_npm_match` | `tests/unit/test_req23_match.py` | `REQ_23` + `FR-244` + `SUC-56` | Direct dep lodash + npm overrides target lodash; source not importing lodash. | `pin_override == True`, `pin_override_kind == "NPM_OVERRIDES"`, status IN_USE. |
| TA-299 | `test_classifier_defers_to_npm_pin_flag` | `tests/unit/test_req23_classifier_integration.py` | `REQ_23` + `REQ_20` + `FR-245` + `SUC-42` | Same fixture. | versioned_node IN_USE, removable False. |

### Security attack (T-35 + T-Phase9-01-style)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-300 | `test_invalid_override_target_rejected` | `tests/security/test_req23_validator.py` | `REQ_23` + `SUC-54` + `SEC-NEW-34` | overrides target name `lodash..`. | Rejected by `_is_valid_npm_name`; not added to override list. |
| TA-301 | `test_homoglyph_override_target_no_match` | same | `REQ_23` + `SUC-54` | overrides target `lodаsh` (Cyrillic а). | Exact-match logic does NOT match `lodash`. |
| TA-302 | `test_npm_overrides_max_entries_2048` | `tests/security/test_req23_caps.py` | `REQ_23` + `SUC-55` + `SEC-NEW-45` | 5000 overrides entries. | 2048 retained; truncation note. |
| TA-303 | `test_npm_overrides_max_nesting_8` | same | `REQ_23` + `SEC-NEW-45` | Targeted overrides tree 12 levels deep. | 8 levels retained; cap note. |

### Reporters

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-304 | `test_pinning_overrides_npm_section` | `tests/unit/test_req23_reporters.py` | `REQ_23` + `FR-246` | At least one npm pin_override. | "Pinning overrides (npm)" sub-table rendered. |
| TA-305 | `test_sarif_TS_DEP_PIN_OVERRIDE_NPM` | same | `REQ_23` + `FR-246` | Same. | Result emitted at severity note. |

### Enum-coverage extension (NEW-ARCH-008)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-306 | `test_safety_function_branches_for_npm_kinds` | `tests/unit/test_arch_pin_kind_enum.py` (extended) | `REQ_19a` + `NEW-ARCH-008` + `SUC-59` | Run safety function with NPM_OVERRIDES, YARN_RESOLUTIONS, PNPM_OVERRIDES synthetic fixtures. | Each triggers a recognised branch. |

### Performance

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-307 | `test_npm_pin_detection_adversarial_perf` | `tests/performance/test_req23_perf.py` | `REQ_23` + `PERF-016` | 2048 overrides × 8 nesting (post-cap). | parse + match < 100 ms. |

### PR-5 landing checklist

Required: TA-295..303, TA-304, TA-305, TA-306. TA-307 advisory.

PR-5 closes the X-Phase9-02 partial-population window for npm. Verify the PR-2 e2e UNCERTAIN-fallback for npm projects is silenced post-PR-5.

---

## PR-6 — REQ-21b (Gradle pinning, including dynamic-DSL UNCERTAIN downgrade)

Lands: `analysers/java/gradle_dsl.py` (NEW MODULE — tree-sitter Groovy/Kotlin walker), `_detect_pin_overrides` for Gradle. Calls `register_pin_detector("gradle")`. SARIF `TS-DEP-PIN-OVERRIDE-GRADLE` with **dual severity** (note for static kinds, warning for `GRADLE_DYNAMIC_PIN`). Markdown reporter renders dynamic-pin deps in dedicated "DO NOT REMOVE — dynamic Gradle pin" section (R-Phase9-02 closure).

### Functional security — DSL walker

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-310 | `test_walker_emits_force_directive` | `tests/unit/test_req21b_force.py` | `REQ_21b` + `FR-220` | build.gradle.kts with `force("com.example:patched-x:1.5")` inside resolutionStrategy. | `GradleForceDirective` emitted with source="resolutionStrategy.force". |
| TA-311 | `test_walker_emits_strictly_directive` | `tests/unit/test_req21b_strictly.py` | `REQ_21b` + `FR-221` | `version { strictly("1.5") }` in dep block. | Directive emitted; source="strictly". |
| TA-312 | `test_walker_emits_constraints_block` | `tests/unit/test_req21b_constraints.py` | `REQ_21b` + `FR-222` | `constraints { implementation("com.lib:z:1.4") }`. | Directive emitted; source="constraints". |
| TA-313 | `test_walker_emits_each_dependency_directive` | `tests/unit/test_req21b_each_dependency.py` | `REQ_21b` + `FR-223` | resolutionStrategy.eachDependency with literal useVersion. | Directive emitted; source="eachDependency.useVersion". |
| TA-314 | `test_walker_emits_exclude_directive` | `tests/unit/test_req21b_exclude.py` | `REQ_21b` + `FR-224` | `implementation(...) { exclude(group: "...", module: "...") }`. | GradleExclusion emitted. |

### Dynamic-DSL fall-through (SUC-48)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-315 | `test_dynamic_useVersion_emits_dynamic_directive` | `tests/unit/test_req21b_dynamic.py` | `REQ_21b` + `FR-225` + `SUC-48` | useVersion call with non-literal argument (variable, function call). | Directive emitted with `dynamic=True`. |
| TA-316 | `test_dynamic_pin_classifies_dep_uncertain` | same | `REQ_21b` + `SUC-48` + R-Phase9-02 | Dependency matched by a dynamic directive. | `pin_override_kind == "GRADLE_DYNAMIC_PIN"`, status UNCERTAIN, reason mentions "manual review required". |
| TA-317 | `test_dynamic_pin_uncertain_NOT_in_generic_uncertain_section` | `tests/unit/test_req21b_reporter_dynamic.py` | `REQ_21b` + R-Phase9-02 | Same. | Markdown reporter renders the dep under "DO NOT REMOVE — dynamic Gradle pin", NOT under generic "Manual review required". |
| TA-318 | `test_sarif_dynamic_pin_severity_warning` | same | `REQ_21b` + R-Phase9-02 | Same. | TS-DEP-PIN-OVERRIDE-GRADLE result has SARIF severity `warning` (not `note`). |
| TA-319 | `test_sarif_static_pin_severity_note` | same | `REQ_21b` | Static-kind dep (FORCE / STRICTLY / CONSTRAINTS / EXCLUSION). | SARIF severity `note`. |

### Security attack

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-320 | `test_max_force_directives_cap_256` | `tests/security/test_req21b_caps.py` | `REQ_21b` + `SUC-49` + `SEC-NEW-41` | build.gradle with 300 force() calls. | 256 retained; truncation note. |
| TA-321 | `test_max_exclusions_gradle_cap_256` | same | `REQ_21b` + `SEC-NEW-41` | build.gradle with 300 exclude() calls. | 256 retained. |
| TA-322 | `test_gradle_parse_timeout_8s` | same | `REQ_21b` + `SEC-NEW-41` | Adversarial build.gradle that stalls tree-sitter. | After 8s, sanitised parse-timeout error; analysis continues without Gradle pin data. NO crash. |

### Enum-coverage extension (NEW-ARCH-008)

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-323 | `test_safety_function_branches_for_gradle_kinds` | `tests/unit/test_arch_pin_kind_enum.py` (extended) | `REQ_19a` + `NEW-ARCH-008` + `SUC-59` | Run safety function with all Gradle kinds. | Each static kind forces IN_USE; GRADLE_DYNAMIC_PIN downgrades to UNCERTAIN. Branch coverage 100%. |

### Performance

| TA | Test | File | Marker | Scenario | Expected |
|---|---|---|---|---|---|
| TA-324 | `test_gradle_pin_detection_per_project_under_100ms` | `tests/performance/test_req21b_perf.py` | `REQ_21b` + `PERF-013` | Typical project: <10 build files × 50 directives. | <100 ms total. |

### PR-6 landing checklist

Required: TA-310..319, TA-320..322, TA-323. TA-324 advisory.

PR-6 closes X-Phase9-02 for Gradle. Verify the PR-2 e2e UNCERTAIN-fallback for Gradle projects is silenced post-PR-6.

After PR-6 lands, the **enum-coverage test (NEW-ARCH-008 / TA-263 + TA-306 + TA-323) reaches full coverage** — every `PinOverrideKind` value has been exercised by at least one safety-function branch test.

---

## Cross-PR penetration scenarios

These narratives complement the automated tests. They are not gating but should be attempted before declaring the Phase-9 work production-ready.

### PEN-Phase9-01 — Adversarial lockfile fuzz

**Scope**: PR-1 lockfile parsers + edge emitter + sanitiser.
**Objectives**: Atheris fuzz of `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `gradle.lockfile` parsers. Expect bounded errors or partial result; never a crash or runaway.
**Key abuse cases**: SAC-40, SAC-41, SAC-43.
**Out of scope**: Network-fetched lockfiles (Scarno reads project files only).

### PEN-Phase9-02 — Adversarial m2 cache fuzz (PR-4)

**Scope**: `analysers/java/abi_diff.py`, m2 path construction, javap invocation under `--deep-inspection`.
**Objectives**: Construct hostile JARs (deeply nested constant pools, oversized class lists) under a temp m2 root; expect timeout, truncation, or sanitised error — never a hang.
**Key abuse cases**: SAC-48, SAC-49, SAC-50.

### PEN-Phase9-03 — Coord-restricted read enforcement (PR-4)

**Scope**: abi_diff cache enumeration.
**Objectives**: Manual inspection that NO code path enumerates `~/.m2` beyond the `dep_edges` coordinates. Atheris fuzz of error-path output to confirm `sanitise()` coverage.
**Key abuse cases**: SAC-50.

### PEN-Phase9-04 — Gradle DSL parse fuzz (PR-6)

**Scope**: `gradle_dsl.py` tree-sitter Groovy + Kotlin walker.
**Objectives**: Atheris-style fuzz of build.gradle / build.gradle.kts; expect tree-sitter parse-timeout (8s) to fire deterministically, no native crash.
**Key abuse cases**: SAC-46, SAC-47.

### PEN-Phase9-05 — Subprocess hardening review (PR-2 + PR-4)

**Scope**: `safe_subprocess_run`, `_invoke_mvn_safe`, `_invoke_gradle_safe`, `_invoke_javap_safe`.
**Objectives**: Code review + targeted manual exploit attempts to confirm:
- argv allowlists for REQ-20 invocations cannot be expanded by adversarial pom.xml / build.gradle content.
- `BinaryNotConfinedError` fires before spawn for crafted MAVEN_HOME / GRADLE_HOME values.
- No subprocess invocation outside `safe_subprocess_run` exists in the codebase except the legacy javap helper.
**Key abuse cases**: T-Phase9-04, S-Phase9-01, SAC-58, SAC-60.

---

## Test categories — distribution

| Category | Approx count | Examples |
|---|---|---|
| Functional security (positive) | ~55 | TA-200..210, TA-220a..d, TA-250..255 etc. |
| Security attack (negative) | ~25 | TA-211..219, TA-258..260, TA-272..274, TA-300..303, TA-320..322 |
| Architecture-invariant (AST scans, registry contracts) | ~10 | TA-222c..d, TA-236a..b, TA-237, TA-274, TA-278, TA-279 |
| Concurrency / determinism | ~5 | TA-280..287 |
| Performance | ~7 | TA-226..227, TA-264, TA-290..291, TA-307, TA-324 |
| Regression / back-compat | ~4 | TA-220, TA-221..223 |
| Penetration (manual narratives) | 5 | PEN-Phase9-01..05 |
| **Total automated** | **~106** | |

The ~106 automated tests cover **every SRTM marker enumerated in `docs/scarno-security-privacy-analysis.md` §21.6**. Coverage map:

| Marker | Covering TA(s) |
|---|---|
| FR-190..195 | TA-200..210, TA-220 |
| FR-200..207 | TA-220a..d, TA-224a, TA-225a, TA-226a, TA-233, TA-234 |
| FR-210..215 | TA-250..257 |
| FR-220..225 | TA-310..316 |
| FR-230..236 | TA-265..271, TA-275, TA-288 |
| FR-240..246 | TA-295..299, TA-304, TA-305 |
| FR-250..255 (NEW-ARCH-006..013) | TA-222a..e, TA-223a..b, TA-227a..d, TA-236a..b, TA-237, TA-278, TA-279, TA-280..284 |
| SEC-NEW-37..38 + SEC-NEW-54 ext | TA-211..219 |
| SEC-NEW-39 | TA-232a..b |
| SEC-NEW-40 | TA-258..260 |
| SEC-NEW-41 | TA-320..322 |
| SEC-NEW-42..44 | TA-272..277 |
| SEC-NEW-45 | TA-302..303 |
| SEC-NEW-46..51 | TA-222c..d, TA-223a..b, TA-236a..b, TA-237, TA-278..279, TA-280..284 |
| SEC-NEW-52 | TA-231a..d |
| SEC-NEW-53 | TA-224..225 (PR-1) |
| SEC-NEW-55 | **TA-228 (gating)**, TA-229, TA-230 |
| SEC-NEW-56 | TA-266 |
| SEC-NEW-57..58 | TA-222c..d, TA-237 |
| PERF-010 | TA-226..227 |
| PERF-011..016 | TA-264, TA-290..291, TA-307, TA-324 |
| PERF-017 | TA-283 |
| COMP-004 | TA-270 (RUNTIME_RISK Finding emission) |
| T-27..37, S/T/R/I/D/E/X-Phase9-* | covered indirectly via the SUC-NN tests above + the §9.5 register status updates |

---

## Untestable controls (feedback to Phase 2)

None identified. Every control documented in REQ-19..23 + REQ-19a is testable as currently specified. The two cross-cutting concerns that depend on operator behaviour rather than code are documented as residual risk:

- **I-Phase9-01** (m2 cache-state timing oracle) — documentation-only; covered by adding a paragraph to `docs/THREAT-MODEL.md` Residual Risk section. Test confirms the documentation paragraph exists (TA-274 already covers the structural side).
- **PEN-Phase9-05** subprocess hardening review — requires manual code-review judgement; cannot be reduced to an automated test beyond the AST scans (TA-237 + TA-278).

No design changes requested.

---

## Test execution

```bash
# Full Phase-9 suite (after PR-6 merges)
uv run --no-sync pytest tests/ -m "REQ_19 or REQ_20 or REQ_21 or REQ_21b or REQ_22 or REQ_23 or REQ_19a" --tb=short -q

# SRTM coverage check (reports any unmarked requirement)
uv run --no-sync pytest tests/ --srtm-check

# Performance tests only (longer wall clock)
uv run --no-sync pytest tests/performance/ -q

# Security tests only (faster than full suite)
uv run --no-sync pytest tests/security/ -m "REQ_19 or REQ_20 or REQ_22 or REQ_19a" -q

# Coverage gate (uses the project's 85% threshold)
uv run --no-sync pytest tests/
```

Per-PR runs use the marker for the PR's primary REQ:

```bash
# After PR-2 merges (REQ-20 + parts of REQ-19a)
uv run --no-sync pytest tests/ -m "REQ_20 or (REQ_19a and (NEW_ARCH_006 or NEW_ARCH_007 or NEW_ARCH_010 or NEW_ARCH_012 or NEW_ARCH_013))" -q
```

---

## SRTM closure summary

Once all six PRs land and the test suite passes:

- SRTM marker count: **256/256** (per analysis §21.5).
- Phase-9 risk register (`docs/THREAT-MODEL.md` §9.5 + §9.11): zero Critical / High findings Open.
- Two findings (D-Phase9-02, R-Phase9-01) flip from Open-by-design to Closed when TA-283 + TA-285..287 land green.
- T-Phase9-04 (HIGH severity) flips from Open / Escalated to Closed when **TA-228** lands green.
