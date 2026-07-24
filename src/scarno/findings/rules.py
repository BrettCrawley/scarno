# Copyright 2026 Brett Crawley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Rule catalogue for the REQ-3c finding engine.

Authoritative home for every detection rule. Rules are **data**, not
code — :mod:`scarno.findings.engine` walks ASTs and matches them
against this table. Unit tests in ``tests/unit/test_req3c_findings.py``
verify that the catalogue contains every rule ID referenced by the
SRTM and the REQ-3c specification.
"""
from __future__ import annotations

from dataclasses import dataclass

from scarno.models import FindingKind, FindingSeverity


@dataclass(frozen=True)
class Rule:
    """Static description of a REQ-3c detection rule.

    The matcher engine consumes this table; the reporter uses `message`
    and `remediation` to render findings.
    """

    rule_id: str
    kind: FindingKind
    severity: FindingSeverity
    message: str
    remediation: str


RULES: dict[str, Rule] = {
    # ── Runtime pip installation ────────────────────────────────────────
    "TS-SI-001": Rule(
        rule_id="TS-SI-001",
        kind=FindingKind.RUNTIME_PIP_INSTALL,
        severity=FindingSeverity.HIGH,
        message=(
            "Runtime pip install via subprocess — deps installed at runtime "
            "bypass Scarno's dependency file analysis and are invisible "
            "to SBOM and CVE tools."
        ),
        remediation=(
            "Declare the package in pyproject.toml, or suppress with "
            "`# scarno: allow TS-SI-001` on the offending line."
        ),
    ),
    "TS-SI-002": Rule(
        rule_id="TS-SI-002",
        kind=FindingKind.RUNTIME_PIP_INSTALL,
        severity=FindingSeverity.HIGH,
        message="Runtime pip install via `python -m pip install`.",
        remediation="Declare the package in a dep file or suppress the rule.",
    ),
    "TS-SI-003": Rule(
        rule_id="TS-SI-003",
        kind=FindingKind.OS_SYSTEM_PIP,
        severity=FindingSeverity.HIGH,
        message="`os.system`/`os.popen` invoking pip install.",
        remediation="Replace with an explicit dep declaration.",
    ),
    "TS-SI-004": Rule(
        rule_id="TS-SI-004",
        kind=FindingKind.RUNTIME_PIP_INSTALL,
        severity=FindingSeverity.HIGH,
        message="Programmatic call to `pip.main` / `pip._internal.main`.",
        remediation="The pip API is private; declare deps statically instead.",
    ),
    # ── Notebook pip magics ─────────────────────────────────────────────
    "TS-SI-005": Rule(
        rule_id="TS-SI-005",
        kind=FindingKind.NOTEBOOK_PIP_MAGIC,
        severity=FindingSeverity.MEDIUM,
        message="Jupyter `!pip install` / `%pip install` in a notebook cell.",
        remediation="Move the dependency to the project's requirements file.",
    ),
    "TS-SI-006": Rule(
        rule_id="TS-SI-006",
        kind=FindingKind.NOTEBOOK_PIP_MAGIC,
        severity=FindingSeverity.MEDIUM,
        message="Jupyter `%conda install` in a notebook cell.",
        remediation="Move the dependency to environment.yml.",
    ),
    # ── Remote code execution ───────────────────────────────────────────
    "TS-CE-001": Rule(
        rule_id="TS-CE-001",
        kind=FindingKind.REMOTE_CODE_EXEC,
        severity=FindingSeverity.CRITICAL,
        message="`exec()` / `eval()` applied to a network response.",
        remediation="Never execute untrusted remote content.",
    ),
    "TS-CE-002": Rule(
        rule_id="TS-CE-002",
        kind=FindingKind.DOWNLOAD_AND_EXEC,
        severity=FindingSeverity.CRITICAL,
        message=(
            "Value fetched from the network is passed to an execution sink "
            "(exec/eval/os.system/subprocess)."
        ),
        remediation="Do not execute downloaded content.",
    ),
    "TS-CE-003": Rule(
        rule_id="TS-CE-003",
        kind=FindingKind.INSECURE_UNPICKLE_REMOTE,
        severity=FindingSeverity.CRITICAL,
        message="`pickle.load*` consuming data that originated from a network fetch.",
        remediation="Never unpickle untrusted data; prefer JSON or msgpack.",
    ),
    "TS-CE-004": Rule(
        rule_id="TS-CE-004",
        kind=FindingKind.DYNAMIC_IMPORT_UNVALIDATED,
        severity=FindingSeverity.HIGH,
        message=(
            "Dynamic import where the module name comes from input(), env "
            "vars, CLI args, or a network fetch."
        ),
        remediation="Validate the module name against an allow-list before importing.",
    ),
    "TS-CE-005": Rule(
        rule_id="TS-CE-005",
        kind=FindingKind.CURL_PIPE_SHELL,
        severity=FindingSeverity.HIGH,
        message="`curl … | sh` pattern in a Dockerfile or CI workflow.",
        remediation=(
            "Download the script, verify its hash, and run it explicitly — "
            "or use a signed package."
        ),
    ),
    "TS-CE-006": Rule(
        rule_id="TS-CE-006",
        kind=FindingKind.SHELL_INJECTION_IN_INSTALL,
        severity=FindingSeverity.CRITICAL,
        message=(
            "`subprocess(..., shell=True)` where the command is constructed "
            "from external input."
        ),
        remediation="Use `shell=False` with a list argument and validate inputs.",
    ),
    # ── Dependency-source hygiene ───────────────────────────────────────
    "TS-DS-001": Rule(
        rule_id="TS-DS-001",
        kind=FindingKind.SETUP_PY_DYNAMIC_DEPS,
        severity=FindingSeverity.MEDIUM,
        message="`setup.py install_requires` assigned from a non-literal value.",
        remediation="Move dependencies to pyproject.toml `[project].dependencies`.",
    ),
    # ── Phase 5 — JS / TS / Node.js + CSS rule extensions ──────────────
    "TS-SI-007": Rule(
        rule_id="TS-SI-007",
        kind=FindingKind.RUNTIME_PIP_INSTALL,  # reused: "runtime install / build-time script"
        severity=FindingSeverity.HIGH,
        message=(
            "`package.json` declares a `postinstall` (or `preinstall` / "
            "`prepare`) lifecycle script — code runs on every `npm install`, "
            "bypassing registry audit tooling."
        ),
        remediation=(
            "Avoid arbitrary code in install hooks. Move build steps to an "
            "explicit build script invoked by CI, or suppress with "
            "`# scarno: allow TS-SI-007`."
        ),
    ),
    "TS-SI-008": Rule(
        rule_id="TS-SI-008",
        kind=FindingKind.RUNTIME_PIP_INSTALL,
        severity=FindingSeverity.MEDIUM,
        message=(
            "`.npmrc` overrides the default npm registry — installs will "
            "fetch packages from a non-default source."
        ),
        remediation=(
            "Verify the alternative registry is trusted and pinned; otherwise "
            "remove the override so installs use registry.npmjs.org."
        ),
    ),
    "TS-SI-009": Rule(
        rule_id="TS-SI-009",
        kind=FindingKind.SHELL_INJECTION_IN_INSTALL,
        severity=FindingSeverity.CRITICAL,
        message=(
            "`child_process.exec(…)` / `execSync(…)` called with a value "
            "that traces to user input — classic shell-injection sink."
        ),
        remediation=(
            "Use `child_process.execFile` / `spawn` with a fixed argv list; "
            "never interpolate untrusted input into a shell string."
        ),
    ),
    "TS-SI-010": Rule(
        rule_id="TS-SI-010",
        kind=FindingKind.REMOTE_CODE_EXEC,
        severity=FindingSeverity.CRITICAL,
        message=(
            "`new Function(…)` or `Function(…)` called with a value that "
            "traces to user input — equivalent to `eval()` of untrusted code."
        ),
        remediation=(
            "Parse the input explicitly; never compile untrusted strings "
            "into executable code."
        ),
    ),
    "TS-SI-011": Rule(
        rule_id="TS-SI-011",
        kind=FindingKind.REMOTE_CODE_EXEC,
        severity=FindingSeverity.CRITICAL,
        message=(
            "Value fetched from the network (`fetch` / `axios` / `http`) is "
            "passed to an execution sink (`eval` / `new Function` / "
            "`vm.runInNewContext`)."
        ),
        remediation="Never execute untrusted remote content.",
    ),
    "TS-CE-007": Rule(
        rule_id="TS-CE-007",
        kind=FindingKind.DOWNLOAD_AND_EXEC,
        severity=FindingSeverity.MEDIUM,
        message=(
            "CSS `@import` / `url(https://…)` pointing at an external host "
            "— build-time fetch of stylesheet or font from an untrusted "
            "origin."
        ),
        remediation=(
            "Vendor the stylesheet into the repo or serve it from an asset "
            "pipeline under your control."
        ),
    ),
    "TS-CE-008": Rule(
        rule_id="TS-CE-008",
        kind=FindingKind.DOWNLOAD_AND_EXEC,
        severity=FindingSeverity.HIGH,
        message=(
            "CSS `url(file:///…)` pointing at an absolute filesystem path "
            "— confinement violation; build output would leak local paths."
        ),
        remediation=(
            "Use a relative URL or an asset-pipeline reference; never bake "
            "`file://` URLs into committed stylesheets."
        ),
    ),
    # ── Phase 6 — Go rule extensions ───────────────────────────────────
    "TS-DS-002": Rule(
        rule_id="TS-DS-002",
        kind=FindingKind.GO_REPLACE_REMOTE_URL,
        severity=FindingSeverity.MEDIUM,
        message=(
            "`go.mod` `replace` directive points at an external URL "
            "instead of a local path — dependencies fetched from an "
            "attacker-controlled origin bypass module proxy checks."
        ),
        remediation=(
            "Use the module proxy (GOPROXY) or replace to a local path; "
            "never replace to an arbitrary HTTPS URL."
        ),
    ),
    "TS-SI-012": Rule(
        rule_id="TS-SI-012",
        kind=FindingKind.UNSAFE_POINTER_USE,
        severity=FindingSeverity.MEDIUM,
        message=(
            "`import \"unsafe\"` — use of `unsafe.Pointer` bypasses Go's "
            "type-safety guarantees and can cause memory corruption."
        ),
        remediation=(
            "Avoid `unsafe` unless absolutely required for FFI / "
            "performance-critical code; document every usage."
        ),
    ),
    "TS-SI-013": Rule(
        rule_id="TS-SI-013",
        kind=FindingKind.CGO_IMPORT,
        severity=FindingSeverity.MEDIUM,
        message=(
            '`import "C"` — cgo embeds C code that runs outside Go\'s '
            "memory-safety model and increases the attack surface."
        ),
        remediation=(
            "Prefer pure-Go alternatives; if cgo is necessary, audit "
            "the linked C code and pin compiler toolchain versions."
        ),
    ),
    "TS-CE-009": Rule(
        rule_id="TS-CE-009",
        kind=FindingKind.EXEC_COMMAND_TAINT,
        severity=FindingSeverity.CRITICAL,
        message=(
            "`exec.Command` / `exec.CommandContext` called with an "
            "argument sourced from environment, stdin, or network — "
            "classic command-injection vector."
        ),
        remediation=(
            "Validate and sanitise arguments via an allow-list; never "
            "interpolate untrusted input into command strings."
        ),
    ),
    # ── Phase 7 — C# / .NET rule extensions ────────────────────────────
    "TS-SI-015": Rule(
        rule_id="TS-SI-015",
        kind=FindingKind.CUSTOM_REGISTRY,
        severity=FindingSeverity.MEDIUM,
        message=(
            "`nuget.config` overrides the default NuGet package source — "
            "installs will fetch packages from a non-default origin."
        ),
        remediation=(
            "Verify the alternative source is trusted and pinned; otherwise "
            "remove the override so restores use api.nuget.org."
        ),
    ),
    "TS-SI-016": Rule(
        rule_id="TS-SI-016",
        kind=FindingKind.MSBUILD_EXEC_TASK,
        severity=FindingSeverity.HIGH,
        message=(
            "MSBuild `<Exec Command=\"…\"/>` runs arbitrary shell commands "
            "at build time — code executes on every `dotnet build`."
        ),
        remediation=(
            "Move build steps to an explicit script invoked by CI; "
            "avoid `<Exec>` for anything beyond trivial file operations."
        ),
    ),
    "TS-SI-017": Rule(
        rule_id="TS-SI-017",
        kind=FindingKind.MSBUILD_USING_TASK,
        severity=FindingSeverity.HIGH,
        message=(
            "MSBuild `<UsingTask>` loads an external assembly at build "
            "time — arbitrary code in the referenced DLL executes during "
            "the build."
        ),
        remediation=(
            "Pin the assembly to a known hash; prefer NuGet-distributed "
            "MSBuild tasks over loose DLL references."
        ),
    ),
    "TS-SI-018": Rule(
        rule_id="TS-SI-018",
        kind=FindingKind.DLLIMPORT_PINVOKE,
        severity=FindingSeverity.MEDIUM,
        message=(
            "`[DllImport(\"…\")]` P/Invoke loads a native library at "
            "runtime — the loaded DLL runs outside the CLR's safety model."
        ),
        remediation=(
            "Prefer managed alternatives; if P/Invoke is required, "
            "pin the library path and audit the native code."
        ),
    ),
    "TS-CE-010": Rule(
        rule_id="TS-CE-010",
        kind=FindingKind.ASSEMBLY_LOAD_TAINT,
        severity=FindingSeverity.CRITICAL,
        message=(
            "`Assembly.Load` / `Assembly.LoadFrom` called with a value "
            "that traces to user input or network — classic .NET code "
            "injection vector."
        ),
        remediation=(
            "Never load assemblies from untrusted sources; use a signed "
            "assembly allow-list and validate strong names."
        ),
    ),
    "TS-CE-011": Rule(
        rule_id="TS-CE-011",
        kind=FindingKind.PROCESS_START_TAINT,
        severity=FindingSeverity.CRITICAL,
        message=(
            "`Process.Start` called with arguments sourced from user "
            "input, environment, or network — command-injection risk."
        ),
        remediation=(
            "Validate and sanitise process arguments via an allow-list; "
            "never interpolate untrusted input."
        ),
    ),
    # ── REQ-22 — cross-version ABI diff (PR-4, --deep-inspection) ────────
    "TS-ABI-RUNTIME-RISK": Rule(
        rule_id="TS-ABI-RUNTIME-RISK",
        kind=FindingKind.ABI_RUNTIME_RISK,
        severity=FindingSeverity.HIGH,
        message=(
            "A symbol called by your source code is REMOVED or "
            "signature-CHANGED between the declared and resolved "
            "versions of this transitive. NoSuchMethodError-class "
            "failure imminent at runtime."
        ),
        remediation=(
            "Pin the dep to the declared version (so the resolved "
            "version matches), or update the call sites to the "
            "resolved-version surface."
        ),
    ),
    "TS-ABI-DRIFT": Rule(
        rule_id="TS-ABI-DRIFT",
        kind=FindingKind.ABI_DRIFT,
        severity=FindingSeverity.MEDIUM,
        message=(
            "ABI surface differs between declared and resolved versions "
            "of this transitive. The differing symbols are NOT called by "
            "your source today, but the diff is surfaced for review — a "
            "future code change could trip a runtime failure."
        ),
        remediation=(
            "Review the listed symbols; if any might be needed, "
            "pin the resolved version to match the declared, or update "
            "your source's expectations."
        ),
    ),
    # ── REQ-24 — cross-index integrity mismatch (SEC-NEW-71) ────────────
    "TS-INTEGRITY-MISMATCH": Rule(
        rule_id="TS-INTEGRITY-MISMATCH",
        kind=FindingKind.ABI_INTEGRITY_MISMATCH,
        severity=FindingSeverity.HIGH,
        message=(
            "An artefact fetched for the cross-version ABI diff returned "
            "different bytes from the top-2 priority indexes for its "
            "ecosystem (after a retry-once jittered backoff). This "
            "suggests one of the indexes is compromised, MITM'd, or has "
            "been polluted — the artefact's contents cannot be trusted."
        ),
        remediation=(
            "Treat the affected coordinate's ABI verdicts as unreliable. "
            "Verify the legitimate hash from your trusted index "
            "out-of-band; if the corp Nexus is the divergent party, "
            "investigate the upstream sync. Until resolved, prefer "
            "fetching from a single trusted index for this coordinate."
        ),
    ),
    # ── HTML / template scanner rule extensions ────────────────────────
    "TS-CE-012": Rule(
        rule_id="TS-CE-012",
        kind=FindingKind.DOWNLOAD_AND_EXEC,
        severity=FindingSeverity.MEDIUM,
        message=(
            "HTML/template loads a remote script or stylesheet via CDN — "
            "the external resource executes in end-user browsers and is "
            "outside the project's version-control boundary."
        ),
        remediation=(
            "Vendor the script/stylesheet into the repo or serve it from "
            "an asset pipeline under your control; pin the CDN URL to a "
            "specific version with subresource integrity (SRI) hashes."
        ),
    ),
}


