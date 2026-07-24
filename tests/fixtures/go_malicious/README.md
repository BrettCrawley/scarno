# go_malicious/ — adversarial Go fixtures (REQ-13 / REQ-14)

| Directory | Payload |
|-----------|---------|
| `replace_remote_url/` | `replace github.com/foo => https://evil.example.com/pkg v0.0.0` → Finding `TS-DS-002` |
| `long_module_path/` | `require github.com/…` with a 10 KB module path → line-length cap rejects (SEC-NEW-24) |
| `vendor_mismatch/` | `vendor/modules.txt` listing a module not in `go.mod` → warning |
| `gomod_line_dos/` | `go.mod` with millions of lines / whitespace-bombed require block → size cap |

Built in-test via `tmp_path`.
