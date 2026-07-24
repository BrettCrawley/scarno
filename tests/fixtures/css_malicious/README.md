# css_malicious/ — adversarial CSS fixtures (REQ-12)

| Directory | Payload |
|-----------|---------|
| `remote_import/` | `@import url("https://evil.example.com/stylesheet.css")` → Finding `TS-CE-007` (MEDIUM) |
| `file_url/` | `@import url("file:///etc/passwd")` → Finding `TS-CE-008` (HIGH), blocked via path confinement |

Built in-test via `tmp_path`.
