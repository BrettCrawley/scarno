# gradle_malicious/

- `redos/` — ReDoS-triggering content is generated in-test via `tmp_path`
  (50,000-char `implementation` line).
- `long_lines/` — 10,000-char line fixture, generated in-test.

See `tests/security/test_adversarial.py::TestGradleReDoS`.
