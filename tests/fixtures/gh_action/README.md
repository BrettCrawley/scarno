# gh_action/ — REQ-8 smoke fixture

When the composite GitHub Action lands (Phase 4), this directory is the
project the smoke workflow analyses. It should be a tiny-but-real
example that exercises the full Scarno pipeline and has a
deterministic expected output. `smoke_fixture/` starts empty — the
Phase 4 agent creates the pyproject.toml / source file matching the
acceptance criteria in REQ-8.
