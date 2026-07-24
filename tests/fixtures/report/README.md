# report/

Reporter fixture projects are constructed in-test via the `make_result`,
`safe_dep`, `in_use_dep`, and `uncertain_dep` conftest fixtures. The
subdirectories below exist for any future golden-file comparison tests.

| Directory | Contents |
|-----------|----------|
| `all_statuses/` | mix of SAFE, UNCERTAIN, IN_USE deps + warnings |
| `empty_result/` | AnalysisResult with no deps |
| `entry_points/` | IN_USE dep with populated entry_points list |
| `ansi_input/` | dep names containing ANSI escape sequences |
