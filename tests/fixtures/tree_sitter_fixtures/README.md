# tree_sitter_fixtures/ — REQ-6b regression fixtures

When tree-sitter replaces the regex JVM source scanner (Phase 4), each
subdirectory here becomes a regression target:

| Directory | Intent |
|-----------|--------|
| `java_comment_with_import/` | `// import com.example.Secret;` — regex-based impl matches this as a real import; tree-sitter impl must NOT |
| `java_string_with_annotation/` | `String s = "@Autowired";` — regex-based impl fires DI match; tree-sitter impl must NOT |
| `java_javadoc_forname/` | `/** Uses Class.forName("com.foo") */` — regex-based impl sees a reflective literal; tree-sitter impl must NOT |
| `kotlin_aliased_import/` | `import com.foo.Bar as B` — currently handled by regex; tree-sitter impl must continue to honour the alias |

The scoring rule for each fixture is the same: every existing Phase 2
REQ-6 test stays green, AND the tree-sitter impl gains the negative
assertions (no false positive) that regex can't make.
