# Robust Java / Kotlin Parsing via tree-sitter

## Overview
Replace REQ-6's regex-based scanning of `.java` / `.kt` source files with proper AST traversal using [tree-sitter](https://tree-sitter.github.io/) grammars. Matches the rigor of Python's `ast`-based source analyser (REQ-3) for the JVM side.

## Problem Statement
Phase 2 ships REQ-6 with regex-based extraction of imports, annotations, and reflective literals. This is a pragmatic MVP choice but brittle against:

| Failure mode | Example |
|--------------|---------|
| Multi-line import formatting | `import\n  com.example.Foo;` |
| Comment containing import-like text | `// import com.example.Secret;` — currently counted as an import |
| String literal containing annotation text | `String doc = "@Autowired injects";` — currently triggers DI match |
| String literal containing reflection signature | `log.debug("Class.forName(\"com.foo\")");` — currently triggers UNCERTAIN |
| Annotations on separate lines from declarations | `@Component\n@Qualifier("x")\nclass Foo {}` — partial coverage |
| Javadoc `@code` / `@link` tags | `/** @see Autowired */` — false-positive annotation match |
| Heredoc / text block literals (Java 15+) | `String s = """@Autowired""";` — false-positive |
| Kotlin complex syntax | `import com.foo.bar as baz`, type aliases, `@file:JvmName` |
| Nested classes in generic bounds | `Map<@NotNull String, ?>` — parenthesised annotation missed |
| Preprocessor-style templating | unusual but legal whitespace / Unicode identifiers |

Every item above has been observed in real Spring / Android / Gradle plugin codebases. Any one of them produces a misclassification that erodes user trust.

## Solution
Use tree-sitter with official grammars:

- `tree-sitter-java` — mature, actively maintained, used by GitHub Code Scanning and VS Code
- `tree-sitter-kotlin` — covers Kotlin 1.9 syntax

Python bindings via the `tree-sitter` PyPI package plus `tree-sitter-java-bindings` / `tree-sitter-kotlin-bindings` (or equivalent pre-built wheels).

Replace the regex extractors in `src/scarno/analysers/java/source_analyser.py` with an AST-walking module. The public surface (`JvmSourceAnalyser.analyse()`, `_invoke_javap_safe()`, `_resolve_javap_binary()`) stays unchanged — this is an internal refactor.

## File Layout

```
src/scarno/analysers/java/
├── __init__.py                  # JavaAnalyser (unchanged)
├── maven.py                     # REQ-4 (unchanged)
├── gradle.py                    # REQ-5 (unchanged)
├── source_analyser.py           # Thin façade — delegates to ast_extractor
└── ast_extractor.py             # NEW — tree-sitter walkers for Java + Kotlin
```

## Public Interface (unchanged)

```python
class JvmSourceAnalyser(BaseAnalyser):
    def analyse(self, project_path: str,
                dependencies: list[Dependency] | None = None) -> AnalysisResult: ...
    def _invoke_javap_safe(self, jar_path: Path, class_name: str) -> str | None: ...
    def _resolve_javap_binary(self) -> str | None: ...
```

## ast_extractor.py Contract

```python
@dataclass
class ExtractedFacts:
    imports: set[str]               # fully-qualified top-level packages
    annotations: set[str]           # simple annotation names
    reflective_literals: set[str]   # string args to Class.forName / loadClass
    file_path: str

def extract_java(source: str, file_path: str) -> ExtractedFacts: ...
def extract_kotlin(source: str, file_path: str) -> ExtractedFacts: ...
```

Key semantics that tree-sitter gives us for free:

- **Comments excluded** — walker visits only `import_declaration`, `annotation`, `method_invocation` nodes; comments are separate node types.
- **String literals excluded** — annotation matching only fires on `annotation` node types, never on `string_literal`.
- **Javadoc tags excluded** — `@see`, `@link`, etc. live inside `block_comment` and `line_comment` nodes.
- **Multi-line declarations handled** — the grammar understands any legal whitespace.
- **Kotlin aliased imports** — `import com.foo.Bar as Baz` → imports includes `com.foo.Bar` via the `import_alias` child node.
- **Text blocks / heredocs** — distinct node type, not confused with regular strings.

## Dependency Footprint

Add to runtime deps:

- `tree-sitter >= 0.22`
- `tree-sitter-java` (or `tree-sitter-languages` aggregate package)
- `tree-sitter-kotlin`

All three ship pre-built wheels for Linux / macOS / Windows on CPython 3.12. No C toolchain required at install time for supported platforms.

When wheels aren't available for a platform, fall back to the regex extractors (kept as a soft-deprecation path). Emit a warning that coverage accuracy is reduced.

## Security Considerations

- Tree-sitter parses untrusted project source files (Zone 3 per THREAT_MODEL.md). The parser is a native-code library — it must not be used on files over `MAX_FILE_BYTES`, matching the existing guard.
- Tree-sitter's parser has known DoS characteristics on pathological inputs. Add a per-file parse timeout (10 s) and reject beyond it with a warning (parallel to the XML parsing ceiling).
- The grammar is compiled data, not code; loading a grammar never executes project content.

## Test Strategy

Every existing `test_jvm_source_analyser.py` test stays green. Add new positive / negative tests that distinguish regex from AST:

| ID | Fixture | Expected |
|---|---|---|
| `test_import_in_line_comment_not_flagged` | `// import com.example.Secret;` + no real import | dep → SAFE (regex impl fails this) |
| `test_annotation_in_string_literal_not_flagged` | `String s = "@Autowired";` + no real annotation | Spring dep → SAFE |
| `test_class_forname_in_javadoc_not_flagged` | `/** Uses Class.forName("com.x.Y") */` | dep → SAFE |
| `test_multi_line_import_handled` | `import\n  com.example.Foo;` | dep → IN_USE |
| `test_kotlin_aliased_import_recognised` | `import com.foo.Bar as B` + use of `B` | dep → IN_USE |
| `test_kotlin_text_block_not_parsed_as_annotation` | `val s = """@Autowired"""` | dep → SAFE |

## SRTM

| ID | Description |
|----|-------------|
| FR-086 | JVM source analysis uses tree-sitter AST, not regex |
| FR-087 | Comments / string literals / Javadoc excluded from annotation + reflection match |
| FR-088 | Graceful fallback to regex when tree-sitter grammars unavailable on host |
| SEC-NEW-19 | tree-sitter parse confined by file size + 10 s timeout |

## Acceptance Criteria
- [] Given a Java source file with `// import com.example.Secret;` and no real import of the dep, When analysed, Then the dep is classified SAFE
- [] Given a Java source file with `String s = "@Autowired";` and no real `@Autowired` annotation, When analysed, Then no DI match fires
- [] Given a Java source file with `Class.forName("com.foo")` inside a Javadoc block, When analysed, Then no reflection match fires
- [] Given a multi-line `import` statement, When analysed, Then the import is captured
- [] Given a Kotlin file with `import com.foo.Bar as B` + use of `B`, When analysed, Then the Bar package is matched against the dep
- [] Given a Kotlin text block containing annotation-looking text, When analysed, Then no DI match fires
- [] Given tree-sitter wheels are unavailable on the host platform, When `JvmSourceAnalyser.analyse()` is called, Then a warning is appended and regex fallback is used
- [] Given a pathological source file (10 MB or a parse-time bomb), When analysed, Then the file is either skipped (size cap) or the parse is aborted within 10 s
- [] Given all existing `test_jvm_source_analyser.py` cases from Phase 2, When the tree-sitter implementation lands, Then every one of them remains green

## Out of Scope
- Replacing the `javap`-based entry-point enumeration (that's valuable precisely because it inspects bytecode, not source)
- Replacing the Groovy-DSL Gradle parser (REQ-5 stays regex-based; REQ-5b could extend this approach if warranted)
