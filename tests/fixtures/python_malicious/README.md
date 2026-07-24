# python_malicious/ — adversarial Python fixtures

The directories under `python_malicious/` enumerate the adversarial payloads
Scarno must defend against when parsing Python dependency files:

| Directory | Payload |
|-----------|---------|
| `ansi_dep/` | dep name containing ANSI escape sequences (e.g. `\x1b[2J`) |
| `control_chars/` | dep name containing C0/C1 control characters (`\x00`, `\x01`, `\r\n`) |
| `rich_markup/` | dep name containing `rich` markup tags (`[bold red]...[/bold red]`) |
| `oversized_req/` | single line of 300 chars for dep name |
| `circular_includes/` | two files that `-r` each other |

**Note:** The tests in `tests/security/test_adversarial.py` construct these
payloads programmatically via `tmp_path` to avoid committing literal escape
bytes to the repo. Directories exist as documentation and for any future
golden-file comparison tests.
