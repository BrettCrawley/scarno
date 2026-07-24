# opengrep rules

Project-specific SAST rules for Scarno. Rule files go in this directory
and are picked up automatically by the `opengrep` CI job.

Planned rules (Phase 0b onward):

- **TS-001** — forbid `eval()`, `exec()`, `compile()` in `src/scarno/`
- **TS-002** — forbid `subprocess.run(..., shell=True)`
- **TS-003** — forbid f-string interpolation into JSON output
- **TS-004** — require `Path.resolve()` before any open-for-read on
  user-supplied paths
- **TS-005** — forbid `xml.etree.ElementTree.parse` without DTD disabling
- **TS-006** — forbid `os.system(...)`
- **TS-007** — require `rich.markup.escape` on any user-supplied string
  passed to `rich.console.Console.print`
- **TS-008** — forbid `socket.connect`, `urllib.request.urlopen`,
  `requests.get`, etc., anywhere in `src/` (enforces privacy commitment)
