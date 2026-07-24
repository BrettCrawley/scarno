"""PR-4 red tests — SUC-51 / SEC-NEW-44 + SUC-52: m2 path confinement
and no wholesale enumeration (TA-272 + TA-273 + TA-274)."""
from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.security


@pytest.mark.requirement("FR-231")
@pytest.mark.requirement("SEC-NEW-44")
def test_m2_jar_path_confined(tmp_path):
    """TA-272 — A coordinate with `<groupId>../../etc</groupId>` is
    rejected by _validate_gav BEFORE any FS access. The differ raises
    or returns None — never attempts to construct the path."""
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer

    differ = CrossVersionAbiDiffer(
        m2_root=tmp_path / "m2",
        invoke_javap=lambda *_a: None,
    )
    # The helper signature is intentionally minimal — caller passes the
    # coordinate string, and the resolver returns None for invalid GAVs.
    path = differ._m2_jar_path("../../etc:passwd", "1.0")
    assert path is None


@pytest.mark.requirement("FR-231")
def test_m2_jar_path_resolves_under_m2_root(tmp_path):
    """TA-273 — A valid coord resolves to a Path under m2_root."""
    from scarno.analysers.java.abi_diff import CrossVersionAbiDiffer

    m2 = tmp_path / "m2"
    jar_dir = m2 / "com" / "thirdparty" / "helper" / "1.2.0"
    jar_dir.mkdir(parents=True)
    jar_path = jar_dir / "helper-1.2.0.jar"
    jar_path.write_bytes(b"")
    differ = CrossVersionAbiDiffer(
        m2_root=m2,
        invoke_javap=lambda *_a: None,
    )
    path = differ._m2_jar_path("com.thirdparty:helper", "1.2.0")
    assert path is not None
    assert path.resolve().is_relative_to(m2.resolve())


@pytest.mark.requirement("SEC-NEW-44")
def test_no_wholesale_m2_enumeration():
    """TA-274 — Static-grep ``analysers/java/abi_diff.py`` for
    wholesale-cache walks (``os.scandir`` / ``Path.iterdir`` /
    ``glob.glob`` rooted at the m2 cache). SUC-52: the differ reads
    JARs ONLY for coordinates already in dep_edges, never enumerates."""
    import re

    abi_path = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "scarno" / "analysers" / "java" / "abi_diff.py"
    )
    text = abi_path.read_text(encoding="utf-8")
    forbidden = (
        re.compile(r"\bos\.scandir\b"),
        re.compile(r"\.iterdir\(\)"),
        re.compile(r"\bglob\.(?:glob|iglob)\b"),
        re.compile(r"\.rglob\("),
        re.compile(r"\.glob\("),
    )
    offenders: list[str] = []
    for pat in forbidden:
        for m in pat.finditer(text):
            offenders.append(
                f"line {text[:m.start()].count(chr(10)) + 1}: "
                f"{m.group(0)}"
            )
    assert not offenders, (
        "abi_diff.py enumerates the m2 cache — violates SUC-52:\n  - "
        + "\n  - ".join(offenders)
    )
