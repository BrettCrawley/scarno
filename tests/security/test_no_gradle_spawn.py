"""SEC-011: scarno never runs Gradle (GitHub issue #1).

Running ``gradle dependencies`` evaluates the analysed project's
``settings.gradle``, ``build.gradle`` and ``init.gradle``, which are
executable Groovy/Kotlin by design. On an untrusted repository that is
code execution as the scanning user. No working directory or flag set
makes it safe, because Gradle offers no mode that reads dependencies
without evaluating the build. Gradle analysis is therefore static only.

An argv-allowlisted ``_invoke_gradle_safe`` helper used to exist with no
production caller. It also ran without ``cwd``, the same vector as
security finding F2. It was removed rather than fixed so that nobody
wires it up later. These tests stop it, or any equivalent, from coming
back silently.

The checks are static (AST over ``src/scarno``) rather than a runtime
monkeypatch, so they cover code paths no fixture exercises.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import scarno

pytestmark = pytest.mark.security

_SRC = Path(scarno.__file__).resolve().parent
_GRADLE_MODULE = _SRC / "analysers" / "java" / "gradle.py"

_GRADLE_BINARIES = {"gradle", "gradlew", "gradlew.bat"}


def _python_files() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if p.is_file())


def _string_constants(node: ast.AST) -> list[str]:
    return [
        n.value
        for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def _names_gradle_binary(value: str) -> bool:
    return Path(value).name.lower() in _GRADLE_BINARIES


@pytest.mark.requirement("SEC-011")
def test_gradle_module_has_no_process_spawning_imports() -> None:
    """The Gradle analyser imports nothing that can start a process."""
    tree = ast.parse(_GRADLE_MODULE.read_text(encoding="utf-8"))
    forbidden_modules = {"subprocess", "shutil", "pty", "multiprocessing"}
    forbidden_names = {"safe_subprocess_run", "system", "popen", "spawn"}
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [
                a.name for a in node.names
                if a.name.split(".")[0] in forbidden_modules
            ]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in forbidden_modules:
                offenders.append(node.module or "")
            offenders += [
                f"{node.module}.{a.name}" for a in node.names
                if a.name in forbidden_names
            ]
    assert offenders == [], (
        f"gradle.py must not import process-spawning APIs: {offenders}"
    )


_SPAWN_CALLS = {
    "run", "Popen", "call", "check_call", "check_output",
    "safe_subprocess_run", "which", "execv", "execvp", "spawnv",
    "spawnvp", "system", "popen",
}


def _gradle_spawn_sites(tree: ast.AST) -> list[tuple[int, str]]:
    """(line, callee) for every call that hands a Gradle binary name to a
    spawn primitive or to ``shutil.which``."""
    sites: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.attr if isinstance(func, ast.Attribute)
            else func.id if isinstance(func, ast.Name)
            else None
        )
        if name not in _SPAWN_CALLS:
            continue
        args = [*node.args, *(k.value for k in node.keywords)]
        if any(
            _names_gradle_binary(s) for a in args for s in _string_constants(a)
        ):
            sites.append((node.lineno, name))
    return sites


@pytest.mark.requirement("SEC-011")
def test_no_source_resolves_or_spawns_a_gradle_binary() -> None:
    """No call anywhere in ``src/scarno`` passes a Gradle binary name to
    a spawn primitive or to ``shutil.which``."""
    offenders = [
        f"{path.relative_to(_SRC)}:{line} {name}(…)"
        for path in _python_files()
        for line, name in _gradle_spawn_sites(
            ast.parse(path.read_text(encoding="utf-8"))
        )
    ]
    assert offenders == [], (
        "scarno must never run Gradle (SEC-011, issue #1); found: "
        f"{offenders}"
    )


@pytest.mark.requirement("SEC-011")
def test_gradle_module_does_not_read_gradle_home() -> None:
    """``GRADLE_HOME`` only matters for locating a binary to run. A
    reference to it is the first sign of the spawn path coming back."""
    text = _GRADLE_MODULE.read_text(encoding="utf-8")
    tree = ast.parse(text)
    assert "GRADLE_HOME" not in _string_constants(tree)


def test_guard_detects_a_reintroduced_spawn() -> None:
    """Self-check: the matcher used above flags the shapes the removed
    helper had (``shutil.which``, absolute binary, wrapper script), and
    ignores a non-Gradle spawn, so a vacuous pass is not possible."""
    sample = (
        "import shutil, subprocess\n"
        "from scarno.security import safe_subprocess_run\n"
        "g = shutil.which('gradle')\n"
        "safe_subprocess_run(['/opt/gradle/bin/gradle', 'dependencies'],"
        " timeout_s=1)\n"
        "subprocess.run(['./gradlew', 'dependencies'])\n"
        "safe_subprocess_run(['mvn', 'dependency:get'], timeout_s=1)\n"
    )
    assert _gradle_spawn_sites(ast.parse(sample)) == [
        (3, "which"),
        (4, "safe_subprocess_run"),
        (5, "run"),
    ]
