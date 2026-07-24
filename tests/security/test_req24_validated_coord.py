"""TA-338 — REQ-24 / SEC-NEW-59 — ``ValidatedCoordinate`` is structurally
non-bypassable.

Three layers of enforcement, one test class each:

* (a) **Runtime token guard** — direct ``ValidatedCoordinate(...)``
  construction without the module-private token raises ``TypeError``.
* (b) **Per-ecosystem validators** reject coords with URL/path/CRLF/
  control-byte components, length-cap each part, and reject
  unregistered ecosystems fail-closed.
* (c) **Static-analysis lint** — AST scan of ``src/`` rejects any
  ``ValidatedCoordinate(...)`` constructor call site outside
  ``scarno/indexing/validator.py``. Mirrors the TS-003 pattern
  (``open()`` calls must go through ``resolve_and_confine``).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from scarno.indexing import (
    CoordinateValidator,
    UnknownEcosystemError,
    ValidatedCoordinate,
)

pytestmark = pytest.mark.security


# ── (a) Runtime token guard ─────────────────────────────────────────────────


class TestRuntimeTokenGuard:
    @pytest.mark.requirement("SEC-NEW-59")
    def test_direct_construction_raises_type_error(self):
        """A naive ``ValidatedCoordinate(ecosystem=…)`` call without the
        private token must raise — the runtime layer of N-1."""
        with pytest.raises(TypeError, match="must be constructed via"):
            ValidatedCoordinate(
                ecosystem="maven",
                components=("g", "a"),
                raw="g:a",
                _token=object(),
            )

    @pytest.mark.requirement("SEC-NEW-59")
    def test_construction_with_no_token_keyword_raises(self):
        """Even a positional / missing-token call raises — the
        constructor is keyword-only and the token check fires."""
        with pytest.raises(TypeError):
            ValidatedCoordinate(  # type: ignore[call-arg]
                ecosystem="maven",
                components=("g", "a"),
                raw="g:a",
            )

    @pytest.mark.requirement("SEC-NEW-59")
    def test_validate_returns_validated_coordinate(self):
        """The legitimate path through ``CoordinateValidator.validate``
        does construct successfully."""
        v = CoordinateValidator.validate("maven", "com.example:lib")
        assert isinstance(v, ValidatedCoordinate)
        assert v.ecosystem == "maven"
        assert v.components == ("com.example", "lib")
        assert v.raw == "com.example:lib"

    @pytest.mark.requirement("SEC-NEW-59")
    def test_validated_coordinate_is_immutable(self):
        """Construction-time only; setattr raises post-construction."""
        v = CoordinateValidator.validate("maven", "com.example:lib")
        with pytest.raises(AttributeError, match="immutable"):
            v.ecosystem = "npm"  # type: ignore[misc]


# ── (b) Per-ecosystem validators ────────────────────────────────────────────


class TestMavenValidator:
    @pytest.mark.requirement("SEC-NEW-59")
    @pytest.mark.parametrize(
        "raw,components",
        [
            ("com.google.guava:guava", ("com.google.guava", "guava")),
            ("org.apache.commons:commons-lang3", ("org.apache.commons", "commons-lang3")),
            ("a:b", ("a", "b")),
        ],
    )
    def test_valid_maven_coords(self, raw, components):
        v = CoordinateValidator.validate("maven", raw)
        assert v.components == components

    @pytest.mark.requirement("SEC-NEW-59")
    @pytest.mark.parametrize(
        "raw,reason",
        [
            # Path traversal in either component
            ("..:lib", "'..'"),
            ("g:..", "'..'"),
            ("g/h:lib", "forbidden character"),
            ("g:lib/x", "forbidden character"),
            # URL-reserved chars
            ("g:lib?evil", "forbidden character"),
            ("g:lib#frag", "forbidden character"),
            ("g@evil:lib", "forbidden character"),
            # CRLF / control bytes
            ("g\nevil:lib", "forbidden character"),
            ("g\revil:lib", "forbidden character"),
            ("g\x00evil:lib", "forbidden character"),
            # Wrong shape
            ("nogroup", "must be 'groupId:artifactId'"),
            ("a:b:c", "must be 'groupId:artifactId'"),
            (":lib", "empty groupId"),
            ("g:", "empty artifactId"),
        ],
    )
    def test_rejects_hostile_maven_coord(self, raw, reason):
        with pytest.raises(ValueError, match=reason):
            CoordinateValidator.validate("maven", raw)

    @pytest.mark.requirement("SEC-NEW-59")
    def test_overlong_component_rejected(self):
        long = "a" * 300
        with pytest.raises(ValueError, match="exceeds cap"):
            CoordinateValidator.validate("maven", f"{long}:lib")


class TestNpmValidator:
    @pytest.mark.requirement("SEC-NEW-59")
    @pytest.mark.parametrize(
        "raw,components",
        [
            ("react", ("react",)),
            ("@scope/pkg", ("@scope", "pkg")),
            ("lodash.merge", ("lodash.merge",)),
        ],
    )
    def test_valid_npm_coords(self, raw, components):
        v = CoordinateValidator.validate("npm", raw)
        assert v.components == components

    @pytest.mark.requirement("SEC-NEW-59")
    @pytest.mark.parametrize(
        "raw",
        [
            "../evil",
            "evil/../escape",
            "evil%2fpath",
            "evil@host",
            "EvilCase",  # npm names are lowercase
            "",
            "a/b/c",  # too many slashes
            "noscope/pkg",  # missing @
        ],
    )
    def test_rejects_hostile_npm_coord(self, raw):
        with pytest.raises(ValueError):
            CoordinateValidator.validate("npm", raw)


class TestUnregisteredEcosystem:
    @pytest.mark.requirement("SEC-NEW-59")
    def test_unknown_ecosystem_fail_closed(self):
        """No registered validator → fail-closed.
        Any ecosystem scarno analyses but has no fetcher for stays
        un-fetchable — the alternative (silent skip) would create a
        coverage illusion."""
        with pytest.raises(UnknownEcosystemError, match="No coordinate validator"):
            CoordinateValidator.validate("not_a_real_ecosystem", "x")

    @pytest.mark.requirement("SEC-NEW-59")
    def test_registered_ecosystems_includes_maven_and_npm(self):
        ecosystems = CoordinateValidator.registered_ecosystems()
        assert "maven" in ecosystems
        assert "npm" in ecosystems


# ── (c) Static-analysis lint ────────────────────────────────────────────────


_VALIDATOR_MODULE = "scarno/indexing/validator.py"


class TestStaticConstructionLint:
    @pytest.mark.requirement("SEC-NEW-59")
    def test_no_direct_construction_outside_validator_module(self):
        """AST-scan all of ``src/scarno/`` and assert that no call
        site outside ``indexing/validator.py`` constructs
        ``ValidatedCoordinate(...)`` directly. Mirrors the TS-003 lint
        pattern (every ``open()`` must go through ``resolve_and_confine``).
        """
        src_root = (
            Path(__file__).resolve().parent.parent.parent
            / "src" / "scarno"
        )
        violators: list[str] = []
        for py_file in src_root.rglob("*.py"):
            rel = py_file.relative_to(src_root.parent.parent).as_posix()
            if rel.endswith(_VALIDATOR_MODULE):
                continue  # the legitimate construction site
            try:
                tree = ast.parse(
                    py_file.read_text(encoding="utf-8"), filename=str(py_file)
                )
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Catch ``ValidatedCoordinate(...)`` and
                    # ``X.ValidatedCoordinate(...)``.
                    name = ""
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        name = node.func.attr
                    if name == "ValidatedCoordinate":
                        violators.append(f"{rel}:{node.lineno}")
        assert not violators, (
            "Direct construction of ValidatedCoordinate outside "
            f"{_VALIDATOR_MODULE} — violates SEC-NEW-59:\n  - "
            + "\n  - ".join(violators)
        )
