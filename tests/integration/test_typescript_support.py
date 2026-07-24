"""REQ-18 — TypeScript first-class support.

End-to-end tests for ``@types/X`` runtime-pairing, ``import type``
distinction, ``.d.ts`` ambient module declarations, and TypeScript
decorator entry-point kinds.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scarno.cli import app


def _w(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _run(tmp: Path) -> dict:
    result = CliRunner().invoke(app, [str(tmp), "--format", "json"])
    assert result.exit_code in (0, 1, 3), result.output
    return json.loads(result.stdout)


def _dep(data: dict, name: str) -> dict:
    matches = [d for d in data["dependencies"] if d["name"] == name]
    assert matches, (
        f"dep {name} missing; got {[d['name'] for d in data['dependencies']]}"
    )
    return matches[0]


# ── @types/X runtime pairing ───────────────────────────────────────────


class TestAtTypesRuntimePair:
    @pytest.mark.requirement("FR-180")
    def test_at_types_runtime_pair(self, tmp_path):
        """`@types/lodash` declared alongside `lodash` is paired and
        classified IN_USE only because the runtime is in use."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
            "devDependencies": {"@types/lodash": "^4"},
        }))
        _w(tmp_path / "src" / "index.ts", """\
import _ from "lodash";
_.debounce(() => {}, 100);
""")
        data = _run(tmp_path)
        types_dep = _dep(data, "@types/lodash")
        assert types_dep["status"] == "IN_USE", (
            f"@types/lodash should be IN_USE when paired runtime is used; "
            f"got {types_dep['status']} (reason: {types_dep['reason']})"
        )
        assert "lodash" in types_dep["reason"].lower()
        assert types_dep["is_type_stub"] is True

    @pytest.mark.requirement("FR-180")
    def test_at_types_orphaned_when_runtime_absent(self, tmp_path):
        """`@types/lodash` without `lodash` declared surfaces a clear
        "runtime package not declared" reason."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "devDependencies": {"@types/lodash": "^4"},
        }))
        _w(tmp_path / "src" / "index.ts", "export const x = 1;\n")
        data = _run(tmp_path)
        types_dep = _dep(data, "@types/lodash")
        assert "not declared" in types_dep["reason"].lower(), (
            f"reason should mention runtime not declared; got "
            f"{types_dep['reason']!r}"
        )

    @pytest.mark.requirement("FR-184")
    def test_scoped_at_types_pair(self, tmp_path):
        """`@types/scope__pkg` pairs with `@scope/pkg` per DefinitelyTyped
        convention (double-underscore = scope separator)."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "dependencies": {"@my-scope/widget": "^1"},
            "devDependencies": {"@types/my-scope__widget": "^1"},
        }))
        _w(tmp_path / "src" / "index.ts", """\
import { Widget } from "@my-scope/widget";
new Widget();
""")
        data = _run(tmp_path)
        types_dep = _dep(data, "@types/my-scope__widget")
        assert types_dep["status"] == "IN_USE"
        assert types_dep["is_type_stub"] is True
        assert "@my-scope/widget" in types_dep["reason"]


# ── import type distinction ────────────────────────────────────────────


class TestImportTypeDistinct:
    @pytest.mark.requirement("FR-181")
    def test_import_type_distinct_kind(self, tmp_path):
        """`import type { Foo } from "x"` surfaces as kind="type-only"."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
        }))
        _w(tmp_path / "src" / "index.ts", """\
import type { DebouncedFunc } from "lodash";

export function makeDebounced<T>(fn: DebouncedFunc<any>): DebouncedFunc<any> {
    return fn;
}
""")
        data = _run(tmp_path)
        lodash = _dep(data, "lodash")
        type_only_eps = [
            ep for ep in lodash["entry_points"]
            if ep["kind"] == "type-only"
        ]
        assert type_only_eps, (
            f"no type-only entry points; got "
            f"{sorted({ep['kind'] for ep in lodash['entry_points']})}"
        )
        # Reason should hint that lodash is type-only used (eligible
        # for devDependencies).
        # Note: classification still IN_USE because TS source uses it,
        # but the "type-only" hint is in entry-point kinds.

    @pytest.mark.requirement("FR-181")
    def test_per_specifier_type_keyword(self, tmp_path):
        """`import { type A, b } from "x"` — A is type-only, b is runtime."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "dependencies": {"lodash": "^4"},
        }))
        _w(tmp_path / "src" / "index.ts", """\
import { type DebouncedFunc, debounce } from "lodash";
const fn: DebouncedFunc<any> = debounce(() => {}, 100);
""")
        data = _run(tmp_path)
        lodash = _dep(data, "lodash")
        kinds = {ep["kind"]: ep for ep in lodash["entry_points"]}
        # Both kinds present.
        assert any(
            ep["kind"] == "type-only" for ep in lodash["entry_points"]
        ), "no type-only entry"
        assert any(
            ep["kind"] == "function" for ep in lodash["entry_points"]
        ), "no runtime-call entry"


# ── .d.ts ambient module declarations ─────────────────────────────────


class TestDtsAmbientModule:
    @pytest.mark.requirement("FR-182")
    def test_dts_ambient_module_declaration(self, tmp_path):
        """A `.d.ts` containing `declare module "x"` marks `x` as type-used."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "dependencies": {"wrapped-lib": "^1"},
        }))
        # Project-local .d.ts wraps an external library.
        _w(tmp_path / "types" / "wrapped-lib.d.ts", """\
declare module "wrapped-lib" {
    export interface Cfg { mode: string; }
    export function init(c: Cfg): void;
}
""")
        # Source uses only the ambient declaration's surface (no
        # runtime import).
        _w(tmp_path / "src" / "index.ts", """\
import type { Cfg } from "wrapped-lib";
export function build(c: Cfg): Cfg { return c; }
""")
        data = _run(tmp_path)
        wrapped = _dep(data, "wrapped-lib")
        # Without the ambient declaration scanner, this would be SAFE.
        # With it, the dep is at least IN_USE / UNCERTAIN with a
        # type-only reason.
        assert wrapped["status"] != "SAFE", (
            f"wrapped-lib falsely SAFE despite declare module + import type; "
            f"reason={wrapped['reason']!r}"
        )


# ── TS decorators ─────────────────────────────────────────────────────


class TestTsDecorators:
    @pytest.mark.requirement("FR-183")
    def test_ts_decorator_kind(self, tmp_path):
        """`@Component(...)` from a NestJS-style import surfaces as
        kind="decorator"."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "dependencies": {"@nestjs/common": "^10"},
        }))
        _w(tmp_path / "tsconfig.json", json.dumps({
            "compilerOptions": {
                "experimentalDecorators": True,
                "emitDecoratorMetadata": True,
            },
        }))
        _w(tmp_path / "src" / "app.ts", """\
import { Controller, Get, Injectable } from "@nestjs/common";

@Injectable()
class Service {
    handle(): string { return "ok"; }
}

@Controller("/api")
class App {
    @Get("/")
    root(): string { return "hello"; }
    @Get("/version")
    version(): string { return "1"; }
}
""")
        data = _run(tmp_path)
        nest = _dep(data, "@nestjs/common")
        decorator_eps = [
            ep for ep in nest["entry_points"]
            if ep["kind"] == "decorator"
        ]
        assert decorator_eps, (
            f"no decorator entries for @nestjs/common; kinds: "
            f"{sorted({ep['kind'] for ep in nest['entry_points']})}"
        )
        names = {ep["name"] for ep in decorator_eps}
        assert any("Controller" in n for n in names), (
            f"@Controller missing; got {names}"
        )
        # @Get appears twice; usage_count should reflect.
        get_eps = [ep for ep in decorator_eps if "Get" in ep["name"]]
        assert get_eps and get_eps[0]["usage_count"] >= 2


# ── Security: traversal in @types/... names ───────────────────────────


class TestAtTypesTraversalSafety:
    @pytest.mark.requirement("SEC-NEW-36")
    @pytest.mark.security
    def test_at_types_traversal_rejected(self, tmp_path):
        """A malicious `@types/<..>` name is rejected by the npm name
        validator (SEC-NEW-34) before any runtime-target pairing is
        attempted."""
        _w(tmp_path / "package.json", json.dumps({
            "name": "demo", "version": "1.0.0",
            "devDependencies": {"@types/..\\..\\etc": "1.0.0"},
        }))
        _w(tmp_path / "src" / "index.ts", "export const x = 1;\n")
        data = _run(tmp_path)
        # The bad name must not appear in the dep list — it was
        # rejected by the validator. No file outside the project
        # was touched.
        names = {d["name"] for d in data["dependencies"]}
        assert "@types/..\\..\\etc" not in names
        assert not any(
            "..\\..\\etc" in d["name"] for d in data["dependencies"]
        )
