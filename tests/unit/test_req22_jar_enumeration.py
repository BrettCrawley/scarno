"""REQ-22 — the differ inspects the classes a JAR actually declares.

Issue #2: ``CrossVersionAbiDiffer`` used to guess one class per JAR by
title-casing the artifact id (``jetty-util`` -> ``org.eclipse.jetty.JettyUtil``).
That names no real class for most coordinates, so javap failed and the
whole diff was skipped — which is why TS-ABI-RUNTIME-RISK rarely fired.

Issue #3: once real classes are enumerated, a library split shows every
relocated class as removed. The resolved classpath is indexed so that
reads as drift naming the new home, not as a NoSuchMethodError claim.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from scarno.analysers.java.abi_diff import (
    CrossVersionAbiDiffer,
    jar_class_names,
)
from scarno.models import (
    AnalysisResult,
    Dependency,
    DependencyStatus,
    VersionedNode,
)


def _jar(path: Path, entries: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for entry in entries:
            zf.writestr(entry, b"\xca\xfe\xba\xbe")
    return path


class TestJarClassNames:
    @pytest.mark.requirement("FR-275")
    def test_lists_classes_including_package_private_and_nested(self, tmp_path):
        """Access level is invisible in a class file's name, and both
        package-private and nested types are referenceable by a legal
        caller — a consumer can declare its own class in the same package.
        """
        jar = _jar(tmp_path / "a.jar", [
            "com/example/Public.class",
            "com/example/PackagePrivate.class",
            "com/example/Outer$Inner.class",
            "com/example/sub/Deep.class",
        ])
        assert jar_class_names(jar) == [
            "com.example.Outer$Inner",
            "com.example.PackagePrivate",
            "com.example.Public",
            "com.example.sub.Deep",
        ]

    @pytest.mark.requirement("FR-275")
    def test_skips_descriptors_and_multi_release_duplicates(self, tmp_path):
        jar = _jar(tmp_path / "b.jar", [
            "com/example/Real.class",
            "module-info.class",
            "com/example/package-info.class",
            "META-INF/versions/11/com/example/Real.class",
            "META-INF/MANIFEST.MF",
            "com/example/notaclass.txt",
        ])
        assert jar_class_names(jar) == ["com.example.Real"]

    @pytest.mark.requirement("FR-275")
    def test_unreadable_jar_yields_no_classes(self, tmp_path):
        broken = tmp_path / "broken.jar"
        broken.write_bytes(b"not a zip")
        assert jar_class_names(broken) == []


def _result(coords_versions, resolved_map):
    nodes, deps = [], []
    for coord, versions in coords_versions.items():
        for v in versions:
            nodes.append(VersionedNode(
                canonical=coord, declared_version=v,
                status=DependencyStatus.IN_USE,
                is_resolved=(v == resolved_map[coord]),
            ))
        deps.append(Dependency(
            name=coord, version=resolved_map[coord],
            status=DependencyStatus.IN_USE, reason="", ecosystem="maven",
        ))
    return AnalysisResult(
        project_type="java", project_path="/tmp",
        dependencies=deps, versioned_nodes=nodes,
        multi_version_coords=[
            c for c, v in coords_versions.items() if len(v) > 1
        ],
    )


class TestEnumerationDrivesTheDiff:
    @pytest.mark.requirement("FR-275")
    def test_class_not_matching_the_artifact_name_is_still_diffed(
        self, tmp_path,
    ):
        """The old probe derived a class name from the coordinate. Real
        artefacts almost never contain such a class, so nothing was
        inspected. Here the only class is deliberately unrelated to the
        artifact id."""
        m2 = tmp_path / "m2"
        base = m2 / "org" / "example" / "widget-util"
        _jar(base / "1.0" / "widget-util-1.0.jar",
             ["org/example/internal/Engine.class"])
        _jar(base / "2.0" / "widget-util-2.0.jar",
             ["org/example/internal/Engine.class"])

        seen: list[list[str]] = []

        def fake_javap(jar_path, class_names):
            seen.append(list(class_names))
            if "1.0" in str(jar_path):
                return (
                    "public class org.example.internal.Engine {\n"
                    "  public void start();\n"
                    "  public void stop();\n"
                    "}\n"
                )
            return (
                "public class org.example.internal.Engine {\n"
                "  public void start();\n"
                "}\n"
            )

        differ = CrossVersionAbiDiffer(m2_root=m2, invoke_javap=fake_javap)
        result = _result(
            {"org.example:widget-util": ["1.0", "2.0"]},
            {"org.example:widget-util": "2.0"},
        )
        findings = differ.diff_all(
            result, {"org.example:widget-util": {"org.example.internal.Engine.stop"}},
        )

        assert seen and seen[0] == ["org.example.internal.Engine"], seen
        messages = " ".join(f.message for f in findings)
        assert "stop" in messages, messages
        assert any(f.rule_id == "TS-ABI-RUNTIME-RISK" for f in findings)


class TestRelocationIsNotARemoval:
    @pytest.mark.requirement("FR-275")
    def test_class_moved_to_a_sibling_artefact_is_drift_not_risk(
        self, tmp_path,
    ):
        """A library split: Engine leaves widget-core and arrives in
        widget-engine, which the resolved graph also provides. Claiming
        NoSuchMethodError for it would be a false positive."""
        m2 = tmp_path / "m2"
        core = m2 / "org" / "example" / "widget-core"
        _jar(core / "1.0" / "widget-core-1.0.jar",
             ["org/example/Engine.class", "org/example/Keep.class"])
        _jar(core / "2.0" / "widget-core-2.0.jar", ["org/example/Keep.class"])
        # The sibling that now ships Engine, resolved in the same graph.
        engine = m2 / "org" / "example" / "widget-engine"
        _jar(engine / "2.0" / "widget-engine-2.0.jar",
             ["org/example/Engine.class"])

        def fake_javap(jar_path, class_names):
            names = list(class_names)
            if "widget-engine" in str(jar_path):
                return ""
            if "1.0" in str(jar_path):
                return (
                    "public class org.example.Engine {\n"
                    "  public void start();\n"
                    "}\n"
                    "public class org.example.Keep {\n"
                    "  public void keep();\n"
                    "}\n"
                )
            return (
                "public class org.example.Keep {\n  public void keep();\n}\n"
            )

        differ = CrossVersionAbiDiffer(m2_root=m2, invoke_javap=fake_javap)
        result = _result(
            {
                "org.example:widget-core": ["1.0", "2.0"],
                "org.example:widget-engine": ["2.0"],
            },
            {
                "org.example:widget-core": "2.0",
                "org.example:widget-engine": "2.0",
            },
        )
        findings = differ.diff_all(
            result,
            {"org.example:widget-core": {"org.example.Engine.start"}},
        )

        engine_findings = [f for f in findings if "Engine" in f.message]
        assert engine_findings, findings
        assert all(
            f.rule_id == "TS-ABI-DRIFT" for f in engine_findings
        ), [f.rule_id for f in engine_findings]
        joined = " ".join(f.message for f in engine_findings)
        assert "moved between artefacts" in joined, joined
        assert "widget-engine" in joined, joined

    @pytest.mark.requirement("FR-275")
    def test_genuine_removal_is_still_a_runtime_risk(self, tmp_path):
        """Absent from every resolved artefact — the real thing."""
        m2 = tmp_path / "m2"
        core = m2 / "org" / "example" / "widget-core"
        _jar(core / "1.0" / "widget-core-1.0.jar",
             ["org/example/Gone.class"])
        _jar(core / "2.0" / "widget-core-2.0.jar",
             ["org/example/Other.class"])

        def fake_javap(jar_path, class_names):
            if "1.0" in str(jar_path):
                return (
                    "public class org.example.Gone {\n"
                    "  public void vanish();\n}\n"
                )
            return "public class org.example.Other {\n  public void x();\n}\n"

        differ = CrossVersionAbiDiffer(m2_root=m2, invoke_javap=fake_javap)
        result = _result(
            {"org.example:widget-core": ["1.0", "2.0"]},
            {"org.example:widget-core": "2.0"},
        )
        findings = differ.diff_all(
            result, {"org.example:widget-core": {"org.example.Gone.vanish"}},
        )

        risks = [f for f in findings if f.rule_id == "TS-ABI-RUNTIME-RISK"]
        assert risks, findings
        assert any("vanish" in f.message for f in risks)


class TestCapsAndFailuresAreReported:
    @pytest.mark.requirement("FR-275")
    def test_class_cap_shortfall_is_reported_not_silent(
        self, tmp_path, monkeypatch,
    ):
        """A silent truncation here would reintroduce exactly the class of
        false negative this enumeration exists to remove, so the shortfall
        goes on the report channel."""
        import scarno.analysers.java.abi_diff as ad

        monkeypatch.setattr(ad, "_MAX_CLASSES_PER_JAR", 2)
        m2 = tmp_path / "m2"
        base = m2 / "org" / "example" / "big"
        entries = [f"org/example/C{i}.class" for i in range(5)]
        _jar(base / "1.0" / "big-1.0.jar", entries)
        _jar(base / "2.0" / "big-2.0.jar", entries)

        differ = ad.CrossVersionAbiDiffer(
            m2_root=m2, invoke_javap=lambda j, n: "",
        )
        result = _result(
            {"org.example:big": ["1.0", "2.0"]}, {"org.example:big": "2.0"},
        )
        differ.diff_all(result, {})

        assert any("inspecting the first 2" in e for e in result.errors), (
            result.errors
        )
        assert any("NOT reported" in e for e in result.errors)

    @pytest.mark.requirement("FR-275")
    def test_jar_with_no_classes_is_reported_and_skipped(self, tmp_path):
        m2 = tmp_path / "m2"
        base = m2 / "org" / "example" / "empty"
        _jar(base / "1.0" / "empty-1.0.jar", ["META-INF/MANIFEST.MF"])
        _jar(base / "2.0" / "empty-2.0.jar", ["META-INF/MANIFEST.MF"])

        differ = CrossVersionAbiDiffer(
            m2_root=m2, invoke_javap=lambda j, n: "should not be called",
        )
        result = _result(
            {"org.example:empty": ["1.0", "2.0"]},
            {"org.example:empty": "2.0"},
        )
        findings = differ.diff_all(result, {})

        assert findings == []
        assert any("no classes listed" in e for e in result.errors), (
            result.errors
        )

    @pytest.mark.requirement("FR-275")
    def test_a_failing_javap_batch_does_not_discard_the_jar(self, tmp_path):
        """One unreadable class must cost only its batch, not the whole
        archive."""
        import scarno.analysers.java.abi_diff as ad

        m2 = tmp_path / "m2"
        base = m2 / "org" / "example" / "lib"
        _jar(base / "1.0" / "lib-1.0.jar", ["org/example/A.class"])
        _jar(base / "2.0" / "lib-2.0.jar", ["org/example/A.class"])

        calls: list[object] = []

        def flaky(jar_path, names):
            calls.append(names)
            # Declared side fails; resolved side answers.
            return None if "1.0" in str(jar_path) else (
                "public class org.example.A {\n  public void x();\n}\n"
            )

        differ = ad.CrossVersionAbiDiffer(m2_root=m2, invoke_javap=flaky)
        result = _result(
            {"org.example:lib": ["1.0", "2.0"]}, {"org.example:lib": "2.0"},
        )
        findings = differ.diff_all(result, {})

        assert calls, "javap was never invoked"
        # The resolved side still parsed, so its members show as ADDED
        # rather than the whole coordinate being skipped.
        assert any("x" in f.message for f in findings), findings


class TestCorruptArchivesAreHandled:
    @pytest.mark.requirement("SEC-NEW-02")
    def test_bad_zip_is_normalised_to_valueerror(self, tmp_path):
        """zipfile.BadZipFile is neither ValueError nor OSError, so every
        caller's error handling missed it and a corrupt JAR ended the
        run."""
        from scarno.security import safe_jar_entries

        broken = tmp_path / "broken.jar"
        broken.write_bytes(b"definitely not a zip archive")
        with pytest.raises(ValueError, match="not a readable archive"):
            safe_jar_entries(broken)

    @pytest.mark.requirement("SEC-NEW-02")
    def test_truncated_central_directory_is_normalised(self, tmp_path):
        good = _jar(tmp_path / "good.jar", ["a/B.class"])
        data = good.read_bytes()
        truncated = tmp_path / "trunc.jar"
        # Keep the local header, destroy the end-of-central-directory.
        truncated.write_bytes(data[: len(data) // 2])
        with pytest.raises(ValueError):
            from scarno.security import safe_jar_entries

            safe_jar_entries(truncated)

    @pytest.mark.requirement("FR-275")
    def test_non_class_entries_are_ignored_defensively(
        self, tmp_path, monkeypatch,
    ):
        """``safe_jar_entries`` filters to ``*.class``, so this guard is
        belt-and-braces — but the stem arithmetic below it would corrupt
        a name that slipped through, so the contract is pinned rather
        than assumed."""
        import scarno.analysers.java.abi_diff as ad

        monkeypatch.setattr(
            ad, "safe_jar_entries",
            lambda p: ["com/example/Real.class", "com/example/notes.txt"],
        )
        assert ad.jar_class_names(tmp_path / "any.jar") == [
            "com.example.Real"
        ]
