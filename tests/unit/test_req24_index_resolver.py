"""TA-326..329 + TA-352 — REQ-24 ``IndexConfigResolver``: CLI/env/
user-config sources merged with per-ecosystem override; env dropped
under ``--allow-remote-fetch`` (SEC-NEW-62); URLs validated
HTTPS-only with no userinfo (SEC-NEW-66 parse-time gate).

Plus: TA-352 — ``IndexEndpoint`` reserved fields (``credential_ref``,
``coordinate_prefix``) exist on the model so the v2 auth + scoping
layer slots in without breaking changes.
"""
from __future__ import annotations

import pytest

from scarno.indexing import (
    IndexConfigSource,
    IndexEndpoint,
    resolve_indexes,
)


# ── TA-326 — CLI parsing + priority ─────────────────────────────────────────


class TestCliParsing:
    @pytest.mark.requirement("FR-256")
    def test_repeatable_index_records_priority_in_order(self):
        endpoints, warnings = resolve_indexes(
            cli_indexes=[
                "maven=https://nexus.corp/repo",
                "maven=https://repo1.maven.org/maven2",
                "npm=https://registry.npmjs.org",
            ],
            fetch_enabled=False,
        )
        maven = [e for e in endpoints if e.ecosystem == "maven"]
        assert len(maven) == 2
        assert [e.priority for e in maven] == [0, 1]
        assert maven[0].url == "https://nexus.corp/repo"
        assert maven[1].url == "https://repo1.maven.org/maven2"
        npm = [e for e in endpoints if e.ecosystem == "npm"]
        assert len(npm) == 1
        assert npm[0].priority == 0
        assert all(e.source is IndexConfigSource.CLI for e in endpoints)
        assert not warnings

    @pytest.mark.requirement("FR-256")
    def test_missing_equals_emits_warning_not_failure(self):
        endpoints, warnings = resolve_indexes(
            cli_indexes=["malformed-no-equals"],
            fetch_enabled=False,
        )
        assert endpoints == []
        assert any("missing '='" in w for w in warnings)

    @pytest.mark.requirement("FR-256")
    @pytest.mark.requirement("SEC-NEW-66")
    @pytest.mark.parametrize(
        "bad",
        [
            "maven=http://insecure",
            "maven=ftp://insecure",
            "maven=file:///etc/passwd",
            "maven=https://user:pass@host/repo",
            "maven=https://",  # missing host
            "maven=not-a-url",
        ],
    )
    def test_https_only_and_no_userinfo(self, bad):
        endpoints, warnings = resolve_indexes(
            cli_indexes=[bad], fetch_enabled=False,
        )
        assert endpoints == []
        assert any("rejected" in w for w in warnings), warnings


# ── TA-327 — env vars + drop-under-fetch ────────────────────────────────────


class TestEnvParsing:
    @pytest.mark.requirement("FR-257")
    def test_env_var_per_ecosystem_space_separated(self, monkeypatch):
        monkeypatch.setenv(
            "SCARNO_INDEX_MAVEN",
            "https://nexus.corp/repo https://repo1.maven.org/maven2",
        )
        monkeypatch.setenv(
            "SCARNO_INDEX_NPM", "https://registry.npmjs.org"
        )
        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        maven = [e for e in endpoints if e.ecosystem == "maven"]
        assert len(maven) == 2
        assert [e.url for e in maven] == [
            "https://nexus.corp/repo",
            "https://repo1.maven.org/maven2",
        ]
        assert all(e.source is IndexConfigSource.ENV for e in endpoints)
        assert not warnings

    @pytest.mark.requirement("SEC-NEW-62")
    def test_env_dropped_when_fetch_enabled(self, monkeypatch):
        """The keystone CI-trust control: env-sourced indexes are
        dropped with a warning when ``--allow-remote-fetch`` is set."""
        monkeypatch.setenv(
            "SCARNO_INDEX_MAVEN", "https://attacker.example/repo",
        )
        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=True,
        )
        # No env-sourced endpoint survived.
        assert all(
            e.source is not IndexConfigSource.ENV for e in endpoints
        )
        # Warning explains why.
        assert any("dropped because --allow-remote-fetch" in w for w in warnings)
        assert any("SEC-NEW-62" in w for w in warnings)

    @pytest.mark.requirement("FR-257")
    def test_env_invalid_url_warned_not_silent(self, monkeypatch):
        monkeypatch.setenv(
            "SCARNO_INDEX_MAVEN", "http://insecure not-a-url",
        )
        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        assert endpoints == []
        # Two rejection warnings (one per bad URL).
        assert sum("rejected" in w for w in warnings) == 2


# ── TA-328 — user-config TOML via the SOLE locator ─────────────────────────


class TestUserConfigParsing:
    @pytest.mark.requirement("FR-258")
    def test_user_config_indexes_table(self, tmp_path, monkeypatch):
        """User-level ``~/.config/scarno/config.toml`` ``[indexes]``
        table is honoured. The locator is the ARCH-SEC-005 sole helper —
        already tested directly in TA-325; this test exercises the
        end-to-end resolver."""
        fake_home = tmp_path / "fake_home"
        cfg_dir = fake_home / ".config" / "scarno"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.toml").write_text(
            "[indexes]\n"
            'maven = ["https://nexus.corp/repo", "https://repo1.maven.org/maven2"]\n'
            'npm = ["https://registry.npmjs.org"]\n'
        )
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        maven = [e for e in endpoints if e.ecosystem == "maven"]
        assert [e.url for e in maven] == [
            "https://nexus.corp/repo",
            "https://repo1.maven.org/maven2",
        ]
        assert all(e.source is IndexConfigSource.USER_CONFIG for e in endpoints)
        assert not warnings

    @pytest.mark.requirement("FR-258")
    def test_user_config_malformed_toml_warned_not_failure(
        self, tmp_path, monkeypatch
    ):
        fake_home = tmp_path / "fake_home"
        cfg_dir = fake_home / ".config" / "scarno"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.toml").write_text("[indexes\n  bogus")
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        assert endpoints == []
        assert any("could not be parsed" in w for w in warnings)


# ── TA-329 — precedence (CLI > user-config > env) ──────────────────────────


class TestPrecedence:
    @pytest.mark.requirement("FR-259")
    def test_cli_overrides_user_config_for_same_ecosystem(
        self, tmp_path, monkeypatch
    ):
        # User config has Maven entries.
        fake_home = tmp_path / "fake_home"
        cfg_dir = fake_home / ".config" / "scarno"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.toml").write_text(
            "[indexes]\n"
            'maven = ["https://user-config-maven/repo"]\n'
        )
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        # CLI has Maven entries — must override entirely (not merge).
        endpoints, _ = resolve_indexes(
            cli_indexes=["maven=https://cli-maven/repo"],
            fetch_enabled=False,
        )
        maven = [e for e in endpoints if e.ecosystem == "maven"]
        assert len(maven) == 1
        assert maven[0].url == "https://cli-maven/repo"
        assert maven[0].source is IndexConfigSource.CLI

    @pytest.mark.requirement("FR-259")
    def test_user_config_overrides_env_for_same_ecosystem(
        self, tmp_path, monkeypatch
    ):
        fake_home = tmp_path / "fake_home"
        cfg_dir = fake_home / ".config" / "scarno"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.toml").write_text(
            "[indexes]\n"
            'maven = ["https://user-config-maven/repo"]\n'
        )
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setenv(
            "SCARNO_INDEX_MAVEN", "https://env-maven/repo"
        )
        endpoints, _ = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        maven = [e for e in endpoints if e.ecosystem == "maven"]
        assert len(maven) == 1
        assert maven[0].source is IndexConfigSource.USER_CONFIG

    @pytest.mark.requirement("FR-259")
    def test_per_ecosystem_override_not_global(
        self, tmp_path, monkeypatch
    ):
        """CLI mentioning ``maven`` doesn't suppress env's ``npm``."""
        monkeypatch.setenv(
            "SCARNO_INDEX_NPM", "https://registry.npmjs.org",
        )
        endpoints, _ = resolve_indexes(
            cli_indexes=["maven=https://cli-maven/repo"],
            fetch_enabled=False,
        )
        assert {e.ecosystem for e in endpoints} == {"maven", "npm"}
        npm = [e for e in endpoints if e.ecosystem == "npm"][0]
        assert npm.source is IndexConfigSource.ENV
        maven = [e for e in endpoints if e.ecosystem == "maven"][0]
        assert maven.source is IndexConfigSource.CLI


# ── TA-352 — IndexEndpoint reserved fields ─────────────────────────────────


class TestEndpointReservedFields:
    @pytest.mark.requirement("SEC-NEW-70")
    def test_credential_ref_reserved_field_exists_and_defaults_none(self):
        """v1 keeps the field unsettable from CLI/env/config (parsers
        never populate it) but the model carries it for the v2 auth
        layer. Verify shape so a v2 PR doesn't have to widen the
        dataclass and break call sites."""
        ep = IndexEndpoint(
            ecosystem="maven",
            url="https://repo.example/m2",
            priority=0,
            source=IndexConfigSource.CLI,
        )
        assert ep.credential_ref is None
        # And the field is settable when a future v2 layer wants to:
        ep2 = IndexEndpoint(
            ecosystem="maven",
            url="https://repo.example/m2",
            priority=0,
            source=IndexConfigSource.CLI,
            credential_ref="corp_nexus_token",
        )
        assert ep2.credential_ref == "corp_nexus_token"

    @pytest.mark.requirement("SEC-NEW-70")
    def test_coordinate_prefix_reserved_field_exists_and_defaults_none(self):
        ep = IndexEndpoint(
            ecosystem="maven",
            url="https://repo.example/m2",
            priority=0,
            source=IndexConfigSource.CLI,
        )
        assert ep.coordinate_prefix is None
        ep2 = IndexEndpoint(
            ecosystem="maven",
            url="https://nexus.corp/repo",
            priority=0,
            source=IndexConfigSource.USER_CONFIG,
            coordinate_prefix="com.corp.",
        )
        assert ep2.coordinate_prefix == "com.corp."


# ── PUC-007 — rejection warnings never carry a credentialed URL ────────────


_CREDENTIALED_URL = "https://ci-bot:glpat-SECRETTOKEN@nexus.corp/maven"
_SECRET_FRAGMENTS = ("ci-bot", "glpat-SECRETTOKEN")


class TestRejectionWarningsRedactCredentials:
    """Rejection warnings land in ``result.errors`` — the persistent
    report channel rendered into JSON / SARIF / Markdown / text. PUC-007
    forbids credentialed URLs there, so the validator must name only the
    redacted endpoint."""

    @pytest.mark.requirement("SEC-NEW-66")
    def test_validator_message_omits_userinfo(self):
        from scarno.indexing.resolver import _validate_url

        with pytest.raises(ValueError) as excinfo:
            _validate_url(_CREDENTIALED_URL)
        message = str(excinfo.value)
        assert "userinfo" in message
        for secret in _SECRET_FRAGMENTS:
            assert secret not in message
        # Still identifies which endpoint was rejected.
        assert "nexus.corp" in message

    @pytest.mark.requirement("SEC-NEW-66")
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("https://ci-bot:tok@nexus.corp/maven", "https://nexus.corp"),
            ("https://ci-bot:tok@nexus.corp/m?token=tok", "https://nexus.corp"),
            ("https://ci-bot:tok@nexus.corp:8443/m", "https://nexus.corp:8443"),
            ("http://ci-bot:tok@nexus.corp", "http://nexus.corp"),
            ("https://ci-bot:tok@nexus.corp:notaport/m", "<unparseable URL>"),
            ("https://", "<no host>"),
            ("not-a-url", "<no host>"),
        ],
    )
    def test_redaction_keeps_only_scheme_host_port(self, raw, expected):
        from scarno.indexing.resolver import _redact_url

        assert _redact_url(raw) == expected

    @pytest.mark.requirement("FR-257")
    def test_env_credentialed_url_not_echoed(self, monkeypatch):
        monkeypatch.setenv("SCARNO_INDEX_MAVEN", _CREDENTIALED_URL)
        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        assert endpoints == []
        assert any("rejected" in w for w in warnings), warnings
        joined = "\n".join(warnings)
        for secret in _SECRET_FRAGMENTS:
            assert secret not in joined, joined

    @pytest.mark.requirement("FR-258")
    def test_user_config_credentialed_url_not_echoed(
        self, tmp_path, monkeypatch
    ):
        fake_home = tmp_path / "fake_home"
        cfg_dir = fake_home / ".config" / "scarno"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.toml").write_text(
            "[indexes]\n" f'maven = ["{_CREDENTIALED_URL}"]\n'
        )
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        assert endpoints == []
        assert any("rejected" in w for w in warnings), warnings
        joined = "\n".join(warnings)
        for secret in _SECRET_FRAGMENTS:
            assert secret not in joined, joined


# ── PUC-007 — no credential reaches the report by any route ────────────────


_NFKC_AT_URL = "https://ci-bot:glpat-SECRETTOKEN＠nexus.corp/maven"   # U+FF20
_SMALL_AT_URL = "https://ci-bot:glpat-SECRETTOKEN﹫nexus.corp/maven"  # U+FE6B


class TestNfkcCredentialLeak:
    """``urlsplit`` normalises the netloc under NFKC before validating it,
    so a full-width or small commercial-at is not userinfo as far as the
    userinfo check is concerned — parsing raises instead, and urllib's
    exception quotes the offending netloc verbatim. Forwarding that
    exception text published a working password into the report.
    """

    @pytest.mark.requirement("SEC-NEW-66")
    @pytest.mark.parametrize("url", [_NFKC_AT_URL, _SMALL_AT_URL])
    def test_unparseable_message_withholds_the_value(self, url):
        from scarno.indexing.resolver import _validate_url

        with pytest.raises(ValueError) as excinfo:
            _validate_url(url)
        message = str(excinfo.value)
        for secret in _SECRET_FRAGMENTS:
            assert secret not in message, message
        assert "withheld" in message

    @pytest.mark.requirement("FR-257")
    @pytest.mark.parametrize("url", [_NFKC_AT_URL, _SMALL_AT_URL])
    def test_env_nfkc_url_not_echoed(self, monkeypatch, url):
        monkeypatch.setenv("SCARNO_INDEX_MAVEN", url)
        endpoints, warnings = resolve_indexes(
            cli_indexes=None, fetch_enabled=False,
        )
        assert endpoints == []
        joined = "\n".join(warnings)
        for secret in _SECRET_FRAGMENTS:
            assert secret not in joined, joined

    @pytest.mark.requirement("FR-256")
    @pytest.mark.parametrize("url", [_NFKC_AT_URL, _CREDENTIALED_URL])
    def test_cli_index_value_not_echoed(self, url):
        """The ``--index`` sites quoted the whole flag back, so the
        credential reached the report even when the validator's own
        message was clean."""
        endpoints, warnings = resolve_indexes(
            cli_indexes=[f"maven={url}"], fetch_enabled=False,
        )
        assert endpoints == []
        joined = "\n".join(warnings)
        for secret in _SECRET_FRAGMENTS:
            assert secret not in joined, joined
        assert "ci-bot" not in joined, joined


class TestRejectionsStayDiagnosable:
    """Withholding the value must not cost the operator the ability to
    tell WHICH index failed — several --index flags produce several
    warnings, and they have to be distinguishable."""

    @pytest.mark.requirement("FR-256")
    def test_each_bad_flag_is_identifiable_by_position_and_ecosystem(self):
        endpoints, warnings = resolve_indexes(
            cli_indexes=[
                "maven=https://good.example/m2",
                f"maven={_NFKC_AT_URL}",
                "maven=http://plain-http.example/m2",
                f"npm={_CREDENTIALED_URL}",
                "noequalssign",
            ],
            fetch_enabled=False,
        )
        assert [e.url for e in endpoints] == ["https://good.example/m2"]
        joined = "\n".join(warnings)
        # Position identifies the flag; ecosystem narrows it further.
        assert "#2 (maven)" in joined, joined
        assert "#3 (maven)" in joined, joined
        assert "#4 (npm)" in joined, joined
        assert "#5" in joined, joined
        # And the reason survives for each.
        assert "must use https" in joined
        assert "must not contain userinfo" in joined
        assert "missing '='" in joined

    @pytest.mark.requirement("FR-256")
    def test_parseable_rejections_still_name_the_host(self):
        """Withholding is only for values that would not parse. When a
        host can be extracted safely it is still shown, so the operator
        does not have to count flags."""
        _, warnings = resolve_indexes(
            cli_indexes=["maven=http://plain-http.example/m2"],
            fetch_enabled=False,
        )
        assert any("plain-http.example" in w for w in warnings), warnings
