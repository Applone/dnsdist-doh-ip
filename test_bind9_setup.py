#!/usr/bin/env python3
"""Comprehensive unit tests for bind9_setup.py.

Every OS-level operation is mocked so tests can run safely without root.
"""
from __future__ import annotations

import textwrap
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import bind9_setup
from bind9_setup import (
    BIND_VERSION_FALLBACK,
    Config,
    SetupError,
    atomic_write,
    backup_config,
    build_argparser,
    compare_versions,
    detect_bind_user,
    fetch_bind_versions,
    generate_certbot_hook,
    generate_logrotate_config,
    generate_named_conf,
    generate_named_conf_local,
    generate_named_conf_logging,
    generate_named_conf_options,
    generate_named_override,
    generate_rpz_service,
    generate_rpz_timer,
    generate_rpz_update_script,
    parse_bind_version,
    resolve_binary,
)


# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def basic_config() -> Config:
    """A minimal Config with defaults — no RPZ, no stats, DoH off."""
    return Config(
        domain="dns.example.com",
        fwd1="8.8.8.8",
        fwd2="1.1.1.1",
        use_rpz=False,
        use_stats=False,
        doh_enabled=False,
    )


@pytest.fixture
def full_config() -> Config:
    """A Config with every feature turned on."""
    return Config(
        domain="dns.example.com",
        fwd1="9.9.9.9",
        fwd2="149.112.112.112",
        use_rpz=True,
        rpz_timer="6h",
        use_stats=True,
        doh_enabled=True,
        bind_user="bind",
        bind_ssl_dir=Path("/etc/bind/ssl"),
    )


@pytest.fixture
def rpz_only_config() -> Config:
    """Config with RPZ enabled but stats and DoH disabled."""
    return Config(
        domain="dns.example.com",
        use_rpz=True,
        rpz_timer="6h",
        use_stats=False,
        doh_enabled=False,
    )


@pytest.fixture
def stats_only_config() -> Config:
    """Config with stats enabled but RPZ and DoH disabled."""
    return Config(
        domain="dns.example.com",
        use_rpz=False,
        use_stats=True,
        doh_enabled=False,
    )


@pytest.fixture
def doh_only_config() -> Config:
    """Config with DoH enabled but RPZ and stats disabled."""
    return Config(
        domain="dns.example.com",
        use_rpz=False,
        use_stats=False,
        doh_enabled=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1. parse_bind_version
# ═══════════════════════════════════════════════════════════════════════════


class TestParseBindVersion:
    def test_parse_bind_version_standard_string(self) -> None:
        result = parse_bind_version(
            "BIND 9.18.24-1ubuntu1 (Extended Support Version)"
        )
        assert result == (9, 18)

    def test_parse_bind_version_with_patch_level(self) -> None:
        result = parse_bind_version("BIND 9.20.7")
        assert result == (9, 20)

    def test_parse_bind_version_with_extra_text(self) -> None:
        result = parse_bind_version(
            "BIND 9.16.48 (Stable Release) -- built with GCC 12"
        )
        assert result == (9, 16)

    def test_parse_bind_version_just_bind_prefix(self) -> None:
        result = parse_bind_version("BIND 10.0")
        assert result == (10, 0)

    def test_parse_bind_version_empty_string_raises(self) -> None:
        with pytest.raises(SetupError, match="Cannot parse BIND version"):
            parse_bind_version("")

    def test_parse_bind_version_no_bind_prefix_raises(self) -> None:
        with pytest.raises(SetupError, match="Cannot parse BIND version"):
            parse_bind_version("9.18.24-1ubuntu1")

    def test_parse_bind_version_garbage_raises(self) -> None:
        with pytest.raises(SetupError, match="Cannot parse BIND version"):
            parse_bind_version("not a version at all")

    def test_parse_bind_version_partial_bind_raises(self) -> None:
        with pytest.raises(SetupError, match="Cannot parse BIND version"):
            parse_bind_version("BIND abc.def")


# ═══════════════════════════════════════════════════════════════════════════
# 2. fetch_bind_versions
# ═══════════════════════════════════════════════════════════════════════════


class TestFetchBindVersions:
    def _mock_urlopen(self, html_content: str) -> MagicMock:
        """Create a mock urlopen context manager returning the given HTML."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = html_content.encode("utf-8")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_fetch_versions_parses_html_correctly(self) -> None:
        html = textwrap.dedent("""\
            <html><body>
            <a href="9.18.33/">9.18.33/</a>
            <a href="9.20.7/">9.20.7/</a>
            <a href="9.16.50/">9.16.50/</a>
            </body></html>
        """)
        with patch("bind9_setup.urlopen", return_value=self._mock_urlopen(html)):
            versions = fetch_bind_versions()
        assert versions == ["9.20.7", "9.18.33", "9.16.50"]

    def test_fetch_versions_sorted_newest_first(self) -> None:
        html = '<a href="9.16.1/">9.16.1/</a><a href="9.20.2/">9.20.2/</a><a href="9.18.5/">9.18.5/</a>'
        with patch("bind9_setup.urlopen", return_value=self._mock_urlopen(html)):
            versions = fetch_bind_versions()
        assert versions[0] == "9.20.2"
        assert versions[-1] == "9.16.1"

    def test_fetch_versions_network_failure_returns_fallback(self) -> None:
        with patch(
            "bind9_setup.urlopen",
            side_effect=urllib.error.URLError("timeout"),
        ):
            versions = fetch_bind_versions()
        assert versions == BIND_VERSION_FALLBACK

    def test_fetch_versions_empty_html_returns_fallback(self) -> None:
        with patch(
            "bind9_setup.urlopen",
            return_value=self._mock_urlopen("<html><body></body></html>"),
        ):
            versions = fetch_bind_versions()
        assert versions == BIND_VERSION_FALLBACK

    def test_fetch_versions_excludes_prerelease(self) -> None:
        html = (
            '<a href="9.20.7/">9.20.7/</a>'
            '<a href="9.19.0rc1/">9.19.0rc1/</a>'
            '<a href="9.18.33/">9.18.33/</a>'
        )
        with patch("bind9_setup.urlopen", return_value=self._mock_urlopen(html)):
            versions = fetch_bind_versions()
        assert "9.19.0rc1" not in versions
        assert "9.20.7" in versions
        assert "9.18.33" in versions

    def test_fetch_versions_deduplication(self) -> None:
        html = (
            '<a href="9.20.7/">9.20.7/</a>'
            '<a href="9.20.7/">9.20.7/</a>'
            '<a href="9.18.33/">9.18.33/</a>'
        )
        with patch("bind9_setup.urlopen", return_value=self._mock_urlopen(html)):
            versions = fetch_bind_versions()
        assert versions.count("9.20.7") == 1

    def test_fetch_versions_oserror_returns_fallback(self) -> None:
        with patch(
            "bind9_setup.urlopen",
            side_effect=OSError("connection refused"),
        ):
            versions = fetch_bind_versions()
        assert versions == BIND_VERSION_FALLBACK


# ═══════════════════════════════════════════════════════════════════════════
# 3. generate_named_conf_options
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateNamedConfOptions:
    def test_basic_config_no_rpz_no_stats_no_doh(self, basic_config: Config) -> None:
        output = generate_named_conf_options(basic_config)
        assert "forwarders" in output
        assert "8.8.8.8" in output
        assert "1.1.1.1" in output
        assert "response-policy" not in output
        assert "statistics-channels" not in output
        assert "port 443" not in output

    def test_rpz_enabled(self, rpz_only_config: Config) -> None:
        output = generate_named_conf_options(rpz_only_config)
        assert "response-policy" in output

    def test_stats_enabled(self, stats_only_config: Config) -> None:
        output = generate_named_conf_options(stats_only_config)
        assert "statistics-channels" in output
        assert "127.0.0.1 port 8053" in output

    def test_doh_enabled(self, doh_only_config: Config) -> None:
        output = generate_named_conf_options(doh_only_config)
        assert "port 443" in output

    def test_all_features_enabled(self, full_config: Config) -> None:
        output = generate_named_conf_options(full_config)
        assert "response-policy" in output
        assert "statistics-channels" in output
        assert "port 443" in output

    def test_forwarder_ips_appear(self, full_config: Config) -> None:
        output = generate_named_conf_options(full_config)
        assert "9.9.9.9" in output
        assert "149.112.112.112" in output

    def test_tls_cert_paths_appear(self, full_config: Config) -> None:
        output = generate_named_conf_options(full_config)
        assert "cert.pem" in output
        assert "key.pem" in output

    def test_contains_options_block(self, basic_config: Config) -> None:
        output = generate_named_conf_options(basic_config)
        assert "options {" in output or "options{" in output

    def test_contains_tls_block_when_domain_set(self, basic_config: Config) -> None:
        output = generate_named_conf_options(basic_config)
        assert "tls local-tls" in output

    def test_dot_listener_always_present(self, basic_config: Config) -> None:
        output = generate_named_conf_options(basic_config)
        assert "port 853" in output

    def test_dnssec_validation_present(self, basic_config: Config) -> None:
        output = generate_named_conf_options(basic_config)
        assert "dnssec-validation auto" in output


# ═══════════════════════════════════════════════════════════════════════════
# 4. generate_named_conf_logging
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateNamedConfLogging:
    def test_contains_logging_block(self) -> None:
        output = generate_named_conf_logging()
        assert "logging {" in output

    def test_contains_default_log_channel(self) -> None:
        output = generate_named_conf_logging()
        assert "default_log" in output

    def test_contains_log_file_path(self) -> None:
        output = generate_named_conf_logging()
        assert "/var/log/named/named.log" in output

    def test_contains_severity(self) -> None:
        output = generate_named_conf_logging()
        assert "severity" in output

    def test_contains_category_default(self) -> None:
        output = generate_named_conf_logging()
        assert "category default" in output


# ═══════════════════════════════════════════════════════════════════════════
# 5. generate_named_conf_local
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateNamedConfLocal:
    def test_rpz_true_contains_zone(self) -> None:
        output = generate_named_conf_local(use_rpz=True)
        assert 'zone "rpz.local"' in output
        assert "type master" in output

    def test_rpz_false_contains_comment_only(self) -> None:
        output = generate_named_conf_local(use_rpz=False)
        assert "RPZ disabled" in output
        # The zone definition should be commented out
        for line in output.splitlines():
            stripped = line.strip()
            if "zone" in stripped and "rpz" in stripped:
                assert stripped.startswith("//"), f"Zone line not commented: {stripped}"


# ═══════════════════════════════════════════════════════════════════════════
# 6. generate_named_conf
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateNamedConf:
    def test_contains_all_four_includes(self) -> None:
        output = generate_named_conf()
        expected_includes = [
            "named.conf.options",
            "named.conf.logging",
            "named.conf.local",
            "named.conf.default-zones",
        ]
        for inc in expected_includes:
            assert inc in output, f"Missing include: {inc}"

    def test_has_exactly_four_include_lines(self) -> None:
        output = generate_named_conf()
        include_lines = [
            line
            for line in output.strip().splitlines()
            if line.strip().startswith("include")
        ]
        assert len(include_lines) == 4


# ═══════════════════════════════════════════════════════════════════════════
# 7. generate_rpz_update_script
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateRpzUpdateScript:
    def test_contains_shebang(self) -> None:
        output = generate_rpz_update_script()
        assert output.lstrip().startswith("#!/")

    def test_contains_blocklist_url(self) -> None:
        output = generate_rpz_update_script()
        # Should contain at least one blocklist URL
        assert "http" in output

    def test_contains_named_compilezone(self) -> None:
        output = generate_rpz_update_script()
        assert "named-compilezone" in output or "named_compilezone" in output

    def test_contains_rndc_reload(self) -> None:
        output = generate_rpz_update_script()
        assert "rndc" in output
        assert "reload" in output

    def test_contains_set_euo_pipefail(self) -> None:
        output = generate_rpz_update_script()
        assert "set -euo pipefail" in output

    def test_contains_cleanup_trap(self) -> None:
        output = generate_rpz_update_script()
        assert "trap cleanup EXIT" in output


# ═══════════════════════════════════════════════════════════════════════════
# 8. generate_rpz_service
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateRpzService:
    def test_contains_unit_section(self, full_config: Config) -> None:
        output = generate_rpz_service(full_config)
        assert "[Unit]" in output

    def test_contains_service_section(self, full_config: Config) -> None:
        output = generate_rpz_service(full_config)
        assert "[Service]" in output

    def test_contains_execstart(self, full_config: Config) -> None:
        output = generate_rpz_service(full_config)
        assert "ExecStart=" in output

    def test_contains_type_oneshot(self, full_config: Config) -> None:
        output = generate_rpz_service(full_config)
        assert "Type=oneshot" in output

    def test_contains_after_named(self, full_config: Config) -> None:
        output = generate_rpz_service(full_config)
        assert "named.service" in output


# ═══════════════════════════════════════════════════════════════════════════
# 9. generate_rpz_timer
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateRpzTimer:
    def test_contains_timer_section(self, full_config: Config) -> None:
        output = generate_rpz_timer(full_config)
        assert "[Timer]" in output

    def test_contains_timer_value(self, full_config: Config) -> None:
        output = generate_rpz_timer(full_config)
        # The timer value should appear somewhere in the output
        assert full_config.rpz_timer in output

    def test_contains_randomized_delay(self, full_config: Config) -> None:
        output = generate_rpz_timer(full_config)
        assert "RandomizedDelaySec" in output

    def test_contains_install_section(self, full_config: Config) -> None:
        output = generate_rpz_timer(full_config)
        assert "[Install]" in output
        assert "WantedBy=timers.target" in output

    def test_contains_persistent(self, full_config: Config) -> None:
        output = generate_rpz_timer(full_config)
        assert "Persistent=true" in output


# ═══════════════════════════════════════════════════════════════════════════
# 10. generate_certbot_hook
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateCertbotHook:
    def test_contains_shebang(self) -> None:
        output = generate_certbot_hook("/usr/sbin/rndc")
        assert output.lstrip().startswith("#!/")

    def test_contains_rndc_bin_path(self) -> None:
        output = generate_certbot_hook("/usr/local/sbin/rndc")
        assert "/usr/local/sbin/rndc" in output

    def test_contains_cert_copy_commands(self) -> None:
        output = generate_certbot_hook("/usr/sbin/rndc")
        assert "cp" in output
        assert "cert.pem" in output or "fullchain.pem" in output
        assert "key.pem" in output or "privkey.pem" in output

    def test_contains_reload(self) -> None:
        output = generate_certbot_hook("/usr/sbin/rndc")
        assert "reload" in output


# ═══════════════════════════════════════════════════════════════════════════
# 11. generate_logrotate_config
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateLogrotateConfig:
    def test_contains_log_file_path(self) -> None:
        output = generate_logrotate_config("/usr/sbin/rndc")
        assert "/var/log/named/named.log" in output

    def test_contains_rndc_bin_path(self) -> None:
        output = generate_logrotate_config("/usr/local/sbin/rndc")
        assert "/usr/local/sbin/rndc" in output

    def test_contains_postrotate(self) -> None:
        output = generate_logrotate_config("/usr/sbin/rndc")
        assert "postrotate" in output

    def test_contains_compress(self) -> None:
        output = generate_logrotate_config("/usr/sbin/rndc")
        assert "compress" in output

    def test_contains_weekly(self) -> None:
        output = generate_logrotate_config("/usr/sbin/rndc")
        assert "weekly" in output

    def test_contains_rotate(self) -> None:
        output = generate_logrotate_config("/usr/sbin/rndc")
        assert "rotate" in output


# ═══════════════════════════════════════════════════════════════════════════
# 12. atomic_write
# ═══════════════════════════════════════════════════════════════════════════


class TestAtomicWrite:
    @patch("bind9_setup.os.replace")
    @patch("bind9_setup.os.close")
    @patch("bind9_setup.os.fchmod")
    @patch("bind9_setup.os.write")
    @patch("bind9_setup.tempfile.mkstemp")
    @patch("bind9_setup.Path.mkdir")
    def test_tempfile_created_in_same_directory(
        self,
        mock_mkdir: MagicMock,
        mock_mkstemp: MagicMock,
        mock_write: MagicMock,
        mock_fchmod: MagicMock,
        mock_close: MagicMock,
        mock_replace: MagicMock,
    ) -> None:
        mock_mkstemp.return_value = (42, "/etc/bind/.named.conf.abcdef")
        atomic_write(Path("/etc/bind/named.conf"), "content")
        mock_mkstemp.assert_called_once()
        call_kwargs = mock_mkstemp.call_args
        assert "dir" in call_kwargs.kwargs or len(call_kwargs.args) == 0
        # Verify dir= is the parent directory of the target
        dir_arg = call_kwargs.kwargs.get("dir") or call_kwargs[1].get("dir")
        assert dir_arg == "/etc/bind" or dir_arg == str(Path("/etc/bind"))

    @patch("bind9_setup.os.replace")
    @patch("bind9_setup.os.close")
    @patch("bind9_setup.os.fchmod")
    @patch("bind9_setup.os.write")
    @patch("bind9_setup.tempfile.mkstemp")
    @patch("bind9_setup.Path.mkdir")
    def test_os_replace_is_called(
        self,
        mock_mkdir: MagicMock,
        mock_mkstemp: MagicMock,
        mock_write: MagicMock,
        mock_fchmod: MagicMock,
        mock_close: MagicMock,
        mock_replace: MagicMock,
    ) -> None:
        mock_mkstemp.return_value = (42, "/etc/bind/.named.conf.abcdef")
        atomic_write(Path("/etc/bind/named.conf"), "content")
        mock_replace.assert_called_once_with(
            "/etc/bind/.named.conf.abcdef", "/etc/bind/named.conf"
        )

    @patch("bind9_setup.os.replace")
    @patch("bind9_setup.os.close")
    @patch("bind9_setup.os.fchmod")
    @patch("bind9_setup.os.write")
    @patch("bind9_setup.tempfile.mkstemp")
    @patch("bind9_setup.Path.mkdir")
    def test_permissions_are_set(
        self,
        mock_mkdir: MagicMock,
        mock_mkstemp: MagicMock,
        mock_write: MagicMock,
        mock_fchmod: MagicMock,
        mock_close: MagicMock,
        mock_replace: MagicMock,
    ) -> None:
        mock_mkstemp.return_value = (42, "/etc/bind/.named.conf.abcdef")
        atomic_write(Path("/etc/bind/named.conf"), "content", mode=0o600)
        mock_fchmod.assert_called_once_with(42, 0o600)

    @patch("bind9_setup.os.fchown")
    @patch("bind9_setup._uid_gid", return_value=(113, 117))
    @patch("bind9_setup.os.replace")
    @patch("bind9_setup.os.close")
    @patch("bind9_setup.os.fchmod")
    @patch("bind9_setup.os.write")
    @patch("bind9_setup.tempfile.mkstemp")
    @patch("bind9_setup.Path.mkdir")
    def test_ownership_set_when_provided(
        self,
        mock_mkdir: MagicMock,
        mock_mkstemp: MagicMock,
        mock_write: MagicMock,
        mock_fchmod: MagicMock,
        mock_close: MagicMock,
        mock_replace: MagicMock,
        mock_uid_gid: MagicMock,
        mock_fchown: MagicMock,
    ) -> None:
        mock_mkstemp.return_value = (42, "/etc/bind/.named.conf.abcdef")
        atomic_write(
            Path("/etc/bind/named.conf"),
            "content",
            owner="bind",
            group="bind",
        )
        mock_fchown.assert_called_once_with(42, 113, 117)

    @patch("bind9_setup.Path.unlink")
    @patch("bind9_setup.os.get_inheritable", return_value=False)
    @patch("bind9_setup.os.close")
    @patch("bind9_setup.os.write", side_effect=OSError("disk full"))
    @patch("bind9_setup.tempfile.mkstemp")
    @patch("bind9_setup.Path.mkdir")
    def test_cleanup_on_failure(
        self,
        mock_mkdir: MagicMock,
        mock_mkstemp: MagicMock,
        mock_write: MagicMock,
        mock_close: MagicMock,
        mock_get_inheritable: MagicMock,
        mock_unlink: MagicMock,
    ) -> None:
        mock_mkstemp.return_value = (42, "/etc/bind/.named.conf.abcdef")
        with pytest.raises(OSError, match="disk full"):
            atomic_write(Path("/etc/bind/named.conf"), "content")

    @patch("bind9_setup.os.replace")
    @patch("bind9_setup.os.close")
    @patch("bind9_setup.os.fchmod")
    @patch("bind9_setup.os.write")
    @patch("bind9_setup.tempfile.mkstemp")
    @patch("bind9_setup.Path.mkdir")
    def test_default_permissions_644(
        self,
        mock_mkdir: MagicMock,
        mock_mkstemp: MagicMock,
        mock_write: MagicMock,
        mock_fchmod: MagicMock,
        mock_close: MagicMock,
        mock_replace: MagicMock,
    ) -> None:
        mock_mkstemp.return_value = (42, "/tmp/.test.abc")
        atomic_write(Path("/tmp/test.txt"), "hello")
        mock_fchmod.assert_called_once_with(42, 0o644)

    @patch("bind9_setup.os.replace")
    @patch("bind9_setup.os.close")
    @patch("bind9_setup.os.fchmod")
    @patch("bind9_setup.os.write")
    @patch("bind9_setup.tempfile.mkstemp")
    @patch("bind9_setup.Path.mkdir")
    def test_content_written_as_bytes(
        self,
        mock_mkdir: MagicMock,
        mock_mkstemp: MagicMock,
        mock_write: MagicMock,
        mock_fchmod: MagicMock,
        mock_close: MagicMock,
        mock_replace: MagicMock,
    ) -> None:
        mock_mkstemp.return_value = (42, "/tmp/.test.abc")
        atomic_write(Path("/tmp/test.txt"), "hëllo wörld")
        mock_write.assert_called_once_with(42, "hëllo wörld".encode())


# ═══════════════════════════════════════════════════════════════════════════
# 13. backup_config
# ═══════════════════════════════════════════════════════════════════════════


class TestBackupConfig:
    @patch("bind9_setup.shutil.copy2")
    @patch("bind9_setup.time.strftime", return_value="20240101120000")
    def test_existing_file_creates_backup(
        self,
        mock_strftime: MagicMock,
        mock_copy2: MagicMock,
        tmp_path: Path,
    ) -> None:
        source = tmp_path / "named.conf"
        source.write_text("test config")
        backup_config(source)
        expected_backup = source.with_suffix(".conf.bak.20240101120000")
        mock_copy2.assert_called_once_with(source, expected_backup)

    def test_nonexistent_file_is_noop(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist.conf"
        # Should not raise, just silently return
        backup_config(missing)

    @patch("bind9_setup.shutil.copy2")
    @patch("bind9_setup.time.strftime", return_value="20240101120000")
    def test_backup_preserves_suffix(
        self,
        mock_strftime: MagicMock,
        mock_copy2: MagicMock,
        tmp_path: Path,
    ) -> None:
        source = tmp_path / "named.conf.options"
        source.write_text("options")
        backup_config(source)
        assert mock_copy2.called
        backup_target = mock_copy2.call_args[0][1]
        assert ".bak.20240101120000" in str(backup_target)


# ═══════════════════════════════════════════════════════════════════════════
# 14. resolve_binary
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveBinary:
    @patch("bind9_setup.shutil.which", return_value="/usr/bin/rndc")
    def test_which_finds_binary(self, mock_which: MagicMock) -> None:
        result = resolve_binary("rndc")
        assert result == "/usr/bin/rndc"
        mock_which.assert_called_once_with("rndc")

    @patch("bind9_setup.os.access", return_value=False)
    @patch("bind9_setup.Path.is_file", return_value=False)
    @patch("bind9_setup.shutil.which", return_value=None)
    def test_which_not_found_returns_bare_name(
        self,
        mock_which: MagicMock,
        mock_is_file: MagicMock,
        mock_access: MagicMock,
    ) -> None:
        result = resolve_binary("rndc")
        # When nothing is found, should return the bare name
        assert "rndc" in result

    @patch("bind9_setup.shutil.which", return_value="/opt/bind/sbin/named-compilezone")
    def test_which_finds_custom_path(self, mock_which: MagicMock) -> None:
        result = resolve_binary("named-compilezone")
        assert result == "/opt/bind/sbin/named-compilezone"


# ═══════════════════════════════════════════════════════════════════════════
# 15. detect_bind_user
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectBindUser:
    @patch("bind9_setup.pwd.getpwnam")
    def test_named_user_exists(self, mock_getpwnam: MagicMock) -> None:
        # First call for "named" succeeds
        mock_getpwnam.return_value = MagicMock()
        result = detect_bind_user()
        assert result == "named"
        mock_getpwnam.assert_called_with("named")

    @patch("bind9_setup.pwd.getpwnam")
    def test_named_not_found_tries_bind(self, mock_getpwnam: MagicMock) -> None:
        # "named" raises KeyError, "bind" succeeds
        def side_effect(name: str) -> MagicMock:
            if name == "named":
                raise KeyError("named")
            return MagicMock()

        mock_getpwnam.side_effect = side_effect
        result = detect_bind_user()
        assert result == "bind"

    @patch("bind9_setup.pwd.getpwnam", side_effect=KeyError("not found"))
    def test_neither_found_returns_bind(self, mock_getpwnam: MagicMock) -> None:
        result = detect_bind_user()
        assert result == "bind"


# ═══════════════════════════════════════════════════════════════════════════
# 16. Config dataclass
# ═══════════════════════════════════════════════════════════════════════════


class TestConfigDataclass:
    def test_creation_with_defaults(self) -> None:
        config = Config()
        assert config.domain == ""

    def test_default_fwd1(self) -> None:
        config = Config()
        assert config.fwd1 == bind9_setup.DEFAULT_FWD1

    def test_default_fwd2(self) -> None:
        config = Config()
        assert config.fwd2 == bind9_setup.DEFAULT_FWD2

    def test_default_use_rpz(self) -> None:
        config = Config()
        assert config.use_rpz is True

    def test_default_rpz_timer(self) -> None:
        config = Config()
        assert config.rpz_timer == bind9_setup.DEFAULT_RPZ_TIMER

    def test_default_use_stats(self) -> None:
        config = Config()
        assert config.use_stats is False

    def test_default_install_mode(self) -> None:
        config = Config()
        assert config.install_mode == "apt"

    def test_default_bind_prefix(self) -> None:
        config = Config()
        assert config.bind_prefix == bind9_setup.DEFAULT_BIND_PREFIX

    def test_default_doh_enabled(self) -> None:
        config = Config()
        assert config.doh_enabled is False

    def test_default_bind_user(self) -> None:
        config = Config()
        assert config.bind_user == "bind"

    def test_custom_values_override_defaults(self) -> None:
        config = Config(
            domain="custom.dns.example.org",
            fwd1="4.4.4.4",
            fwd2="4.4.8.8",
            use_rpz=False,
            rpz_timer="12h",
            use_stats=True,
            install_mode="source",
            bind_version="9.20.7",
            bind_prefix="/usr/local",
            doh_enabled=True,
            bind_user="named",
        )
        assert config.domain == "custom.dns.example.org"
        assert config.fwd1 == "4.4.4.4"
        assert config.fwd2 == "4.4.8.8"
        assert config.use_rpz is False
        assert config.rpz_timer == "12h"
        assert config.use_stats is True
        assert config.install_mode == "source"
        assert config.bind_version == "9.20.7"
        assert config.bind_prefix == "/usr/local"
        assert config.doh_enabled is True
        assert config.bind_user == "named"

    def test_bind_dir_default(self) -> None:
        config = Config()
        assert config.bind_dir == Path("/etc/bind")

    def test_bind_ssl_dir_default(self) -> None:
        config = Config()
        assert config.bind_ssl_dir == Path("/etc/bind/ssl")


# ═══════════════════════════════════════════════════════════════════════════
# 17. Argument parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestArgumentParsing:
    def test_non_interactive_flag(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--non-interactive", "--domain", "dns.example.com"])
        assert args.domain == "dns.example.com"
        assert args.non_interactive is True

    def test_default_values(self) -> None:
        parser = build_argparser()
        args = parser.parse_args([])
        assert args.domain is None
        assert args.fwd1 is None
        assert args.fwd2 is None
        assert args.rpz is None
        assert args.stats is None
        assert args.non_interactive is False

    def test_domain_flag(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--domain", "dns.example.com"])
        assert args.domain == "dns.example.com"

    def test_rpz_flag_true(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--rpz", "true"])
        assert args.rpz is True

    def test_rpz_flag_false(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--rpz", "false"])
        assert args.rpz is False

    def test_stats_flag_true(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--stats", "true"])
        assert args.stats is True

    def test_install_mode_source(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--install-mode", "source"])
        assert args.install_mode == "source"

    def test_install_mode_apt(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--install-mode", "apt"])
        assert args.install_mode == "apt"

    def test_bind_version(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--bind-version", "9.20.7"])
        assert args.bind_version == "9.20.7"

    def test_bind_prefix(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--bind-prefix", "/usr/local"])
        assert args.bind_prefix == "/usr/local"

    def test_skip_certbot_flag(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--skip-certbot"])
        assert args.skip_certbot is True

    def test_skip_firewall_flag(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--skip-firewall"])
        assert args.skip_firewall is True

    def test_debug_flag(self) -> None:
        parser = build_argparser()
        args = parser.parse_args(["--debug"])
        assert args.debug is True


# ═══════════════════════════════════════════════════════════════════════════
# 18. compare_versions
# ═══════════════════════════════════════════════════════════════════════════


class TestCompareVersions:
    def test_greater_version(self) -> None:
        assert compare_versions("9.20.7", "9.18.33") == 1

    def test_lesser_version(self) -> None:
        assert compare_versions("9.18.33", "9.20.7") == -1

    def test_equal_version(self) -> None:
        assert compare_versions("9.18.33", "9.18.33") == 0

    def test_major_version_difference(self) -> None:
        assert compare_versions("10.0.0", "9.20.7") == 1

    def test_patch_level_difference(self) -> None:
        assert compare_versions("9.18.34", "9.18.33") == 1

    def test_two_part_versions(self) -> None:
        assert compare_versions("9.20", "9.18") == 1

    def test_four_part_versions(self) -> None:
        assert compare_versions("9.18.33.1", "9.18.33.0") == 1


# ═══════════════════════════════════════════════════════════════════════════
# 19. generate_named_override
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateNamedOverride:
    def test_contains_service_section(self) -> None:
        output = generate_named_override("/usr/local")
        assert "[Service]" in output

    def test_contains_execstart_with_prefix_path(self) -> None:
        output = generate_named_override("/usr/local")
        assert "/usr/local/sbin/named" in output

    def test_contains_execstart_reset(self) -> None:
        output = generate_named_override("/usr/local")
        lines = output.splitlines()
        # There should be an empty ExecStart= line (reset)
        execstart_lines = [line.strip() for line in lines if "ExecStart" in line]
        assert any(line == "ExecStart=" for line in execstart_lines)

    def test_default_prefix(self) -> None:
        output = generate_named_override("/usr")
        assert "/usr/sbin/named" in output

    def test_custom_prefix(self) -> None:
        output = generate_named_override("/opt/bind9")
        assert "/opt/bind9/sbin/named" in output


# ═══════════════════════════════════════════════════════════════════════════
# Additional edge-case and integration-style tests
# ═══════════════════════════════════════════════════════════════════════════


class TestSetupErrorException:
    def test_setup_error_is_exception(self) -> None:
        assert issubclass(SetupError, Exception)

    def test_setup_error_can_be_raised(self) -> None:
        with pytest.raises(SetupError, match="test error"):
            raise SetupError("test error")


class TestBindVersionFallback:
    def test_fallback_is_list(self) -> None:
        assert isinstance(BIND_VERSION_FALLBACK, list)

    def test_fallback_contains_versions(self) -> None:
        assert len(BIND_VERSION_FALLBACK) >= 2

    def test_fallback_versions_are_valid(self) -> None:
        for v in BIND_VERSION_FALLBACK:
            parts = v.split(".")
            assert len(parts) == 3, f"Invalid version format: {v}"
            for p in parts:
                assert p.isdigit(), f"Non-numeric component in version: {v}"


class TestGenerateNamedConfOptionsEdgeCases:
    def test_ipv6_forwarder(self) -> None:
        config = Config(
            domain="dns.example.com",
            fwd1="2001:4860:4860::8888",
            fwd2="2001:4860:4860::8844",
        )
        output = generate_named_conf_options(config)
        assert "2001:4860:4860::8888" in output
        assert "2001:4860:4860::8844" in output

    def test_recursion_present(self) -> None:
        config = Config(domain="dns.example.com")
        output = generate_named_conf_options(config)
        assert "recursion yes" in output

    def test_listen_on_port_53(self) -> None:
        config = Config(domain="dns.example.com")
        output = generate_named_conf_options(config)
        assert "port 53" in output
