"""Unit tests for the pure config-file renderers in bind9_setup."""
import bind9_setup as b


def make_cfg(**kw):
    cfg = b.Config(domain="dns.example.com", fwd1="8.8.8.8", fwd2="1.1.1.1")
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def test_options_includes_forwarders():
    out = b.render_named_conf_options(make_cfg())
    assert "8.8.8.8;" in out
    assert "1.1.1.1;" in out
    assert 'directory              "/var/cache/bind";' in out


def test_options_rpz_block_toggles():
    on = b.render_named_conf_options(make_cfg(use_rpz=True))
    off = b.render_named_conf_options(make_cfg(use_rpz=False))
    assert "response-policy" in on
    assert "response-policy" not in off


def test_options_stats_block_toggles():
    on = b.render_named_conf_options(make_cfg(use_stats=True))
    off = b.render_named_conf_options(make_cfg(use_stats=False))
    assert "statistics-channels" in on
    assert "port 8053" in on
    assert "statistics-channels" not in off


def test_options_doh_listener_toggles():
    on = b.render_named_conf_options(make_cfg(doh_enabled=True))
    off = b.render_named_conf_options(make_cfg(doh_enabled=False))
    assert "listen-on port 443" in on
    assert "listen-on port 443" not in off
    # DoT must always be present regardless of DoH.
    assert "port 853" in on
    assert "port 853" in off


def test_named_conf_local_rpz():
    assert "rpz.adblock" in b.render_named_conf_local(True)
    assert "No local zones" in b.render_named_conf_local(False)


def test_named_conf_includes():
    out = b.render_named_conf()
    for inc in ("named.conf.options", "named.conf.local",
                "named.conf.default-zones", "named.conf.logging"):
        assert inc in out


def test_rpz_service_uses_user_and_script():
    out = b.render_rpz_service("/etc/bind/update-rpz.sh", "bind")
    assert "User=bind" in out
    assert "ExecStart=/etc/bind/update-rpz.sh" in out
    assert "Type=oneshot" in out


def test_rpz_timer_oncalendar():
    out = b.render_rpz_timer("*-*-* 04:00:00")
    assert "OnCalendar=*-*-* 04:00:00" in out
    assert "RandomizedDelaySec=300" in out


def test_named_override_prefix():
    out = b.render_named_override("/usr/local")
    assert "/usr/local/sbin/named" in out
    assert out.count("ExecStart=") == 2  # reset + new value


def test_deploy_hook_embeds_rndc():
    out = b.render_deploy_hook("/usr/local/sbin/rndc")
    assert "/usr/local/sbin/rndc" in out
    assert "reconfig" in out


def test_logrotate_embeds_rndc():
    out = b.render_logrotate("/usr/sbin/rndc")
    assert "/usr/sbin/rndc reopen" in out


def test_ssl_path_derived_from_bind_dir():
    cfg = make_cfg(bind_dir="/custom/bind")
    assert cfg.bind_ssl == "/custom/bind/ssl"
