"""Unit tests for the async subprocess and network helpers in bind9_setup."""
import asyncio

import bind9_setup as b


def run(coro):
    return asyncio.run(coro)


def test_run_captures_output():
    code, out = run(b.run("echo", "hello", capture=True))
    assert code == 0
    assert out.strip() == "hello"


def test_run_check_raises_on_failure():
    try:
        run(b.run("false", check=True))
    except b.CommandError as e:
        assert e.code != 0
    else:
        raise AssertionError("CommandError not raised")


def test_run_no_check_returns_code():
    code, _ = run(b.run("false", check=False))
    assert code != 0


def test_run_ok_true_false():
    assert run(b.run_ok("true")) is True
    assert run(b.run_ok("false")) is False


def test_run_ok_missing_binary():
    assert run(b.run_ok("definitely-not-a-real-binary-xyz")) is False


def test_fetch_bind_versions_offline_fallback(monkeypatch):
    async def boom(*a, **k):
        raise OSError("offline")

    monkeypatch.setattr(b, "http_get_text", boom)
    versions, online = run(b.fetch_bind_versions())
    assert online is False
    assert versions == b.BIND_VERSION_FALLBACK


def test_fetch_bind_versions_online(monkeypatch):
    async def fake(*a, **k):
        return '9.20.7/ 9.18.33/'

    monkeypatch.setattr(b, "http_get_text", fake)
    versions, online = run(b.fetch_bind_versions())
    assert online is True
    assert versions == ["9.20.7", "9.18.33"]


def test_concurrent_runs_overlap():
    # Two 0.3s sleeps run concurrently should finish in well under 0.6s.
    async def go():
        await asyncio.gather(
            b.run("sleep", "0.3"),
            b.run("sleep", "0.3"),
        )

    loop = asyncio.new_event_loop()
    try:
        start = loop.time()
        loop.run_until_complete(go())
        elapsed = loop.time() - start
    finally:
        loop.close()
    assert elapsed < 0.55
