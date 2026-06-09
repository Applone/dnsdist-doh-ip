"""Tests for interactive prompt handling and EOF resilience in bind9_setup.

These guard against the regression where prompting inside the asyncio context
crashed with an EOFError as soon as stdin was exhausted (e.g. when the script
is delivered via `curl ... | python3`).
"""
import asyncio
import os
import subprocess
import sys

import bind9_setup as b

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(coro):
    return asyncio.run(coro)


def _feed(monkeypatch, answers):
    """Replace the line reader with a scripted sequence of answers."""
    it = iter(answers)

    def fake(_prompt_text):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr(b, "_read_line", fake)


def test_prompt_returns_typed_value(monkeypatch):
    _feed(monkeypatch, ["dns.example.com"])
    assert run(b.prompt("Domain")) == "dns.example.com"


def test_prompt_returns_default_when_blank(monkeypatch):
    _feed(monkeypatch, [""])
    assert run(b.prompt("Forwarder", "8.8.8.8")) == "8.8.8.8"


def test_ask_yes_true_and_false(monkeypatch):
    _feed(monkeypatch, ["yes"])
    assert run(b.ask_yes("OK?")) is True
    _feed(monkeypatch, ["n"])
    assert run(b.ask_yes("OK?")) is False


def test_prompt_eof_exits_gracefully(monkeypatch):
    def boom(_prompt_text):
        raise EOFError

    monkeypatch.setattr(b, "_read_line", boom)
    try:
        run(b.prompt("Domain"))
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("prompt did not exit on EOF")


def test_gather_config_consumes_piped_answers(monkeypatch):
    _feed(monkeypatch, ["dns.example.com", "", "", "n", "n", "1", ""])

    async def fake_versions():
        return (["9.20.7"], False)

    cfg = b.Config()

    async def go():
        versions_task = asyncio.ensure_future(fake_versions())
        await b.gather_config(cfg, versions_task)
        if not versions_task.done():
            versions_task.cancel()

    run(go())
    assert cfg.domain == "dns.example.com"
    assert cfg.fwd1 == "8.8.8.8"
    assert cfg.fwd2 == "1.1.1.1"
    assert cfg.install_mode == "distro"


# Driver run in a fresh interpreter to exercise the real input path end to end.
_DRIVER = (
    "import asyncio, bind9_setup as b\n"
    "async def fv():\n"
    "    return (['9.20.7'], False)\n"
    "async def main():\n"
    "    cfg = b.Config()\n"
    "    vt = asyncio.ensure_future(fv())\n"
    "    await b.gather_config(cfg, vt)\n"
    "    vt.cancel()\n"
    "    print('DOMAIN=' + cfg.domain)\n"
    "asyncio.run(main())\n"
)


def _driver_proc(stdin_text, **popen_kw):
    env = {**os.environ, "PYTHONPATH": REPO_ROOT}
    return subprocess.run(
        [sys.executable, "-c", _DRIVER],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=env, start_new_session=True, timeout=60, **popen_kw,
    )


def test_subprocess_reads_piped_answers():
    proc = _driver_proc(None, input="dns.example.com\n\n\nn\nn\n1\n\n")
    assert proc.returncode == 0, proc.stdout
    assert "DOMAIN=dns.example.com" in proc.stdout


def test_subprocess_no_stdin_no_eof_traceback():
    # With no stdin and no controlling terminal (start_new_session detaches it),
    # the script must exit gracefully rather than dumping an EOFError traceback.
    proc = _driver_proc(None, stdin=subprocess.DEVNULL)
    assert "EOFError" not in proc.stdout, proc.stdout
    assert proc.returncode != 0
