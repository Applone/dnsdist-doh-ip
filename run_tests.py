#!/usr/bin/env python3
"""Test runner: ruff lint → unit tests → live Podman integration tests.

Renders a dynamic, in-place updating CLI. On a modern free-threaded (no-GIL)
interpreter the stages run concurrently across CPU cores via threads; otherwise
they run synchronously.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tests import integration_podman as ipod  # noqa: E402

# ── ANSI ─────────────────────────────────────────────────────────────────────
RESET = "\033[0m"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

STATUS_COLOR = {
    "WAIT": "\033[2;90m",   # dim grey
    "RUN": "\033[1;36m",    # bold cyan
    "OK": "\033[1;32m",     # bold green
    "FAIL": "\033[1;31m",   # bold red
    "SKIP": "\033[2;33m",   # dim yellow
}


def gil_disabled() -> bool:
    """True on a free-threaded build where the GIL is off (Python 3.13+)."""
    checker = getattr(sys, "_is_gil_enabled", None)
    if checker is None:
        # Pre-3.13 interpreters always have the GIL; future GIL-less builds
        # that drop the symbol entirely are treated as free-threaded.
        return sys.version_info >= (3, 15)
    return not checker()


class SkipStage(RuntimeError):
    """Raised by a stage function to mark itself skipped."""


@dataclass
class Stage:
    name: str
    func: Callable[[], tuple[bool, str]]
    status: str = "WAIT"
    duration: float = 0.0
    start: float = 0.0
    log: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)


# ── Display ──────────────────────────────────────────────────────────────────
class Display:
    """Redraws the stage list in place using ANSI cursor movement."""

    def __init__(self, stages: list[Stage]):
        self.stages = stages
        self.name_w = max(len(s.name) for s in stages)
        self.fancy = sys.stdout.isatty()
        self._frame = 0
        self._drawn = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._plain_seen: set[str] = set()

    def _badge(self, status: str) -> str:
        color = STATUS_COLOR[status]
        if status == "RUN":
            content = f"{SPINNER[self._frame % len(SPINNER)]:^4}"
        else:
            content = f"{status:<4}"
        return f"{color}[ {content} ]{RESET}"

    def _time_str(self, s: Stage) -> str:
        if s.status in ("OK", "FAIL"):
            return f"{s.duration:.1f}s"
        if s.status == "RUN":
            return f"{time.monotonic() - s.start:.1f}s"
        return ""

    def _line(self, s: Stage) -> str:
        color = STATUS_COLOR[s.status]
        t = self._time_str(s)
        return f"  {self._badge(s.status)}  {s.name:<{self.name_w}}  {color}{t:>7}{RESET}"

    def _render_fancy(self) -> None:
        out = sys.stdout
        if self._drawn:
            out.write(f"\033[{len(self.stages)}A")
        for s in self.stages:
            out.write(f"\r\033[K{self._line(s)}\n")
        out.flush()
        self._drawn = True

    def _render_plain(self) -> None:
        # On a non-TTY emit a single line per settled stage, once.
        for s in self.stages:
            if s.status in ("OK", "FAIL", "SKIP") and s.name not in self._plain_seen:
                self._plain_seen.add(s.name)
                tag = {"OK": "ok", "FAIL": "FAIL", "SKIP": "skip"}[s.status]
                extra = f"  {s.duration:.1f}s" if s.status != "SKIP" else ""
                print(f"  [{tag}] {s.name}{extra}", flush=True)

    def refresh(self) -> None:
        if self.fancy:
            self._render_fancy()
        else:
            self._render_plain()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._frame += 1
            self.refresh()
            time.sleep(0.08)

    def start(self) -> None:
        if self.fancy:
            sys.stdout.write(HIDE_CURSOR)
            sys.stdout.flush()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()
        self.refresh()
        if self.fancy:
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.flush()


# ── Stage execution ──────────────────────────────────────────────────────────
def run_stage(stage: Stage) -> None:
    with stage.lock:
        stage.status = "RUN"
        stage.start = time.monotonic()
    try:
        passed, log = stage.func()
        status = "OK" if passed else "FAIL"
    except SkipStage as exc:
        with stage.lock:
            stage.status = "SKIP"
            stage.log = str(exc)
            stage.duration = time.monotonic() - stage.start
        return
    except Exception:  # noqa: BLE001 — surface any failure as a stage FAIL
        status, log = "FAIL", traceback.format_exc()
    with stage.lock:
        stage.status = status
        stage.log = log
        stage.duration = time.monotonic() - stage.start


def run_parallel(stages: list[Stage]) -> None:
    """Run every stage concurrently, capped at the CPU count."""
    sem = threading.Semaphore(os.cpu_count() or 1)
    threads: list[threading.Thread] = []

    def worker(st: Stage) -> None:
        with sem:
            run_stage(st)

    for st in stages:
        t = threading.Thread(target=worker, args=(st,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def run_sequential(stages: list[Stage]) -> None:
    """Run stages in order; on the first failure, skip the remainder."""
    aborted = False
    for st in stages:
        if aborted:
            with st.lock:
                st.status = "SKIP"
                st.log = "skipped after an earlier failure"
            continue
        run_stage(st)
        if st.status == "FAIL":
            aborted = True


# ── Summary ──────────────────────────────────────────────────────────────────
def print_summary(stages: list[Stage], total: float) -> None:
    passed = sum(1 for s in stages if s.status == "OK")
    failed = sum(1 for s in stages if s.status == "FAIL")
    skipped = sum(1 for s in stages if s.status == "SKIP")

    green = STATUS_COLOR["OK"]
    red = STATUS_COLOR["FAIL"]
    yellow = STATUS_COLOR["SKIP"]
    width = 40
    print()
    print(f"  ┌{'─' * width}┐")
    print(f"  │ {'Summary':<{width - 2}} │")
    print(f"  ├{'─' * width}┤")
    rows = [
        ("Total Time", f"{total:.1f}s", RESET),
        ("Passed", str(passed), green),
        ("Skipped", str(skipped), yellow),
        ("Failed", str(failed), red),
    ]
    for label, value, color in rows:
        cell = f"{label:<14}{color}{value}{RESET}"
        # Visible length is label field (14) + value; pad the remainder.
        pad = width - 2 - (14 + len(value))
        print(f"  │ {cell}{' ' * pad} │")
    print(f"  └{'─' * width}┘")


def print_failures(stages: list[Stage]) -> None:
    red = STATUS_COLOR["FAIL"]
    for s in stages:
        if s.status == "FAIL":
            print()
            print(f"{red}━━━ FAILED: {s.name} ━━━{RESET}")
            print(s.log.rstrip() or "(no output captured)")


# ── Stage definitions ────────────────────────────────────────────────────────
def stage_ruff() -> tuple[bool, str]:
    targets = ["bind9_setup.py", "run_tests.py", "tests"]
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", *targets],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode == 0, proc.stdout


def stage_unit() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode == 0, proc.stdout


def stage_integration_apt() -> tuple[bool, str]:
    try:
        return ipod.integration_apt()
    except ipod.SkipIntegration as exc:
        raise SkipStage(str(exc)) from exc


def stage_integration_source() -> tuple[bool, str]:
    try:
        return ipod.integration_source()
    except ipod.SkipIntegration as exc:
        raise SkipStage(str(exc)) from exc


def build_stages(no_podman: bool) -> list[Stage]:
    stages = [
        Stage("Ruff lint", stage_ruff),
        Stage("Unit tests", stage_unit),
    ]
    if not no_podman:
        stages.append(Stage("Podman: apt install", stage_integration_apt))
        stages.append(Stage("Podman: source build", stage_integration_source))
    return stages


def main() -> int:
    no_podman = "--no-podman" in sys.argv
    stages = build_stages(no_podman)

    free_threaded = gil_disabled()
    mode = "parallel (no-GIL)" if free_threaded else "sequential (GIL)"
    print(f"Running {len(stages)} stages — {mode}\n")

    display = Display(stages)
    display.start()
    start = time.monotonic()
    try:
        if free_threaded:
            run_parallel(stages)
        else:
            run_sequential(stages)
    finally:
        display.stop()
    total = time.monotonic() - start

    print_summary(stages, total)

    if any(s.status == "FAIL" for s in stages):
        print_failures(stages)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
