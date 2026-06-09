"""Live Podman integration tests for bind9_setup.

Each test spins up a fresh `debian:trixie-slim` container, drives the real
installation routines from bind9_setup, and asserts that a working `named`
binary results. Two installation methods are covered:

  * apt    — distro mirror install (Config.install_mode == "distro")
  * source — ISC tarball build      (build_bind_from_source over /usr)

The container runs the actual project code (mounted read-only) so the tests
exercise bind9_setup itself rather than a re-implementation.
"""
from __future__ import annotations

import os
import shutil
import subprocess

IMAGE = "debian:trixie-slim"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Built from the fallback list so the source build does not depend on the ISC
# directory index being reachable for version discovery.
SOURCE_VERSION = "9.20.7"


class SkipIntegration(RuntimeError):
    """Raised when the integration environment is unavailable."""


def podman_available() -> bool:
    """True when podman is installed and its service responds."""
    if not shutil.which("podman"):
        return False
    try:
        proc = subprocess.run(
            ["podman", "info"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# Driver executed inside the container for the apt path. It calls the real
# install_packages routine and confirms named is installed and executable.
_APT_DRIVER = """
import asyncio, os, shutil, bind9_setup as b
async def main():
    cfg = b.Config()
    await b.install_packages(cfg)
    named = shutil.which("named")
    assert named, "named not found after apt install"
    assert os.access(named, os.X_OK), "named is not executable"
    code, out = await b.run("named", "-v", capture=True)
    assert code == 0 and "BIND" in out, out
asyncio.run(main())
print("INTEGRATION_OK")
"""

# Driver for the source path. Builds over /usr so the systemd-override branch
# (which needs a running systemd) is skipped entirely inside the container.
_SOURCE_DRIVER = f"""
import asyncio, os, shutil, bind9_setup as b
async def main():
    cfg = b.Config(install_mode="source", bind_prefix="/usr")
    await b.build_bind_from_source(cfg, "{SOURCE_VERSION}", "/usr")
    named = shutil.which("named") or "/usr/sbin/named"
    assert os.path.exists(named), "named not found after source build"
    assert os.access(named, os.X_OK), "named is not executable"
    code, out = await b.run(named, "-v", capture=True)
    assert code == 0 and "BIND" in out, out
asyncio.run(main())
print("INTEGRATION_OK")
"""


def _container_command(prereqs: str, driver: str) -> list[str]:
    """Assemble a `podman run` invocation that installs prereqs then drives."""
    inner = (
        "set -e\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update -qq\n"
        f"apt-get install -y {prereqs} >/dev/null\n"
        "PYTHONPATH=/opt/app python3 - <<'PYEOF'\n"
        f"{driver}\n"
        "PYEOF\n"
    )
    return [
        "podman", "run", "--rm",
        "-v", f"{REPO_ROOT}:/opt/app:ro",
        IMAGE, "bash", "-c", inner,
    ]


def _run(cmd: list[str], timeout: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return False, f"timed out after {timeout}s\n{exc.output or ''}"
    except OSError as exc:
        return False, f"failed to launch podman: {exc}"
    passed = proc.returncode == 0 and "INTEGRATION_OK" in proc.stdout
    return passed, proc.stdout


def integration_apt() -> tuple[bool, str]:
    """Validate the apt (distro mirror) installation method in a container."""
    if not podman_available():
        raise SkipIntegration("podman unavailable")
    cmd = _container_command("python3 ca-certificates", _APT_DRIVER)
    return _run(cmd, timeout=600)


def integration_source() -> tuple[bool, str]:
    """Validate the source-build installation method in a container."""
    if not podman_available():
        raise SkipIntegration("podman unavailable")
    # curl/tar/xz are needed by build_bind_from_source for download + extract.
    prereqs = "python3 curl ca-certificates xz-utils tar"
    cmd = _container_command(prereqs, _SOURCE_DRIVER)
    return _run(cmd, timeout=2400)
