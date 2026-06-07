#!/usr/bin/env python3
"""bind9_setup.py — Set up BIND9 with DoT/DoH and optional RPZ adblocking on Debian/Ubuntu.

Complete Python 3.10+ rewrite of bind9-setup.sh.
Requires root privileges to run.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import logging
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BIND_VERSION_FALLBACK: list[str] = ["9.20.7", "9.18.33"]
ISC_DOWNLOAD_BASE = "https://downloads.isc.org/isc/bind9"
ISC_VERSION_INDEX = f"{ISC_DOWNLOAD_BASE}/"

DEFAULT_FWD1 = "1.1.1.1"
DEFAULT_FWD2 = "8.8.8.8"
DEFAULT_RPZ_TIMER = "6h"
DEFAULT_BIND_PREFIX = "/usr"

REQUIRED_APT_PACKAGES = [
    "bind9",
    "bind9utils",
    "dnsutils",
    "certbot",
    "curl",
    "util-linux",
]

SOURCE_BUILD_DEPS = [
    "build-essential",
    "libssl-dev",
    "libcap-dev",
    "libuv1-dev",
    "libnghttp2-dev",
    "libjemalloc-dev",
    "libmaxminddb-dev",
    "pkg-config",
    "python3",
    "meson",
    "ninja-build",
    "dnsutils",
    "certbot",
    "curl",
    "util-linux",
]

CONFLICTING_WEB_SERVICES = ["nginx", "apache2", "lighttpd", "caddy"]

RPZ_BLOCKLISTS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adaway.org/hosts.txt",
]

LOG = logging.getLogger("bind9_setup")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SetupError(Exception):
    """Raised when a setup step fails irrecoverably."""


# ---------------------------------------------------------------------------
# Colored logging
# ---------------------------------------------------------------------------


class ColoredFormatter(logging.Formatter):
    """Logging formatter that adds ANSI colours to level names."""

    COLORS = {
        logging.DEBUG: "\033[2;37m",      # dim grey
        logging.INFO: "\033[0;36m",       # cyan
        logging.WARNING: "\033[0;33m",    # yellow
        logging.ERROR: "\033[0;31m",      # red
        logging.CRITICAL: "\033[1;31m",   # bold red
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(debug: bool = False) -> None:
    """Configure the root logger with coloured console output."""
    level = logging.DEBUG if debug else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        ColoredFormatter(fmt="%(levelname)s %(message)s")
    )
    LOG.setLevel(level)
    LOG.addHandler(handler)


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class Config:
    """Holds every user-supplied and derived setting."""

    domain: str = ""
    fwd1: str = DEFAULT_FWD1
    fwd2: str = DEFAULT_FWD2
    use_rpz: bool = True
    rpz_timer: str = DEFAULT_RPZ_TIMER
    use_stats: bool = False
    install_mode: str = "apt"          # "apt" | "source"
    bind_version: str = ""
    bind_prefix: str = DEFAULT_BIND_PREFIX
    doh_enabled: bool = False
    bind_user: str = "bind"
    bind_dir: Path = field(default_factory=lambda: Path("/etc/bind"))
    bind_ssl_dir: Path = field(default_factory=lambda: Path("/etc/bind/ssl"))
    skip_certbot: bool = False
    skip_firewall: bool = False
    non_interactive: bool = False

    # Resolved at runtime
    rndc_bin: str = ""
    named_compilezone_bin: str = ""
    named_checkconf_bin: str = ""


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def run_cmd(
    cmd: list[str],
    check: bool = True,
    capture: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Run a command via subprocess, logging the invocation."""
    LOG.debug("exec: %s", " ".join(cmd))
    stdout = subprocess.PIPE if capture else None
    stderr = subprocess.PIPE if capture else None
    result = subprocess.run(
        cmd,
        text=True,
        stdout=stdout,
        stderr=stderr,
        **kwargs,
    )
    if check and result.returncode != 0:
        detail = ""
        if result.stderr:
            detail = f"\n  stderr: {result.stderr.strip()}"
        raise SetupError(
            f"Command failed (rc={result.returncode}): {' '.join(cmd)}{detail}"
        )
    return result


def resolve_binary(name: str, prefix: str = "/usr") -> str:
    """Locate a binary using shutil.which with fallback paths."""
    found = shutil.which(name)
    if found:
        return found
    # Try common prefix-relative paths
    for subdir in ("sbin", "bin", "local/sbin", "local/bin"):
        candidate = Path(prefix) / subdir / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    # Last-resort search
    for search in ("/usr/sbin", "/usr/bin", "/usr/local/sbin", "/usr/local/bin"):
        candidate = Path(search) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    LOG.warning("Binary '%s' not found in PATH or prefix '%s'", name, prefix)
    return name  # return bare name, let the caller fail with a clear message


def detect_bind_user() -> str:
    """Return the BIND runtime user name."""
    for candidate in ("named", "bind"):
        try:
            pwd.getpwnam(candidate)
            LOG.debug("Detected BIND user: %s", candidate)
            return candidate
        except KeyError:
            continue
    LOG.warning("Could not detect BIND user; defaulting to 'bind'")
    return "bind"


def _uid_gid(user: str, group: str | None = None) -> tuple[int, int]:
    """Resolve numeric uid/gid for user and optional group."""
    pw = pwd.getpwnam(user)
    uid = pw.pw_uid
    if group:
        gid = grp.getgrnam(group).gr_gid
    else:
        gid = pw.pw_gid
    return uid, gid


def atomic_write(
    path: Path,
    content: str,
    mode: int = 0o644,
    owner: str | None = None,
    group: str | None = None,
) -> None:
    """Write *content* to *path* atomically via tempfile + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        os.write(fd, content.encode())
        os.fchmod(fd, mode)
        if owner:
            uid, gid = _uid_gid(owner, group)
            os.fchown(fd, uid, gid)
        os.close(fd)
        os.replace(tmp, str(path))
        LOG.debug("Wrote %s (%d bytes)", path, len(content))
    except BaseException:
        os.close(fd) if not os.get_inheritable(fd) else None  # noqa: E501
        Path(tmp).unlink(missing_ok=True)
        raise


def backup_config(path: Path) -> None:
    """If *path* exists, copy it to path.bak.<timestamp>."""
    if not path.exists():
        return
    ts = time.strftime("%Y%m%d%H%M%S")
    bak = path.with_suffix(f"{path.suffix}.bak.{ts}")
    shutil.copy2(path, bak)
    LOG.info("Backed up %s → %s", path, bak)


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


def _version_key(v: str) -> tuple[int, ...]:
    """Return a sortable tuple of ints for a version string like '9.20.7'."""
    return tuple(int(x) for x in v.split("."))


def fetch_bind_versions() -> list[str]:
    """Fetch available BIND 9 versions from ISC downloads page.

    Returns a deduplicated list of version strings, newest first.
    Falls back to BIND_VERSION_FALLBACK on network errors.
    """
    LOG.info("Fetching available BIND versions from ISC …")
    try:
        req = Request(ISC_VERSION_INDEX, headers={"User-Agent": "bind9_setup/1.0"})
        with urlopen(req, timeout=15) as resp:
            page = resp.read().decode("utf-8", errors="replace")
        matches = re.findall(r"9\.\d+\.\d+(?=/)", page)
        if not matches:
            LOG.warning("No versions parsed from ISC page; using fallback list")
            return list(BIND_VERSION_FALLBACK)
        seen: set[str] = set()
        unique: list[str] = []
        for v in matches:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        unique.sort(key=_version_key, reverse=True)
        LOG.debug("Found %d BIND versions", len(unique))
        return unique
    except (URLError, OSError, ValueError) as exc:
        LOG.warning("Cannot fetch versions (%s); using fallback list", exc)
        return list(BIND_VERSION_FALLBACK)


def parse_bind_version(version_string: str) -> tuple[int, int]:
    """Extract (major, minor) from ``named -v`` output.

    >>> parse_bind_version("BIND 9.20.7-1ubuntu1 (Stable Release)")
    (9, 20)
    """
    m = re.search(r"BIND\s+(\d+)\.(\d+)", version_string)
    if not m:
        raise SetupError(f"Cannot parse BIND version from: {version_string!r}")
    return int(m.group(1)), int(m.group(2))


def compare_versions(v1: str, v2: str) -> int:
    """Compare two dotted version strings.

    Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
    """
    k1, k2 = _version_key(v1), _version_key(v2)
    if k1 < k2:
        return -1
    if k1 > k2:
        return 1
    return 0


def detect_existing_bind(config: Config) -> tuple[bool, str]:
    """Check if BIND9 is already installed.

    Returns (is_installed, version_string).
    """
    named_bin = shutil.which("named")
    if not named_bin:
        return False, ""
    result = run_cmd([named_bin, "-v"], capture=True, check=False)
    if result.returncode != 0:
        return False, ""
    version_str = result.stdout.strip()
    LOG.info("Existing BIND9 detected: %s", version_str)
    return True, version_str


def is_bind_from_apt() -> bool:
    """Check if the currently installed BIND9 came from apt."""
    result = run_cmd(
        ["dpkg", "-l", "bind9"],
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        return False
    return bool(re.search(r"^ii\s+bind9\s", result.stdout, re.MULTILINE))


def remove_apt_bind() -> None:
    """Remove BIND9 packages installed via apt."""
    LOG.info("Removing apt-installed BIND9 packages …")
    # Stop the service first
    run_cmd(["systemctl", "stop", "named"], check=False)
    run_cmd(["systemctl", "stop", "bind9"], check=False)
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    run_cmd(
        ["apt-get", "remove", "--purge", "-y", "bind9", "bind9utils", "bind9-utils"],
        env=env,
        check=False,
    )
    run_cmd(["apt-get", "autoremove", "-y"], env=env, check=False)
    LOG.info("Apt-installed BIND9 packages removed ✓")


def handle_existing_bind(config: Config) -> None:
    """If BIND9 is already installed, ask the user whether to reinstall from source.

    When the user opts to reinstall:
    - If the existing install is from apt, purge the apt packages first.
    - If the existing install is from source (not apt), the new source build
      will simply override the systemd unit (the scripts already support this).
    - Forces config.install_mode to 'source'.
    """
    is_installed, version_str = detect_existing_bind(config)
    if not is_installed:
        return

    LOG.warning("Existing BIND9 installation found: %s", version_str)

    if config.non_interactive:
        LOG.info("Non-interactive mode — keeping existing BIND9 installation")
        return

    reinstall = _prompt_yes_no(
        f"BIND9 is already installed ({version_str}). "
        "Do you want to reinstall from source?",
        default=False,
    )
    if not reinstall:
        LOG.info("Keeping existing BIND9 installation")
        return

    # Check if installed via apt and remove if so
    if is_bind_from_apt():
        LOG.info("Existing BIND9 was installed via apt")
        remove_apt_bind()
    else:
        LOG.info(
            "Existing BIND9 is not from apt (likely a previous source build). "
            "The new source build will override it via the systemd unit."
        )

    # Force source mode for the rest of the setup
    config.install_mode = "source"
    LOG.info("Install mode forced to 'source' for reinstall")


# ---------------------------------------------------------------------------
# Package installation
# ---------------------------------------------------------------------------


def install_packages(packages: list[str]) -> None:
    """Install Debian/Ubuntu packages via apt-get."""
    LOG.info("Installing packages: %s", " ".join(packages))
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    run_cmd(["apt-get", "update", "-qq"], env=env)
    run_cmd(
        ["apt-get", "install", "-y", "-qq", "--no-install-recommends"] + packages,
        env=env,
    )
    LOG.info("Package installation complete")


# ---------------------------------------------------------------------------
# Source build
# ---------------------------------------------------------------------------


def _download_with_progress(url: str, description: str) -> bytes:
    """Download URL content into memory, logging progress."""
    LOG.info("Downloading %s …", description)
    req = Request(url, headers={"User-Agent": "bind9_setup/1.0"})
    with urlopen(req, timeout=120) as resp:
        data = resp.read()
    LOG.info("Downloaded %s (%d bytes)", description, len(data))
    return data


def build_bind_from_source(version: str, prefix: str) -> None:
    """Download, verify, build and install BIND from source."""
    tarball_name = f"bind-{version}.tar.xz"
    tarball_url = f"{ISC_DOWNLOAD_BASE}/{version}/{tarball_name}"
    sha512_url = f"{tarball_url}.sha512"

    # Download tarball
    tarball_data = _download_with_progress(tarball_url, tarball_name)

    # Download and verify SHA-512
    try:
        sha_data = _download_with_progress(sha512_url, f"{tarball_name}.sha512")
        expected_hash = sha_data.decode().strip().split()[0].lower()
        actual_hash = hashlib.sha512(tarball_data).hexdigest().lower()
        if actual_hash != expected_hash:
            raise SetupError(
                f"SHA-512 mismatch for {tarball_name}:\n"
                f"  expected: {expected_hash}\n"
                f"  actual:   {actual_hash}"
            )
        LOG.info("SHA-512 checksum verified ✓")
    except (URLError, OSError) as exc:
        LOG.warning("Could not verify SHA-512 checksum: %s — continuing anyway", exc)

    # Extract
    build_dir = Path("/usr/local/src/bind9-build")
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    LOG.info("Extracting %s …", tarball_name)
    with tarfile.open(fileobj=BytesIO(tarball_data), mode="r:xz") as tf:
        tf.extractall(path=str(build_dir))

    # Find the extracted directory
    subdirs = [d for d in build_dir.iterdir() if d.is_dir()]
    if not subdirs:
        raise SetupError("Tarball extraction produced no directory")
    src_dir = subdirs[0]
    LOG.info("Source directory: %s", src_dir)

    # Detect build system: BIND 9.21+ uses meson, older versions use autotools
    uses_meson = (src_dir / "meson.build").is_file()
    uses_autotools = (src_dir / "configure").is_file()

    if uses_meson:
        LOG.info("Detected meson build system (BIND 9.21+)")

        # Configure via meson setup
        meson_args = [
            "meson", "setup", str(src_dir / "builddir"), str(src_dir),
            f"--prefix={prefix}",
            "--sysconfdir=/etc/bind",
            "--localstatedir=/var",
        ]
        LOG.info("Configuring BIND %s (meson, prefix=%s) …", version, prefix)
        run_cmd(meson_args)

        # Build via ninja
        ncpu = os.cpu_count() or 2
        LOG.info("Building BIND %s (using %d parallel jobs) …", version, ncpu)
        run_cmd(["ninja", "-C", str(src_dir / "builddir"), f"-j{ncpu}"])

        # Install
        LOG.info("Installing BIND %s to %s …", version, prefix)
        run_cmd(["meson", "install", "-C", str(src_dir / "builddir")])

    elif uses_autotools:
        LOG.info("Detected autotools build system (BIND ≤9.20)")

        # Configure
        LOG.info("Configuring BIND %s (prefix=%s) …", version, prefix)
        configure_args = [
            str(src_dir / "configure"),
            f"--prefix={prefix}",
            "--sysconfdir=/etc/bind",
            "--localstatedir=/var",
            "--with-libnghttp2",
            "--enable-doh",
            "--with-openssl",
            "--disable-linux-caps",
        ]
        run_cmd(configure_args, cwd=str(src_dir))

        # Build
        ncpu = os.cpu_count() or 2
        LOG.info("Building BIND %s (using %d parallel jobs) …", version, ncpu)
        run_cmd(["make", f"-j{ncpu}"], cwd=str(src_dir))

        # Install
        LOG.info("Installing BIND %s to %s …", version, prefix)
        run_cmd(["make", "install"], cwd=str(src_dir))

    else:
        raise SetupError(
            f"Cannot determine build system: neither meson.build nor configure "
            f"found in {src_dir}"
        )

    run_cmd(["ldconfig"])

    # Create systemd override if prefix != /usr
    if prefix != "/usr":
        override_dir = Path("/etc/systemd/system/named.service.d")
        override_dir.mkdir(parents=True, exist_ok=True)
        override_content = generate_named_override(prefix)
        atomic_write(override_dir / "override.conf", override_content)
        run_cmd(["systemctl", "daemon-reload"])
        LOG.info("Created systemd override for prefix %s", prefix)

    LOG.info("BIND %s built and installed successfully ✓", version)


# ---------------------------------------------------------------------------
# BIND version check
# ---------------------------------------------------------------------------


def check_bind_version(config: Config) -> None:
    """Check installed BIND version and set config.doh_enabled accordingly."""
    named_bin = resolve_binary("named", config.bind_prefix)
    result = run_cmd([named_bin, "-v"], capture=True, check=False)
    if result.returncode != 0:
        LOG.warning("Could not run 'named -v'; assuming DoH is unavailable")
        config.doh_enabled = False
        return

    version_output = result.stdout.strip()
    LOG.info("Installed BIND: %s", version_output)
    major, minor = parse_bind_version(version_output)

    if major >= 9 and minor >= 18:
        LOG.info("BIND %d.%d supports DNS-over-HTTPS ✓", major, minor)
        config.doh_enabled = True
    else:
        LOG.warning(
            "BIND %d.%d does not support DoH (requires 9.18+). "
            "DNS-over-TLS only.",
            major,
            minor,
        )
        config.doh_enabled = False

        # Try backports for apt mode
        if config.install_mode == "apt":
            LOG.info("Attempting to install newer BIND from backports …")
            try:
                # Detect distro codename
                result2 = run_cmd(
                    ["lsb_release", "-cs"], capture=True, check=False
                )
                codename = result2.stdout.strip() if result2.returncode == 0 else ""
                if codename:
                    backport_src = f"deb http://deb.debian.org/debian {codename}-backports main"
                    sources_list = Path("/etc/apt/sources.list.d/backports.list")
                    if not sources_list.exists():
                        atomic_write(sources_list, backport_src + "\n")
                    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
                    run_cmd(["apt-get", "update", "-qq"], env=env)
                    run_cmd(
                        [
                            "apt-get",
                            "install",
                            "-y",
                            "-qq",
                            f"-t{codename}-backports",
                            "bind9",
                            "bind9utils",
                        ],
                        env=env,
                    )
                    # Re-check
                    result3 = run_cmd([named_bin, "-v"], capture=True, check=False)
                    if result3.returncode == 0:
                        maj2, min2 = parse_bind_version(result3.stdout.strip())
                        if maj2 >= 9 and min2 >= 18:
                            config.doh_enabled = True
                            LOG.info("Backports BIND %d.%d supports DoH ✓", maj2, min2)
            except SetupError as exc:
                LOG.warning("Backports attempt failed: %s", exc)


# ---------------------------------------------------------------------------
# Certificate management
# ---------------------------------------------------------------------------


def obtain_certificate(domain: str) -> None:
    """Obtain a TLS certificate via certbot standalone."""
    LOG.info("Obtaining TLS certificate for %s via certbot …", domain)

    # Stop conflicting web servers
    stopped_services: list[str] = []
    for svc in CONFLICTING_WEB_SERVICES:
        result = run_cmd(
            ["systemctl", "is-active", "--quiet", svc], check=False
        )
        if result.returncode == 0:
            LOG.info("Temporarily stopping %s …", svc)
            run_cmd(["systemctl", "stop", svc])
            stopped_services.append(svc)

    try:
        run_cmd(
            [
                "certbot",
                "certonly",
                "--standalone",
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
                "-d",
                domain,
            ]
        )
        LOG.info("Certificate obtained ✓")
    finally:
        # Restart stopped services
        for svc in stopped_services:
            LOG.info("Restarting %s …", svc)
            run_cmd(["systemctl", "start", svc], check=False)


def install_certificates(config: Config) -> None:
    """Copy Let's Encrypt certificates to BIND ssl directory."""
    le_dir = Path(f"/etc/letsencrypt/live/{config.domain}")
    if not le_dir.is_dir():
        raise SetupError(
            f"Certificate directory not found: {le_dir}\n"
            "Run certbot first or use --skip-certbot."
        )

    ssl_dir = config.bind_ssl_dir
    ssl_dir.mkdir(parents=True, exist_ok=True)

    cert_src = le_dir / "fullchain.pem"
    key_src = le_dir / "privkey.pem"

    cert_dst = ssl_dir / "cert.pem"
    key_dst = ssl_dir / "key.pem"

    LOG.info("Copying certificates to %s …", ssl_dir)
    shutil.copy2(cert_src, cert_dst)
    shutil.copy2(key_src, key_dst)

    uid, gid = _uid_gid(config.bind_user)
    os.chown(ssl_dir, uid, gid)
    os.chown(cert_dst, uid, gid)
    os.chown(key_dst, uid, gid)
    os.chmod(cert_dst, 0o640)
    os.chmod(key_dst, 0o640)
    os.chmod(ssl_dir, 0o750)

    LOG.info("Certificates installed ✓")

    # Deploy hook for automatic renewal
    hook_dir = Path("/etc/letsencrypt/renewal-hooks/deploy")
    hook_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hook_dir / "bind-cert-deploy.sh"
    hook_content = generate_certbot_hook(config.rndc_bin)
    atomic_write(hook_path, hook_content, mode=0o755)
    LOG.info("Certbot renewal deploy hook installed at %s", hook_path)


# ---------------------------------------------------------------------------
# Config file generators (pure functions)
# ---------------------------------------------------------------------------


def generate_named_conf_options(config: Config) -> str:
    """Return the full named.conf.options content."""
    rpz_block = ""
    if config.use_rpz:
        rpz_block = textwrap.dedent("""\

            response-policy {
                zone "rpz.local" policy given;
            };
        """)

    stats_block = ""
    if config.use_stats:
        stats_block = textwrap.dedent("""\

            statistics-channels {
                inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
            };
        """)

    doh_listeners = ""
    if config.doh_enabled:
        doh_listeners = textwrap.dedent("""\

            // DNS-over-HTTPS (DoH) listener
            listen-on port 443 tls local-tls http local-http { any; };
            listen-on-v6 port 443 tls local-tls http local-http { any; };
        """)

    tls_block = ""
    if config.domain:
        tls_block = textwrap.dedent(f"""\

        tls local-tls {{
            cert-file "{config.bind_ssl_dir}/cert.pem";
            key-file "{config.bind_ssl_dir}/key.pem";
        }};
        """)

    http_block = ""
    if config.doh_enabled:
        http_block = textwrap.dedent("""\

        http local-http {
            endpoints { "/dns-query"; };
        };
        """)

    content = textwrap.dedent(f"""\
        // Generated by bind9_setup.py — do not edit manually
        // {time.strftime("%Y-%m-%d %H:%M:%S")}

        acl trusted {{
            localhost;
            localnets;
        }};
        {tls_block}{http_block}
        options {{
            directory "/var/cache/bind";
            recursion yes;
            allow-recursion {{ trusted; }};
            allow-query {{ any; }};
            dnssec-validation auto;

            forwarders {{
                {config.fwd1};
                {config.fwd2};
            }};
            forward only;

            // DNS-over-TLS (DoT) listener
            listen-on port 853 tls local-tls {{ any; }};
            listen-on-v6 port 853 tls local-tls {{ any; }};

            // Standard DNS
            listen-on port 53 {{ any; }};
            listen-on-v6 port 53 {{ any; }};
        {doh_listeners}{rpz_block}{stats_block}
        }};
    """)
    return content


def generate_named_conf_logging() -> str:
    """Return the logging configuration."""
    return textwrap.dedent("""\
        // Generated by bind9_setup.py
        logging {
            channel default_log {
                file "/var/log/named/named.log" versions 5 size 50m;
                severity info;
                print-time yes;
                print-severity yes;
                print-category yes;
            };
            channel query_log {
                file "/var/log/named/query.log" versions 3 size 20m;
                severity info;
                print-time yes;
            };
            category default { default_log; };
            category queries { query_log; };
            category query-errors { default_log; };
            category security { default_log; };
            category dnssec { default_log; };
        };
    """)


def generate_named_conf_local(use_rpz: bool) -> str:
    """Return named.conf.local content."""
    rpz_zone = ""
    if use_rpz:
        rpz_zone = textwrap.dedent("""\

            zone "rpz.local" {
                type master;
                file "/etc/bind/zones/db.rpz.local";
                allow-query { none; };
            };
        """)
    else:
        rpz_zone = textwrap.dedent("""\

            // RPZ disabled
            // zone "rpz.local" {
            //     type master;
            //     file "/etc/bind/zones/db.rpz.local";
            //     allow-query { none; };
            // };
        """)

    return textwrap.dedent(f"""\
        // Generated by bind9_setup.py
        // Local configuration
        {rpz_zone}
    """)


def generate_named_conf() -> str:
    """Return the master named.conf that includes other config files."""
    return textwrap.dedent("""\
        // Generated by bind9_setup.py — master BIND configuration

        include "/etc/bind/named.conf.options";
        include "/etc/bind/named.conf.logging";
        include "/etc/bind/named.conf.local";
        include "/etc/bind/named.conf.default-zones";
    """)


def generate_rpz_update_script() -> str:
    """Return the RPZ blocklist update bash script."""
    blocklist_urls = "\n".join(f'    "{url}"' for url in RPZ_BLOCKLISTS)
    return textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # rpz-update.sh — Fetch and compile RPZ blocklist
        # Generated by bind9_setup.py — do not edit manually
        set -euo pipefail

        ZONE_FILE="/etc/bind/zones/db.rpz.local"
        TMP_HOSTS="$(mktemp)"
        TMP_ZONE="$(mktemp)"
        NAMED_COMPILEZONE="$(command -v named-compilezone || echo /usr/sbin/named-compilezone)"
        RNDC="$(command -v rndc || echo /usr/sbin/rndc)"

        BLOCKLISTS=(
        {blocklist_urls}
        )

        cleanup() {{
            rm -f "$TMP_HOSTS" "$TMP_ZONE"
        }}
        trap cleanup EXIT

        SERIAL="$(date +%Y%m%d%H)"

        # Header
        cat > "$TMP_ZONE" <<HEADER
        \\$TTL 300
        @  IN  SOA  localhost. admin.localhost. (
                $SERIAL  ; serial
                3600     ; refresh
                600      ; retry
                86400    ; expire
                300      ; minimum
        )
           IN  NS   localhost.
        HEADER

        # Fetch and merge blocklists
        for url in "${{BLOCKLISTS[@]}}"; do
            curl -sSfL --max-time 30 "$url" >> "$TMP_HOSTS" 2>/dev/null || true
        done

        # Convert hosts entries to RPZ CNAME records
        grep -E '^0\\.0\\.0\\.0|^127\\.0\\.0\\.1' "$TMP_HOSTS" \\
            | awk '{{print $2}}' \\
            | grep -v 'localhost' \\
            | sort -u \\
            | while read -r domain; do
                # Skip empty/invalid
                [[ -z "$domain" || "$domain" == "#"* ]] && continue
                echo "$domain  CNAME  ."
            done >> "$TMP_ZONE"

        # Validate zone
        if "$NAMED_COMPILEZONE" -i none -o /dev/null rpz.local "$TMP_ZONE" >/dev/null 2>&1; then
            cp -f "$TMP_ZONE" "$ZONE_FILE"
            chown bind:bind "$ZONE_FILE" 2>/dev/null || chown named:named "$ZONE_FILE" 2>/dev/null || true
            "$RNDC" reload rpz.local 2>/dev/null || "$RNDC" reload 2>/dev/null || true
            echo "[rpz-update] Zone updated successfully (serial $SERIAL)"
        else
            echo "[rpz-update] Zone validation failed — keeping previous version" >&2
            exit 1
        fi
    """)


def generate_rpz_service(config: Config) -> str:
    """Return the systemd service unit for RPZ updates."""
    return textwrap.dedent("""\
        [Unit]
        Description=RPZ blocklist updater for BIND9
        After=network-online.target named.service
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart=/usr/local/sbin/rpz-update.sh
        User=root
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
    """)


def generate_rpz_timer(config: Config) -> str:
    """Return the systemd timer unit for RPZ updates."""
    return textwrap.dedent(f"""\
        [Unit]
        Description=Periodic RPZ blocklist update

        [Timer]
        OnBootSec=5min
        OnUnitActiveSec={config.rpz_timer}
        Persistent=true
        RandomizedDelaySec=120

        [Install]
        WantedBy=timers.target
    """)


def generate_certbot_hook(rndc_bin: str) -> str:
    """Return the certbot renewal deploy hook script."""
    return textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # Certbot renewal deploy hook for BIND9 TLS certificates
        # Generated by bind9_setup.py

        set -euo pipefail

        BIND_SSL_DIR="/etc/bind/ssl"
        BIND_USER="$(stat -c '%U' "$BIND_SSL_DIR" 2>/dev/null || echo bind)"

        # Copy renewed certificates
        cp -f "$RENEWED_LINEAGE/fullchain.pem" "$BIND_SSL_DIR/cert.pem"
        cp -f "$RENEWED_LINEAGE/privkey.pem"   "$BIND_SSL_DIR/key.pem"

        # Fix ownership and permissions
        chown "$BIND_USER":"$BIND_USER" "$BIND_SSL_DIR/cert.pem" "$BIND_SSL_DIR/key.pem"
        chmod 640 "$BIND_SSL_DIR/cert.pem" "$BIND_SSL_DIR/key.pem"

        # Reload BIND
        {rndc_bin} reload 2>/dev/null || systemctl reload named 2>/dev/null || true
        echo "[certbot-hook] BIND certificates renewed and reloaded"
    """)


def generate_logrotate_config(rndc_bin: str) -> str:
    """Return logrotate config for BIND log files."""
    return textwrap.dedent(f"""\
        /var/log/named/named.log
        /var/log/named/query.log {{
            weekly
            rotate 8
            compress
            delaycompress
            missingok
            notifempty
            create 0640 bind bind
            postrotate
                {rndc_bin} reload >/dev/null 2>&1 || true
            endscript
        }}
    """)


def generate_named_override(prefix: str) -> str:
    """Return the systemd override.conf for a non-standard BIND prefix."""
    return textwrap.dedent(f"""\
        # Generated by bind9_setup.py
        [Service]
        ExecStart=
        ExecStart={prefix}/sbin/named -f -u bind -c /etc/bind/named.conf
        ExecReload=
        ExecReload={prefix}/sbin/rndc reload
    """)


def _generate_rpz_placeholder_zone() -> str:
    """Return a minimal RPZ zone file used as a placeholder."""
    serial = time.strftime("%Y%m%d") + "01"
    return textwrap.dedent(f"""\
        $TTL 300
        @  IN  SOA  localhost. admin.localhost. (
                {serial}  ; serial
                3600      ; refresh
                600       ; retry
                86400     ; expire
                300       ; minimum
        )
           IN  NS   localhost.
        ; Placeholder — will be populated by rpz-update.sh
    """)


# ---------------------------------------------------------------------------
# High-level setup steps
# ---------------------------------------------------------------------------


def write_bind_config(config: Config) -> None:
    """Write all BIND configuration files, backing up existing ones."""
    LOG.info("Writing BIND configuration files …")

    bind_dir = config.bind_dir

    # Ensure directories exist
    bind_dir.mkdir(parents=True, exist_ok=True)
    Path("/var/cache/bind").mkdir(parents=True, exist_ok=True)

    log_dir = Path("/var/log/named")
    log_dir.mkdir(parents=True, exist_ok=True)
    uid, gid = _uid_gid(config.bind_user)
    os.chown(log_dir, uid, gid)

    # Backup existing configs
    config_files = [
        bind_dir / "named.conf",
        bind_dir / "named.conf.options",
        bind_dir / "named.conf.logging",
        bind_dir / "named.conf.local",
    ]
    for cf in config_files:
        backup_config(cf)

    # Write configs
    atomic_write(
        bind_dir / "named.conf.options",
        generate_named_conf_options(config),
        owner=config.bind_user,
    )
    atomic_write(
        bind_dir / "named.conf.logging",
        generate_named_conf_logging(),
        owner=config.bind_user,
    )
    atomic_write(
        bind_dir / "named.conf.local",
        generate_named_conf_local(config.use_rpz),
        owner=config.bind_user,
    )
    atomic_write(
        bind_dir / "named.conf",
        generate_named_conf(),
        owner=config.bind_user,
    )

    # Logrotate
    atomic_write(
        Path("/etc/logrotate.d/named"),
        generate_logrotate_config(config.rndc_bin),
    )

    # Check config syntax
    LOG.info("Validating BIND configuration …")
    result = run_cmd([config.named_checkconf_bin, str(bind_dir / "named.conf")], check=False, capture=True)
    if result.returncode != 0:
        LOG.warning(
            "named-checkconf reported issues:\n%s",
            (result.stdout or "") + (result.stderr or ""),
        )
    else:
        LOG.info("named-checkconf: OK ✓")


def setup_rpz(config: Config) -> None:
    """Create placeholder RPZ zone, deploy update script and systemd units."""
    if not config.use_rpz:
        LOG.info("RPZ adblocking is disabled — skipping")
        return

    LOG.info("Setting up RPZ adblocking …")

    # Zone directory and placeholder zone
    zone_dir = config.bind_dir / "zones"
    zone_dir.mkdir(parents=True, exist_ok=True)
    uid, gid = _uid_gid(config.bind_user)
    os.chown(zone_dir, uid, gid)

    zone_file = zone_dir / "db.rpz.local"
    if not zone_file.exists():
        atomic_write(
            zone_file,
            _generate_rpz_placeholder_zone(),
            owner=config.bind_user,
        )
        LOG.info("Created placeholder RPZ zone at %s", zone_file)

    # Update script
    script_path = Path("/usr/local/sbin/rpz-update.sh")
    atomic_write(script_path, generate_rpz_update_script(), mode=0o755)
    LOG.info("Deployed RPZ update script at %s", script_path)

    # Systemd service
    svc_path = Path("/etc/systemd/system/rpz-updater.service")
    atomic_write(svc_path, generate_rpz_service(config))

    # Systemd timer
    timer_path = Path("/etc/systemd/system/rpz-updater.timer")
    atomic_write(timer_path, generate_rpz_timer(config))

    run_cmd(["systemctl", "daemon-reload"])
    run_cmd(["systemctl", "enable", "--now", "rpz-updater.timer"])
    LOG.info("RPZ systemd timer enabled (interval: %s) ✓", config.rpz_timer)


def configure_firewall(config: Config) -> None:
    """Add firewall rules for DNS, DoT, and optionally DoH."""
    if config.skip_firewall:
        LOG.info("Firewall configuration skipped (--skip-firewall)")
        return

    LOG.info("Configuring firewall rules …")

    ports = [
        ("53", "tcp", "DNS"),
        ("53", "udp", "DNS"),
        ("853", "tcp", "DoT"),
    ]
    if config.doh_enabled:
        ports.append(("443", "tcp", "DoH"))

    # Detect firewall tool
    ufw_bin = shutil.which("ufw")
    if ufw_bin:
        for port, proto, label in ports:
            run_cmd(
                ["ufw", "allow", f"{port}/{proto}", "comment", f"BIND9 {label}"],
                check=False,
            )
        LOG.info("UFW rules added ✓")
        return

    iptables_bin = shutil.which("iptables")
    if iptables_bin:
        for port, proto, label in ports:
            # Check if rule already exists
            check = run_cmd(
                [
                    "iptables",
                    "-C",
                    "INPUT",
                    "-p",
                    proto,
                    "--dport",
                    port,
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                capture=True,
            )
            if check.returncode != 0:
                run_cmd(
                    [
                        "iptables",
                        "-A",
                        "INPUT",
                        "-p",
                        proto,
                        "--dport",
                        port,
                        "-j",
                        "ACCEPT",
                        "-m",
                        "comment",
                        "--comment",
                        f"BIND9 {label}",
                    ],
                    check=False,
                )
        # Also for ip6tables
        ip6tables_bin = shutil.which("ip6tables")
        if ip6tables_bin:
            for port, proto, label in ports:
                check6 = run_cmd(
                    [
                        "ip6tables",
                        "-C",
                        "INPUT",
                        "-p",
                        proto,
                        "--dport",
                        port,
                        "-j",
                        "ACCEPT",
                    ],
                    check=False,
                    capture=True,
                )
                if check6.returncode != 0:
                    run_cmd(
                        [
                            "ip6tables",
                            "-A",
                            "INPUT",
                            "-p",
                            proto,
                            "--dport",
                            port,
                            "-j",
                            "ACCEPT",
                            "-m",
                            "comment",
                            "--comment",
                            f"BIND9 {label}",
                        ],
                        check=False,
                    )
        LOG.info("iptables rules added ✓")
        return

    LOG.warning("No supported firewall tool found (ufw or iptables) — skipping")


def start_bind() -> None:
    """Enable and restart the BIND9 named service."""
    LOG.info("Starting BIND9 …")
    run_cmd(["systemctl", "enable", "named"], check=False)
    # Also try bind9 service name (Debian/Ubuntu default)
    run_cmd(["systemctl", "enable", "bind9"], check=False)
    run_cmd(["systemctl", "restart", "named"], check=False)
    # Fallback to bind9 service name
    run_cmd(["systemctl", "restart", "bind9"], check=False)

    # Wait a moment for the service to start
    time.sleep(2)

    # Verify
    result_named = run_cmd(
        ["systemctl", "is-active", "--quiet", "named"], check=False
    )
    result_bind9 = run_cmd(
        ["systemctl", "is-active", "--quiet", "bind9"], check=False
    )
    if result_named.returncode == 0 or result_bind9.returncode == 0:
        LOG.info("BIND9 is running ✓")
    else:
        LOG.error("BIND9 does not appear to be running!")
        LOG.error("Check 'systemctl status named' or 'journalctl -xeu named'")
        raise SetupError("BIND9 failed to start")


def run_initial_rpz_update() -> None:
    """Trigger the initial RPZ blocklist update."""
    LOG.info("Running initial RPZ blocklist update …")
    result = run_cmd(
        ["systemctl", "start", "rpz-updater.service"], check=False
    )
    if result.returncode == 0:
        LOG.info("Initial RPZ update triggered ✓")
    else:
        LOG.warning("Initial RPZ update may have failed — check 'journalctl -u rpz-updater'")


def run_smoke_test(domain: str) -> None:
    """Run a quick dig test against the local resolver."""
    LOG.info("Running smoke test …")
    dig_bin = shutil.which("dig") or "dig"
    result = run_cmd(
        [dig_bin, "@127.0.0.1", "example.com", "A", "+short"],
        capture=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        LOG.info("Smoke test passed ✓  — example.com → %s", result.stdout.strip())
    else:
        LOG.warning("Smoke test: dig returned no answer — DNS may not be fully ready yet")

    # Test DoT if domain is available
    if domain:
        result_dot = run_cmd(
            [
                dig_bin,
                "@127.0.0.1",
                "-p",
                "853",
                "+tls",
                "example.com",
                "A",
                "+short",
            ],
            capture=True,
            check=False,
        )
        if result_dot.returncode == 0 and result_dot.stdout.strip():
            LOG.info("DoT test passed ✓  — example.com → %s", result_dot.stdout.strip())
        else:
            LOG.debug("DoT test did not return an answer (may need TLS config)")


def print_summary(config: Config) -> None:
    """Print a final summary of the setup."""
    sep = "=" * 60
    lines = [
        "",
        sep,
        "  BIND9 DoT/DoH Setup Complete",
        sep,
        "",
        f"  Domain:          {config.domain or '(none — TLS disabled)'}",
        f"  Forwarders:      {config.fwd1}, {config.fwd2}",
        f"  RPZ adblocking:  {'enabled' if config.use_rpz else 'disabled'}",
        f"  Statistics:      {'enabled (port 8053)' if config.use_stats else 'disabled'}",
        f"  DNS-over-TLS:    {'enabled (port 853)' if config.domain else 'disabled'}",
        f"  DNS-over-HTTPS:  {'enabled (port 443)' if config.doh_enabled else 'disabled'}",
        f"  Install mode:    {config.install_mode}",
        f"  BIND prefix:     {config.bind_prefix}",
        f"  BIND user:       {config.bind_user}",
        "",
        "  Endpoints:",
        f"    DNS:    {config.domain or 'localhost'} port 53",
    ]
    if config.domain:
        lines.append(f"    DoT:    tls://{config.domain}:853")
    if config.doh_enabled and config.domain:
        lines.append(f"    DoH:    https://{config.domain}/dns-query")
    lines += [
        "",
        "  Config files:",
        f"    {config.bind_dir / 'named.conf'}",
        f"    {config.bind_dir / 'named.conf.options'}",
        f"    {config.bind_dir / 'named.conf.logging'}",
        f"    {config.bind_dir / 'named.conf.local'}",
    ]
    if config.use_rpz:
        lines += [
            f"    {config.bind_dir / 'zones' / 'db.rpz.local'}",
            "    /usr/local/sbin/rpz-update.sh",
        ]
    if config.domain:
        lines.append(f"    {config.bind_ssl_dir / 'cert.pem'}")
        lines.append(f"    {config.bind_ssl_dir / 'key.pem'}")
    lines += [
        "",
        "  Useful commands:",
        "    systemctl status named",
        "    journalctl -feu named",
        f"    {config.rndc_bin or 'rndc'} status",
        "    dig @127.0.0.1 example.com",
    ]
    if config.use_rpz:
        lines += [
            "    systemctl start rpz-updater.service   # manual RPZ update",
            "    systemctl status rpz-updater.timer     # check timer",
        ]
    lines += [
        "",
        sep,
    ]
    print("\n".join(lines))


# ---------------------------------------------------------------------------
# Interactive prompting
# ---------------------------------------------------------------------------


def _prompt(message: str, default: str = "") -> str:
    """Prompt the user for input with an optional default."""
    if default:
        raw = input(f"{message} [{default}]: ").strip()
        return raw if raw else default
    return input(f"{message}: ").strip()


def _prompt_yes_no(message: str, default: bool = True) -> bool:
    """Prompt for a yes/no answer."""
    suffix = " [Y/n]" if default else " [y/N]"
    raw = input(f"{message}{suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def _prompt_choice(message: str, choices: list[str], default: str = "") -> str:
    """Prompt the user to pick from a list of choices."""
    print(message)
    for i, choice in enumerate(choices, 1):
        marker = " *" if choice == default else ""
        print(f"  {i}) {choice}{marker}")
    while True:
        raw = input(f"Enter choice [1-{len(choices)}]: ").strip()
        if not raw and default:
            return default
        try:
            idx = int(raw)
            if 1 <= idx <= len(choices):
                return choices[idx - 1]
        except ValueError:
            # Maybe they typed the version string directly
            if raw in choices:
                return raw
        print(f"  Invalid choice. Please enter 1-{len(choices)}.")


def gather_config_interactive(args: argparse.Namespace) -> Config:
    """Build a Config from CLI args, prompting interactively for missing values."""
    config = Config()

    # Domain
    if args.domain:
        config.domain = args.domain
    elif not args.non_interactive:
        config.domain = _prompt(
            "Enter your domain name for TLS (leave blank to skip TLS)", ""
        )

    # Forwarders
    config.fwd1 = args.fwd1 or (
        _prompt("Upstream forwarder #1", DEFAULT_FWD1)
        if not args.non_interactive
        else DEFAULT_FWD1
    )
    config.fwd2 = args.fwd2 or (
        _prompt("Upstream forwarder #2", DEFAULT_FWD2)
        if not args.non_interactive
        else DEFAULT_FWD2
    )

    # RPZ
    if args.rpz is not None:
        config.use_rpz = args.rpz
    elif not args.non_interactive:
        config.use_rpz = _prompt_yes_no("Enable RPZ adblocking?", True)

    # RPZ timer interval
    config.rpz_timer = args.rpz_timer or (
        _prompt("RPZ update interval (systemd OnUnitActiveSec)", DEFAULT_RPZ_TIMER)
        if not args.non_interactive and config.use_rpz
        else DEFAULT_RPZ_TIMER
    )

    # Stats
    if args.stats is not None:
        config.use_stats = args.stats
    elif not args.non_interactive:
        config.use_stats = _prompt_yes_no("Enable BIND statistics channel?", False)

    # Install mode
    if args.install_mode:
        config.install_mode = args.install_mode
    elif not args.non_interactive:
        mode = _prompt_choice(
            "BIND installation mode:",
            ["apt", "source"],
            default="apt",
        )
        config.install_mode = mode

    # BIND version (for source build)
    if config.install_mode == "source":
        available_versions = fetch_bind_versions()
        if args.bind_version:
            config.bind_version = args.bind_version
        elif not args.non_interactive:
            display = available_versions[:10]  # show top 10
            config.bind_version = _prompt_choice(
                "Select BIND version to build:",
                display,
                default=display[0] if display else BIND_VERSION_FALLBACK[0],
            )
        else:
            config.bind_version = available_versions[0] if available_versions else BIND_VERSION_FALLBACK[0]

    # BIND prefix
    config.bind_prefix = args.bind_prefix or (
        _prompt("BIND install prefix", DEFAULT_BIND_PREFIX)
        if not args.non_interactive and config.install_mode == "source"
        else DEFAULT_BIND_PREFIX
    )

    config.skip_certbot = args.skip_certbot
    config.skip_firewall = args.skip_firewall
    config.non_interactive = args.non_interactive

    return config


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def build_argparser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    p = argparse.ArgumentParser(
        description="Set up BIND9 with DoT/DoH and optional RPZ adblocking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Fully interactive:
              sudo python3 bind9_setup.py

              # Non-interactive, apt mode:
              sudo python3 bind9_setup.py --non-interactive --domain dns.example.com

              # Source build, specific version:
              sudo python3 bind9_setup.py --install-mode source --bind-version 9.20.7

              # Minimal (no TLS, no RPZ):
              sudo python3 bind9_setup.py --non-interactive --rpz false --skip-certbot
        """),
    )
    p.add_argument("--domain", help="Domain name for TLS certificate")
    p.add_argument("--fwd1", help=f"Primary upstream forwarder (default: {DEFAULT_FWD1})")
    p.add_argument("--fwd2", help=f"Secondary upstream forwarder (default: {DEFAULT_FWD2})")
    p.add_argument(
        "--rpz",
        type=lambda v: v.lower() in ("true", "1", "yes"),
        default=None,
        help="Enable RPZ adblocking (true/false)",
    )
    p.add_argument("--rpz-timer", help=f"RPZ update interval (default: {DEFAULT_RPZ_TIMER})")
    p.add_argument(
        "--stats",
        type=lambda v: v.lower() in ("true", "1", "yes"),
        default=None,
        help="Enable BIND statistics channel (true/false)",
    )
    p.add_argument(
        "--install-mode",
        choices=["apt", "source"],
        help="Install BIND via apt or build from source",
    )
    p.add_argument("--bind-version", help="BIND version to build (source mode)")
    p.add_argument("--bind-prefix", help=f"Install prefix for source build (default: {DEFAULT_BIND_PREFIX})")
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Run without interactive prompts (use defaults for unset options)",
    )
    p.add_argument("--skip-certbot", action="store_true", help="Skip TLS certificate obtainment")
    p.add_argument("--skip-firewall", action="store_true", help="Skip firewall rule configuration")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    p.add_argument(
        "--reinstall",
        action="store_true",
        help="Force reinstall from source even if BIND9 is already installed",
    )
    return p


def main() -> None:
    """Entry point — orchestrates the full BIND9 setup."""
    parser = build_argparser()
    args = parser.parse_args()

    setup_logging(debug=args.debug)

    # Root check
    if os.geteuid() != 0:
        LOG.critical("This script must be run as root (use sudo).")
        sys.exit(1)

    LOG.info("=== BIND9 DoT/DoH Setup ===")

    # ---- Step 1: Gather configuration ----
    try:
        config = gather_config_interactive(args)
    except (KeyboardInterrupt, EOFError):
        print()
        LOG.info("Setup cancelled by user.")
        sys.exit(0)

    LOG.info("Configuration:")
    LOG.info("  Domain:       %s", config.domain or "(none)")
    LOG.info("  Forwarders:   %s, %s", config.fwd1, config.fwd2)
    LOG.info("  RPZ:          %s", config.use_rpz)
    LOG.info("  Stats:        %s", config.use_stats)
    LOG.info("  Install mode: %s", config.install_mode)
    if config.install_mode == "source":
        LOG.info("  BIND version: %s", config.bind_version)
        LOG.info("  Prefix:       %s", config.bind_prefix)

    # ---- Step 1b: Detect existing BIND9 and handle reinstall ----
    if args.reinstall:
        config.install_mode = "source"
        is_installed, version_str = detect_existing_bind(config)
        if is_installed:
            LOG.warning("--reinstall: existing BIND9 found: %s", version_str)
            if is_bind_from_apt():
                remove_apt_bind()
            else:
                LOG.info("Existing BIND9 is not from apt; will override via systemd unit")
    else:
        handle_existing_bind(config)

    # ---- Step 2: Install packages ----
    try:
        if config.install_mode == "apt":
            install_packages(REQUIRED_APT_PACKAGES)
        else:
            install_packages(SOURCE_BUILD_DEPS)
    except SetupError as exc:
        LOG.error("Package installation failed: %s", exc)
        LOG.exception("Details:")
        sys.exit(1)

    # ---- Step 3: Source build (if selected) ----
    if config.install_mode == "source":
        try:
            build_bind_from_source(config.bind_version, config.bind_prefix)
        except SetupError as exc:
            LOG.error("Source build failed: %s", exc)
            LOG.exception("Details:")
            sys.exit(1)

    # ---- Step 4: Detect BIND user and resolve binaries ----
    config.bind_user = detect_bind_user()
    config.rndc_bin = resolve_binary("rndc", config.bind_prefix)
    config.named_compilezone_bin = resolve_binary("named-compilezone", config.bind_prefix)
    config.named_checkconf_bin = resolve_binary("named-checkconf", config.bind_prefix)
    LOG.debug("rndc:               %s", config.rndc_bin)
    LOG.debug("named-compilezone:  %s", config.named_compilezone_bin)
    LOG.debug("named-checkconf:    %s", config.named_checkconf_bin)

    # ---- Step 5: Check BIND version / DoH support ----
    try:
        check_bind_version(config)
    except SetupError as exc:
        LOG.warning("BIND version check issue: %s", exc)
        config.doh_enabled = False

    # ---- Step 6: Obtain TLS certificate ----
    if config.domain and not config.skip_certbot:
        try:
            obtain_certificate(config.domain)
        except SetupError as exc:
            LOG.error("Certificate obtainment failed: %s", exc)
            LOG.error("You can re-run with --skip-certbot after obtaining certs manually.")
            sys.exit(1)

    # ---- Step 7: Install certificates ----
    if config.domain:
        try:
            install_certificates(config)
        except SetupError as exc:
            LOG.error("Certificate installation failed: %s", exc)
            LOG.exception("Details:")
            sys.exit(1)

    # ---- Step 8: Write BIND configuration ----
    try:
        write_bind_config(config)
    except SetupError as exc:
        LOG.error("Config writing failed: %s", exc)
        LOG.exception("Details:")
        sys.exit(1)

    # ---- Step 9: Setup RPZ ----
    try:
        setup_rpz(config)
    except SetupError as exc:
        LOG.error("RPZ setup failed: %s", exc)
        LOG.exception("Details:")
        # Non-fatal, continue

    # ---- Step 10: Configure firewall ----
    try:
        configure_firewall(config)
    except SetupError as exc:
        LOG.warning("Firewall configuration issue: %s", exc)

    # ---- Step 11: Start BIND ----
    try:
        start_bind()
    except SetupError as exc:
        LOG.error("Failed to start BIND: %s", exc)
        LOG.error("Check 'journalctl -xeu named' for details.")
        sys.exit(1)

    # ---- Step 12: Initial RPZ update ----
    if config.use_rpz:
        run_initial_rpz_update()

    # ---- Step 13: Smoke test ----
    try:
        run_smoke_test(config.domain)
    except SetupError as exc:
        LOG.warning("Smoke test issue: %s", exc)

    # ---- Step 14: Summary ----
    print_summary(config)

    LOG.info("Setup complete. Enjoy your secure DNS resolver! 🎉")


if __name__ == "__main__":
    main()
