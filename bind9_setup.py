#!/usr/bin/env python3
"""BIND9 Setup — DNS / DoT / DoH + optional RPZ adblock.

Async rewrite of bind9-setup.sh. Supports Debian 11/12, Ubuntu 20.04/22.04/24.04.
Requires root, an open port 80 (certbot) and a domain pointed at this server.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field

# ── Colours ──────────────────────────────────────────────────────────────────
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

# Fallback version list used when the ISC mirror cannot be reached.
BIND_VERSION_FALLBACK = ["9.20.7", "9.18.33"]

# Highest minor release allowed: 9.21+ is a development-only branch.
BIND_MAX_MINOR = 20

ISC_BASE = "https://downloads.isc.org/isc/bind9"

# Binaries cleaned up before a meson install to avoid file conflicts.
BIND_BINARIES = [
    "named", "named-checkconf", "named-checkzone", "named-compilezone",
    "named-journalprint", "named-nzd2nzf", "named-rrchecker", "rndc",
    "rndc-confgen", "tsig-keygen", "ddns-confgen", "delv", "dig", "host",
    "nslookup", "nsupdate", "dnssec-cds", "dnssec-dsfromkey",
    "dnssec-importkey", "dnssec-keyfromlabel", "dnssec-keygen",
    "dnssec-revoke", "dnssec-settime", "dnssec-signzone", "dnssec-verify",
    "mdig", "arpaname", "dnstap-read", "nsec3hash",
]


def info(msg: str) -> None:
    print(f"{CYAN}[INFO]{NC}  {msg}")


def ok(msg: str) -> None:
    print(f"{GREEN}[ OK ]{NC}  {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC}  {msg}")


def die(msg: str) -> None:
    print(f"{RED}[ERR ]{NC}  {msg}", file=sys.stderr)
    raise SystemExit(1)


def header(msg: str) -> None:
    print(
        f"\n{BOLD}══════════════════════════════════════\n"
        f"  {msg}\n"
        f"══════════════════════════════════════{NC}"
    )


# ── Async process / network helpers ──────────────────────────────────────────
class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], code: int, output: str):
        super().__init__(f"command failed ({code}): {' '.join(cmd)}\n{output}")
        self.cmd = cmd
        self.code = code
        self.output = output


async def run(
    *cmd: str,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[int, str]:
    """Run a subprocess asynchronously. Returns (returncode, combined output)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE if capture else None,
        stderr=asyncio.subprocess.STDOUT if capture else None,
        env=env,
        cwd=cwd,
    )
    out_b, _ = await proc.communicate()
    out = out_b.decode(errors="replace") if out_b else ""
    code = proc.returncode or 0
    if check and code != 0:
        raise CommandError(list(cmd), code, out)
    return code, out


async def run_ok(*cmd: str, **kw: object) -> bool:
    """Run a command, swallowing failures. Returns success boolean."""
    try:
        code, _ = await run(*cmd, check=False, **kw)  # type: ignore[arg-type]
        return code == 0
    except FileNotFoundError:
        return False


async def http_get_text(url: str, timeout: int = 30) -> str:
    """Fetch a URL body as text without blocking the event loop."""
    def _get() -> str:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode(errors="replace")

    return await asyncio.to_thread(_get)


async def curl_download(url: str, dest: str, *, max_time: int = 300) -> bool:
    """Download a file with curl, mirroring the retry policy of the bash script."""
    return await run_ok(
        "curl", "-sS", "-f", "--connect-timeout", "10",
        "--max-time", str(max_time), "--retry", "3",
        "--retry-all-errors", "--retry-delay", "5",
        "-o", dest, url,
    )


# ── Version discovery ────────────────────────────────────────────────────────
def parse_bind_versions(html: str, max_minor: int = BIND_MAX_MINOR) -> list[str]:
    """Extract stable x.y.z versions from the ISC index, newest first.

    Drops rc/beta/alpha pre-releases and development branches above max_minor.
    """
    found = re.findall(r"9\.\d+\.\d+(?=/)", html)
    keep = [v for v in set(found) if int(v.split(".")[1]) <= max_minor]
    keep.sort(key=lambda v: tuple(int(p) for p in v.split(".")), reverse=True)
    return keep


async def fetch_bind_versions() -> tuple[list[str], bool]:
    """Return (versions, online). Falls back to a built-in list when offline."""
    try:
        html = await http_get_text(f"{ISC_BASE}/", timeout=30)
        versions = parse_bind_versions(html)
        if versions:
            return versions, True
    except Exception:
        pass
    return list(BIND_VERSION_FALLBACK), False


def parse_named_version(named_output: str) -> tuple[int, int] | None:
    """Parse 'BIND 9.18.33-...' output into a (major, minor) tuple."""
    m = re.search(r"BIND (\d+)\.(\d+)", named_output)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def doh_supported(major: int, minor: int) -> bool:
    """DoH (port 443) requires BIND 9.18+."""
    return major > 9 or (major == 9 and minor >= 18)


# ── Configuration model ──────────────────────────────────────────────────────
@dataclass
class Config:
    domain: str = ""
    fwd1: str = "8.8.8.8"
    fwd2: str = "1.1.1.1"
    use_rpz: bool = False
    rpz_timer: str = "*-*-* 04:00:00"
    use_stats: bool = False
    install_mode: str = "distro"  # "distro" | "source"
    bind_src_ver: str = ""
    bind_prefix: str = "/usr"
    force_source_reinstall: bool = False
    # Runtime-resolved values
    bind_user: str = "bind"
    doh_enabled: bool = False
    bind_dir: str = "/etc/bind"
    named_compilezone: str = "/usr/sbin/named-compilezone"
    rndc: str = "/usr/sbin/rndc"
    extra_path: list[str] = field(default_factory=list)

    @property
    def bind_ssl(self) -> str:
        return f"{self.bind_dir}/ssl"


# ── Config-file renderers (pure, unit-testable) ──────────────────────────────
def render_named_conf_options(cfg: Config) -> str:
    rpz_block = ""
    if cfg.use_rpz:
        rpz_block = (
            "\n    response-policy {\n"
            '        zone "rpz.adblock";\n'
            "    };\n"
        )

    stats_block = ""
    if cfg.use_stats:
        stats_block = (
            "\nstatistics-channels {\n"
            "    inet 127.0.0.1 port 8053 allow { 127.0.0.1; };\n"
            "};\n"
        )

    doh_listen = ""
    if cfg.doh_enabled:
        doh_listen = (
            "\n    listen-on port 443\n"
            "        tls local-tls\n"
            "        http local-http-server { any; };"
        )

    return f"""options {{
    directory              "/var/cache/bind";
    managed-keys-directory "/var/lib/bind";

    // ── Recursion ────────────────────────────────────────────────────────
    recursion       yes;
    allow-recursion {{ any; }};   // restrict to your subnets in production
    allow-query     {{ any; }};

    // ── Forwarding ───────────────────────────────────────────────────────
    forward  only;
    forwarders {{
        {cfg.fwd1};
        {cfg.fwd2};
    }};

    // ── Rate limiting ────────────────────────────────────────────────────
    rate-limit {{
        responses-per-second 20;
        errors-per-second     5;
        all-per-second       50;
        log-only             no;
        window               15;
    }};

    max-recursion-depth   20;
    max-recursion-queries 100;

    // ── DNSSEC ───────────────────────────────────────────────────────────
    dnssec-validation auto;

    // ── Misc hardening ───────────────────────────────────────────────────
    minimal-any yes;
    version  "none";
    hostname "none";
    server-id "none";
{rpz_block}
    // ── Cache ────────────────────────────────────────────────────────────
    max-cache-size 200m;
    max-cache-ttl  86400;
    min-cache-ttl  60;

    // ── Listeners ────────────────────────────────────────────────────────
    listen-on      port 53  {{ any; }};
    listen-on-v6   port 53  {{ any; }};

    listen-on port 853
        tls local-tls
        {{ any; }};
    listen-on-v6 port 853
        tls local-tls
        {{ any; }};{doh_listen}
}};

tls local-tls {{
    cert-file "{cfg.bind_ssl}/fullchain.pem";
    key-file  "{cfg.bind_ssl}/privkey.pem";
}};

http local-http-server {{
    endpoints {{ "/dns-query"; }};
}};
{stats_block}"""


def render_logging_conf() -> str:
    return """logging {
    channel "main_log" {
        file "/var/log/named/named.log" versions 3 size 20m;
        severity warning;
        print-category yes;
        print-severity yes;
        print-time     yes;
    };
    category default { "main_log"; };
    category queries { "null"; };     // disable query logging (noisy); change to "main_log" to enable
};
"""


def render_named_conf_local(use_rpz: bool) -> str:
    if use_rpz:
        return (
            'zone "rpz.adblock" {\n'
            "    type primary;\n"
            '    file "/var/lib/bind/db.rpz.adblock.raw";\n'
            "    masterfile-format raw;\n"
            "};\n"
        )
    return "// No local zones configured.\n"


def render_named_conf() -> str:
    return (
        'include "/etc/bind/named.conf.options";\n'
        'include "/etc/bind/named.conf.local";\n'
        'include "/etc/bind/named.conf.default-zones";\n'
        'include "/etc/bind/named.conf.logging";\n'
    )


def render_placeholder_zone() -> str:
    return """$TTL 300
@ SOA localhost. root.localhost. (
    1       ; serial
    3600    ; refresh
    600     ; retry
    86400   ; expire
    300 )   ; minimum
  NS  localhost.
"""


def render_deploy_hook(rndc_bin: str) -> str:
    return f"""#!/bin/bash
# Auto-deployed by bind9_setup.py — copies renewed certs and reloads BIND
BIND_SSL="/etc/bind/ssl"
BIND_USER="$(id -un named 2>/dev/null || echo bind)"

cp -L "$RENEWED_LINEAGE/fullchain.pem" "$BIND_SSL/fullchain.pem"
cp -L "$RENEWED_LINEAGE/privkey.pem"   "$BIND_SSL/privkey.pem"
chown "root:$BIND_USER" "$BIND_SSL/fullchain.pem" "$BIND_SSL/privkey.pem"
chmod 640                "$BIND_SSL/fullchain.pem" "$BIND_SSL/privkey.pem"

"{rndc_bin}" reconfig && echo "[$(date)] BIND reloaded after cert renewal for $RENEWED_LINEAGE." \\
  || echo "[$(date)] WARNING: rndc reconfig failed after renewal."
"""


def render_rpz_script() -> str:
    return r"""#!/bin/bash
# RPZ adblock zone updater — hagezi/dns-blocklists pro
# Managed by systemd rpz-updater.service / rpz-updater.timer
set -euo pipefail

# Dynamic util paths
NAMED_COMPILEZONE_BIN=$(which named-compilezone 2>/dev/null || echo "/usr/sbin/named-compilezone")
RNDC_BIN=$(which rndc 2>/dev/null || echo "/usr/sbin/rndc")

URL="https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/rpz/pro.txt"
ZONE_NAME="rpz.adblock"
BIND_DIR="/var/lib/bind"
TEXT_FILE="$BIND_DIR/db.rpz.adblock.txt"
RAW_FILE="$BIND_DIR/db.rpz.adblock.raw"
KEY_FILE="/etc/bind/rndc.key"

# Temp files on the same filesystem as the destination — ensures atomic mv
TEMP_FILE=$(mktemp -p "$BIND_DIR")
TEMP_RAW=$(mktemp -p "$BIND_DIR")

cleanup() {
    rm -f "$TEMP_FILE" "$TEMP_RAW"
}
trap cleanup EXIT

if ! curl -sS -f --connect-timeout 10 --max-time 180 \
        --retry 3 --retry-all-errors --retry-delay 5 \
        -o "$TEMP_FILE" "$URL"; then
    echo "Error: Download failed." >&2
    exit 1
fi

if [ ! -s "$TEMP_FILE" ]; then
    echo "Error: Downloaded file is empty." >&2
    exit 1
fi

[ -f "$TEXT_FILE" ] || touch "$TEXT_FILE"

if cmp -s "$TEMP_FILE" "$TEXT_FILE"; then
    echo "No changes detected. Skipping update."
    exit 0
fi

echo "Update detected. Compiling zone..."

if ! "$NAMED_COMPILEZONE_BIN" -f text -F raw -q -o "$TEMP_RAW" "$ZONE_NAME" "$TEMP_FILE"; then
    echo "Error: Zone compilation failed." >&2
    exit 1
fi

chmod 644 "$TEMP_RAW" "$TEMP_FILE"

# Atomic replacement (same filesystem guaranteed by mktemp -p)
mv "$TEMP_RAW" "$RAW_FILE"
mv "$TEMP_FILE" "$TEXT_FILE"

if "$RNDC_BIN" -k "$KEY_FILE" reload "$ZONE_NAME"; then
    echo "Zone $ZONE_NAME reloaded successfully."
else
    echo "Error: rndc reload failed." >&2
    exit 1
fi
"""


def render_rpz_service(rpz_script: str, bind_user: str) -> str:
    return f"""[Unit]
Description=Update RPZ adblock zone (hagezi/dns-blocklists pro)
After=network-online.target named.service
Wants=network-online.target

[Service]
Type=oneshot
User={bind_user}
Group={bind_user}
ExecStart={rpz_script}

# Hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
StateDirectory=bind
ReadWritePaths=/var/lib/bind /etc/bind
"""


def render_rpz_timer(rpz_timer: str) -> str:
    return f"""[Unit]
Description=Timer for RPZ adblock zone update

[Timer]
OnCalendar={rpz_timer}
Unit=rpz-updater.service
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
"""


def render_named_override(prefix: str) -> str:
    return f"""[Service]
ExecStart=
ExecStart={prefix}/sbin/named -f -u bind -c /etc/bind/named.conf
"""


def render_logrotate(rndc_bin: str) -> str:
    return f"""/var/log/named/named.log {{
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 640 bind bind
    postrotate
        {rndc_bin} reopen > /dev/null 2>&1 || true
    endscript
}}
"""


# ── Interactive prompts ──────────────────────────────────────────────────────
def prompt(question: str, default: str = "") -> str:
    q = question
    if default:
        q += f" [{default}]"
    reply = input(f"  {q}: ").strip()
    return reply or default


def ask_yes(question: str) -> bool:
    return input(f"  {question}: ").strip().lower().startswith("y")


def write_file(path: str, content: str, *, mode: int | None = None) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    if mode is not None:
        os.chmod(path, mode)


# ── Phases ───────────────────────────────────────────────────────────────────
async def detect_existing_bind(cfg: Config) -> None:
    """Offer a source reinstall when BIND is already present."""
    if not shutil.which("named"):
        return
    _, out = await run("named", "-v", check=False, capture=True)
    warn(f"Existing BIND9 detected: {out.strip().splitlines()[0] if out.strip() else 'unknown'}")
    if not ask_yes("Do you want to reinstall BIND9 from source? [y/N]"):
        info("Keeping existing BIND9 installation.")
        return
    code, dpkg_out = await run("dpkg", "-l", "bind9", check=False, capture=True)
    if code == 0 and any(line.startswith("ii") for line in dpkg_out.splitlines()):
        info("Existing BIND9 was installed via apt. Removing apt packages first...")
        await run_ok("systemctl", "stop", "named")
        await run_ok("systemctl", "stop", "bind9")
        await run_ok("apt-get", "remove", "--purge", "-y", "bind9", "bind9utils", "bind9-utils")
        await run_ok("apt-get", "autoremove", "-y")
        ok("Apt-installed BIND9 packages removed.")
    else:
        info("Existing BIND9 is not from apt (likely a previous source build).")
        info("The new source build will override it via the systemd unit.")
    cfg.force_source_reinstall = True


async def gather_config(cfg: Config, versions_task: asyncio.Task) -> None:
    header("Configuration")

    cfg.domain = prompt("Domain for DoT/DoH (e.g. dns.example.com)", "")
    if not cfg.domain:
        die("Domain is required.")

    cfg.fwd1 = prompt("Upstream forwarder 1", "8.8.8.8")
    cfg.fwd2 = prompt("Upstream forwarder 2", "1.1.1.1")

    cfg.use_rpz = ask_yes("Enable RPZ adblock (hagezi/dns-blocklists pro list)? [y/N]")
    if cfg.use_rpz:
        cfg.rpz_timer = prompt("RPZ timer schedule (systemd OnCalendar)", "*-*-* 04:00:00")

    cfg.use_stats = ask_yes("Enable statistics channel on 127.0.0.1:8053? [y/N]")

    print()
    print(f"  {BOLD}Where should BIND9 come from?{NC}")
    print("    1) Distro mirror (apt)          — fast, whatever your release ships")
    print("    2) Build a specific version from ISC source")
    choice = prompt("Choose 1 or 2", "1")

    if cfg.force_source_reinstall:
        cfg.install_mode = "source"
        choice = "2"

    if choice == "2" or cfg.install_mode == "source":
        cfg.install_mode = "source"
        info("Fetching available BIND9 versions from downloads.isc.org ...")
        versions, online = await versions_task
        if not online:
            warn("Could not reach ISC mirror — offering a built-in fallback list.")

        print()
        print(f"  {BOLD}Available BIND9 versions{NC} (newest first):")
        shown = versions[:15]
        for i, ver in enumerate(shown, start=1):
            print(f"    {i:2d}) {ver}")
        sel = prompt("Select a version number (or type an exact version)", "1")
        if sel.isdigit() and 1 <= int(sel) <= len(shown):
            cfg.bind_src_ver = shown[int(sel) - 1]
        elif re.fullmatch(r"9\.\d+\.\d+", sel):
            cfg.bind_src_ver = sel
        else:
            die(f"Invalid selection: '{sel}'.")

        print()
        if ask_yes("Overwrite the distro BIND binaries in /usr? [y/N]"):
            cfg.bind_prefix = "/usr"
        else:
            cfg.bind_prefix = "/usr/local"

    print()
    print(f"  {BOLD}Domain:{NC}     {cfg.domain}")
    print(f"  {BOLD}Forwarders:{NC} {cfg.fwd1} / {cfg.fwd2}")
    if cfg.install_mode == "source":
        print(f"  {BOLD}BIND9:{NC}      build {cfg.bind_src_ver} from source (prefix {cfg.bind_prefix})")
    else:
        print(f"  {BOLD}BIND9:{NC}      distro mirror (apt)")
    print(f"  {BOLD}RPZ:{NC}        {'enabled (' + cfg.rpz_timer + ')' if cfg.use_rpz else 'disabled'}")
    print(f"  {BOLD}Stats:{NC}      {'enabled' if cfg.use_stats else 'disabled'}")
    print()
    if input("  Proceed? [Y/n]: ").strip().lower().startswith("n"):
        raise SystemExit(0)


async def install_packages(cfg: Config) -> None:
    header("Installing packages")
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    await run("apt-get", "update", "-qq", env=env)
    await run(
        "apt-get", "install", "-y",
        "bind9", "bind9utils", "dnsutils", "certbot", "curl", "util-linux",
        env=env,
    )
    ok("Base packages installed.")


async def build_bind_from_source(cfg: Config, ver: str, prefix: str) -> None:
    """Compile BIND9 from the ISC tarball with DoH (libnghttp2) support."""
    base = f"{ISC_BASE}/{ver}"
    tarball = f"bind-{ver}.tar.xz"
    header(f"Building BIND {ver} from source (prefix {prefix})")

    info("Installing build dependencies...")
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    await run(
        "apt-get", "install", "-y",
        "build-essential", "pkg-config", "xz-utils", "perl",
        "libssl-dev", "libuv1-dev", "libcap-dev", "libnghttp2-dev",
        "libxml2-dev", "libjson-c-dev", "liburcu-dev", "libjemalloc-dev",
        "liblmdb-dev", "libmaxminddb-dev",
        "meson", "ninja-build", "python3-pip",
        env=env,
    )

    work = tempfile.mkdtemp()
    try:
        tar_path = os.path.join(work, tarball)
        info(f"Downloading {tarball} ...")
        # Fetch the tarball and its checksum file concurrently.
        dl_task = asyncio.create_task(curl_download(f"{base}/{tarball}", tar_path))
        sum_task = asyncio.create_task(
            curl_download(f"{base}/{tarball}.sha512.asc",
                          tar_path + ".sha512.asc", max_time=30)
        )
        if not await dl_task:
            die(f"Download failed: {base}/{tarball}")

        if await sum_task:
            want = ""
            with open(tar_path + ".sha512.asc") as fh:
                m = re.search(r"[0-9a-f]{128}", fh.read())
                if m:
                    want = m.group(0)
            if want:
                _, got_out = await run("sha512sum", tar_path, capture=True)
                got = got_out.split()[0]
                if want != got:
                    die(f"Checksum mismatch for {tarball} (expected {want}, got {got}).")
                ok("Checksum verified.")
            else:
                warn("No checksum found in published file; skipping verification.")
        else:
            warn("Could not fetch checksum file; skipping verification.")

        info("Extracting...")
        await run("tar", "-xf", tar_path, "-C", work)
        src = os.path.join(work, f"bind-{ver}")
        if not os.path.isdir(src):
            die(f"Unexpected tarball layout: {src} not found.")

        if os.path.isfile(os.path.join(src, "meson.build")):
            info("Detected meson build system (BIND 9.21+).")
            meson_args = (
                ["--prefix=/usr", "--sysconfdir=/etc/bind", "--localstatedir=/var"]
                if prefix == "/usr" else [f"--prefix={prefix}"]
            )
            info(f"Configuring (meson setup {' '.join(meson_args)}) ...")
            if not await run_ok("meson", "setup",
                                os.path.join(src, "builddir"), src, *meson_args):
                die("meson setup failed — check the build output above.")

            info("Compiling (this can take several minutes)...")
            if not await run_ok("ninja", "-C", os.path.join(src, "builddir"),
                                f"-j{os.cpu_count() or 1}"):
                die("ninja build failed.")

            info("Cleaning up old BIND binaries to prevent meson install conflicts...")
            for binname in BIND_BINARIES:
                for d in (f"{prefix}/bin", f"{prefix}/sbin", "/usr/bin", "/usr/sbin"):
                    try:
                        os.remove(os.path.join(d, binname))
                    except OSError:
                        pass

            if not await run_ok("meson", "install", "-C", os.path.join(src, "builddir")):
                die("meson install failed.")
        elif os.path.isfile(os.path.join(src, "configure")):
            info("Detected autotools build system (BIND ≤9.20).")
            cfg_args = ["--with-libnghttp2"]
            if prefix == "/usr":
                cfg_args += ["--prefix=/usr", "--sysconfdir=/etc/bind", "--localstatedir=/var"]
            else:
                cfg_args += [f"--prefix={prefix}"]
            info(f"Configuring ({' '.join(cfg_args)}) ...")
            if not await run_ok("./configure", *cfg_args, cwd=src):
                die("./configure failed — check the build output above.")
            info("Compiling (this can take several minutes)...")
            if not await run_ok("make", f"-j{os.cpu_count() or 1}", cwd=src):
                die("make failed.")
            if not await run_ok("make", "install", cwd=src):
                die("make install failed.")
        else:
            die(f"Cannot determine build system: neither meson.build nor configure found in {src}")

        await run("ldconfig")

        if prefix != "/usr":
            write_file(
                "/etc/systemd/system/named.service.d/override.conf",
                render_named_override(prefix),
            )
            await run("systemctl", "daemon-reload")
            cfg.extra_path = [f"{prefix}/sbin", f"{prefix}/bin"]
            os.environ["PATH"] = os.pathsep.join(cfg.extra_path + [os.environ.get("PATH", "")])
            ok(f"named.service repointed to {prefix}/sbin/named.")

        _, vout = await run(f"{prefix}/sbin/named", "-v", check=False, capture=True)
        ok(f"BIND {ver} installed: {vout.strip().splitlines()[0] if vout.strip() else ver}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def which_or(name: str, fallback: str, extra_path: list[str]) -> str:
    path = os.pathsep.join(extra_path + [os.environ.get("PATH", "")]) if extra_path else None
    return shutil.which(name, path=path) or fallback


async def resolve_bind(cfg: Config) -> None:
    """Resolve util paths, verify version and enable DoH where supported."""
    cfg.named_compilezone = which_or("named-compilezone", "/usr/sbin/named-compilezone", cfg.extra_path)
    cfg.rndc = which_or("rndc", "/usr/sbin/rndc", cfg.extra_path)

    _, vout = await run("named", "-v", check=False, capture=True)
    parsed = parse_named_version(vout)
    major, minor = parsed if parsed else (0, 0)
    info(f"Detected BIND {major}.{minor}")

    if cfg.install_mode != "source" and not doh_supported(major, minor):
        warn(f"BIND {major}.{minor} detected — DoH (port 443) requires BIND 9.18+.")
        warn("DoT (port 853) will still work. Trying to install bind9 from backports...")
        codename = ""
        try:
            with open("/etc/os-release") as fh:
                osrel = fh.read()
            m = re.search(r"VERSION_CODENAME=([^\n]+)", osrel)
            if m:
                codename = m.group(1).strip().strip('"')
            is_debian = "debian" in osrel.lower()
        except OSError:
            is_debian = False
        if codename and is_debian:
            write_file(
                "/etc/apt/sources.list.d/backports.list",
                f"deb http://deb.debian.org/debian {codename}-backports main\n",
            )
            await run("apt-get", "update", "-qq")
            if await run_ok("apt-get", "install", "-y", "-t",
                            f"{codename}-backports", "bind9", "bind9utils"):
                ok("Updated BIND from backports.")
            else:
                warn(f"Backports install failed; continuing with {major}.{minor}.")
        _, vout = await run("named", "-v", check=False, capture=True)
        parsed = parse_named_version(vout)
        major, minor = parsed if parsed else (major, minor)

    cfg.doh_enabled = doh_supported(major, minor)
    if cfg.doh_enabled:
        ok(f"DoH support confirmed (BIND {major}.{minor}).")
    else:
        warn(f"DoH disabled (BIND {major}.{minor} < 9.18). DoT + plain DNS will work.")

    _, uid_out = await run("id", "-un", "named", check=False, capture=True)
    cfg.bind_user = uid_out.strip() or "bind"
    return None


async def obtain_certificate(cfg: Config) -> None:
    header("Obtaining TLS certificate via certbot")
    info(f"Domain {cfg.domain} must resolve to this server and port 80 must be reachable.")

    stopped_svc = ""
    for svc in ("nginx", "apache2", "lighttpd", "caddy"):
        if await run_ok("systemctl", "is-active", "--quiet", svc):
            stopped_svc = svc
            await run("systemctl", "stop", svc)
            warn(f"Temporarily stopped {svc} to free port 80.")
            break

    if not await run_ok(
        "certbot", "certonly", "--standalone", "--non-interactive",
        "--agree-tos", "--register-unsafely-without-email", "-d", cfg.domain,
    ):
        die(f"Certbot failed. Verify that {cfg.domain} points here and port 80/tcp is open.")

    if stopped_svc:
        await run("systemctl", "start", stopped_svc)
        ok(f"Restarted {stopped_svc}.")

    cert_src = f"/etc/letsencrypt/live/{cfg.domain}"
    os.makedirs(cfg.bind_ssl, exist_ok=True)
    for fname in ("fullchain.pem", "privkey.pem"):
        shutil.copyfile(f"{cert_src}/{fname}", f"{cfg.bind_ssl}/{fname}")
    await run("chown", f"root:{cfg.bind_user}",
              f"{cfg.bind_ssl}/fullchain.pem", f"{cfg.bind_ssl}/privkey.pem")
    for fname in ("fullchain.pem", "privkey.pem"):
        os.chmod(f"{cfg.bind_ssl}/{fname}", 0o640)
    ok(f"Certificate installed to {cfg.bind_ssl}.")

    write_file(
        "/etc/letsencrypt/renewal-hooks/deploy/bind9-reload.sh",
        render_deploy_hook(cfg.rndc), mode=0o755,
    )
    ok("Certbot renewal hook installed.")


async def write_bind_config(cfg: Config) -> None:
    header("Writing BIND9 configuration")

    for f in ("named.conf", "named.conf.options", "named.conf.local"):
        path = f"{cfg.bind_dir}/{f}"
        if os.path.isfile(path):
            shutil.copyfile(path, f"{path}.bak.{int(time.time())}")

    write_file(f"{cfg.bind_dir}/named.conf.options", render_named_conf_options(cfg))

    os.makedirs("/var/log/named", exist_ok=True)
    await run("chown", f"{cfg.bind_user}:{cfg.bind_user}", "/var/log/named")
    os.chmod("/var/log/named", 0o755)
    write_file(f"{cfg.bind_dir}/named.conf.logging", render_logging_conf())

    write_file(f"{cfg.bind_dir}/named.conf.local", render_named_conf_local(cfg.use_rpz))

    if cfg.use_rpz:
        raw_file = "/var/lib/bind/db.rpz.adblock.raw"
        txt_file = "/var/lib/bind/db.rpz.adblock.txt"
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(render_placeholder_zone())
            zone_tmp = tmp.name
        try:
            if not await run_ok(cfg.named_compilezone, "-f", "text", "-F", "raw", "-q",
                                "-o", raw_file, "rpz.adblock", zone_tmp):
                die("named-compilezone failed on placeholder zone.")
        finally:
            os.unlink(zone_tmp)
        open(txt_file, "a").close()
        await run("chown", f"{cfg.bind_user}:{cfg.bind_user}", raw_file, txt_file)
        os.chmod(raw_file, 0o644)
        os.chmod(txt_file, 0o644)
        ok(f"Placeholder RPZ zone created ({raw_file}).")

    write_file(f"{cfg.bind_dir}/named.conf", render_named_conf())

    if not await run_ok("named-checkconf", f"{cfg.bind_dir}/named.conf"):
        die("named.conf validation failed! Check output above.")
    ok("BIND configuration written and validated.")


async def deploy_rpz(cfg: Config) -> None:
    if not cfg.use_rpz:
        return
    header("Deploying RPZ auto-update")
    rpz_script = "/etc/bind/update-rpz.sh"
    write_file(rpz_script, render_rpz_script(), mode=0o750)
    await run("chown", f"root:{cfg.bind_user}", rpz_script)
    ok(f"RPZ update script deployed to {rpz_script}.")

    write_file("/etc/systemd/system/rpz-updater.service",
               render_rpz_service(rpz_script, cfg.bind_user))
    write_file("/etc/systemd/system/rpz-updater.timer",
               render_rpz_timer(cfg.rpz_timer))
    await run("systemctl", "daemon-reload")
    await run("systemctl", "enable", "--now", "rpz-updater.timer")
    ok(f"systemd timer enabled: rpz-updater.timer ({cfg.rpz_timer}, ±5 min jitter).")


async def setup_logrotate(cfg: Config) -> None:
    write_file("/etc/logrotate.d/named-custom", render_logrotate(cfg.rndc))


async def configure_firewall(cfg: Config) -> None:
    header("Firewall")
    ufw_active = False
    if shutil.which("ufw"):
        _, status = await run("ufw", "status", check=False, capture=True)
        ufw_active = "Status: active" in status
    if ufw_active:
        await run_ok("ufw", "allow", "53/tcp", "comment", "DNS")
        await run_ok("ufw", "allow", "53/udp", "comment", "DNS")
        await run_ok("ufw", "allow", "853/tcp", "comment", "DoT")
        if cfg.doh_enabled:
            await run_ok("ufw", "allow", "443/tcp", "comment", "DoH")
        await run_ok("ufw", "reload")
        ok(f"UFW rules added (53, 853{', 443' if cfg.doh_enabled else ''}).")
    elif shutil.which("iptables"):
        warn("UFW not active. Adding iptables rules manually.")
        await run_ok("iptables", "-I", "INPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
        await run_ok("iptables", "-I", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT")
        await run_ok("iptables", "-I", "INPUT", "-p", "tcp", "--dport", "853", "-j", "ACCEPT")
        if cfg.doh_enabled:
            await run_ok("iptables", "-I", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT")
        warn("iptables rules are not persistent — install iptables-persistent to save them.")
    else:
        extra = ", 443/tcp" if cfg.doh_enabled else ""
        warn(f"No firewall tool found. Open ports 53/tcp+udp, 853/tcp{extra} manually.")


async def start_named(cfg: Config) -> None:
    header("Starting BIND9")
    await run("systemctl", "enable", "named")
    await run("systemctl", "restart", "named")
    await asyncio.sleep(2)
    if not await run_ok("systemctl", "is-active", "--quiet", "named"):
        die("named failed to start. Run: journalctl -xe -u named")
    ok("named is running.")


async def initial_rpz_update(cfg: Config) -> None:
    if not cfg.use_rpz:
        return
    header("Running initial RPZ update")
    info("Downloading hagezi pro blocklist via systemd service (may take a minute)...")
    if await run_ok("systemctl", "start", "rpz-updater.service"):
        ok("Initial RPZ update complete.")
    else:
        warn(f"Initial RPZ update failed. It will retry at the next timer trigger ({cfg.rpz_timer}).")
        warn("Check logs: journalctl -u rpz-updater.service")
        warn("Run manually: systemctl start rpz-updater.service")


async def smoke_test(cfg: Config) -> None:
    header("Smoke test")
    if not shutil.which("dig"):
        warn("dig not found — skipping smoke test.")
        return
    _, result = await run("dig", "+short", "+timeout=5", "@127.0.0.1",
                          "example.com", "A", check=False, capture=True)
    result = result.strip()
    if result:
        ok(f"dig @127.0.0.1 example.com → {result}")
    else:
        warn("DNS query returned empty result. Check named logs: journalctl -u named")


def print_summary(cfg: Config, bind_ver: str) -> None:
    print()
    print(f"{BOLD}{GREEN}╔══════════════════════════════════════════╗")
    print("║         Setup complete! ✓                ║")
    print(f"╚══════════════════════════════════════════╝{NC}")
    print()
    print(f"  {BOLD}Plain DNS{NC}   →  {cfg.domain}:53  (TCP/UDP)")
    print(f"  {BOLD}DNS-over-TLS{NC} →  {cfg.domain}:853")
    if cfg.doh_enabled:
        print(f"  {BOLD}DNS-over-HTTPS{NC} →  https://{cfg.domain}/dns-query")
    print()
    if cfg.install_mode == "source":
        print(f"  {BOLD}BIND9:{NC}      {bind_ver} (built from source, prefix {cfg.bind_prefix})")
    else:
        print(f"  {BOLD}BIND9:{NC}      {bind_ver} (distro mirror)")
    print()
    print(f"  {BOLD}Config files:{NC}")
    print(f"    {cfg.bind_dir}/named.conf.options")
    print(f"    {cfg.bind_dir}/named.conf.local")
    print(f"    {cfg.bind_dir}/named.conf.logging")
    print(f"    {cfg.bind_ssl}/  (TLS certs)")
    if cfg.use_rpz:
        print()
        print(f"  {BOLD}RPZ:{NC}")
        print("    Update script: /etc/bind/update-rpz.sh")
        print(f"    Timer:         {cfg.rpz_timer}  (±5 min jitter)")
        print("    Logs:          journalctl -u rpz-updater.service")
    print()
    print(f"  {BOLD}Useful commands:{NC}")
    print("    systemctl status named")
    print("    journalctl -u named -f")
    print(f"    named-checkconf {cfg.bind_dir}/named.conf")
    print("    rndc status")
    print("    certbot renew --dry-run")
    if cfg.use_rpz:
        print("    systemctl list-timers rpz-updater.timer")
    print()


async def sanity_checks() -> None:
    if os.geteuid() != 0:
        die(f"Run as root (sudo {sys.argv[0]}).")
    if not os.path.isfile("/etc/debian_version"):
        die("Only Debian/Ubuntu is supported.")


async def main() -> None:
    await sanity_checks()
    cfg = Config()

    # Kick off the (network-bound) version listing early so it overlaps prompts.
    versions_task = asyncio.create_task(fetch_bind_versions())

    await detect_existing_bind(cfg)
    await gather_config(cfg, versions_task)
    if not versions_task.done():
        versions_task.cancel()

    await install_packages(cfg)
    if cfg.install_mode == "source":
        await build_bind_from_source(cfg, cfg.bind_src_ver, cfg.bind_prefix)

    await resolve_bind(cfg)
    await obtain_certificate(cfg)
    await write_bind_config(cfg)
    await deploy_rpz(cfg)
    await setup_logrotate(cfg)
    await configure_firewall(cfg)
    await start_named(cfg)
    await initial_rpz_update(cfg)
    await smoke_test(cfg)

    _, vout = await run("named", "-v", check=False, capture=True)
    parsed = parse_named_version(vout)
    bind_ver = f"{parsed[0]}.{parsed[1]}" if parsed else "unknown"
    print_summary(cfg, bind_ver)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        die("Interrupted.")
