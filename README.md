# dnsdist-doh-ip

Two self-contained Bash installers for standing up a public, encrypted DNS
resolver on a Debian/Ubuntu server — one built on **dnsdist**, the other on
**BIND9**. Both expose DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) and obtain
their own Let's Encrypt certificates. Pick whichever backend you prefer; you do
not need both.

| | `dnsdist-setup.sh` | `bind9-setup.sh` |
|---|---|---|
| Role | DoH/DoT **front-end** that forwards to public resolvers | Full **recursive/forwarding** resolver |
| Cert subject | Server's **public IP** (RFC 8738 IP cert) | A **domain name** you point at the server |
| Upstreams | Google / Cloudflare / Quad9 over DoH | Two forwarders you choose (default 8.8.8.8 / 1.1.1.1) |
| Ad-blocking | Optional dnsdist `SuffixMatchNode` blocklist | Optional BIND **RPZ** zone (hagezi pro) |
| Cert tool | `acme.sh` (6-day short-lived certs) | `certbot` (standalone) |

Both scripts must run as **root**, target Debian 11/12 and Ubuntu
20.04–24.04, and need inbound port **80** reachable during issuance plus
**443/853** open afterward.

---

## `dnsdist-setup.sh`

A thin encrypted front-end. dnsdist terminates DoH (443) and DoT (853) on the
server's **public IP** and load-balances queries out to Google, Cloudflare and
Quad9 over validated outgoing DoH.

**What it does**
1. Detects the public IPv4 (`ifconfig.me`) and installs `dnsdist` from the
   official PowerDNS repo, plus `acme.sh`.
2. Issues a Let's Encrypt **IP-address** certificate (short-lived, 6-day
   profile) via the standalone http-01 challenge, and installs a 12-hour
   renewal cron job.
3. Writes `/etc/dnsdist/dnsdist.conf` with a packet cache, QPS-per-IP rate
   limiting, and `bind.`/`server.` chaos-query hardening.
4. *(optional)* Prompts to enable an ad/tracker **blocklist**, downloaded to
   `/etc/dnsdist/blocklist.txt` and refreshed daily by cron.
5. Grants `CAP_NET_BIND_SERVICE` via a systemd drop-in and starts the service.

**Run**
```bash
sudo ./dnsdist-setup.sh
```

**Endpoints**
- DoH → `https://<public-ip>/dns-query`
- DoT → `tls://<public-ip>:853`

> No domain name required — the certificate is issued for the IP itself.

---

## `bind9-setup.sh`

A complete BIND9 resolver serving plain DNS (53), DoT (853) and — on BIND
9.18+ — DoH (443) for a **domain** you control.

**What it does**
1. Prompts for the domain, two upstream forwarders, optional **RPZ** ad-block,
   and an optional stats channel.
2. Lets you choose where BIND9 comes from (see below).
3. Obtains a Let's Encrypt certificate for the domain via `certbot --standalone`
   and installs a renewal deploy-hook that reloads BIND.
4. Writes a hardened `named.conf.*` set (DNSSEC validation, rate limiting,
   cache tuning, minimal version/hostname disclosure) and the TLS/HTTP
   listeners.
5. *(optional)* Deploys an **RPZ** zone (hagezi `dns-blocklists` pro) with a
   systemd timer that refreshes it on a schedule you pick.
6. Configures logging/logrotate, opens the firewall (UFW or iptables), starts
   `named`, and runs a `dig` smoke test.

**Choosing the BIND9 version**

Early in the run the script asks where BIND should come from:

1. **Distro mirror (apt)** — fast; installs whatever your release ships. If
   that's older than 9.18 (so no DoH) it tries Debian backports automatically.
2. **Build a specific version from ISC source** — fetches the live list of
   releases from `downloads.isc.org`, lets you pick one (or type an exact
   `9.x.y`), verifies the SHA512 checksum, and compiles it with DoH
   (`libnghttp2`) support. You're then asked whether to **overwrite the distro
   binaries in `/usr`** (clean, but a later `apt upgrade` could replace them) or
   install under **`/usr/local`** (a systemd drop-in repoints `named.service` at
   the built binary, surviving apt upgrades).

   In both cases the distro `bind9` package is installed first to provide the
   `bind` user, `/etc/bind` skeleton, `rndc.key` and base `named.service`.

**Run**
```bash
sudo ./bind9-setup.sh
```

**Endpoints**
- Plain DNS → `<domain>:53` (TCP/UDP)
- DoT → `<domain>:853`
- DoH → `https://<domain>/dns-query` *(BIND 9.18+ only)*

---

## Requirements & notes

- Run as **root** on Debian/Ubuntu.
- Point the relevant DNS/A record (BIND) or just have a public IP (dnsdist) at
  the server, and ensure port **80/tcp** is free for ACME validation.
- Certificates renew automatically (cron for dnsdist, certbot deploy-hook for
  BIND); the service reloads only when a cert actually changes.
- Building BIND from source can take several minutes.
