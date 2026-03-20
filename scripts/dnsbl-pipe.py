#!/usr/bin/env python3
"""PowerDNS pipe backend for dnsbl.whizardries.com.

Handles DNSBL lookups against the blocklist MariaDB database,
replacing rbldnsd. PowerDNS owns port 53; this script is a
long-lived child process that PowerDNS forks and communicates
with via stdin/stdout using the pipe backend ABI (version 1).

Protocol reference:
  https://doc.powerdns.com/authoritative/backends/pipe.html

Handshake
---------
  pdns → script : HELO\t1
  script → pdns : OK\tdnsbl-pipe.py v1

Query
-----
  pdns → script : Q\t<qname>\t<qclass>\t<qtype>\t<id>\t<remote-ip>

Reply
-----
  script → pdns : DATA\t<qname>\t<qclass>\t<qtype>\t<ttl>\t<id>\t<content>
                  (zero or more DATA lines)
  script → pdns : END
  script → pdns : FAIL    (on internal error — pdns will retry once)

Query types answered
--------------------
  A       → 127.0.0.2 if listed, else NXDOMAIN (return END with no DATA)
  TXT     → listing reason text if listed, else NXDOMAIN
  ANY     → both A and TXT records if listed
  SOA     → SOA for the zone apex
  NS      → NS records for the zone apex

Lookup logic
------------
  Query name: <label(s)>.<zone>
  Strip the zone suffix to get the subject.

  Subject looks like a reversed-octet IP  →  IP / CIDR lookup
    e.g. 4.3.2.1.dnsbl.whizardries.com  →  subject = 4.3.2.1
    Un-reverse it: 1.2.3.4
    1. Exact match on ip.address = '1.2.3.4' AND entry_type = 'ip'
    2. CIDR containment: INET_ATON('1.2.3.4') between
       INET_ATON(ip.address) and INET_ATON(ip.address) + (POW(2, 32-ip.cidr) - 1)
       for all active CIDR entries

  Subject looks like a hostname            →  hostname lookup
    e.g. mail.example.com.dnsbl.whizardries.com  →  subject = mail.example.com
    1. Exact match on ip.address = 'mail.example.com' AND entry_type = 'hostname'
    2. Wildcard match: ip.address = '.example.com'  (leading dot = wildcard)
    3. Walk up labels: .com checked only if '.com' is stored (unusual but supported)

Configuration
-------------
  Read from /opt/blocklist/blocklist.conf (shell-style key=value).
  Required keys: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS
  Optional keys: DNSBL_ZONE, DNSBL_RETURN, DNSBL_TTL,
                 SOA_ORIGIN, SOA_HOSTMASTER, SOA_TTL, SOA_REFRESH,
                 SOA_RETRY, SOA_EXPIRE, SOA_MINTTL,
                 NS_HOST, NS_TTL, PIPE_LOG

Installation
------------
  cp scripts/dnsbl-pipe.py /opt/blocklist/dnsbl-pipe.py
  chmod 755 /opt/blocklist/dnsbl-pipe.py
  chown root:pdns /opt/blocklist/dnsbl-pipe.py
  pip3 install PyMySQL   # or: apt install python3-pymysql
"""

import sys
import os
import re
import logging
import ipaddress
from pathlib import Path

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    import pymysql
    import pymysql.cursors
except ImportError:
    sys.stderr.write(
        "ERROR: PyMySQL not found. Install with: pip3 install PyMySQL\n"
        "       or: apt install python3-pymysql\n"
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------
CONF_PATH = "/opt/blocklist/blocklist.conf"

def load_conf(path: str) -> dict:
    """Parse a shell-style key=value config file. Strips quotes."""
    conf = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"\'')
                conf[key] = val
    except FileNotFoundError:
        sys.stderr.write(f"ERROR: Config file not found: {path}\n")
        sys.exit(1)
    return conf

conf = load_conf(CONF_PATH)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FILE = conf.get("PIPE_LOG", "/var/log/dnsbl-pipe.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("dnsbl-pipe")

# ---------------------------------------------------------------------------
# Zone / return-value config
# ---------------------------------------------------------------------------
DNSBL_ZONE   = conf.get("DNSBL_ZONE",   "dnsbl.whizardries.com").rstrip(".")
DNSBL_RETURN = conf.get("DNSBL_RETURN", "127.0.0.2")
DNSBL_TTL    = int(conf.get("DNSBL_TTL", "300"))

# SOA values
SOA_ORIGIN     = conf.get("SOA_ORIGIN",     f"ns1.{DNSBL_ZONE}.")
SOA_HOSTMASTER = conf.get("SOA_HOSTMASTER", f"hostmaster.{DNSBL_ZONE.split('.', 1)[-1] if '.' in DNSBL_ZONE else DNSBL_ZONE}.")
SOA_TTL        = int(conf.get("SOA_TTL",    "3600"))
SOA_REFRESH    = int(conf.get("SOA_REFRESH", "3600"))
SOA_RETRY      = int(conf.get("SOA_RETRY",   "600"))
SOA_EXPIRE     = int(conf.get("SOA_EXPIRE",  "86400"))
SOA_MINTTL     = int(conf.get("SOA_MINTTL",  "300"))
SOA_SERIAL     = 1  # static; PowerDNS doesn't require incrementing for pipe backend

NS_HOST = conf.get("NS_HOST", f"ns1.{DNSBL_ZONE}.")
NS_TTL  = int(conf.get("NS_TTL", "3600"))

# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------
DB_CONFIG = {
    "host":    conf.get("DB_HOST", "localhost"),
    "port":    int(conf.get("DB_PORT", "3306")),
    "db":      conf.get("DB_NAME", "blocklist"),
    "user":    conf.get("DB_USER", ""),
    "passwd":  conf.get("DB_PASS", ""),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "connect_timeout": 5,
    "autocommit": True,
}

_conn = None

def get_conn():
    """Return a live database connection, reconnecting if needed."""
    global _conn
    try:
        if _conn is None:
            _conn = pymysql.connect(**DB_CONFIG)
        else:
            _conn.ping(reconnect=True)
    except Exception as e:
        log.error("DB connection failed: %s", e)
        _conn = None
        raise
    return _conn

# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def _is_reversed_ip(subject: str) -> bool:
    """Return True if subject looks like a reversed-octet dotted quad."""
    parts = subject.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def _unreverse_ip(subject: str) -> str:
    """Convert '4.3.2.1' → '1.2.3.4'."""
    return ".".join(reversed(subject.split(".")))

def lookup_ip(ip_str: str):
    """
    Look up an IPv4 address against the blocklist.
    Returns (True, reason_text) if listed, (False, None) if not.
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False, None

    conn = get_conn()
    with conn.cursor() as cur:
        # 1. Exact IP match
        cur.execute(
            """
            SELECT id FROM ip
            WHERE entry_type = 'ip'
              AND active = 1
              AND address = %s
              AND (expires IS NULL OR expires > NOW())
            LIMIT 1
            """,
            (ip_str,),
        )
        row = cur.fetchone()
        if row:
            _touch_last_hit(cur, row["id"])
            return True, f"Listed in {DNSBL_ZONE}"

        # 2. CIDR containment
        ip_int = int(ip_obj)
        cur.execute(
            """
            SELECT id, address, cidr FROM ip
            WHERE entry_type = 'cidr'
              AND active = 1
              AND (expires IS NULL OR expires > NOW())
            """
        )
        for row in cur.fetchall():
            try:
                net = ipaddress.IPv4Network(f"{row['address']}/{row['cidr']}", strict=False)
                if ip_obj in net:
                    _touch_last_hit(cur, row["id"])
                    return True, f"Listed in {DNSBL_ZONE} (CIDR {row['address']}/{row['cidr']})"
            except ValueError:
                continue

    return False, None

def lookup_hostname(subject: str):
    """
    Look up a hostname against the blocklist.
    Returns (True, reason_text) if listed, (False, None) if not.

    Tries in order:
      1. Exact hostname match
      2. Wildcard match (.example.com covers all subdomains of example.com)
      3. Walk up label-by-label looking for stored wildcards
    """
    conn = get_conn()
    with conn.cursor() as cur:
        # 1. Exact match
        cur.execute(
            """
            SELECT id FROM ip
            WHERE entry_type = 'hostname'
              AND active = 1
              AND address = %s
              AND (expires IS NULL OR expires > NOW())
            LIMIT 1
            """,
            (subject,),
        )
        row = cur.fetchone()
        if row:
            _touch_last_hit(cur, row["id"])
            return True, f"Listed in {DNSBL_ZONE}"

        # 2 & 3. Wildcard walk-up
        # For 'mail.example.com', try '.mail.example.com', '.example.com', '.com'
        labels = subject.split(".")
        for i in range(len(labels) - 1):       # don't try '.' alone
            wildcard = "." + ".".join(labels[i + 1:])
            cur.execute(
                """
                SELECT id FROM ip
                WHERE entry_type = 'hostname'
                  AND active = 1
                  AND address = %s
                  AND (expires IS NULL OR expires > NOW())
                LIMIT 1
                """,
                (wildcard,),
            )
            row = cur.fetchone()
            if row:
                _touch_last_hit(cur, row["id"])
                return True, f"Listed in {DNSBL_ZONE} (wildcard {wildcard})"

    return False, None

def _touch_last_hit(cursor, entry_id: int):
    """Update last_hit timestamp. Best-effort — swallow errors."""
    try:
        cursor.execute(
            "UPDATE ip SET last_hit = NOW() WHERE id = %s",
            (entry_id,),
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Answer builders
# ---------------------------------------------------------------------------

def soa_record(qname: str) -> str:
    return (
        f"DATA\t{qname}\tIN\tSOA\t{SOA_TTL}\t-1\t"
        f"{SOA_ORIGIN} {SOA_HOSTMASTER} {SOA_SERIAL} "
        f"{SOA_REFRESH} {SOA_RETRY} {SOA_EXPIRE} {SOA_MINTTL}"
    )

def ns_record(qname: str) -> str:
    return f"DATA\t{qname}\tIN\tNS\t{NS_TTL}\t-1\t{NS_HOST}"

def a_record(qname: str) -> str:
    return f"DATA\t{qname}\tIN\tA\t{DNSBL_TTL}\t-1\t{DNSBL_RETURN}"

def txt_record(qname: str, text: str) -> str:
    # TXT content must be double-quoted in the pipe protocol
    safe = text.replace('"', '\\"')
    return f'DATA\t{qname}\tIN\tTXT\t{DNSBL_TTL}\t-1\t"{safe}"'

# ---------------------------------------------------------------------------
# Query dispatcher
# ---------------------------------------------------------------------------
ZONE_SUFFIX = f".{DNSBL_ZONE}"
ZONE_APEX   = DNSBL_ZONE  # lower-case for comparison

def handle_query(qname: str, qtype: str) -> list:
    """
    Process one DNS query. Returns a list of strings to write to stdout
    (DATA lines, then END — or just END for NXDOMAIN).
    FAIL is returned as a single-element list ["FAIL"].
    """
    qname_lower = qname.lower().rstrip(".")
    lines = []

    try:
        # ── Zone apex: SOA / NS ────────────────────────────────────────────
        if qname_lower == ZONE_APEX:
            if qtype in ("SOA", "ANY", "NS"):
                if qtype in ("SOA", "ANY"):
                    lines.append(soa_record(qname))
                if qtype in ("NS", "ANY"):
                    lines.append(ns_record(qname))
            # NS2 if configured
            ns2 = conf.get("NS2_HOST")
            if ns2 and qtype in ("NS", "ANY"):
                lines.append(f"DATA\t{qname}\tIN\tNS\t{NS_TTL}\t-1\t{ns2}")
            lines.append("END")
            return lines

        # ── Sub-zone SOA fallback (needed for NXDOMAIN NSEC, etc.) ─────────
        if not qname_lower.endswith(ZONE_SUFFIX):
            # Not in our zone at all
            lines.append("END")
            return lines

        # ── Strip zone suffix to get the subject ───────────────────────────
        subject = qname_lower[: -len(ZONE_SUFFIX)]

        if not subject:
            lines.append("END")
            return lines

        # ── Only answer A, TXT, ANY queries ───────────────────────────────
        # For other qtypes (MX, AAAA, etc.) just return END (NXDOMAIN effect)
        if qtype not in ("A", "TXT", "ANY", "SOA"):
            lines.append("END")
            return lines

        # SOA within the zone — return the apex SOA
        if qtype == "SOA":
            lines.append(soa_record(DNSBL_ZONE))
            lines.append("END")
            return lines

        # ── Dispatch to IP or hostname lookup ─────────────────────────────
        if _is_reversed_ip(subject):
            ip_str = _unreverse_ip(subject)
            listed, reason = lookup_ip(ip_str)
        else:
            # Hostname: the subject may itself be dotted, e.g.
            # 'mail.example.com' from 'mail.example.com.dnsbl.whizardries.com'
            listed, reason = lookup_hostname(subject)

        if listed:
            if qtype in ("A", "ANY"):
                lines.append(a_record(qname))
            if qtype in ("TXT", "ANY"):
                lines.append(txt_record(qname, reason))

        lines.append("END")
        return lines

    except Exception as e:
        log.error("Error handling query %s/%s: %s", qname, qtype, e)
        return ["FAIL"]

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    # Flush stdout immediately — PowerDNS reads line by line
    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)

    log.info("dnsbl-pipe.py starting, zone=%s", DNSBL_ZONE)

    # Handshake
    hello = sys.stdin.readline().rstrip("\n")
    if not hello.startswith("HELO"):
        log.error("Expected HELO, got: %r", hello)
        sys.stdout.write("FAIL\n")
        sys.exit(1)

    sys.stdout.write("OK\tdnsbl-pipe.py v1 zone=" + DNSBL_ZONE + "\n")
    log.info("Handshake complete")

    # Pre-connect to DB
    try:
        get_conn()
        log.info("Database connected: %s@%s/%s", DB_CONFIG["user"], DB_CONFIG["host"], DB_CONFIG["db"])
    except Exception as e:
        log.error("Initial DB connect failed: %s", e)
        # Don't exit — will retry on first query

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue

        parts = line.split("\t")

        if parts[0] == "Q":
            if len(parts) < 6:
                log.warning("Malformed Q line: %r", line)
                sys.stdout.write("FAIL\n")
                continue

            qname  = parts[1]
            qtype  = parts[3].upper()
            # parts[4] = id, parts[5] = remote-ip (ignore both)

            answers = handle_query(qname, qtype)
            for ans in answers:
                sys.stdout.write(ans + "\n")

        elif parts[0] == "AXFR":
            # We don't support AXFR — just END it
            sys.stdout.write("END\n")

        elif parts[0] == "PING":
            sys.stdout.write("END\n")

        else:
            log.debug("Unknown command: %r", line)
            sys.stdout.write("END\n")

if __name__ == "__main__":
    main()
