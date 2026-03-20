#!/bin/bash
# /opt/blocklist/reload-rbldnsd.sh
#
# Regenerates rbldnsd zone files from MariaDB, then signals rbldnsd to
# reload them into memory via SIGHUP.
#
# Called by Lucee via cfexecute after any add/edit/deactivate operation.
# Must run as a user that can write to /var/lib/rbldns/ and signal rbldnsd.
#
# Setup:
#   1. Place this file at /opt/blocklist/reload-rbldnsd.sh
#   2. chmod +x /opt/blocklist/reload-rbldnsd.sh
#   3. Place generate-zone.sh at /opt/blocklist/generate-zone.sh
#   4. Allow the Lucee service user to run this script:
#      Add to /etc/sudoers.d/blocklist:
#        lucee ALL=(root) NOPASSWD: /opt/blocklist/reload-rbldnsd.sh
#   5. Update application.rbldnsdReloadScript in config/settings.cfm:
#        /usr/bin/sudo /opt/blocklist/reload-rbldnsd.sh

set -euo pipefail

PIDFILE="/var/run/rbldnsd.pid"
LOGFILE="/var/log/rbldnsd-reload.log"
GENERATE_SCRIPT="/opt/blocklist/generate-zone.sh"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# ── Step 1: Regenerate zone files from MariaDB ─────────────────────────────
# rbldnsd reads flat zone files — it has no database connectivity of its own.
# generate-zone.sh queries MariaDB and writes /var/lib/rbldns/ips.txt and
# /var/lib/rbldns/domains.txt before rbldnsd is signalled to reload.

if [ ! -x "$GENERATE_SCRIPT" ]; then
    echo "[$TIMESTAMP] ERROR: $GENERATE_SCRIPT not found or not executable" >> "$LOGFILE"
    exit 1
fi

if ! "$GENERATE_SCRIPT" >> "$LOGFILE" 2>&1; then
    echo "[$TIMESTAMP] ERROR: Zone file generation failed — rbldnsd not reloaded" >> "$LOGFILE"
    exit 1
fi

# ── Step 2: Signal rbldnsd to reload the new zone files ────────────────────

if [ ! -f "$PIDFILE" ]; then
    echo "[$TIMESTAMP] ERROR: rbldnsd pidfile not found at $PIDFILE" >> "$LOGFILE"
    exit 1
fi

PID=$(cat "$PIDFILE")

if ! kill -0 "$PID" 2>/dev/null; then
    echo "[$TIMESTAMP] ERROR: rbldnsd not running (PID $PID)" >> "$LOGFILE"
    exit 1
fi

kill -HUP "$PID"
echo "[$TIMESTAMP] Zone files regenerated and SIGHUP sent to rbldnsd (PID $PID)" >> "$LOGFILE"
exit 0
