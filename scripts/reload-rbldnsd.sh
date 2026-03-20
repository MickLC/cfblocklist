#!/bin/bash
# /opt/blocklist/reload-rbldnsd.sh
#
# Regenerates rbldnsd zone files from MariaDB, then signals rbldnsd to
# reload them into memory via SIGHUP.
#
# Called by Lucee via cfexecute after any add/edit/deactivate operation.
#
# Setup:
#   1. Copy scripts/ to /opt/blocklist/scripts/
#   2. chmod +x /opt/blocklist/scripts/*.sh
#   3. Copy scripts/blocklist.conf.example to /opt/blocklist/blocklist.conf and fill in values
#   4. Allow the Lucee service user to run this script without a password:
#      Add to /etc/sudoers.d/blocklist:
#        www-data ALL=(root) NOPASSWD: /opt/blocklist/scripts/reload-rbldnsd.sh
#   5. Update application.rbldnsdReloadScript in config/settings.cfm:
#        /usr/bin/sudo /opt/blocklist/scripts/reload-rbldnsd.sh

set -euo pipefail

CONF="/opt/blocklist/blocklist.conf"

if [ ! -f "$CONF" ]; then
    echo "ERROR: $CONF not found. Copy blocklist.conf.example and fill in your values." >&2
    exit 1
fi

# shellcheck source=/dev/null
. "$CONF"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
GENERATE_SCRIPT="/opt/blocklist/scripts/generate-zone.sh"

# ── Step 1: Regenerate zone files from MariaDB ─────────────────────────────
if [ ! -x "$GENERATE_SCRIPT" ]; then
    echo "[$TIMESTAMP] ERROR: $GENERATE_SCRIPT not found or not executable" >> "$RELOAD_LOG"
    exit 1
fi

if ! "$GENERATE_SCRIPT" >> "$RELOAD_LOG" 2>&1; then
    echo "[$TIMESTAMP] ERROR: Zone file generation failed — rbldnsd not reloaded" >> "$RELOAD_LOG"
    exit 1
fi

# ── Step 2: Signal rbldnsd to reload ──────────────────────────────────────
if [ ! -f "$RBLDNSD_PIDFILE" ]; then
    echo "[$TIMESTAMP] ERROR: rbldnsd pidfile not found at $RBLDNSD_PIDFILE" >> "$RELOAD_LOG"
    exit 1
fi

PID=$(cat "$RBLDNSD_PIDFILE")

if ! kill -0 "$PID" 2>/dev/null; then
    echo "[$TIMESTAMP] ERROR: rbldnsd not running (PID $PID)" >> "$RELOAD_LOG"
    exit 1
fi

kill -HUP "$PID"
echo "[$TIMESTAMP] Zone files regenerated and SIGHUP sent to rbldnsd (PID $PID)" >> "$RELOAD_LOG"
exit 0
