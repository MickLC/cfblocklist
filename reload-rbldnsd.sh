#!/bin/bash
# /opt/blocklist/reload-rbldnsd.sh
#
# Signals rbldnsd to reload its zone data.
# Called by ColdFusion via cfexecute after any add/edit/delete operation.
#
# Setup:
#   1. Place this file at /opt/blocklist/reload-rbldnsd.sh
#   2. chmod +x /opt/blocklist/reload-rbldnsd.sh
#   3. Allow the Lucee service user (e.g. lucee or tomcat) to run it via sudo:
#      Add to /etc/sudoers.d/blocklist:
#        lucee ALL=(root) NOPASSWD: /opt/blocklist/reload-rbldnsd.sh
#   4. If you need sudo, update application.rbldnsdReloadScript in config/settings.cfm to:
#        /usr/bin/sudo /opt/blocklist/reload-rbldnsd.sh
#
# rbldnsd reloads its data on SIGHUP. If it reads from a DB-generated flat file,
# regenerate that file here first.

set -euo pipefail

PIDFILE="/var/run/rbldnsd.pid"
LOGFILE="/var/log/rbldnsd-reload.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# ── Optional: regenerate the zone data file from MariaDB ───────────────────
# Uncomment and adapt if rbldnsd reads a flat file rather than querying the DB live.
# /opt/blocklist/generate-zone.sh >> "$LOGFILE" 2>&1

# ── Signal rbldnsd ──────────────────────────────────────────────────────────
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
echo "[$TIMESTAMP] Sent SIGHUP to rbldnsd (PID $PID)" >> "$LOGFILE"
exit 0
