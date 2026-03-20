#!/bin/bash
# /opt/blocklist/expire-entries.sh
#
# Deactivates blocklist entries whose expiry time has passed.
# Expiry is measured from last_hit if set, otherwise from added_date.
# Locked entries and entries with auto_expire=0 are always skipped.
#
# Run daily via cron:
#   0 3 * * * /opt/blocklist/expire-entries.sh
#
# Setup:
#   1. Place this file at /opt/blocklist/expire-entries.sh
#   2. chmod +x /opt/blocklist/expire-entries.sh
#   3. Copy blocklist.conf.example to /opt/blocklist/blocklist.conf and fill in values

set -euo pipefail

CONF="/opt/blocklist/blocklist.conf"

if [ ! -f "$CONF" ]; then
    echo "ERROR: $CONF not found. Copy blocklist.conf.example and fill in your values." >&2
    exit 1
fi

# shellcheck source=/dev/null
. "$CONF"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
MYSQL="mariadb --batch --skip-column-names -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p${DB_PASS} ${DB_NAME}"

echo "[$TIMESTAMP] === Starting expiry check ===" >> "$EXPIRE_LOG"

# ── Find entries due for expiry ────────────────────────────────────────────
EXPIRED_LIST=$($MYSQL << 'SQL'
SELECT id, address, cidr, entry_type, expires, last_hit
FROM ip
WHERE active      = 1
  AND locked      = 0
  AND auto_expire = 1
  AND expires     IS NOT NULL
  AND expires     < NOW()
ORDER BY expires ASC;
SQL
)

if [ -z "$EXPIRED_LIST" ]; then
    echo "[$TIMESTAMP] No entries due for expiry" >> "$EXPIRE_LOG"
    exit 0
fi

EXPIRED_COUNT=$(echo "$EXPIRED_LIST" | wc -l)
echo "[$TIMESTAMP] Found $EXPIRED_COUNT entries to deactivate:" >> "$EXPIRE_LOG"

while IFS=$'\t' read -r id address cidr entry_type expires last_hit; do
    if [ "$entry_type" = "cidr" ]; then
        display="$address/$cidr"
    else
        display="$address"
    fi
    echo "[$TIMESTAMP]   Expiring: $display (expires: $expires, last_hit: ${last_hit:-never})" >> "$EXPIRE_LOG"
done <<< "$EXPIRED_LIST"

# ── Deactivate expired entries ─────────────────────────────────────────────
$MYSQL << 'SQL'
UPDATE ip
SET    active        = 0,
       modified_date = NOW()
WHERE  active      = 1
  AND  locked      = 0
  AND  auto_expire = 1
  AND  expires     IS NOT NULL
  AND  expires     < NOW();
SQL

echo "[$TIMESTAMP] Deactivation complete" >> "$EXPIRE_LOG"

# ── Reload rbldnsd ─────────────────────────────────────────────────────────
RELOAD_SCRIPT="/opt/blocklist/scripts/reload-rbldnsd.sh"
if [ -x "$RELOAD_SCRIPT" ]; then
    if "$RELOAD_SCRIPT" >> "$EXPIRE_LOG" 2>&1; then
        echo "[$TIMESTAMP] rbldnsd reloaded successfully" >> "$EXPIRE_LOG"
    else
        echo "[$TIMESTAMP] WARNING: rbldnsd reload failed — zone may be stale" >> "$EXPIRE_LOG"
    fi
else
    echo "[$TIMESTAMP] WARNING: $RELOAD_SCRIPT not found — rbldnsd not reloaded" >> "$EXPIRE_LOG"
fi

echo "[$TIMESTAMP] === Expiry check complete ===" >> "$EXPIRE_LOG"
exit 0
