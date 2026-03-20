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
#   3. Edit DB_* variables below to match your environment
#   4. Ensure the script user can execute reload-rbldnsd.sh

set -euo pipefail

# ── Database connection ────────────────────────────────────────────────────
DB_HOST="45.58.55.152"
DB_PORT="3306"
DB_NAME="blocklist"
DB_USER="blocklist_app"
# Password via ~/.my.cnf — see generate-zone.sh for setup instructions

# ── Config ─────────────────────────────────────────────────────────────────
RELOAD_SCRIPT="/opt/blocklist/reload-rbldnsd.sh"
LOGFILE="/var/log/blocklist-expire.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL="mariadb --batch --skip-column-names -h $DB_HOST -P $DB_PORT -u $DB_USER $DB_NAME"

echo "[$TIMESTAMP] === Starting expiry check ===" >> "$LOGFILE"

# ── Find entries due for expiry ────────────────────────────────────────────
# Expiry logic:
#   - entry must be active (active = 1)
#   - entry must not be locked (locked = 0)
#   - entry must participate in auto-expiry (auto_expire = 1)
#   - expires column must be set (NOT NULL) and in the past
#
# Note: the expires column is set at insert time based on defaultExpiryDays,
# but is measured from last_hit if that column has been updated by a web lookup.
# The expires value is recalculated dynamically here using last_hit or added_date
# plus the stored expires offset — or more simply, we store the absolute expiry
# datetime and update it when last_hit changes (handled in default.cfm).

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
    echo "[$TIMESTAMP] No entries due for expiry" >> "$LOGFILE"
    exit 0
fi

# ── Count how many will be deactivated ────────────────────────────────────
EXPIRED_COUNT=$(echo "$EXPIRED_LIST" | wc -l)
echo "[$TIMESTAMP] Found $EXPIRED_COUNT entries to deactivate:" >> "$LOGFILE"

# Log each entry being expired
while IFS=$'\t' read -r id address cidr entry_type expires last_hit; do
    if [ "$entry_type" = "cidr" ]; then
        display="$address/$cidr"
    else
        display="$address"
    fi
    echo "[$TIMESTAMP]   Expiring: $display (expires: $expires, last_hit: ${last_hit:-never})" >> "$LOGFILE"
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

ROWS_AFFECTED=$($MYSQL -e "SELECT ROW_COUNT();" 2>/dev/null || echo "?")
echo "[$TIMESTAMP] Deactivated $ROWS_AFFECTED entries" >> "$LOGFILE"

# ── Reload rbldnsd to reflect changes ─────────────────────────────────────
if [ -x "$RELOAD_SCRIPT" ]; then
    if "$RELOAD_SCRIPT" >> "$LOGFILE" 2>&1; then
        echo "[$TIMESTAMP] rbldnsd reloaded successfully" >> "$LOGFILE"
    else
        echo "[$TIMESTAMP] WARNING: rbldnsd reload failed — zone may be stale" >> "$LOGFILE"
    fi
else
    echo "[$TIMESTAMP] WARNING: $RELOAD_SCRIPT not found — rbldnsd not reloaded" >> "$LOGFILE"
fi

echo "[$TIMESTAMP] === Expiry check complete ===" >> "$LOGFILE"
exit 0
