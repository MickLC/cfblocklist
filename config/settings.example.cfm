<!---
    config/settings.cfm
    Central configuration for cfblocklist.
    This file IS committed to version control — do not put secrets here.
    The pepper lives outside this file entirely; see Application.cfm.
--->
<cfscript>
// ── Site identity ──────────────────────────────────────────────────────────
application.siteName    = "My DNSBL";
application.siteTagline = "DNS-based Block List for spam and abuse sources";
application.siteURL     = "https://bl.example.com"; // no trailing slash
application.adminEmail  = "admin@example.com";
application.contactText = "If you believe your listing is in error, use the lookup below.";

// ── DNS zone ────────────────────────────────────────────────────────────────
// The zone name rbldnsd answers for. Shown in the public About page
// in dig / Postfix configuration examples.
application.dnsZone = "bl.example.com";

// ── Pepper flat-file path ───────────────────────────────────────────────────
// If you are storing the pepper in a file above the web root, set the full
// absolute path here. The file should contain only the pepper value
// (output of: openssl rand -hex 32) with no extra whitespace.
// The file must be outside the web root — e.g. one directory above it.
// Leave as "" if you are using the environment variable method instead.
// See Application.cfm for full setup instructions.
application.pepperFile = "";
// Example: application.pepperFile = "/home/youruser/.blocklist/pepper.txt";

// ── rbldnsd reload ─────────────────────────────────────────────────────────
// Full path to the shell script that signals rbldnsd to reload.
// The script sends SIGHUP to the rbldnsd process.
// No sudo needed if the Lucee service user owns the rbldnsd process,
// or if a sudo rule is in place for this specific script.
// Set to "" to disable automatic reload (reload manually instead).
application.rbldnsdReloadScript = "/opt/blocklist/reload-rbldnsd.sh";

// ── Self-delist settings ────────────────────────────────────────────────────
// One-click delist for unlocked entries — immediate, no email confirmation.
// Set to true to receive an admin notification email on every self-delist.
application.delistNotifyAdmin = true;


// ── Entry expiry ────────────────────────────────────────────────────────────
// Default number of days before an unlocked, active entry is automatically
// deactivated. Applied when a new entry is created.
// Set to 0 to default new entries to never-expire (can still be set per entry).
// Locked entries are always exempt from auto-expiry regardless of this setting.
application.defaultExpiryDays = 90;
// ── Pagination ──────────────────────────────────────────────────────────────
application.pageSize = 25;

// ── Lucee datasource name ───────────────────────────────────────────────────
// Must match the datasource name configured in Lucee Administrator.
application.dsn = "blocklist";
</cfscript>
