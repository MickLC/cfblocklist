<!---
    config/settings.cfm
    Central configuration for cfblocklist.
    Include this wherever you need site-wide settings:
        <cfinclude template="/config/settings.cfm">
--->
<cfscript>
// ── Site identity ──────────────────────────────────────────────────────────
application.siteName    = "Whizardries DNSBL";
application.siteTagline = "DNS-based Block List for spam and abuse sources";
application.siteURL     = "https://blocklist.whizardries.com"; // no trailing slash
application.adminEmail  = "postmaster@whizardries.com";
application.contactText = "If you believe your listing is in error, use the lookup below.";

// ── DNS zone ────────────────────────────────────────────────────────────────
// The zone name rbldnsd answers for. Used in the public About page to show
// correct dig / Postfix configuration examples.
// Example: "bl.whizardries.com"
application.dnsZone = "bl.whizardries.com";

// ── rbldnsd reload ─────────────────────────────────────────────────────────
// Path to the shell script that signals rbldnsd to reload its data.
// The script should contain something like:
//   #!/bin/bash
//   kill -HUP $(cat /var/run/rbldnsd.pid)
// Make sure the ColdFusion/Lucee process user can execute this script via sudo.
// Set to "" to disable automatic reload (you'll reload manually).
application.rbldnsdReloadScript = "/opt/blocklist/reload-rbldnsd.sh";

// ── Self-delist settings ────────────────────────────────────────────────────
// One-click delist for unlocked entries (no email confirmation).
// A record is removed from the blocklist immediately on delist.
// Set delistNotifyAdmin = true to receive an email when a delist occurs.
application.delistNotifyAdmin = true;

// ── Pagination ──────────────────────────────────────────────────────────────
application.pageSize = 25;

// ── Lucee datasource name ───────────────────────────────────────────────────
// Must match the datasource configured in Lucee admin.
application.dsn = "blocklist";
</cfscript>
