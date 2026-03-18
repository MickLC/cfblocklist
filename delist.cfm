<!---
    delist.cfm  —  One-click self-delist for unlocked entries
    URL param: ?id=<integer>

    No email confirmation required for unlocked entries.
    Sets active = 0 (preserves entry and evidence in DB) rather than hard-deleting.
    Locked entries redirect back to evidence page with an error.
--->
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">

<cfparam name="url.id"      default="0">
<cfparam name="form.confirm" default="">

<!--- Validate ID --->
<cfif NOT isNumeric(url.id) OR val(url.id) LT 1>
    <cflocation url="/" addtoken="no">
</cfif>

<cfset entryId = val(url.id)>

<!--- Fetch entry — abort if not found or locked --->
<cfquery datasource="#application.dsn#" name="entry">
    SELECT id, entry_type, address, cidr, locked
    FROM   ip
    WHERE  id = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer">
    LIMIT  1
</cfquery>

<cfif entry.recordCount EQ 0>
    <cflocation url="/" addtoken="no">
</cfif>

<cfif entry.locked>
    <!--- Locked — can't delist, bounce back to evidence page --->
    <cflocation url="/evidence.cfm?id=#encodeForURL(entryId)#&locked=1" addtoken="no">
</cfif>

<!--- Build display string --->
<cfscript>
switch (entry.entry_type) {
    case "cidr":     displayEntry = "#entry.address#/#entry.cidr#"; break;
    default:         displayEntry = entry.address;
}
</cfscript>

<!--- Process delist on POST confirmation --->
<cfif cgi.request_method EQ "POST" AND form.confirm EQ "1">

    <!--- Delete the entry (evidence cascades via FK) --->
    <cfquery datasource="#application.dsn#">
        UPDATE ip
        SET    active      = <cfqueryparam value="0" cfsqltype="cf_sql_tinyint">,
               modified_date = NOW()
        WHERE  id     = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer">
          AND  locked  = <cfqueryparam value="0"        cfsqltype="cf_sql_tinyint">
          AND  active  = <cfqueryparam value="1"        cfsqltype="cf_sql_tinyint">
    </cfquery>

    <!--- Audit log (no admin session — note as public delist) --->
    <cfset writeAuditLog(
        action    = "DELIST",
        target    = displayEntry,
        entryType = entry.entry_type,
        detail    = "Self-delist via public interface from #cgi.remote_addr#"
    )>

    <!--- Notify admin if configured --->
    <cfif application.delistNotifyAdmin>
        <cftry>
            <cfmail
                to      = "#application.adminEmail#"
                from    = "#application.adminEmail#"
                subject = "Self-delist: #displayEntry# removed from #application.siteName#"
                type    = "text">
Self-delist performed via public interface. Entry set to inactive (not deleted).

Entry:     #displayEntry#
Type:      #entry.entry_type#
Client IP: #cgi.remote_addr#
Time:      #now()#

The entry and its evidence remain in the database.
To reactivate, use the admin panel.
            </cfmail>
        <cfcatch>
            <!--- Mail failure is non-fatal --->
        </cfcatch>
        </cftry>
    </cfif>

    <!--- Trigger rbldnsd reload --->
    <cfset reloadRbldnsd()>

    <!--- Show success page --->
    <cfparam name="attributes.pageTitle" default="Delist successful">
    <cfinclude template="/includes/header_public.cfm">

    <div class="row justify-content-center">
        <div class="col-md-7">
            <div class="card border-success shadow-sm text-center p-4">
                <div class="mb-3">
                    <svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" fill="#198754" viewBox="0 0 16 16">
                        <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>
                    </svg>
                </div>
                <h3 class="fw-bold">Delist successful</h3>
                <p class="text-muted">
                    <strong><cfoutput>#encodeForHTML(displayEntry)#</cfoutput></strong>
                    has been removed from <cfoutput>#encodeForHTML(application.siteName)#</cfoutput>.
                </p>
                <p class="small text-muted">
                    Your listing record is retained for administrative purposes.
                    DNS propagation may take a short time. If you continue to experience issues
                    after 30 minutes, please contact
                    <a href="mailto:<cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput>"><cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput></a>.
                </p>
                <a href="/" class="btn btn-outline-secondary mt-2">Return to lookup</a>
            </div>
        </div>
    </div>

    <cfinclude template="/includes/footer_public.cfm">
    <cfabort>
</cfif>

<!--- ── Confirmation page (GET) ─────────────────────────────────────────── --->
<cfparam name="attributes.pageTitle" default="Confirm delist">
<cfinclude template="/includes/header_public.cfm">

<div class="row justify-content-center">
    <div class="col-md-7">
        <div class="card shadow-sm">
            <div class="card-header bg-warning text-dark">
                <strong>Confirm delist request</strong>
            </div>
            <div class="card-body">
                <p>You are about to remove the following entry from the blocklist:</p>
                <p class="font-monospace fs-5 fw-bold text-center my-3">
                    <cfoutput>#encodeForHTML(displayEntry)#</cfoutput>
                </p>
                <p class="text-muted small">
                    This action is <strong>immediate</strong>. The entry will be removed from the
                    DNS blocklist on the next zone reload. If the listing was in error, please also
                    investigate the underlying issue to prevent re-listing.
                </p>
                <div class="d-flex gap-3 justify-content-end mt-4">
                    <a href="/evidence.cfm?id=<cfoutput>#encodeForURL(entryId)#</cfoutput>"
                       class="btn btn-outline-secondary">
                        Cancel — view evidence
                    </a>
                    <form method="post" action="/delist.cfm?id=<cfoutput>#encodeForURL(entryId)#</cfoutput>" class="d-inline">
                        <input type="hidden" name="confirm" value="1">
                        <button type="submit" class="btn btn-danger">
                            Yes, remove this listing
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<cfinclude template="/includes/footer_public.cfm">
