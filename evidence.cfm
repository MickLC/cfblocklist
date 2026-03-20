<!---
    evidence.cfm  —  Public evidence display for a blocklist entry
    URL param: ?id=<integer>

    Evidence text is redacted before display to protect spamtrap addresses
    and any other identifying recipient information. The raw text is preserved
    unchanged in the database and remains fully visible in the admin UI.
--->
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">

<cfparam name="url.id" default="0">

<!--- Validate numeric ID --->
<cfif NOT isNumeric(url.id) OR val(url.id) LT 1>
    <cflocation url="/" addtoken="no">
</cfif>

<!--- Fetch entry --->
<cfquery datasource="#application.dsn#" name="entry">
    SELECT  id, entry_type, address, cidr, locked, active, added_date
    FROM    ip
    WHERE   id = <cfqueryparam value="#val(url.id)#" cfsqltype="cf_sql_integer">
    LIMIT 1
</cfquery>

<cfif entry.recordCount EQ 0>
    <cflocation url="/" addtoken="no">
</cfif>

<!--- Inactive entries are not publicly listed — redirect to not-found --->
<cfif NOT entry.active>
    <cflocation url="/?delisted=1&q=#encodeForURL(entry.address)#" addtoken="no">
</cfif>

<!--- Fetch all evidence records for this entry --->
<cfquery datasource="#application.dsn#" name="evidenceRows">
    SELECT  id, evidence, added_date
    FROM    evidence
    WHERE   ip_id = <cfqueryparam value="#entry.id#" cfsqltype="cf_sql_integer">
    ORDER BY added_date ASC
</cfquery>

<!--- Build display title --->
<cfscript>
switch (entry.entry_type) {
    case "cidr":     displayEntry = "#entry.address#/#entry.cidr#"; break;
    case "hostname": displayEntry = entry.address; break;
    default:         displayEntry = entry.address;
}
// Pre-encode values used in JS/URL contexts outside cfoutput blocks
safeDisplayEntry    = encodeForHTML(displayEntry);
safeDisplayEntryURL = encodeForURL(displayEntry);
safeAdminEmail      = encodeForHTML(application.adminEmail);
safeAdminEmailURL   = encodeForURL(application.adminEmail);
safeContactText     = encodeForHTML(application.contactText);
safeEntryId         = encodeForURL(entry.id);
</cfscript>

<cfparam name="attributes.pageTitle" default="Evidence — #encodeForHTML(displayEntry)#">
<cfinclude template="/includes/header_public.cfm">

<nav aria-label="breadcrumb" class="mb-3">
    <ol class="breadcrumb">
        <li class="breadcrumb-item"><a href="/">Lookup</a></li>
        <li class="breadcrumb-item active" aria-current="page">Evidence</li>
    </ol>
</nav>

<div class="row">
    <div class="col-lg-9">

        <div class="card shadow-sm mb-3">
            <div class="card-header d-flex align-items-center justify-content-between">
                <div>
                    <span class="font-monospace fw-bold fs-5"><cfoutput>#safeDisplayEntry#</cfoutput></span>
                    <cfoutput>
                    <span class="badge ms-2
                        <cfif entry.entry_type EQ 'hostname'>text-white" style="background:##6f42c1
                        <cfelseif entry.entry_type EQ 'cidr'>bg-primary
                        <cfelse>bg-info text-dark</cfif>">
                        #uCase(entry.entry_type)#
                    </span>
                    </cfoutput>
                </div>
                <cfif entry.locked>
                    <span class="badge bg-danger">Locked</span>
                <cfelse>
                    <span class="badge bg-success">Unlocked</span>
                </cfif>
            </div>
            <div class="card-body">
                <dl class="row mb-2">
                    <dt class="col-sm-3">Listed entry</dt>
                    <dd class="col-sm-9 font-monospace"><cfoutput>#safeDisplayEntry#</cfoutput></dd>
                    <dt class="col-sm-3">Date listed</dt>
                    <dd class="col-sm-9"><cfoutput>#dateFormat(entry.added_date,"mmmm d, yyyy")# at #timeFormat(entry.added_date,"h:mm tt")#</cfoutput></dd>
                    <dt class="col-sm-3">Status</dt>
                    <dd class="col-sm-9">
                        <cfif entry.locked>
                            <span class="text-danger">Locked — delist not available via self-service</span>
                        <cfelse>
                            <span class="text-success">Unlocked — self-delist available</span>
                        </cfif>
                    </dd>
                </dl>

                <div class="d-flex gap-2 mt-3">
                    <a href="/" class="btn btn-sm btn-outline-secondary">&larr; Back to lookup</a>
                    <cfif NOT entry.locked>
                        <a href="/delist.cfm?id=<cfoutput>#safeEntryId#</cfoutput>"
                           class="btn btn-sm btn-success"
                           onclick="return confirm('Remove <cfoutput>#safeDisplayEntry#</cfoutput> from the blocklist? This is immediate.')">
                            Delist this entry
                        </a>
                    <cfelse>
                        <a href="mailto:<cfoutput>#safeAdminEmail#</cfoutput>?subject=Delist+request+for+<cfoutput>#safeDisplayEntryURL#</cfoutput>"
                           class="btn btn-sm btn-outline-warning">
                            Contact administrator
                        </a>
                    </cfif>
                </div>
            </div>
        </div>

        <!--- Evidence records --->
        <h5 class="fw-semibold mb-3">
            Evidence
            <span class="badge bg-secondary ms-1"><cfoutput>#evidenceRows.recordCount#</cfoutput></span>
        </h5>

        <p class="text-muted small mb-3">
            Some information has been redacted from the evidence below to protect
            internal addressing details. The evidence otherwise reflects the original
            messages and logs that resulted in this listing.
        </p>

        <cfif evidenceRows.recordCount EQ 0>
            <div class="alert alert-info">No evidence records are attached to this entry.</div>
        <cfelse>
            <cfoutput query="evidenceRows">
                <div class="card mb-3 shadow-sm">
                    <div class="card-header small text-muted">
                        Evidence record ###evidenceRows.currentRow#
                        &mdash; added #dateFormat(added_date,"mmm d, yyyy")# at #timeFormat(added_date,"h:mm tt")#
                    </div>
                    <div class="card-body p-0">
<!--- NOTE: No whitespace between > and # below — pre-wrap renders it literally --->
<div class="evidence-box rounded-bottom" style="border-top:0;border-radius:0 0 .375rem .375rem;padding:1rem;font-family:monospace;font-size:.85rem;white-space:pre-wrap;word-break:break-all;background:##fff">#encodeForHTML(trim(redactEvidence(evidence)))#</div>
                    </div>
                </div>
            </cfoutput>
        </cfif>

        <cfif entry.locked>
            <div class="alert alert-warning mt-2">
                <strong>Locked listing.</strong>
                <cfoutput>#safeContactText#</cfoutput>
                Contact <a href="mailto:<cfoutput>#safeAdminEmail#</cfoutput>"><cfoutput>#safeAdminEmail#</cfoutput></a> to appeal.
            </div>
        </cfif>

    </div>
</div>

<cfinclude template="/includes/footer_public.cfm">
