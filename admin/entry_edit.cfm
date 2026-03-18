<!---
    admin/entry_edit.cfm  —  Edit a blocklist entry (evidence, lock status, add more evidence)
--->
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfset requireLogin()>

<cfparam name="url.id"           default="0">
<cfparam name="form.locked"      default="">
<cfparam name="form.new_evidence" default="">
<cfparam name="form.action"      default="">
<cfparam name="form.evid_id"     default="0">
<cfparam name="form.evid_text"   default="">

<cfif NOT isNumeric(url.id) OR val(url.id) LT 1>
    <cflocation url="/admin/entries.cfm" addtoken="no">
</cfif>

<cfset entryId   = val(url.id)>
<cfset formErrors = []>
<cfset successMsg = "">

<!--- Fetch entry --->
<cfquery datasource="#application.dsn#" name="entry">
    SELECT  i.id, i.entry_type, i.address, i.cidr, i.locked, i.active,
            i.added_date, i.modified_date,
            l.name AS added_by_name
    FROM    ip i
    LEFT JOIN login l ON i.added_by = l.id
    WHERE   i.id = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer">
    LIMIT   1
</cfquery>

<cfif entry.recordCount EQ 0>
    <cflocation url="/admin/entries.cfm" addtoken="no">
</cfif>

<cfscript>
displayEntry = entry.entry_type EQ "cidr"
    ? "#entry.address#/#entry.cidr#"
    : entry.address;
</cfscript>

<!--- ── Process form actions ────────────────────────────────────────────── --->
<cfif len(form.action)>
    <cfswitch expression="#form.action#">

        <!--- Activate / deactivate --->
        <cfcase value="setactive">
            <cfset newActive = (form.active EQ "1") ? 1 : 0>
            <cfquery datasource="#application.dsn#">
                UPDATE ip
                SET active       = <cfqueryparam value="#newActive#"         cfsqltype="cf_sql_tinyint">,
                    modified_by  = <cfqueryparam value="#session.adminId#"   cfsqltype="cf_sql_integer">,
                    modified_date = NOW()
                WHERE id = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer">
            </cfquery>
            <cfset writeAuditLog(
                action    = (newActive ? "ACTIVATE" : "DEACTIVATE"),
                target    = displayEntry,
                entryType = entry.entry_type
            )>
            <cfset reloadRbldnsd()>
            <cfset successMsg = "Active status updated.">
            <cfquery datasource="#application.dsn#" name="entry">
                SELECT i.*, l.name AS added_by_name FROM ip i LEFT JOIN login l ON i.added_by = l.id
                WHERE i.id = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer"> LIMIT 1
            </cfquery>
        </cfcase>

        <!--- Update lock status --->
        <cfcase value="updatelock">
            <cfset newLocked = (form.locked EQ "1") ? 1 : 0>
            <cfquery datasource="#application.dsn#">
                UPDATE ip
                SET locked       = <cfqueryparam value="#newLocked#"         cfsqltype="cf_sql_tinyint">,
                    modified_by  = <cfqueryparam value="#session.adminId#"   cfsqltype="cf_sql_integer">,
                    modified_date = NOW()
                WHERE id = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer">
            </cfquery>
            <cfset writeAuditLog(
                action    = (newLocked ? "LOCK" : "UNLOCK"),
                target    = displayEntry,
                entryType = entry.entry_type
            )>
            <cfset successMsg = "Lock status updated.">
            <!--- Refresh entry --->
            <cfquery datasource="#application.dsn#" name="entry">
                SELECT i.*, l.name AS added_by_name FROM ip i LEFT JOIN login l ON i.added_by = l.id <!--- includes active --->
                WHERE i.id = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer"> LIMIT 1
            </cfquery>
        </cfcase>

        <!--- Add new evidence record --->
        <cfcase value="addevidence">
            <cfif NOT len(trim(form.new_evidence))>
                <cfset arrayAppend(formErrors, "Evidence text cannot be empty.")>
            <cfelse>
                <cfquery datasource="#application.dsn#">
                    INSERT INTO evidence (ip_id, evidence, added_by)
                    VALUES (
                        <cfqueryparam value="#entryId#"              cfsqltype="cf_sql_integer">,
                        <cfqueryparam value="#trim(form.new_evidence)#" cfsqltype="cf_sql_clob">,
                        <cfqueryparam value="#session.adminId#"      cfsqltype="cf_sql_integer">
                    )
                </cfquery>
                <cfset writeAuditLog(action="EDIT", target=displayEntry, entryType=entry.entry_type, detail="Added evidence record")>
                <cfset successMsg = "Evidence record added.">
                <cfset form.new_evidence = "">
            </cfif>
        </cfcase>

        <!--- Update an existing evidence record --->
        <cfcase value="updateevidence">
            <cfif NOT isNumeric(form.evid_id) OR val(form.evid_id) LT 1>
                <cfset arrayAppend(formErrors, "Invalid evidence ID.")>
            <cfelseif NOT len(trim(form.evid_text))>
                <cfset arrayAppend(formErrors, "Evidence text cannot be empty.")>
            <cfelse>
                <cfquery datasource="#application.dsn#">
                    UPDATE evidence
                    SET evidence = <cfqueryparam value="#trim(form.evid_text)#" cfsqltype="cf_sql_clob">
                    WHERE id   = <cfqueryparam value="#val(form.evid_id)#"    cfsqltype="cf_sql_integer">
                      AND ip_id = <cfqueryparam value="#entryId#"              cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="EDIT", target=displayEntry, entryType=entry.entry_type, detail="Updated evidence record ##form.evid_id#")>
                <cfset successMsg = "Evidence record updated.">
            </cfif>
        </cfcase>

        <!--- Delete an evidence record --->
        <cfcase value="deleteevidence">
            <cfif isNumeric(form.evid_id) AND val(form.evid_id) GT 0>
                <cfquery datasource="#application.dsn#">
                    DELETE FROM evidence
                    WHERE id   = <cfqueryparam value="#val(form.evid_id)#" cfsqltype="cf_sql_integer">
                      AND ip_id = <cfqueryparam value="#entryId#"           cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="EDIT", target=displayEntry, entryType=entry.entry_type, detail="Deleted evidence record ##form.evid_id#")>
                <cfset successMsg = "Evidence record deleted.">
            </cfif>
        </cfcase>

    </cfswitch>
</cfif>

<!--- Fetch evidence (after any edits) --->
<cfquery datasource="#application.dsn#" name="evidenceRows">
    SELECT id, evidence, added_date
    FROM   evidence
    WHERE  ip_id = <cfqueryparam value="#entryId#" cfsqltype="cf_sql_integer">
    ORDER BY added_date ASC
</cfquery>

<cfparam name="attributes.pageTitle" default="Edit — #encodeForHTML(displayEntry)#">
<cfinclude template="/includes/header_admin.cfm">

<nav aria-label="breadcrumb" class="mb-3">
    <ol class="breadcrumb">
        <li class="breadcrumb-item"><a href="/admin/entries.cfm">Entries</a></li>
        <li class="breadcrumb-item active"><cfoutput>#encodeForHTML(displayEntry)#</cfoutput></li>
    </ol>
</nav>

<cfif len(successMsg)>
    <div class="alert alert-success"><cfoutput>#encodeForHTML(successMsg)#</cfoutput></div>
</cfif>
<cfif arrayLen(formErrors)>
    <div class="alert alert-danger">
        <ul class="mb-0"><cfloop array="#formErrors#" item="e"><li><cfoutput>#encodeForHTML(e)#</cfoutput></li></cfloop></ul>
    </div>
</cfif>

<div class="row g-4">

    <!--- ── Entry details + lock card ───────────────────────────────────── --->
    <div class="col-lg-4">
        <div class="card shadow-sm mb-3">
            <div class="card-header fw-semibold">Entry details</div>
            <div class="card-body">
                <dl class="row small mb-0">
                    <dt class="col-5">Address</dt>
                    <dd class="col-7 font-monospace fw-bold"><cfoutput>#encodeForHTML(displayEntry)#</cfoutput></dd>
                    <dt class="col-5">Type</dt>
                    <dd class="col-7">
                        <cfoutput>
                        <span class="badge
                            <cfif entry.entry_type EQ 'hostname'>text-white" style="background:##6f42c1
                            <cfelseif entry.entry_type EQ 'cidr'>bg-primary
                            <cfelse>bg-info text-dark</cfif>">
                            #uCase(entry.entry_type)#
                        </span>
                        </cfoutput>
                    </dd>
                    <dt class="col-5">Added</dt>
                    <dd class="col-7 text-muted"><cfoutput>#dateFormat(entry.added_date,"mmm d, yyyy")#</cfoutput></dd>
                    <dt class="col-5">By</dt>
                    <dd class="col-7 text-muted"><cfoutput>#encodeForHTML(entry.added_by_name)#</cfoutput></dd>
                </dl>
            </div>
        </div>

        <!--- Lock control --->
        <div class="card shadow-sm mb-3">
            <div class="card-header fw-semibold">Delist lock</div>
            <div class="card-body">
                <p class="small text-muted">
                    Locked entries cannot be self-delisted by the listed party.
                </p>
                <form method="post" action="/admin/entry_edit.cfm?id=<cfoutput>#encodeForURL(entryId)#</cfoutput>">
                    <input type="hidden" name="action" value="updatelock">
                    <div class="form-check form-switch mb-3">
                        <input  class="form-check-input"
                                type="checkbox"
                                role="switch"
                                id="locked"
                                name="locked"
                                value="1"
                                <cfif entry.locked>checked</cfif>>
                        <label class="form-check-label" for="locked">
                            <cfif entry.locked>
                                <span class="text-danger fw-semibold">Locked</span>
                            <cfelse>
                                <span class="text-success fw-semibold">Unlocked</span>
                            </cfif>
                        </label>
                    </div>
                    <button type="submit" class="btn btn-sm btn-outline-secondary w-100">Save lock status</button>
                </form>
            </div>
        </div>

        <!--- Active / inactive control --->
        <div class="card shadow-sm mb-3">
            <div class="card-header fw-semibold">Listing status</div>
            <div class="card-body">
                <p class="small text-muted">
                    Inactive entries are removed from the live blocklist but
                    retained in the database with all evidence intact.
                    Public lookups will not find them.
                </p>
                <form method="post" action="/admin/entry_edit.cfm?id=<cfoutput>#encodeForURL(entryId)#</cfoutput>">
                    <input type="hidden" name="action" value="setactive">
                    <div class="form-check form-switch mb-3">
                        <input  class="form-check-input"
                                type="checkbox"
                                role="switch"
                                id="active"
                                name="active"
                                value="1"
                                <cfif entry.active>checked</cfif>>
                        <label class="form-check-label" for="active">
                            <cfif entry.active>
                                <span class="text-success fw-semibold">Active</span> — listed in blocklist
                            <cfelse>
                                <span class="text-secondary fw-semibold">Inactive</span> — not in live blocklist
                            </cfif>
                        </label>
                    </div>
                    <button type="submit" class="btn btn-sm btn-outline-secondary w-100">Save listing status</button>
                </form>
            </div>
        </div>

        <!--- Danger zone --->
        <div class="card shadow-sm border-danger">
            <div class="card-header text-danger fw-semibold">Danger zone</div>
            <div class="card-body">
                <a href="/admin/entries.cfm?action=delete&id=<cfoutput>#encodeForURL(entryId)#</cfoutput>"
                   class="btn btn-danger btn-sm w-100"
                   onclick="return confirm('Permanently delete #encodeForHTML(displayEntry)#? All evidence will be removed. This cannot be undone.')">
                    Delete this entry
                </a>
            </div>
        </div>
    </div>

    <!--- ── Evidence records ─────────────────────────────────────────────── --->
    <div class="col-lg-8">
        <div class="card shadow-sm mb-3">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span class="fw-semibold">
                    Evidence records
                    <span class="badge bg-secondary ms-1"><cfoutput>#evidenceRows.recordCount#</cfoutput></span>
                </span>
                <a href="/evidence.cfm?id=<cfoutput>#encodeForURL(entryId)#</cfoutput>" target="_blank"
                   class="btn btn-sm btn-outline-secondary">Public view</a>
            </div>
            <div class="card-body">

                <cfif evidenceRows.recordCount EQ 0>
                    <p class="text-muted small">No evidence records attached. Add one below.</p>
                </cfif>

                <cfoutput query="evidenceRows">
                    <div class="mb-4 border rounded p-3 bg-light">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <small class="text-muted">Record ##<cfoutput>#evidenceRows.currentRow#</cfoutput> &mdash; added <cfoutput>#dateFormat(added_date,"mmm d, yyyy")#</cfoutput></small>
                            <form method="post" action="/admin/entry_edit.cfm?id=#encodeForURL(entryId)#" class="d-inline">
                                <input type="hidden" name="action"  value="deleteevidence">
                                <input type="hidden" name="evid_id" value="#id#">
                                <button type="submit" class="btn btn-sm btn-link text-danger p-0"
                                        onclick="return confirm('Delete this evidence record?')">Delete</button>
                            </form>
                        </div>
                        <form method="post" action="/admin/entry_edit.cfm?id=#encodeForURL(entryId)#">
                            <input type="hidden" name="action"  value="updateevidence">
                            <input type="hidden" name="evid_id" value="#id#">
                            <textarea class="form-control font-monospace mb-2"
                                      name="evid_text"
                                      rows="8"
                                      style="font-size:.82rem">#encodeForHTML(evidence)#</textarea>
                            <button type="submit" class="btn btn-sm btn-outline-secondary">Update record</button>
                        </form>
                    </div>
                </cfoutput>

                <!--- Add new evidence --->
                <hr>
                <h6 class="fw-semibold mb-2">Add evidence record</h6>
                <form method="post" action="/admin/entry_edit.cfm?id=<cfoutput>#encodeForURL(entryId)#</cfoutput>">
                    <input type="hidden" name="action" value="addevidence">
                    <textarea   class="form-control font-monospace mb-2"
                                name="new_evidence"
                                rows="8"
                                placeholder="Paste additional log lines, headers, or notes."
                                style="font-size:.82rem"><cfoutput>#encodeForHTML(form.new_evidence)#</cfoutput></textarea>
                    <button type="submit" class="btn btn-primary btn-sm">Add evidence record</button>
                </form>
            </div>
        </div>
    </div>
</div>

<cfinclude template="/includes/footer_admin.cfm">
