<!---
    admin/entries.cfm  —  Paginated entry list with search, filter, lock/unlock, activate/deactivate, delete
--->
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfset requireLogin()>

<!--- ── URL params ──────────────────────────────────────────────────────── --->
<cfparam name="url.q"       default="">
<cfparam name="url.type"    default="">
<cfparam name="url.locked"  default="">
<cfparam name="url.active"  default="">
<cfparam name="url.page"    default="1">
<cfparam name="url.action"  default="">
<cfparam name="url.id"      default="0">

<!--- ── Inline actions ──────────────────────────────────────────────────── --->
<cfif len(url.action) AND isNumeric(url.id) AND val(url.id) GT 0>
    <cfset actionId = val(url.id)>

    <cfquery datasource="#application.dsn#" name="actionEntry">
        SELECT id, entry_type, address, cidr FROM ip
        WHERE id = <cfqueryparam value="#actionId#" cfsqltype="cf_sql_integer">
        LIMIT 1
    </cfquery>

    <cfif actionEntry.recordCount GT 0>
        <cfscript>
        aDisplay = actionEntry.entry_type EQ "cidr"
            ? "#actionEntry.address#/#actionEntry.cidr#"
            : actionEntry.address;
        </cfscript>

        <cfswitch expression="#url.action#">
            <cfcase value="lock">
                <cfquery datasource="#application.dsn#">
                    UPDATE ip SET locked = 1,
                        modified_by = <cfqueryparam value="#session.adminId#" cfsqltype="cf_sql_integer">,
                        modified_date = NOW()
                    WHERE id = <cfqueryparam value="#actionId#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="LOCK", target=aDisplay, entryType=actionEntry.entry_type)>
            </cfcase>
            <cfcase value="unlock">
                <cfquery datasource="#application.dsn#">
                    UPDATE ip SET locked = 0,
                        modified_by = <cfqueryparam value="#session.adminId#" cfsqltype="cf_sql_integer">,
                        modified_date = NOW()
                    WHERE id = <cfqueryparam value="#actionId#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="UNLOCK", target=aDisplay, entryType=actionEntry.entry_type)>
            </cfcase>
            <cfcase value="deactivate">
                <cfquery datasource="#application.dsn#">
                    UPDATE ip SET active = 0,
                        modified_by = <cfqueryparam value="#session.adminId#" cfsqltype="cf_sql_integer">,
                        modified_date = NOW()
                    WHERE id = <cfqueryparam value="#actionId#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="DEACTIVATE", target=aDisplay, entryType=actionEntry.entry_type)>
                <cfset reloadRbldnsd()>
            </cfcase>
            <cfcase value="activate">
                <cfquery datasource="#application.dsn#">
                    UPDATE ip SET active = 1,
                        modified_by = <cfqueryparam value="#session.adminId#" cfsqltype="cf_sql_integer">,
                        modified_date = NOW()
                    WHERE id = <cfqueryparam value="#actionId#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="ACTIVATE", target=aDisplay, entryType=actionEntry.entry_type)>
                <cfset reloadRbldnsd()>
            </cfcase>
            <cfcase value="delete">
                <!--- Hard delete — admin only, removes record and all evidence --->
                <cfquery datasource="#application.dsn#">
                    DELETE FROM ip WHERE id = <cfqueryparam value="#actionId#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="DELETE", target=aDisplay, entryType=actionEntry.entry_type)>
                <cfset reloadRbldnsd()>
            </cfcase>
        </cfswitch>

        <cflocation url="/admin/entries.cfm?q=#encodeForURL(url.q)#&type=#encodeForURL(url.type)#&locked=#encodeForURL(url.locked)#&active=#encodeForURL(url.active)#&page=#encodeForURL(url.page)#" addtoken="no">
    </cfif>
</cfif>

<!--- ── Count for pagination ────────────────────────────────────────────── --->
<cfquery datasource="#application.dsn#" name="countRows">
    SELECT COUNT(*) AS total
    FROM   ip
    WHERE  1=1
    <cfif len(trim(url.q))>
        AND address LIKE <cfqueryparam value="%#trim(url.q)#%" cfsqltype="cf_sql_varchar">
    </cfif>
    <cfif url.type EQ "ip" OR url.type EQ "cidr" OR url.type EQ "hostname">
        AND entry_type = <cfqueryparam value="#url.type#" cfsqltype="cf_sql_varchar">
    </cfif>
    <cfif url.locked EQ "1">
        AND locked = 1
    <cfelseif url.locked EQ "0">
        AND locked = 0
    </cfif>
    <cfif url.active EQ "1">
        AND active = 1
    <cfelseif url.active EQ "0">
        AND active = 0
    </cfif>
</cfquery>

<cfset pg = getPaginationVars(countRows.total, val(url.page))>

<!--- ── Fetch page of entries ───────────────────────────────────────────── --->
<cfquery datasource="#application.dsn#" name="entries">
    SELECT  i.id, i.entry_type, i.address, i.cidr, i.locked, i.active, i.expires, i.auto_expire,
            i.added_date, i.modified_date,
            l.name AS added_by_name,
            (SELECT COUNT(*) FROM evidence e WHERE e.ip_id = i.id) AS evidence_count
    FROM    ip i
    LEFT JOIN login l ON i.added_by = l.id
    WHERE   1=1
    <cfif len(trim(url.q))>
        AND i.address LIKE <cfqueryparam value="%#trim(url.q)#%" cfsqltype="cf_sql_varchar">
    </cfif>
    <cfif url.type EQ "ip" OR url.type EQ "cidr" OR url.type EQ "hostname">
        AND i.entry_type = <cfqueryparam value="#url.type#" cfsqltype="cf_sql_varchar">
    </cfif>
    <cfif url.locked EQ "1">
        AND i.locked = 1
    <cfelseif url.locked EQ "0">
        AND i.locked = 0
    </cfif>
    <cfif url.active EQ "1">
        AND i.active = 1
    <cfelseif url.active EQ "0">
        AND i.active = 0
    </cfif>
    ORDER BY i.added_date DESC
    LIMIT  <cfqueryparam value="#pg.pageSize#" cfsqltype="cf_sql_integer">
    OFFSET <cfqueryparam value="#pg.offset#"   cfsqltype="cf_sql_integer">
</cfquery>

<cfset filterQS = "q=#encodeForURL(url.q)#&type=#encodeForURL(url.type)#&locked=#encodeForURL(url.locked)#&active=#encodeForURL(url.active)#">

<cfparam name="attributes.pageTitle" default="Entries">
<cfinclude template="/includes/header_admin.cfm">

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 fw-bold mb-0">
        Blocklist entries
        <span class="text-muted fw-normal fs-6 ms-1">(<cfoutput>#countRows.total#</cfoutput> total)</span>
    </h2>
    <a href="/admin/entry_add.cfm" class="btn btn-primary btn-sm">+ Add entry</a>
</div>

<!--- ── Filter bar ──────────────────────────────────────────────────────── --->
<form method="get" action="/admin/entries.cfm" class="card shadow-sm mb-4">
    <div class="card-body py-2">
        <div class="row g-2 align-items-end">
            <div class="col-md-4">
                <label class="form-label small mb-1">Search address</label>
                <input  type="text"
                        class="form-control form-control-sm"
                        name="q"
                        value="<cfoutput>#encodeForHTML(url.q)#</cfoutput>"
                        placeholder="IP, CIDR, or hostname fragment">
            </div>
            <div class="col-md-2">
                <label class="form-label small mb-1">Type</label>
                <select class="form-select form-select-sm" name="type">
                    <option value="">All types</option>
                    <option value="ip"       <cfif url.type EQ "ip">selected</cfif>>IP</option>
                    <option value="cidr"     <cfif url.type EQ "cidr">selected</cfif>>CIDR</option>
                    <option value="hostname" <cfif url.type EQ "hostname">selected</cfif>>Hostname</option>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label small mb-1">Lock status</label>
                <select class="form-select form-select-sm" name="locked">
                    <option value="">All</option>
                    <option value="1" <cfif url.locked EQ "1">selected</cfif>>Locked</option>
                    <option value="0" <cfif url.locked EQ "0">selected</cfif>>Unlocked</option>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label small mb-1">Active status</label>
                <select class="form-select form-select-sm" name="active">
                    <option value="">All</option>
                    <option value="1" <cfif url.active EQ "1">selected</cfif>>Active</option>
                    <option value="0" <cfif url.active EQ "0">selected</cfif>>Inactive</option>
                </select>
            </div>
            <div class="col-md-2 d-flex gap-2">
                <button type="submit" class="btn btn-sm btn-primary flex-fill">Filter</button>
                <a href="/admin/entries.cfm" class="btn btn-sm btn-outline-secondary">Clear</a>
            </div>
        </div>
    </div>
</form>

<!--- ── Entry table ─────────────────────────────────────────────────────── --->
<div class="card shadow-sm">
    <div class="table-responsive">
        <table class="table table-sm table-hover align-middle mb-0">
            <thead class="table-light">
                <tr>
                    <th>Entry</th>
                    <th>Type</th>
                    <th>Lock</th>
                    <th>Active</th>
                    <th>Expires</th>
                    <th>Evidence</th>
                    <th>Added</th>
                    <th>By</th>
                    <th class="text-end">Actions</th>
                </tr>
            </thead>
            <tbody>
                <cfoutput query="entries">
                <tr class="<cfif NOT active>table-secondary</cfif>">
                    <td class="font-monospace small fw-semibold <cfif NOT active>text-muted</cfif>">
                        #encodeForHTML(address)#<cfif entry_type EQ "cidr">/#encodeForHTML(cidr)#</cfif>
                    </td>
                    <td>
                        <span class="badge
                            <cfif entry_type EQ 'hostname'>text-white" style="background:##6f42c1
                            <cfelseif entry_type EQ 'cidr'>bg-primary
                            <cfelse>bg-info text-dark</cfif>">
                            #uCase(entry_type)#
                        </span>
                    </td>
                    <td>
                        <cfif locked>
                            <span class="badge bg-danger">Locked</span>
                        <cfelse>
                            <span class="badge bg-success">Open</span>
                        </cfif>
                    </td>
                    <td>
                        <cfif active>
                            <span class="badge bg-success">Active</span>
                        <cfelse>
                            <span class="badge bg-secondary">Inactive</span>
                        </cfif>
                    </td>
                    <td class="small text-nowrap">
                        <cfif isDate(expires)>
                            <cfif expires LT now()>
                                <span class="text-warning"><cfoutput>#dateFormat(expires,"mmm d, yy")#</cfoutput></span>
                            <cfelse>
                                <cfoutput>#dateFormat(expires,"mmm d, yy")#</cfoutput>
                            </cfif>
                        <cfelse>
                            <span class="text-muted">—</span>
                        </cfif>
                    </td>
                    <td class="text-center">
                        <cfif evidence_count GT 0>
                            <a href="/evidence.cfm?id=#encodeForURL(id)#" target="_blank"
                               class="badge bg-secondary text-decoration-none">#evidence_count#</a>
                        <cfelse>
                            <span class="text-muted">—</span>
                        </cfif>
                    </td>
                    <td class="small text-muted text-nowrap">#dateFormat(added_date,"mmm d, yyyy")#</td>
                    <td class="small text-muted">#encodeForHTML(added_by_name)#</td>
                    <td class="text-end table-actions text-nowrap">
                        <a href="/admin/entry_edit.cfm?id=#encodeForURL(id)#"
                           class="btn btn-sm btn-outline-secondary">Edit</a>

                        <cfif locked>
                            <a href="/admin/entries.cfm?action=unlock&id=#encodeForURL(id)#&#filterQS#&page=#encodeForURL(pg.currentPage)#"
                               class="btn btn-sm btn-outline-success"
                               onclick="return confirm('Unlock this entry? Users will be able to self-delist.')">
                                Unlock
                            </a>
                        <cfelse>
                            <a href="/admin/entries.cfm?action=lock&id=#encodeForURL(id)#&#filterQS#&page=#encodeForURL(pg.currentPage)#"
                               class="btn btn-sm btn-outline-warning">
                                Lock
                            </a>
                        </cfif>

                        <cfif active>
                            <a href="/admin/entries.cfm?action=deactivate&id=#encodeForURL(id)#&#filterQS#&page=#encodeForURL(pg.currentPage)#"
                               class="btn btn-sm btn-outline-secondary"
                               onclick="return confirm('Deactivate #encodeForHTML(address)#? It will be removed from the live blocklist but kept in the database.')">
                                Deactivate
                            </a>
                        <cfelse>
                            <a href="/admin/entries.cfm?action=activate&id=#encodeForURL(id)#&#filterQS#&page=#encodeForURL(pg.currentPage)#"
                               class="btn btn-sm btn-outline-success">
                                Reactivate
                            </a>
                        </cfif>

                        <a href="/admin/entries.cfm?action=delete&id=#encodeForURL(id)#&#filterQS#&page=#encodeForURL(pg.currentPage)#"
                           class="btn btn-sm btn-outline-danger"
                           onclick="return confirm('Permanently DELETE #encodeForHTML(address)# and all its evidence? This cannot be undone.')">
                            Delete
                        </a>
                    </td>
                </tr>
                </cfoutput>

                <cfif entries.recordCount EQ 0>
                    <tr>
                        <td colspan="9" class="text-center text-muted py-4">
                            No entries match your filter.
                        </td>
                    </tr>
                </cfif>
            </tbody>
        </table>
    </div>

    <cfif pg.totalPages GT 1>
        <div class="card-footer d-flex justify-content-between align-items-center">
            <small class="text-muted">
                Showing rows <cfoutput>#pg.startRow#</cfoutput>–<cfoutput>#min(pg.startRow + pg.pageSize - 1, countRows.total)#</cfoutput>
                of <cfoutput>#countRows.total#</cfoutput>
            </small>
            <nav>
                <ul class="pagination pagination-sm mb-0">
                    <li class="page-item <cfif pg.currentPage EQ 1>disabled</cfif>">
                        <a class="page-link" href="/admin/entries.cfm?<cfoutput>#filterQS#</cfoutput>&page=<cfoutput>#pg.currentPage - 1#</cfoutput>">&laquo;</a>
                    </li>
                    <cfloop from="1" to="#pg.totalPages#" index="p">
                        <cfif p GTE pg.currentPage - 2 AND p LTE pg.currentPage + 2>
                            <li class="page-item <cfif p EQ pg.currentPage>active</cfif>">
                                <a class="page-link" href="/admin/entries.cfm?<cfoutput>#filterQS#</cfoutput>&page=<cfoutput>#p#</cfoutput>"><cfoutput>#p#</cfoutput></a>
                            </li>
                        </cfif>
                    </cfloop>
                    <li class="page-item <cfif pg.currentPage EQ pg.totalPages>disabled</cfif>">
                        <a class="page-link" href="/admin/entries.cfm?<cfoutput>#filterQS#</cfoutput>&page=<cfoutput>#pg.currentPage + 1#</cfoutput>">&raquo;</a>
                    </li>
                </ul>
            </nav>
        </div>
    </cfif>
</div>

<cfinclude template="/includes/footer_admin.cfm">
