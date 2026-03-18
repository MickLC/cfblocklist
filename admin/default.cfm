<!---
    admin/default.cfm  —  Admin dashboard
--->
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfset requireLogin()>

<!--- Stats --->
<cfquery datasource="#application.dsn#" name="stats">
    SELECT
        COUNT(*)                                        AS total_entries,
        SUM(CASE WHEN locked  = 1 THEN 1 ELSE 0 END)   AS locked_count,
        SUM(CASE WHEN locked  = 0 THEN 1 ELSE 0 END)   AS unlocked_count,
        SUM(CASE WHEN entry_type = 'ip'       THEN 1 ELSE 0 END) AS ip_count,
        SUM(CASE WHEN entry_type = 'cidr'     THEN 1 ELSE 0 END) AS cidr_count,
        SUM(CASE WHEN entry_type = 'hostname' THEN 1 ELSE 0 END) AS hostname_count,
        SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) AS active_count,
        SUM(CASE WHEN active = 0 THEN 1 ELSE 0 END) AS inactive_count
    FROM ip
</cfquery>

<!--- Recent entries (last 10 added) --->
<cfquery datasource="#application.dsn#" name="recentEntries">
    SELECT  i.id, i.entry_type, i.address, i.cidr, i.locked, i.added_date,
            l.name AS added_by_name
    FROM    ip i
    LEFT JOIN login l ON i.added_by = l.id
    ORDER BY i.added_date DESC
    LIMIT 10
</cfquery>

<!--- Recent audit log (last 15 actions) --->
<cfquery datasource="#application.dsn#" name="recentAudit">
    SELECT  a.action, a.target, a.entry_type, a.detail, a.ip_addr, a.log_date,
            l.name AS admin_name
    FROM    audit_log a
    LEFT JOIN login l ON a.admin_id = l.id
    ORDER BY a.log_date DESC
    LIMIT 15
</cfquery>

<cfparam name="attributes.pageTitle" default="Dashboard">
<cfinclude template="/includes/header_admin.cfm">

<h2 class="h4 fw-bold mb-4">Dashboard</h2>

<!--- ── Stat cards ──────────────────────────────────────────────────────── --->
<div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
        <div class="card text-center shadow-sm h-100">
            <div class="card-body">
                <div class="fs-1 fw-bold text-primary"><cfoutput>#stats.total_entries#</cfoutput></div>
                <div class="text-muted small">Total entries</div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card text-center shadow-sm h-100">
            <div class="card-body">
                <div class="fs-1 fw-bold text-danger"><cfoutput>#stats.locked_count#</cfoutput></div>
                <div class="text-muted small">Locked</div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card text-center shadow-sm h-100">
            <div class="card-body">
                <div class="fs-1 fw-bold text-success"><cfoutput>#stats.unlocked_count#</cfoutput></div>
                <div class="text-muted small">Unlocked (self-delist OK)</div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card text-center shadow-sm h-100">
            <div class="card-body">
                <div class="d-flex justify-content-around mt-1">
                    <div>
                        <div class="fw-bold"><cfoutput>#stats.ip_count#</cfoutput></div>
                        <div class="text-muted" style="font-size:.7rem">IP</div>
                    </div>
                    <div>
                        <div class="fw-bold"><cfoutput>#stats.cidr_count#</cfoutput></div>
                        <div class="text-muted" style="font-size:.7rem">CIDR</div>
                    </div>
                    <div>
                        <div class="fw-bold"><cfoutput>#stats.hostname_count#</cfoutput></div>
                        <div class="text-muted" style="font-size:.7rem">Host</div>
                    </div>
                </div>
                <div class="text-muted small mt-1">By type</div>
            </div>
        </div>
    </div>
</div>
<div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
        <div class="card text-center shadow-sm h-100">
            <div class="card-body">
                <div class="fs-1 fw-bold text-success"><cfoutput>#stats.active_count#</cfoutput></div>
                <div class="text-muted small">Active (live)</div>
            </div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="card text-center shadow-sm h-100">
            <div class="card-body">
                <div class="fs-1 fw-bold text-secondary"><cfoutput>#stats.inactive_count#</cfoutput></div>
                <div class="text-muted small">Inactive (delisted)</div>
            </div>
        </div>
    </div>
</div>

<!--- ── Quick actions ────────────────────────────────────────────────────── --->
<div class="mb-4">
    <a href="/admin/entry_add.cfm" class="btn btn-primary me-2">+ Add entry</a>
    <a href="/admin/entries.cfm"   class="btn btn-outline-secondary me-2">Browse all entries</a>
    <a href="/admin/audit.cfm"     class="btn btn-outline-secondary">Audit log</a>
</div>

<div class="row g-4">
    <!--- ── Recent entries ───────────────────────────────────────────────── --->
    <div class="col-lg-7">
        <div class="card shadow-sm">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span class="fw-semibold">Recently added</span>
                <a href="/admin/entries.cfm" class="btn btn-sm btn-outline-secondary">View all</a>
            </div>
            <div class="table-responsive">
                <table class="table table-sm table-hover mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>Entry</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Added</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <cfoutput query="recentEntries">
                        <tr>
                            <td class="font-monospace small">
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
                            <td class="small text-muted text-nowrap">
                                #dateFormat(added_date,"mmm d")#
                            </td>
                            <td class="table-actions">
                                <a href="/admin/entry_edit.cfm?id=#encodeForURL(id)#" class="btn btn-sm btn-outline-secondary">Edit</a>
                            </td>
                        </tr>
                        </cfoutput>
                        <cfif recentEntries.recordCount EQ 0>
                            <tr><td colspan="5" class="text-muted text-center py-3">No entries yet.</td></tr>
                        </cfif>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!--- ── Recent audit ─────────────────────────────────────────────────── --->
    <div class="col-lg-5">
        <div class="card shadow-sm">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span class="fw-semibold">Recent activity</span>
                <a href="/admin/audit.cfm" class="btn btn-sm btn-outline-secondary">Full log</a>
            </div>
            <div class="table-responsive">
                <table class="table table-sm mb-0">
                    <tbody>
                        <cfoutput query="recentAudit">
                        <tr>
                            <td class="text-nowrap">
                                <cfswitch expression="#action#">
                                    <cfcase value="ADD">     <span class="badge bg-success">#action#</span></cfcase>
                                    <cfcase value="DELETE">  <span class="badge bg-danger">#action#</span></cfcase>
                                    <cfcase value="DELIST">     <span class="badge bg-warning text-dark">#action#</span></cfcase>
                                    <cfcase value="DEACTIVATE"><span class="badge bg-secondary">#action#</span></cfcase>
                                    <cfcase value="ACTIVATE">  <span class="badge bg-success">#action#</span></cfcase>
                                    <cfcase value="LOCK">    <span class="badge bg-danger">#action#</span></cfcase>
                                    <cfcase value="UNLOCK">  <span class="badge bg-success">#action#</span></cfcase>
                                    <cfcase value="EDIT">    <span class="badge bg-secondary">#action#</span></cfcase>
                                    <cfdefaultcase>          <span class="badge bg-light text-dark">#encodeForHTML(action)#</span></cfdefaultcase>
                                </cfswitch>
                            </td>
                            <td class="small font-monospace">#encodeForHTML(target)#</td>
                            <td class="small text-muted text-nowrap">#dateFormat(log_date,"mmm d")# #timeFormat(log_date,"H:mm")#</td>
                        </tr>
                        </cfoutput>
                        <cfif recentAudit.recordCount EQ 0>
                            <tr><td colspan="3" class="text-muted text-center py-3">No activity yet.</td></tr>
                        </cfif>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<cfinclude template="/includes/footer_admin.cfm">
