<!---
    admin/audit.cfm  —  Full audit log with filtering and pagination
--->
<cfinclude template="/config/pepper.cfm">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfset requireLogin()>

<cfparam name="url.action"  default="">
<cfparam name="url.admin"   default="">
<cfparam name="url.q"       default="">
<cfparam name="url.page"    default="1">

<!--- Count --->
<cfquery datasource="#application.dsn#" name="countRows">
    SELECT COUNT(*) AS total
    FROM   audit_log a
    LEFT JOIN login l ON a.admin_id = l.id
    WHERE  1=1
    <cfif len(trim(url.action))>
        AND a.action = <cfqueryparam value="#trim(url.action)#" cfsqltype="cf_sql_varchar" maxlength="32">
    </cfif>
    <cfif isNumeric(url.admin) AND val(url.admin) GT 0>
        AND a.admin_id = <cfqueryparam value="#val(url.admin)#" cfsqltype="cf_sql_integer">
    </cfif>
    <cfif len(trim(url.q))>
        AND (a.target LIKE <cfqueryparam value="%#trim(url.q)#%" cfsqltype="cf_sql_varchar">
          OR a.detail LIKE <cfqueryparam value="%#trim(url.q)#%" cfsqltype="cf_sql_varchar">)
    </cfif>
</cfquery>

<cfset pg = getPaginationVars(countRows.total, val(url.page))>

<cfquery datasource="#application.dsn#" name="auditRows">
    SELECT  a.id, a.action, a.entry_type, a.target, a.detail, a.ip_addr, a.log_date,
            l.name AS admin_name
    FROM    audit_log a
    LEFT JOIN login l ON a.admin_id = l.id
    WHERE  1=1
    <cfif len(trim(url.action))>
        AND a.action = <cfqueryparam value="#trim(url.action)#" cfsqltype="cf_sql_varchar" maxlength="32">
    </cfif>
    <cfif isNumeric(url.admin) AND val(url.admin) GT 0>
        AND a.admin_id = <cfqueryparam value="#val(url.admin)#" cfsqltype="cf_sql_integer">
    </cfif>
    <cfif len(trim(url.q))>
        AND (a.target LIKE <cfqueryparam value="%#trim(url.q)#%" cfsqltype="cf_sql_varchar">
          OR a.detail LIKE <cfqueryparam value="%#trim(url.q)#%" cfsqltype="cf_sql_varchar">)
    </cfif>
    ORDER BY a.log_date DESC
    LIMIT  <cfqueryparam value="#pg.pageSize#" cfsqltype="cf_sql_integer">
    OFFSET <cfqueryparam value="#pg.offset#"   cfsqltype="cf_sql_integer">
</cfquery>

<!--- Admin list for filter dropdown --->
<cfquery datasource="#application.dsn#" name="adminList">
    SELECT id, name FROM login WHERE active = 1 ORDER BY name
</cfquery>

<cfset filterQS = "action=#encodeForURL(url.action)#&admin=#encodeForURL(url.admin)#&q=#encodeForURL(url.q)#">

<cfparam name="attributes.pageTitle" default="Audit Log">
<cfinclude template="/includes/header_admin.cfm">

<div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h4 fw-bold mb-0">
        Audit log
        <span class="text-muted fw-normal fs-6 ms-1">(<cfoutput>#countRows.total#</cfoutput> records)</span>
    </h2>
</div>

<!--- Filter bar --->
<form method="get" action="/admin/audit.cfm" class="card shadow-sm mb-4">
    <div class="card-body py-2">
        <div class="row g-2 align-items-end">
            <div class="col-md-4">
                <label class="form-label small mb-1">Search target / detail</label>
                <input type="text" class="form-control form-control-sm" name="q"
                       value="<cfoutput>#encodeForHTML(url.q)#</cfoutput>" placeholder="IP, hostname, or detail text">
            </div>
            <div class="col-md-2">
                <label class="form-label small mb-1">Action</label>
                <select class="form-select form-select-sm" name="action">
                    <option value="">All actions</option>
                    <cfloop list="ADD,EDIT,DELETE,LOCK,UNLOCK,DELIST,ACTIVATE,DEACTIVATE,LOGIN,LOGOUT" index="a">
                        <option value="<cfoutput>#a#</cfoutput>" <cfif url.action EQ a>selected</cfif>>
                            <cfoutput>#a#</cfoutput>
                        </option>
                    </cfloop>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label small mb-1">Admin user</label>
                <select class="form-select form-select-sm" name="admin">
                    <option value="">All users</option>
                    <cfoutput query="adminList">
                        <option value="#id#" <cfif url.admin EQ id>selected</cfif>>#encodeForHTML(name)#</option>
                    </cfoutput>
                </select>
            </div>
            <div class="col-md-4 d-flex gap-2">
                <button type="submit" class="btn btn-sm btn-primary flex-fill">Filter</button>
                <a href="/admin/audit.cfm" class="btn btn-sm btn-outline-secondary">Clear</a>
            </div>
        </div>
    </div>
</form>

<div class="card shadow-sm">
    <div class="table-responsive">
        <table class="table table-sm table-hover align-middle mb-0">
            <thead class="table-light">
                <tr>
                    <th style="width:140px">Time</th>
                    <th style="width:90px">Action</th>
                    <th>Target</th>
                    <th>Detail</th>
                    <th>By</th>
                    <th>From IP</th>
                </tr>
            </thead>
            <tbody>
                <cfoutput query="auditRows">
                <tr>
                    <td class="small text-muted text-nowrap">
                        #dateFormat(log_date,"mmm d, yyyy")# #timeFormat(log_date,"HH:mm")#
                    </td>
                    <td>
                        <cfswitch expression="#action#">
                            <cfcase value="ADD">     <span class="badge bg-success">#action#</span></cfcase>
                            <cfcase value="DELETE">  <span class="badge bg-danger">#action#</span></cfcase>
                            <cfcase value="DELIST">     <span class="badge bg-warning text-dark">#action#</span></cfcase>
                                    <cfcase value="DEACTIVATE"><span class="badge bg-secondary">#action#</span></cfcase>
                                    <cfcase value="ACTIVATE">  <span class="badge bg-success">#action#</span></cfcase>
                            <cfcase value="LOCK">    <span class="badge bg-danger">#action#</span></cfcase>
                            <cfcase value="UNLOCK">  <span class="badge bg-success">#action#</span></cfcase>
                            <cfcase value="EDIT">    <span class="badge bg-secondary">#action#</span></cfcase>
                            <cfcase value="LOGIN">   <span class="badge bg-info text-dark">#action#</span></cfcase>
                            <cfcase value="LOGOUT">  <span class="badge bg-light text-dark border">#action#</span></cfcase>
                            <cfdefaultcase>          <span class="badge bg-light text-dark border">#encodeForHTML(action)#</span></cfdefaultcase>
                        </cfswitch>
                    </td>
                    <td class="font-monospace small">#encodeForHTML(target)#</td>
                    <td class="small text-muted">#encodeForHTML(detail)#</td>
                    <td class="small">#encodeForHTML(admin_name)#</td>
                    <td class="small font-monospace text-muted">#encodeForHTML(ip_addr)#</td>
                </tr>
                </cfoutput>
                <cfif auditRows.recordCount EQ 0>
                    <tr><td colspan="6" class="text-center text-muted py-4">No records match your filter.</td></tr>
                </cfif>
            </tbody>
        </table>
    </div>

    <!--- Pagination --->
    <cfif pg.totalPages GT 1>
        <div class="card-footer d-flex justify-content-between align-items-center">
            <small class="text-muted">
                Rows <cfoutput>#pg.startRow#</cfoutput>–<cfoutput>#min(pg.startRow + pg.pageSize - 1, countRows.total)#</cfoutput>
                of <cfoutput>#countRows.total#</cfoutput>
            </small>
            <nav>
                <ul class="pagination pagination-sm mb-0">
                    <li class="page-item <cfif pg.currentPage EQ 1>disabled</cfif>">
                        <a class="page-link" href="/admin/audit.cfm?<cfoutput>#filterQS#</cfoutput>&page=<cfoutput>#pg.currentPage - 1#</cfoutput>">&laquo;</a>
                    </li>
                    <cfloop from="1" to="#pg.totalPages#" index="p">
                        <cfif p GTE pg.currentPage - 2 AND p LTE pg.currentPage + 2>
                            <li class="page-item <cfif p EQ pg.currentPage>active</cfif>">
                                <a class="page-link" href="/admin/audit.cfm?<cfoutput>#filterQS#</cfoutput>&page=<cfoutput>#p#</cfoutput>"><cfoutput>#p#</cfoutput></a>
                            </li>
                        </cfif>
                    </cfloop>
                    <li class="page-item <cfif pg.currentPage EQ pg.totalPages>disabled</cfif>">
                        <a class="page-link" href="/admin/audit.cfm?<cfoutput>#filterQS#</cfoutput>&page=<cfoutput>#pg.currentPage + 1#</cfoutput>">&raquo;</a>
                    </li>
                </ul>
            </nav>
        </div>
    </cfif>
</div>

<cfinclude template="/includes/footer_admin.cfm">
