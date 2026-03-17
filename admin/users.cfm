<!---
    admin/users.cfm  —  Admin user management (add, deactivate, reset password)
--->
<cfinclude template="/config/pepper.cfm">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfset requireLogin()>

<cfparam name="form.action"    default="">
<cfparam name="form.username"  default="">
<cfparam name="form.password1" default="">
<cfparam name="form.password2" default="">
<cfparam name="form.user_id"   default="0">

<cfset formErrors = []>
<cfset successMsg = "">

<!--- Process form actions --->
<cfif len(form.action)>
    <cfswitch expression="#form.action#">

        <!--- Add new admin user --->
        <cfcase value="adduser">
            <cfif NOT len(trim(form.username))>
                <cfset arrayAppend(formErrors, "Username is required.")>
            <cfelseif len(trim(form.username)) LT 2>
                <cfset arrayAppend(formErrors, "Username must be at least 2 characters.")>
            </cfif>
            <cfif NOT len(form.password1) OR len(form.password1) LT 8>
                <cfset arrayAppend(formErrors, "Password must be at least 8 characters.")>
            </cfif>
            <cfif form.password1 NEQ form.password2>
                <cfset arrayAppend(formErrors, "Passwords do not match.")>
            </cfif>

            <cfif NOT arrayLen(formErrors)>
                <!--- Check for duplicate username --->
                <cfquery datasource="#application.dsn#" name="dupCheck">
                    SELECT id FROM login WHERE name = <cfqueryparam value="#trim(form.username)#" cfsqltype="cf_sql_varchar" maxlength="64">
                </cfquery>
                <cfif dupCheck.recordCount GT 0>
                    <cfset arrayAppend(formErrors, "That username already exists.")>
                <cfelse>
                    <cfquery datasource="#application.dsn#">
                        INSERT INTO login (name, password, access_level, active)
                        VALUES (
                            <cfqueryparam value="#trim(form.username)#"    cfsqltype="cf_sql_varchar" maxlength="64">,
                            <cfqueryparam value="#generateHash(form.password1)#" cfsqltype="cf_sql_varchar" maxlength="255">,
                            1000,
                            1
                        )
                    </cfquery>
                    <cfset writeAuditLog(action="ADD", entryType="user", target=trim(form.username), detail="New admin user created")>
                    <cfset successMsg = "User '#encodeForHTML(trim(form.username))#' created successfully.">
                    <cfset form.username  = "">
                    <cfset form.password1 = "">
                    <cfset form.password2 = "">
                </cfif>
            </cfif>
        </cfcase>

        <!--- Change own password --->
        <cfcase value="changepassword">
            <cfparam name="form.old_password" default="">
            <cfif NOT len(form.old_password)>
                <cfset arrayAppend(formErrors, "Current password is required.")>
            </cfif>
            <cfif NOT len(form.password1) OR len(form.password1) LT 8>
                <cfset arrayAppend(formErrors, "New password must be at least 8 characters.")>
            </cfif>
            <cfif form.password1 NEQ form.password2>
                <cfset arrayAppend(formErrors, "New passwords do not match.")>
            </cfif>

            <cfif NOT arrayLen(formErrors)>
                <cfquery datasource="#application.dsn#" name="getMe">
                    SELECT id, password FROM login WHERE id = <cfqueryparam value="#session.adminId#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfif NOT verifyHash(form.old_password, getMe.password)>
                    <cfset arrayAppend(formErrors, "Current password is incorrect.")>
                <cfelse>
                    <cfquery datasource="#application.dsn#">
                        UPDATE login
                        SET password = <cfqueryparam value="#generateHash(form.password1)#" cfsqltype="cf_sql_varchar" maxlength="255">
                        WHERE id = <cfqueryparam value="#session.adminId#" cfsqltype="cf_sql_integer">
                    </cfquery>
                    <cfset writeAuditLog(action="EDIT", entryType="user", target=session.adminName, detail="Password changed")>
                    <cfset successMsg = "Password changed successfully.">
                </cfif>
            </cfif>
        </cfcase>

        <!--- Deactivate user --->
        <cfcase value="deactivate">
            <cfif isNumeric(form.user_id) AND val(form.user_id) GT 0 AND val(form.user_id) NEQ session.adminId>
                <cfquery datasource="#application.dsn#" name="deactUser">
                    SELECT name FROM login WHERE id = <cfqueryparam value="#val(form.user_id)#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfquery datasource="#application.dsn#">
                    UPDATE login SET active = 0
                    WHERE id = <cfqueryparam value="#val(form.user_id)#" cfsqltype="cf_sql_integer">
                      AND id != <cfqueryparam value="#session.adminId#"  cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="EDIT", entryType="user", target=deactUser.name, detail="User deactivated")>
                <cfset successMsg = "User deactivated.">
            <cfelse>
                <cfset arrayAppend(formErrors, "Cannot deactivate your own account.")>
            </cfif>
        </cfcase>

        <!--- Reactivate user --->
        <cfcase value="reactivate">
            <cfif isNumeric(form.user_id) AND val(form.user_id) GT 0>
                <cfquery datasource="#application.dsn#" name="reactUser">
                    SELECT name FROM login WHERE id = <cfqueryparam value="#val(form.user_id)#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfquery datasource="#application.dsn#">
                    UPDATE login SET active = 1
                    WHERE id = <cfqueryparam value="#val(form.user_id)#" cfsqltype="cf_sql_integer">
                </cfquery>
                <cfset writeAuditLog(action="EDIT", entryType="user", target=reactUser.name, detail="User reactivated")>
                <cfset successMsg = "User reactivated.">
            </cfif>
        </cfcase>

    </cfswitch>
</cfif>

<!--- Fetch users --->
<cfquery datasource="#application.dsn#" name="users">
    SELECT id, name, access_level, active, last_login
    FROM   login
    ORDER BY name
</cfquery>

<cfparam name="attributes.pageTitle" default="Users">
<cfinclude template="/includes/header_admin.cfm">

<h2 class="h4 fw-bold mb-4">User management</h2>

<cfif len(successMsg)>
    <div class="alert alert-success"><cfoutput>#successMsg#</cfoutput></div>
</cfif>
<cfif arrayLen(formErrors)>
    <div class="alert alert-danger">
        <ul class="mb-0"><cfloop array="#formErrors#" item="e"><li><cfoutput>#encodeForHTML(e)#</cfoutput></li></cfloop></ul>
    </div>
</cfif>

<div class="row g-4">

    <!--- User list --->
    <div class="col-lg-7">
        <div class="card shadow-sm">
            <div class="card-header fw-semibold">Admin users</div>
            <div class="table-responsive">
                <table class="table table-sm table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>Username</th>
                            <th>Status</th>
                            <th>Last login</th>
                            <th class="text-end">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <cfoutput query="users">
                        <tr class="<cfif NOT active>table-secondary text-muted</cfif>">
                            <td>
                                #encodeForHTML(name)#
                                <cfif id EQ session.adminId>
                                    <span class="badge bg-info text-dark ms-1">you</span>
                                </cfif>
                            </td>
                            <td>
                                <cfif active>
                                    <span class="badge bg-success">Active</span>
                                <cfelse>
                                    <span class="badge bg-secondary">Inactive</span>
                                </cfif>
                            </td>
                            <td class="small text-muted">
                                <cfif isDate(last_login)>
                                    #dateFormat(last_login,"mmm d, yyyy")# #timeFormat(last_login,"H:mm")#
                                <cfelse>
                                    Never
                                </cfif>
                            </td>
                            <td class="text-end">
                                <cfif id NEQ session.adminId>
                                    <form method="post" action="/admin/users.cfm" class="d-inline">
                                        <input type="hidden" name="user_id" value="#id#">
                                        <cfif active>
                                            <input type="hidden" name="action" value="deactivate">
                                            <button type="submit" class="btn btn-sm btn-outline-warning"
                                                onclick="return confirm('Deactivate user #encodeForHTML(name)#?')">Deactivate</button>
                                        <cfelse>
                                            <input type="hidden" name="action" value="reactivate">
                                            <button type="submit" class="btn btn-sm btn-outline-success">Reactivate</button>
                                        </cfif>
                                    </form>
                                </cfif>
                            </td>
                        </tr>
                        </cfoutput>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="col-lg-5">

        <!--- Add user --->
        <div class="card shadow-sm mb-3">
            <div class="card-header fw-semibold">Add admin user</div>
            <div class="card-body">
                <form method="post" action="/admin/users.cfm" novalidate>
                    <input type="hidden" name="action" value="adduser">
                    <div class="mb-2">
                        <label class="form-label small mb-1">Username</label>
                        <input type="text" class="form-control form-control-sm" name="username"
                               value="<cfoutput>#encodeForHTML(form.username)#</cfoutput>" autocomplete="off">
                    </div>
                    <div class="mb-2">
                        <label class="form-label small mb-1">Password <span class="text-muted">(min 8 chars)</span></label>
                        <input type="password" class="form-control form-control-sm" name="password1" autocomplete="new-password">
                    </div>
                    <div class="mb-3">
                        <label class="form-label small mb-1">Confirm password</label>
                        <input type="password" class="form-control form-control-sm" name="password2" autocomplete="new-password">
                    </div>
                    <button type="submit" class="btn btn-primary btn-sm w-100">Create user</button>
                </form>
            </div>
        </div>

        <!--- Change own password --->
        <div class="card shadow-sm">
            <div class="card-header fw-semibold">Change my password</div>
            <div class="card-body">
                <form method="post" action="/admin/users.cfm" novalidate>
                    <input type="hidden" name="action" value="changepassword">
                    <div class="mb-2">
                        <label class="form-label small mb-1">Current password</label>
                        <input type="password" class="form-control form-control-sm" name="old_password" autocomplete="current-password">
                    </div>
                    <div class="mb-2">
                        <label class="form-label small mb-1">New password</label>
                        <input type="password" class="form-control form-control-sm" name="password1" autocomplete="new-password">
                    </div>
                    <div class="mb-3">
                        <label class="form-label small mb-1">Confirm new password</label>
                        <input type="password" class="form-control form-control-sm" name="password2" autocomplete="new-password">
                    </div>
                    <button type="submit" class="btn btn-outline-secondary btn-sm w-100">Change password</button>
                </form>
            </div>
        </div>

    </div>
</div>

<cfinclude template="/includes/footer_admin.cfm">
