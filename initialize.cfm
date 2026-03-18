<!---
    initialize.cfm  —  First-run admin user creation
    Redirects permanently once any user exists in the login table.
    Uses the same generateHash() function as the rest of the application
    (PBKDF2WithHmacSHA256, random salt, random iterations 50k-100k).
--->

<!--- Application.cfm already loaded settings, functions, and resolved pepper --->

<cfquery datasource="#application.dsn#" name="anyUsers">
    SELECT COUNT(*) AS numRows FROM login
</cfquery>

<!--- If users already exist, there's nothing to do here --->
<cfif anyUsers.numRows GT 0>
    <cflocation url="/" addtoken="no">
</cfif>

<cfparam name="form.username"  default="">
<cfparam name="form.password1" default="">
<cfparam name="form.password2" default="">
<cfparam name="form.submit"    default="">

<cfset formErrors = []>

<cfif len(form.submit)>

    <cfif len(trim(form.username)) LT 2>
        <cfset arrayAppend(formErrors, "Username must be at least 2 characters.")>
    </cfif>
    <cfif len(form.password1) LT 8>
        <cfset arrayAppend(formErrors, "Password must be at least 8 characters.")>
    </cfif>
    <cfif form.password1 NEQ form.password2>
        <cfset arrayAppend(formErrors, "Passwords do not match.")>
    </cfif>

    <cfif NOT arrayLen(formErrors)>
        <cfquery datasource="#application.dsn#">
            INSERT INTO login (name, password, access_level, active)
            VALUES (
                <cfqueryparam value="#trim(form.username)#"    cfsqltype="cf_sql_varchar" maxlength="64">,
                <cfqueryparam value="#generateHash(form.password1)#" cfsqltype="cf_sql_varchar" maxlength="255">,
                10000,
                1
            )
        </cfquery>
        <cflocation url="/admin/" addtoken="no">
    </cfif>

</cfif>

<cfparam name="attributes.pageTitle" default="First-time setup">
<cfinclude template="/includes/header_public.cfm">

<div class="row justify-content-center">
    <div class="col-md-5">
        <div class="card shadow-sm">
            <div class="card-header fw-semibold">Create first admin user</div>
            <div class="card-body">

                <p class="text-muted small mb-3">
                    This page is only available before any admin user exists.
                    It will redirect away permanently once setup is complete.
                </p>

                <cfif arrayLen(formErrors)>
                    <div class="alert alert-danger py-2">
                        <ul class="mb-0 small">
                            <cfloop array="#formErrors#" item="e">
                                <li><cfoutput>#encodeForHTML(e)#</cfoutput></li>
                            </cfloop>
                        </ul>
                    </div>
                </cfif>

                <form method="post" action="/initialize.cfm" novalidate>
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input  type="text"
                                class="form-control"
                                id="username"
                                name="username"
                                value="<cfoutput>#encodeForHTML(form.username)#</cfoutput>"
                                autocomplete="username"
                                autofocus>
                    </div>
                    <div class="mb-3">
                        <label for="password1" class="form-label">
                            Password
                            <span class="text-muted fw-normal">(min 8 characters)</span>
                        </label>
                        <input  type="password"
                                class="form-control"
                                id="password1"
                                name="password1"
                                autocomplete="new-password">
                    </div>
                    <div class="mb-4">
                        <label for="password2" class="form-label">Confirm password</label>
                        <input  type="password"
                                class="form-control"
                                id="password2"
                                name="password2"
                                autocomplete="new-password">
                    </div>
                    <button type="submit" name="submit" value="1" class="btn btn-primary w-100">
                        Create admin user
                    </button>
                </form>

            </div>
        </div>
    </div>
</div>

<cfinclude template="/includes/footer_public.cfm">
