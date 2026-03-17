<!---
    admin/login.cfm  —  Admin login form
--->
<cfinclude template="/config/pepper.cfm">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">

<!--- Already logged in? --->
<cfif isDefined("session.adminId") AND session.adminId GT 0>
    <cflocation url="/admin/" addtoken="no">
</cfif>

<cfparam name="form.username" default="">
<cfparam name="form.password" default="">
<cfparam name="form.submit"   default="">
<cfset loginError = "">

<cfif len(form.submit)>
    <cfif NOT len(trim(form.username)) OR NOT len(trim(form.password))>
        <cfset loginError = "Username and password are required.">
    <cfelse>
        <cfquery datasource="#application.dsn#" name="getUser">
            SELECT id, name, password, access_level, active
            FROM   login
            WHERE  name   = <cfqueryparam value="#trim(form.username)#" cfsqltype="cf_sql_varchar" maxlength="64">
              AND  active  = 1
            LIMIT  1
        </cfquery>

        <cfif getUser.recordCount EQ 0 OR NOT verifyHash(form.password, getUser.password)>
            <cfset loginError = "Invalid username or password.">
            <!--- Generic message prevents username enumeration --->
        <cfelse>
            <cfset session.adminId    = getUser.id>
            <cfset session.adminName  = getUser.name>
            <cfset session.adminLevel = getUser.access_level>

            <!--- Record last login --->
            <cfquery datasource="#application.dsn#">
                UPDATE login SET last_login = NOW()
                WHERE id = <cfqueryparam value="#getUser.id#" cfsqltype="cf_sql_integer">
            </cfquery>

            <cfset writeAuditLog(action="LOGIN", detail="Successful login")>
            <cflocation url="/admin/" addtoken="no">
        </cfif>
    </cfif>
</cfif>
--->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Login &mdash; <cfoutput>#encodeForHTML(application.siteName)#</cfoutput></title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
          crossorigin="anonymous">
    <style>
        body { background: #212529; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .login-card { width: 100%; max-width: 380px; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="card shadow-lg border-0">
            <div class="card-body p-4">
                <h4 class="card-title fw-bold mb-1">
                    <cfoutput>#encodeForHTML(application.siteName)#</cfoutput>
                </h4>
                <p class="text-muted small mb-4">Admin login</p>

                <cfif len(loginError)>
                    <div class="alert alert-danger py-2 small">
                        <cfoutput>#encodeForHTML(loginError)#</cfoutput>
                    </div>
                </cfif>

                <form method="post" action="/admin/login.cfm" novalidate>
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
                    <div class="mb-4">
                        <label for="password" class="form-label">Password</label>
                        <input  type="password"
                                class="form-control"
                                id="password"
                                name="password"
                                autocomplete="current-password">
                    </div>
                    <button type="submit" name="submit" value="1" class="btn btn-primary w-100">
                        Log in
                    </button>
                </form>
            </div>
        </div>
        <div class="text-center mt-3">
            <a href="/" class="text-secondary small">&larr; Public site</a>
        </div>
    </div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc4s9bIOgUxi8T/jzmKG0GFqkKqmEdV8V4xn9ZFpFpOlHmNMk"
        crossorigin="anonymous"></script>
</body>
</html>
