<!---
    Application.cfm  —  Lucee application bootstrap
    Runs before every request in this directory tree.
--->
<cfapplication
    name              = "blocklist"
    datasource        = "blocklist"
    loginStorage      = "session"
    sessionManagement = "yes"
    sessionTimeout    = "#CreateTimeSpan(0,4,0,0)#"
    setClientCookies  = "yes"
    secureJSON        = "yes" />

<!--- Global error handler --->
<cferror type="exception" template="/includes/error.cfm" />

<!--- Load site config and utility functions for every request --->
<cfinclude template="/config/pepper.cfm">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">

<!--- Redirect all /admin/* requests to login if not authenticated --->
<cfif cgi.script_name CONTAINS "/admin/" AND
      cgi.script_name DOES NOT CONTAIN "/admin/login.cfm" AND
      cgi.script_name DOES NOT CONTAIN "/admin/logout.cfm">
    <cfif NOT (isDefined("session.adminId") AND isNumeric(session.adminId) AND session.adminId GT 0)>
        <cflocation url="/admin/login.cfm" addtoken="no">
    </cfif>
</cfif>
