<!--- admin/logout.cfm --->
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfif isDefined("session.adminId")>
    <cfset writeAuditLog(action="LOGOUT")>
</cfif>
<cfset structClear(session)>
<cflocation url="/admin/login.cfm" addtoken="no">
