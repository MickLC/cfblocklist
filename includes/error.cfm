<!--- includes/error.cfm --->
<cfparam name="attributes.pageTitle" default="Error">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/header_public.cfm">
<div class="alert alert-danger">
    <h4 class="alert-heading">An error occurred</h4>
    <p>Something went wrong. Please try again or contact the administrator.</p>
    <cfif isDefined("error") && cgi.server_name contains "local">
        <hr>
        <pre class="mb-0 small"><cfoutput>#encodeForHTML(error.message)#</cfoutput></pre>
    </cfif>
</div>
<a href="/" class="btn btn-secondary">Return to Home</a>
<cfinclude template="/includes/footer_public.cfm">
