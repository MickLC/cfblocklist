<!--- includes/error.cfm --->
<cfparam name="attributes.pageTitle" default="Error">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/header_public.cfm">
<div class="alert alert-danger">
    <h4 class="alert-heading">An error occurred</h4>
    <p>Something went wrong. Please try again or contact the administrator.</p>
    <cfif isDefined("error")>
        <hr>
        <p class="mb-1 small fw-bold">Error message:</p>
        <pre class="mb-2 small"><cfoutput>#encodeForHTML(error.message)#</cfoutput></pre>
        <p class="mb-1 small fw-bold">Detail:</p>
        <pre class="mb-2 small"><cfoutput>#encodeForHTML(error.detail)#</cfoutput></pre>
        <p class="mb-1 small fw-bold">Template:</p>
        <pre class="mb-0 small"><cfoutput>#encodeForHTML(error.template)#</cfoutput></pre>
    </cfif>
</div>
<a href="/" class="btn btn-secondary">Return to Home</a>
<cfinclude template="/includes/footer_public.cfm">
