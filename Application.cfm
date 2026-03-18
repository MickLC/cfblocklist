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
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">

<!---
    ── Pepper resolution (two-tier fallback, no root/sudo required) ──────────

    The pepper is a secret value mixed into every password hash. It must never
    be stored inside the web root where a browser or path traversal could reach it.

    Resolution order (first one that produces a value wins):

    1. Environment variable  BLOCKLIST_PEPPER
       Set this in Lucee's own startup script — no root needed if you own
       the Lucee installation:

         Edit {lucee-install}/tomcat/bin/setenv.sh and add:
           export BLOCKLIST_PEPPER="your-hex-string"

       Or in {lucee-install}/tomcat/conf/catalina.properties add:
           BLOCKLIST_PEPPER=your-hex-string

       Restart Lucee after changing either file.

    2. Flat file above the web root
       Create a plain-text file containing only the pepper value, somewhere
       the Lucee process can read but that your web server cannot serve.
       A directory one level above your web root works on any standard hosting
       layout — no root needed, just write access to your own home directory.

       Example (web root is /home/youruser/public_html):
         echo "your-hex-string" > /home/youruser/.blocklist/pepper.txt
         chmod 600 /home/youruser/.blocklist/pepper.txt

       Then set the full path in config/settings.cfm:
         application.pepperFile = "/home/youruser/.blocklist/pepper.txt";

    Generate a suitable value with:  openssl rand -hex 32

    If neither is configured, the app displays a clear setup error and refuses
    to start rather than running with no pepper.
--->
<cfif NOT isDefined("application.pepper") OR NOT len(trim(application.pepper))>

    <!--- Tier 1: environment variable --->
    <cfscript>
    try {
        local.envPepper = createObject("java", "java.lang.System").getenv("BLOCKLIST_PEPPER");
        if (!isNull(local.envPepper) && len(trim(local.envPepper))) {
            application.pepper = trim(local.envPepper);
        }
    } catch (any e) { /* not available in this JVM */ }
    </cfscript>

    <!--- Tier 2: flat file above the web root --->
    <cfif NOT isDefined("application.pepper") OR NOT len(trim(application.pepper))>
        <cfif isDefined("application.pepperFile") AND len(trim(application.pepperFile))>
            <cfif fileExists(application.pepperFile)>
                <cftry>
                    <cfset application.pepper = trim(fileRead(application.pepperFile))>
                <cfcatch>
                    <!--- Will fall through to the error below --->
                </cfcatch>
                </cftry>
            </cfif>
        </cfif>
    </cfif>

    <!--- Neither worked — refuse to start --->
    <cfif NOT isDefined("application.pepper") OR NOT len(trim(application.pepper))>
        <cfheader statuscode="500" statustext="Configuration Error">
        <cfoutput>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Setup required</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
        </head>
        <body class="bg-light">
        <div class="container py-5" style="max-width:680px">
            <div class="alert alert-danger">
                <h4 class="alert-heading">cfblocklist: pepper not configured</h4>
                <p>
                    The application cannot start without a pepper value.
                    Configure it using <strong>one</strong> of these methods
                    (no root or sudo required for either):
                </p>
                <hr>
                <h6>Option A &mdash; Environment variable (preferred)</h6>
                <p>
                    Add the following line to
                    <code>{lucee-install}/tomcat/bin/setenv.sh</code>
                    and restart Lucee:
                </p>
                <pre class="bg-white border rounded p-2">export BLOCKLIST_PEPPER="your-hex-string"</pre>

                <h6 class="mt-3">Option B &mdash; Flat file above the web root</h6>
                <p>
                    Create a file <strong>outside</strong> the web root containing only
                    the pepper value, then set its path in
                    <code>config/settings.cfm</code>:
                </p>
                <pre class="bg-white border rounded p-2">application.pepperFile = "/home/youruser/.blocklist/pepper.txt";</pre>
                <hr>
                <p class="mb-0">
                    Generate a value: <code>openssl rand -hex 32</code>
                </p>
            </div>
        </div>
        </body></html>
        </cfoutput>
        <cfabort>
    </cfif>

</cfif>

<!--- Redirect all /admin/* requests to login if not authenticated --->
<cfif cgi.script_name CONTAINS "/admin/" AND
      cgi.script_name DOES NOT CONTAIN "/admin/login.cfm" AND
      cgi.script_name DOES NOT CONTAIN "/admin/logout.cfm">
    <cfif NOT (isDefined("session.adminId") AND isNumeric(session.adminId) AND session.adminId GT 0)>
        <cflocation url="/admin/login.cfm" addtoken="no">
    </cfif>
</cfif>
