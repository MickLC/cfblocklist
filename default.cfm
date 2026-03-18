<!---
    default.cfm  —  Public homepage: DNSBL explanation + IP/hostname lookup
--->
<cfinclude template="/config/pepper.cfm">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">

<cfparam name="form.submit"  default="">
<cfparam name="url.delisted"  default="">
<cfparam name="url.q"         default="">
<cfparam name="form.query"   default="">
<cfparam name="attributes.pageTitle" default="IP & Domain Lookup">

<cfset searched   = false>
<cfset lookupVal  = "">
<cfset checkResult = queryNew("")>

<cfif len(trim(form.query)) AND len(form.submit)>
    <cfset searched  = true>
    <cfset lookupVal = trim(form.query)>

    <!--- Determine what kind of thing was looked up --->
    <cfset lType = detectEntryType(lookupVal)>

    <cfif lType EQ "ip" OR lType EQ "cidr">
        <!--- IPv4 lookup: exact match OR falls within a CIDR range --->
        <cfquery datasource="#application.dsn#" name="checkResult">
            SELECT  i.id, i.entry_type, i.address, i.cidr, i.locked, i.added_date
            FROM    ip i
            WHERE   i.entry_type IN ('ip','cidr')
              AND   i.active = 1
              AND (
                    i.address = <cfqueryparam value="#lookupVal#" cfsqltype="cf_sql_varchar" maxlength="253">
                 OR (
                        i.entry_type = 'cidr'
                    AND INET_ATON(<cfqueryparam value="#lookupVal#" cfsqltype="cf_sql_varchar" maxlength="253">)
                        BETWEEN INET_ATON(i.address) AND INET_ATON(i.address) + POW(2, 32 - i.cidr) - 1
                    )
              )
            LIMIT 1
        </cfquery>
    <cfelseif lType EQ "hostname">
        <!--- Hostname lookup: exact + wildcard parent domain match --->
        <cfquery datasource="#application.dsn#" name="checkResult">
            SELECT  i.id, i.entry_type, i.address, i.cidr, i.locked, i.added_date
            FROM    ip i
            WHERE   i.entry_type = 'hostname'
              AND   i.active = 1
              AND (
                    i.address = <cfqueryparam value="#lookupVal#" cfsqltype="cf_sql_varchar" maxlength="253">
                 OR i.address = <cfqueryparam value=".#listRest(lookupVal,'.')#" cfsqltype="cf_sql_varchar" maxlength="253">
              )
            LIMIT 1
        </cfquery>
    <cfelse>
        <!--- Not a valid format — show an error --->
        <cfset lookupError = "Please enter a valid IPv4 address, CIDR range, or hostname.">
    </cfif>
</cfif>

<cfinclude template="/includes/header_public.cfm">

<!--- ── Hero / explanation ─────────────────────────────────────────────── --->
<div class="row mb-4">
    <div class="col-lg-8">
        <h1 class="h3 fw-bold mb-1"><cfoutput>#encodeForHTML(application.siteName)#</cfoutput></h1>
        <p class="text-muted mb-0"><cfoutput>#encodeForHTML(application.siteTagline)#</cfoutput></p>
    </div>
</div>

<div class="row g-4 mb-4">
    <div class="col-md-8">

        <!--- ── Lookup form ──────────────────────────────────────────────── --->
        <div class="card shadow-sm">
            <div class="card-body">
                <h2 class="h5 card-title mb-3">Check an IP address or hostname</h2>
                <form method="post" action="/" novalidate>
                    <div class="input-group">
                        <input  type="text"
                                class="form-control form-control-lg"
                                id="query"
                                name="query"
                                placeholder="192.0.2.1  or  192.0.2.0/24  or  example.com"
                                value="<cfoutput>#encodeForHTML(lookupVal)#</cfoutput>"
                                autocomplete="off"
                                autofocus>
                        <button class="btn btn-primary btn-lg" type="submit" name="submit" value="1">
                            Look up
                        </button>
                    </div>
                    <div class="form-text mt-1">
                        Accepts IPv4 addresses, CIDR ranges (e.g. 192.0.2.0/24), or hostnames / domains.
                    </div>
                </form>
            </div>
        </div>

        <!--- ── Results ──────────────────────────────────────────────────── --->
        <cfif searched>
            <div class="mt-3">
                <cfif url.delisted EQ "1" AND NOT len(form.submit)>
                    <div class="alert alert-info">
                        <strong>No longer listed:</strong>
                        <cfif len(url.q)><cfoutput>#encodeForHTML(url.q)#</cfoutput> is</cfif>
                        not currently in this blocklist.
                    </div>
                    <div class="alert alert-warning">
                        <strong>Invalid input:</strong> <cfoutput>#encodeForHTML(lookupError)#</cfoutput>
                    </div>

                <cfelseif checkResult.recordCount GT 0>
                    <div class="card border-danger shadow-sm">
                        <div class="card-header bg-danger text-white d-flex align-items-center justify-content-between">
                            <span>
                                <strong>Listed</strong>
                                &mdash; <cfoutput>#encodeForHTML(lookupVal)#</cfoutput>
                            </span>
                            <cfif checkResult.locked>
                                <span class="badge bg-light text-danger">Locked — delist not available</span>
                            <cfelse>
                                <span class="badge bg-light text-success">Self-delist available</span>
                            </cfif>
                        </div>
                        <div class="card-body">
                            <dl class="row mb-0">
                                <dt class="col-sm-3">Listed entry</dt>
                                <dd class="col-sm-9 font-monospace">
                                    <cfoutput>
                                    #encodeForHTML(checkResult.address)#<cfif checkResult.entry_type EQ "cidr">/#encodeForHTML(checkResult.cidr)#</cfif>
                                    </cfoutput>
                                </dd>
                                <dt class="col-sm-3">Entry type</dt>
                                <dd class="col-sm-9">
                                    <cfoutput>
                                    <span class="badge
                                        <cfif checkResult.entry_type EQ 'hostname'>bg-purple text-white" style="background:#6f42c1
                                        <cfelseif checkResult.entry_type EQ 'cidr'>bg-primary
                                        <cfelse>bg-info text-dark</cfif>">
                                        #uCase(checkResult.entry_type)#
                                    </span>
                                    </cfoutput>
                                </dd>
                                <dt class="col-sm-3">Date listed</dt>
                                <dd class="col-sm-9"><cfoutput>#dateFormat(checkResult.added_date,"mmm d, yyyy")#</cfoutput></dd>
                            </dl>

                            <div class="mt-3 d-flex gap-2">
                                <a href="/evidence.cfm?id=<cfoutput>#encodeForURL(checkResult.id)#</cfoutput>"
                                   class="btn btn-outline-danger btn-sm">
                                    View evidence
                                </a>
                                <cfif NOT checkResult.locked>
                                    <a href="/delist.cfm?id=<cfoutput>#encodeForURL(checkResult.id)#</cfoutput>"
                                       class="btn btn-outline-success btn-sm"
                                       onclick="return confirm('Remove this listing? This action is immediate and cannot be undone.')">
                                        Request delist
                                    </a>
                                </cfif>
                            </div>

                            <cfif checkResult.locked>
                                <div class="alert alert-warning mt-3 mb-0 small">
                                    This listing is locked and cannot be self-delisted.
                                    <cfoutput>#encodeForHTML(application.contactText)#</cfoutput>
                                    Contact <a href="mailto:#encodeForHTML(application.adminEmail)#"><cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput></a>.
                                </div>
                            </cfif>
                        </div>
                    </div>

                <cfelse>
                    <div class="alert alert-success">
                        <strong>Not listed:</strong>
                        <cfoutput>#encodeForHTML(lookupVal)#</cfoutput>
                        is not currently in this blocklist.
                    </div>
                </cfif>
            </div>
        </cfif>

    </div>

    <!--- ── Info sidebar ─────────────────────────────────────────────────── --->
    <div class="col-md-4">
        <div class="card shadow-sm">
            <div class="card-body">
                <h5 class="card-title">About this blocklist</h5>
                <p class="small text-muted">
                    This DNSBL lists IP addresses, IP ranges, and hostnames that have been
                    identified as sources of spam, abuse, or other policy violations.
                </p>
                <p class="small text-muted">
                    Mail servers and other systems query this list via DNS to make filtering decisions.
                </p>
                <hr>
                <h6 class="small fw-bold">If you are listed</h6>
                <p class="small text-muted mb-1">
                    Use the lookup above to find your entry. If your listing is
                    <span class="text-success fw-semibold">unlocked</span>, you may
                    self-delist immediately. Locked entries require administrator review —
                    please contact <a href="mailto:<cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput>"><cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput></a>.
                </p>
            </div>
        </div>
    </div>
</div>

<cfinclude template="/includes/footer_public.cfm">
