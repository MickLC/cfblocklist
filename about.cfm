<!---
    about.cfm  —  Public about/policy page explaining the DNSBL
--->
<cfinclude template="/config/pepper.cfm">
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfparam name="attributes.pageTitle" default="About">

<cfquery datasource="#application.dsn#" name="stats">
    SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN entry_type = 'ip'       THEN 1 ELSE 0 END) AS ip_count,
        SUM(CASE WHEN entry_type = 'cidr'     THEN 1 ELSE 0 END) AS cidr_count,
        SUM(CASE WHEN entry_type = 'hostname' THEN 1 ELSE 0 END) AS hostname_count
    FROM ip
</cfquery>

<cfinclude template="/includes/header_public.cfm">

<div class="row">
    <div class="col-lg-8">

        <h1 class="h3 fw-bold mb-1"><cfoutput>#encodeForHTML(application.siteName)#</cfoutput></h1>
        <p class="text-muted mb-4"><cfoutput>#encodeForHTML(application.siteTagline)#</cfoutput></p>

        <h2 class="h5 fw-semibold">What is this list?</h2>
        <p>
            <cfoutput>#encodeForHTML(application.siteName)#</cfoutput> is a
            DNS-based Block List (DNSBL) — a real-time list of IP addresses, IP ranges,
            and hostnames associated with spam, abuse, or policy violations.
            Mail servers and other systems query this list via DNS to help make
            filtering decisions.
        </p>

        <h2 class="h5 fw-semibold mt-4">What gets listed?</h2>
        <p>Entries are added when an IP address, IP range, or hostname has been observed:</p>
        <ul>
            <li>Sending unsolicited bulk email (spam)</li>
            <li>Participating in botnet or zombie activity</li>
            <li>Conducting brute-force or dictionary attacks</li>
            <li>Engaging in other abusive or policy-violating behaviour</li>
        </ul>
        <p>
            Every listing includes evidence — raw log excerpts, mail headers, or
            other documentation — visible via the public evidence page.
        </p>

        <h2 class="h5 fw-semibold mt-4">How do I check if I am listed?</h2>
        <p>
            Use the <a href="/">lookup form on the home page</a>. Enter a single IPv4 address,
            a CIDR range, or a hostname. If a match is found, you will see the listing
            details and a link to the associated evidence.
        </p>

        <h2 class="h5 fw-semibold mt-4">How do I get delisted?</h2>
        <p>
            Listings fall into two categories:
        </p>
        <ul>
            <li>
                <span class="badge bg-success">Unlocked</span>
                entries may be self-delisted immediately using the
                <em>Delist</em> button on the lookup result or evidence page.
                No account or email verification is required.
            </li>
            <li>
                <span class="badge bg-danger">Locked</span>
                entries are reserved for confirmed or repeat offenders.
                Self-delist is not available. To appeal a locked listing,
                contact <a href="mailto:<cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput>"><cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput></a>
                with details of the corrective action taken.
            </li>
        </ul>
        <p>
            <strong>Important:</strong> Delisting removes the entry from the DNS zone on
            the next zone reload, but DNS propagation across caching resolvers may take
            up to 30 minutes. If you continue to experience deliverability issues after
            that window, verify you are checking the correct IP or hostname.
        </p>

        <h2 class="h5 fw-semibold mt-4">How do I query this list via DNS?</h2>
        <p>
            To check whether <code>192.0.2.1</code> is listed, reverse the octets
            and append the zone name:
        </p>
        <pre class="bg-light border rounded p-3"><code>dig 1.2.0.192.<cfoutput>#encodeForHTML(application.dnsZone)#</cfoutput> A</code></pre>
        <p>
            A response of <code>127.0.0.2</code> means the address is listed.
            <code>NXDOMAIN</code> means it is not listed.
        </p>
        <p>
            For use in a mail server (e.g. Postfix), add the zone to your
            <code>smtpd_recipient_restrictions</code> or
            <code>smtpd_client_restrictions</code>:
        </p>
        <pre class="bg-light border rounded p-3"><code>reject_rbl_client <cfoutput>#encodeForHTML(application.dnsZone)#</cfoutput></code></pre>

        <h2 class="h5 fw-semibold mt-4">Contact</h2>
        <p>
            For questions, appeals of locked listings, or to report abuse from an
            IP not yet listed, contact:
            <a href="mailto:<cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput>"><cfoutput>#encodeForHTML(application.adminEmail)#</cfoutput></a>.
        </p>

    </div>

    <!--- Stats sidebar --->
    <div class="col-lg-4">
        <div class="card shadow-sm">
            <div class="card-header fw-semibold">Current list statistics</div>
            <div class="card-body">
                <dl class="row mb-0">
                    <dt class="col-7">Total listings</dt>
                    <dd class="col-5 fw-bold"><cfoutput>#stats.total#</cfoutput></dd>

                    <dt class="col-7">Individual IPs</dt>
                    <dd class="col-5"><cfoutput>#stats.ip_count#</cfoutput></dd>

                    <dt class="col-7">CIDR ranges</dt>
                    <dd class="col-5"><cfoutput>#stats.cidr_count#</cfoutput></dd>

                    <dt class="col-7">Hostnames</dt>
                    <dd class="col-5"><cfoutput>#stats.hostname_count#</cfoutput></dd>
                </dl>
            </div>
        </div>

        <div class="card shadow-sm mt-3">
            <div class="card-body">
                <a href="/" class="btn btn-primary w-100">Check an IP or hostname</a>
            </div>
        </div>
    </div>
</div>

<cfinclude template="/includes/footer_public.cfm">
