<!---
    admin/entry_add.cfm  —  Add a new blocklist entry with evidence
--->
<cfinclude template="/config/settings.cfm">
<cfinclude template="/includes/functions.cfm">
<cfset requireLogin()>

<cfparam name="form.address"  default="">
<cfparam name="form.locked"   default="0">
<cfparam name="form.evidence"   default="">
<cfparam name="form.auto_expire" default="1">
<cfparam name="form.expires"     default="">
<cfparam name="form.submit"   default="">

<cfset formErrors  = []>

<!--- Pre-populate expiry date from default setting --->
<cfif NOT len(form.expires) AND application.defaultExpiryDays GT 0>
    <cfset form.expires = dateFormat(dateAdd("d", application.defaultExpiryDays, now()), "yyyy-mm-dd")>
</cfif>
<cfset successMsg  = "">

<cfif len(form.submit)>
    <cfset addr = trim(form.address)>

    <!--- Validation --->
    <cfif NOT len(addr)>
        <cfset arrayAppend(formErrors, "Address is required.")>
    <cfelse>
        <cfset detectedType = detectEntryType(addr)>
        <cfif detectedType EQ "unknown">
            <cfset arrayAppend(formErrors, "Address does not appear to be a valid IPv4 address, CIDR range, or hostname.")>
        </cfif>
    </cfif>

    <cfif NOT len(trim(form.evidence))>
        <cfset arrayAppend(formErrors, "Evidence is required. Document why this address is being listed.")>
    </cfif>

    <!--- Duplicate check --->
    <cfif NOT arrayLen(formErrors)>
        <cfif detectedType EQ "cidr">
            <cfset cidrBase = listFirst(addr, '/')>
            <cfset cidrBits = val(listLast(addr, '/'))>
        <cfelse>
            <cfset cidrBase = addr>
            <cfset cidrBits = 0>
        </cfif>

        <cfquery datasource="#application.dsn#" name="dupCheck">
            SELECT id FROM ip
            WHERE address = <cfqueryparam value="#cidrBase#" cfsqltype="cf_sql_varchar" maxlength="253">
              AND (
                    (<cfqueryparam value="#detectedType#" cfsqltype="cf_sql_varchar"> != 'cidr' AND cidr IS NULL)
                 OR (cidr = <cfqueryparam value="#cidrBits#" cfsqltype="cf_sql_tinyint">)
              )
            LIMIT 1
        </cfquery>
        <cfif dupCheck.recordCount GT 0>
            <cfset arrayAppend(formErrors, "This address is already listed. Use the edit page to update its evidence.")>
        </cfif>
    </cfif>

    <!--- Insert --->
    <cfif NOT arrayLen(formErrors)>
        <cfquery datasource="#application.dsn#" name="insertEntry" result="insertResult">
            INSERT INTO ip (entry_type, address, cidr, locked, active, expires, auto_expire, added_by)
            VALUES (
                <cfqueryparam value="#detectedType#" cfsqltype="cf_sql_varchar" maxlength="16">,
                <cfqueryparam value="#cidrBase#"     cfsqltype="cf_sql_varchar" maxlength="253">,
                <cfif detectedType EQ "cidr">
                    <cfqueryparam value="#cidrBits#" cfsqltype="cf_sql_tinyint">
                <cfelse>
                    NULL
                </cfif>,
                <cfqueryparam value="#val(form.locked)#" cfsqltype="cf_sql_tinyint">,
                1,
                <cfif len(trim(form.expires)) AND isDate(trim(form.expires))>
                    <cfqueryparam value="#dateFormat(trim(form.expires),'yyyy-mm-dd')# 23:59:59" cfsqltype="cf_sql_timestamp">
                <cfelse>
                    NULL
                </cfif>,
                <cfqueryparam value="#(form.auto_expire EQ '1') ? 1 : 0#" cfsqltype="cf_sql_tinyint">,
                <cfqueryparam value="#session.adminId#"  cfsqltype="cf_sql_integer">
            )
        </cfquery>

        <cfset newId = insertResult.generatedKey>

        <!--- Insert evidence --->
        <cfquery datasource="#application.dsn#">
            INSERT INTO evidence (ip_id, evidence, added_by)
            VALUES (
                <cfqueryparam value="#newId#"             cfsqltype="cf_sql_integer">,
                <cfqueryparam value="#trim(form.evidence)#" cfsqltype="cf_sql_clob">,
                <cfqueryparam value="#session.adminId#"   cfsqltype="cf_sql_integer">
            )
        </cfquery>

        <cfset writeAuditLog(
            action    = "ADD",
            target    = addr,
            entryType = detectedType,
            detail    = "locked=#form.locked#"
        )>

        <!--- Clear form on success --->
        <cfset form.address  = "">
        <cfset form.evidence = "">
        <cfset form.locked   = "0">
        <cfset successMsg = "Entry added successfully. <a href='/admin/entry_edit.cfm?id=#newId#'>View/edit</a> or add another below.">
    </cfif>
</cfif>

<cfparam name="attributes.pageTitle" default="Add entry">
<cfinclude template="/includes/header_admin.cfm">

<div class="row justify-content-center">
    <div class="col-lg-8">
        <div class="d-flex align-items-center mb-3">
            <h2 class="h4 fw-bold mb-0">Add blocklist entry</h2>
        </div>

        <cfif len(successMsg)>
            <div class="alert alert-success"><cfoutput>#successMsg#</cfoutput></div>
        </cfif>

        <cfif arrayLen(formErrors)>
            <div class="alert alert-danger">
                <ul class="mb-0">
                    <cfloop array="#formErrors#" item="e">
                        <li><cfoutput>#encodeForHTML(e)#</cfoutput></li>
                    </cfloop>
                </ul>
            </div>
        </cfif>

        <div class="card shadow-sm">
            <div class="card-body">
                <form method="post" action="/admin/entry_add.cfm" novalidate>

                    <div class="mb-3">
                        <label for="address" class="form-label fw-semibold">
                            IP address, CIDR range, or hostname
                            <span class="text-danger">*</span>
                        </label>
                        <input  type="text"
                                class="form-control font-monospace"
                                id="address"
                                name="address"
                                value="<cfoutput>#encodeForHTML(form.address)#</cfoutput>"
                                placeholder="192.0.2.1  or  192.0.2.0/24  or  spammer.example.com"
                                autocomplete="off"
                                autofocus>
                        <div class="form-text">
                            Single IPv4, CIDR notation (e.g. 192.0.2.0/24),
                            or hostname / domain (prefix with <code>.</code> for wildcard zone, e.g. <code>.example.com</code>).
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="evidence" class="form-label fw-semibold">
                            Evidence <span class="text-danger">*</span>
                        </label>
                        <textarea   class="form-control font-monospace"
                                    id="evidence"
                                    name="evidence"
                                    rows="12"
                                    placeholder="Paste raw log lines, spam sample headers, abuse report, etc."
                                    style="font-size:.85rem"><cfoutput>#encodeForHTML(form.evidence)#</cfoutput></textarea>
                        <div class="form-text">
                            This is displayed publicly on the evidence page. Redact any private information.
                        </div>
                    </div>

                    <div class="mb-4">
                        <div class="form-check form-switch">
                            <input  class="form-check-input"
                                    type="checkbox"
                                    role="switch"
                                    id="locked"
                                    name="locked"
                                    value="1"
                                    <cfif form.locked EQ "1">checked</cfif>>
                            <label class="form-check-label" for="locked">
                                <strong>Lock this entry</strong>
                                — prevent self-delist by the listed party
                            </label>
                        </div>
                        <div class="form-text ms-4">
                            Use for confirmed spammers, bot networks, or repeat offenders
                            where self-delist should not be permitted.
                        </div>
                    </div>

                    <div class="d-flex gap-2">
                        <button type="submit" name="submit" value="1" class="btn btn-primary">
                            Add to blocklist
                        </button>
                        <a href="/admin/entries.cfm" class="btn btn-outline-secondary">Cancel</a>
                    </div>
                </form>
            </div>
        </div>

        <div class="card mt-3 border-0 bg-light">
            <div class="card-body py-2 small text-muted">
                <strong>Tips:</strong>
                New entries take effect immediately.
                Evidence is shown publicly — paste raw log lines or mail headers.
                HTML is escaped; plain text only.
            </div>
        </div>
    </div>
</div>

<cfinclude template="/includes/footer_admin.cfm">
