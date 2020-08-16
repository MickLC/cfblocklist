<cfquery datasource="blocklist" name="currentlist">
    SELECT i.id, i.address, i.cidr, r.reason_text
    FROM ip i, reason r
    WHERE i.reason_id = r.id
    ORDER BY i.address
</cfquery>
<html>
    <body>
        <h1>Whizardries DNSBL</h1>
        <h2>Admin Area</h2>
        <h3>Current Listings</h3>
        <cfoutput>
            <form action="/admin/edit.cfm" method="POST">
                <input name="ip" type="text" list="comboid">
					<datalist id="comboid">
						<cfloop index="i" from="1" to="#currentlist.recordCount#">
							<cfoutput>
								<option value="#currentlist.id#">#currentlist.ip#/#currentlist.cidr# (#currentlist.reason_text#)</option>
							</cfoutput>
						</cfloop>
					</datalist>
				<input type="submit" name="submit" value="Submit">
            </form>
        </cfoutput>
    </body>
</html>