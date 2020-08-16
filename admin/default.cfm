<cfquery datasource="blocklist" name="currentlist">
    SELECT i.id, i.address, i.cidr, r.reason_text
    FROM ip i, reason r
    WHERE i.reason_id = r.id
    ORDER BY INET_ATON(i.address)
</cfquery>
<cfquery datasource="blocklist" name="stats">
    select i.address, i.cidr, r.reason_text, i.expire
    from ip i, reason r 
    where i.reason_id = r.id
</cfquery>
<cfquery name="reason" dbtype="query">
    select count(*), reason_text
    from stats
    group by reason_text
    order by count(*) desc
</cfquery>
<html>
    <body>
        <h1>Whizardries DNSBL</h1>
        <h2>Admin Area</h2>
        <h3>Current Listings</h3>
        <cfoutput>
            <form action="/admin/edit.cfm" method="POST">
                <label for="ip">Current entries:</label>
                <select name="ip" id="ip">
                    <cfloop query="currentlist">
                        <option value="#currentlist.id#">#currentlist.address#/#currentlist.cidr# (#currentlist.reason_text#)</option>
                    </cfloop>
                </select><br />
				<input type="submit" name="submit" value="Submit">
            </form>
        </cfoutput>
        <h3>Stats</h3>
        <table>
            <tr>
                <th>Most common reason:</th>
                <td><cfoutput>#reason.reason_text# (#reason.count(*)#)</cfoutput></td>
            </tr>
            <tr>
                <th>Next 10 to expire:</th>
                <td>Coming with live data</td>
            </tr>
        </table>
    </body>
</html>