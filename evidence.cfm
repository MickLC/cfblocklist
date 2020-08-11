<cfquery datasource="blocklist" name="check">
    SELECT * FROM ip 
    WHERE address = '#url.ip#'
    OR INET_ATON('#url.ip#') BETWEEN 
    INET_ATON(address) AND INET_ATON(address) + POW(2,32-CIDR) - 1;
</cfquery>
<cfquery datasource="blocklist" name="evidence">
    SELECT * FROM evidence
    WHERE ip_id = check.id
</cfquery>
<cfoutput>
<html>
    <body>
        <h1>Evidence File for #ip.address#/#ip.cidr#</h1>
        <p>#evidence.evidence#</p>
    </body>
</html>
</cfoutput>