<cfquery datasource="blocklist" name="check">
    SELECT * FROM ip 
    WHERE address = '#url.ip#'
    OR INET_ATON('#url.ip#') BETWEEN 
    INET_ATON(address) AND INET_ATON(address) + POW(2,32-CIDR) - 1;
</cfquery>
<cfif check.recordCount is 0>
    <cflocation url="/" addtoken="no" />
</cfif>
<cfquery datasource="blocklist" name="evidence">
    SELECT * FROM evidence
    WHERE ip_id = #check.id#
</cfquery>
<cfoutput>
<html>
    <body>
        <h1>Evidence File for #check.address#/#check.cidr#</h1>
        #replace(replace(evidence.evidence,"#chr(60)#","&lt;","all"),"#chr(10)#","<br />","all")#
    </body>
</html>
</cfoutput>