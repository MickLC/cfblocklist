<cfquery datasource="blocklist" name="check">
    SELECT * FROM ip 
    WHERE address = '#url.ip#'
    OR INET_ATON('#url.ip#') BETWEEN 
    INET_ATON(address) AND INET_ATON(address) + POW(2,32-CIDR) - 1;
</cfquery>
<cfquery datasource="blocklist" name="evidence">
    SELECT * FROM evidence
    WHERE ip_id = #check.id#
</cfquery>
<cfoutput>
<html>
    <body>
        <h1>Evidence File for #check.address#/#check.cidr#</h1>
        <cfloop from="1" to="35" index="i">
            #mid(evidence.evidence,i,1)# #asc(mid(evidence.evidence,i,1))#<br />
        </cfloop>
        #evidence.evidence#
    </body>
</html>
</cfoutput>