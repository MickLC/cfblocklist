<cfif isDefined("form.submit")>
    <cfset testresult = "<br />We would check " & form.ip_addr & " here." />
</cfif>
<html>
    <body>
        <h1>Whizardries DNSBL</h1>
        <form method="POST" action="default.cfm">
            <table border="0">
                <tr>
                    <td><label for="ip_addr">Enter IP to check:</label></td>
                    <td><input type="text" id="ip_addr" name="ip_addr"/></td>
                </tr>
                <tr>
                    <td><input type="submit" name="submit" value="submit"/></td>
                </tr> 
            </table>
        </form>
        <cfif isDefined("testresult")>
            <cfoutput>#testresult#</cfoutput>
        </cfif>
    </body>
</html>