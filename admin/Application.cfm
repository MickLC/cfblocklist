<cfinclude template="/config/pepper.cfm" runonce="true">
<cfscript>
    function checkPassword(
    required string password,
    required string hash
    ) {
        var iterations = ListGetAt(arguments.hash, 1, ':');
        var salt = ListGetAt(arguments.hash, 2, ':');
        return ( generateHash(arguments.password , salt , iterations) EQ arguments.hash );
    }
</cfscript>
<cfquery datasource="blocklist" name="any_users">
    select count(*) as numRows
    from login
</cfquery>
<cfif any_users.numRows GT 0>
    <cfif not isdefined("session.USERAUTH") or session.USERAUTH is "0">
        <cfif isdefined("form.loginpost")>
            <cfquery datasource="reputation" name="auth">
                select * 
                from login 
                where login.name='#form.username#'
            </cfquery>
            <cfif auth.recordcount GT 0>
                <cfif checkPassword(#form.password#,#auth.password#) EQ "true">
                    <cfset session.userauth = #auth.access_level#>
                </cfif>
            <cfelse>
                <cfset session.userauth = 0>
                Not authorized.
                <cfabort>	
            </cfif>
        <cfelse>
            <form method="post" action=".">
                <input type="hidden" name="loginpost" value="true">
                Username: <input name="username" type="text" size="32" maxlength="64"><br />
                Password: <input name="password" type="password" size="32" maxlength="64"><br />
                <input type="submit" value="Enter" name="login"><br>
            </form>
            <cfabort />
        </cfif>
    </cfif>
<cfelse>
    <cflocation url="/initialize.cfm" addtoken="no" />
</cfif>