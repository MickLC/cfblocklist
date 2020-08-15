<cfinclude name="/config/pepper.cfm">
<cfscript>
    function generateHash(
        required string password,
        string salt = GenerateSecretKey( 'AES' , '256' ),
        numeric iterations = randRange( 50000 , 100000 , 'SHA1PRNG' )
    ) {
        return arguments.iterations & ':' & arguments.salt & ':' & GeneratePBKDFkey( 'PBKDF2WithHmacSHA1' , arguments.password1 , arguments.salt & application.pepper , arguments.iterations );
    }
</cfscript>
<cfquery datasource="blocklist" name="any_users">
    select count(*) as numRows
    from login
</cfquery>
<cfif any_users.numRows GT 0>
    <cflocation url="/" addtoken="no" />
<cfelseif isDefined(form.submit)>
    <cfquery datasource="blocklist" name="insertfirstuser">
        insert into login
        (name,password,access_level)
        values
        ('#form.username#','#generateHash(form.password1)#',10000)
    </cfquery>
    <cflocation url="/admin/" addtoken="no" />
</cfelse>
    <html>
        <head>
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.19.1/jquery.validate.min.js"></script>
        </head>
        <body>
            <p>Please create your first user.</p>
            <form action="." method="POST" name="inituser">
                <table>
                    <tr><td>Username: <cfinput type="text" name="username" size="32" maxlength="64" /></td></tr>
                    <tr><td>Password: <cfinput type="password" name="password1" size="32" /></td></tr>
                    <tr><td>Retype password: <cfinput type="password" name="password2" size="32" /></td></tr>
                    <tr><td><input type="submit" value="Submit" name="submit" /></td></tr>
                </table>
            </form>
        </body>
    </html>
</cfif>