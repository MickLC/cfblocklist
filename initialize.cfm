<cfinclude template="/config/pepper.cfm" runonce="true">
<cfscript>
    function generateHash(
        required string password,
        string salt = GenerateSecretKey( 'AES' , '256' ),
        numeric iterations = randRange( 50000 , 100000 , 'SHA1PRNG' )
    ) {
        return arguments.iterations & ':' & arguments.salt & ':' & GeneratePBKDFkey( 'PBKDF2WithHmacSHA1' , arguments.password , arguments.salt & application.pepper , arguments.iterations );
    }
</cfscript>
<cfquery datasource="blocklist" name="any_users">
    select count(*) as numRows
    from login
</cfquery>
<cfif isDefined("form.submit")>
    <cfquery datasource="blocklist" name="insertfirstuser">
        insert into login
        (name,password,access_level)
        values
        ('#form.username#','#generateHash(form.password1)#',10000)
    </cfquery>
    <cflocation url="/admin/" addtoken="no" />
<cfelseif any_users.numRows GT 0>
    <cflocation url="/" addtoken="no" />
<cfelse>
    <html>
        <head>
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.19.1/jquery.validate.min.js"></script>
            <script>
                $().ready(function() {
                    // validate signup form on keyup and submit
                    $("#inituser").validate({
                        rules: {
                            username: {
                                required: true,
                                minlength: 2
                            },
                            password1: {
                                required: true,
                                minlength: 5
                            },
                            password2: {
                                required: true,
                                minlength: 5,
                                equalTo: "#password1"
                            }
                        },
                        messages: {
                            username: {
                                required: "Please enter a username",
                                minlength: "Your username must consist of at least 2 characters"
                            },
                            password1: {
                                required: "Please provide a password",
                                minlength: "Your password must be at least 5 characters long"
                            },
                            password2: {
                                required: "Please provide a password",
                                minlength: "Your password must be at least 5 characters long",
                                equalTo: "Please enter the same password as above"
                            }
                        }
                    });
                });
            </script>
        </head>
        <body>
            <p>Please create your first user.</p>
            <form action="/initialize.cfm" id="inituser" method="POST">
                <table>
                    <tr><td>Username: <input type="text" id="username" name="username" size="32" maxlength="64" /></td></tr>
                    <tr><td>Password: <input type="password" id="password1" name="password1" size="32" /></td></tr>
                    <tr><td>Retype password: <input type="password" id="password2" name="password2" size="32" /></td></tr>
                    <tr><td><input type="submit" value="Submit" name="submit" /></td></tr>
                </table>
            </form>
        </body>
    </html>
</cfif>