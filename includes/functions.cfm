<!---
    includes/functions.cfm
    Shared utility functions. Include once per request via Application.cfm
    or at the top of each template as needed.
--->
<cfscript>
// ── Password hashing (PBKDF2 via Lucee's GeneratePBKDFKey) ─────────────────
function generateHash(
    required string password,
    string  salt       = GenerateSecretKey('AES', '256'),
    numeric iterations = randRange(50000, 100000, 'SHA1PRNG')
) {
    var derived = GeneratePBKDFKey(
        'PBKDF2WithHmacSHA256',
        arguments.password,
        arguments.salt & application.pepper,
        arguments.iterations,
        256
    );
    return arguments.iterations & ':' & arguments.salt & ':' & derived;
}

function verifyHash(required string password, required string stored) {
    var parts      = listToArray(arguments.stored, ':');
    var iterations = val(parts[1]);
    var salt       = parts[2];
    var expected   = parts[3];
    var derived    = GeneratePBKDFKey(
        'PBKDF2WithHmacSHA256',
        arguments.password,
        salt & application.pepper,
        iterations,
        256
    );
    // Constant-time comparison
    return (derived == expected);
}

// ── Input sanitisation ────────────────────────────────────────────────────
function h(required string s) {
    return encodeForHTML(arguments.s);
}

// ── IP validation helpers ─────────────────────────────────────────────────
function isValidIPv4(required string addr) {
    return reFind(
        '^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$',
        trim(arguments.addr)
    ) GT 0;
}

function isValidCIDR(required string addr) {
    // Accepts "1.2.3.0/24" style
    if (!find('/', arguments.addr)) return false;
    var base = listFirst(arguments.addr, '/');
    var bits = val(listLast(arguments.addr, '/'));
    return isValidIPv4(base) && bits >= 0 && bits <= 32;
}

function isValidHostname(required string addr) {
    // Accepts plain hostnames and domain names, including leading dot for wildcard zones
    var s = trim(arguments.addr);
    if (left(s, 1) == '.') s = mid(s, 2, len(s)-1); // strip leading dot
    return reFind('^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', s) GT 0;
}

function detectEntryType(required string addr) {
    var s = trim(arguments.addr);
    if (find('/', s) && isValidCIDR(s))          return 'cidr';
    if (isValidIPv4(s))                           return 'ip';
    if (isValidHostname(s))                       return 'hostname';
    return 'unknown';
}

// ── rbldnsd reload ────────────────────────────────────────────────────────
function reloadRbldnsd() {
    if (len(trim(application.rbldnsdReloadScript)) == 0) return;
    try {
        cfexecute(
            name      = application.rbldnsdReloadScript,
            timeout   = 10,
            variable  = "local.execOut",
            errorVariable = "local.execErr"
        );
    } catch(any e) {
        // Log but don't surface to user — the entry was already saved
        cflog(
            file = "blocklist",
            type = "error",
            text = "rbldnsd reload failed: #e.message#"
        );
    }
}

// ── Audit logging ─────────────────────────────────────────────────────────
function writeAuditLog(
    required string action,
    string target    = '',
    string entryType = '',
    string detail    = ''
) {
    var adminId = isDefined('session.adminId') ? session.adminId : javaCast('null', '');
    var browserIP = cgi.remote_addr;

    cfquery(datasource=application.dsn) {
        echo("INSERT INTO audit_log (admin_id, action, entry_type, target, detail, ip_addr)
              VALUES (");
        if (isNull(adminId)) {
            echo("NULL");
        } else {
            cfqueryparam(value=adminId, cfsqltype="cf_sql_integer");
        }
        echo(", ");
        cfqueryparam(value=action,    cfsqltype="cf_sql_varchar", maxlength=32);
        echo(", ");
        cfqueryparam(value=entryType, cfsqltype="cf_sql_varchar", maxlength=16, null=(!len(entryType)));
        echo(", ");
        cfqueryparam(value=target,    cfsqltype="cf_sql_varchar", maxlength=253, null=(!len(target)));
        echo(", ");
        cfqueryparam(value=detail,    cfsqltype="cf_sql_clob",    null=(!len(detail)));
        echo(", ");
        cfqueryparam(value=browserIP, cfsqltype="cf_sql_varchar", maxlength=45);
        echo(")");
    }
}

// ── Session auth check ────────────────────────────────────────────────────
function requireLogin() {
    if (!isDefined('session.adminId') || !session.adminId) {
        location(url="/admin/login.cfm", addtoken=false);
        abort;
    }
}

// ── Pagination helper ─────────────────────────────────────────────────────
function getPaginationVars(numeric totalRows, numeric currentPage=1, numeric pageSize=application.pageSize) {
    var p = {};
    p.totalRows   = arguments.totalRows;
    p.pageSize    = arguments.pageSize;
    p.totalPages  = max(1, ceiling(arguments.totalRows / arguments.pageSize));
    p.currentPage = max(1, min(arguments.currentPage, p.totalPages));
    p.startRow    = ((p.currentPage - 1) * p.pageSize) + 1;
    p.offset      = p.startRow - 1;
    return p;
}
</cfscript>
