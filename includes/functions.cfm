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
    // Constant-time comparison via java.security.MessageDigest.isEqual().
    var jMD = createObject("java", "java.security.MessageDigest");
    return jMD.isEqual(
        derived.getBytes("UTF-8"),
        expected.getBytes("UTF-8")
    );
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
    if (!find('/', arguments.addr)) return false;
    var base = listFirst(arguments.addr, '/');
    var bits = val(listLast(arguments.addr, '/'));
    return isValidIPv4(base) && bits >= 0 && bits <= 32;
}

function isValidHostname(required string addr) {
    var s = trim(arguments.addr);
    if (left(s, 1) == '.') s = mid(s, 2, len(s)-1);
    return reFind('^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', s) GT 0;
}

function detectEntryType(required string addr) {
    var s = trim(arguments.addr);
    if (find('/', s) && isValidCIDR(s))          return 'cidr';
    if (isValidIPv4(s))                           return 'ip';
    if (isValidHostname(s))                       return 'hostname';
    return 'unknown';
}

// ── Evidence redaction (public display only — raw text is preserved in DB) ──
//
// Removes information that could identify spamtrap addresses or internal
// infrastructure. Applied only in evidence.cfm (public view); the admin
// entry_edit.cfm always shows the unredacted original.
//
// Rules applied in order:
//   1. Manual blocks:  [REDACT]...[/REDACT]  → [redacted]
//   2. Recipient-revealing headers (whole line after the colon):
//        To: / Cc: / Bcc: / X-Original-To: / Delivered-To:
//        X-Forwarded-To: / Envelope-To: / X-Envelope-To:
//        X-RCPT-To: / X-Spam-Rcpt:
//   3. Return-Path: address (the angle-bracket envelope form)
//   4. Received: lines — redact the "for <addr>" clause only,
//      preserving the relay hop info which is the useful part
//   5. Any remaining bare email address anywhere in the text
//
function redactEvidence(required string text) {
    var s = arguments.text;

    // 1. Manual redaction blocks (case-insensitive, spanning newlines)
    s = reReplaceNoCase(s, '\[REDACT\].*?\[/REDACT\]', '[redacted]', 'ALL');

    // 2. Headers that directly expose the recipient address.
    //    Matches the header name at the start of a line (after optional
    //    whitespace for folded headers), replaces everything after the colon.
    var recipientHeaders =
        'To|Cc|Bcc' &
        '|X-Original-To|Delivered-To|X-Forwarded-To' &
        '|Envelope-To|X-Envelope-To' &
        '|X-RCPT-To|X-Spam-Rcpt';
    s = reReplaceNoCase(
        s,
        '(?m)^([ \t]*(?:' & recipientHeaders & '):[ \t]*).*$',
        '\1[redacted]',
        'ALL'
    );

    // 3. Return-Path: redact the address inside angle brackets.
    //    Keep the header name so the structure of the message is clear.
    s = reReplaceNoCase(
        s,
        '(?m)^([ \t]*Return-Path:[ \t]*)<[^>]*>',
        '\1<[redacted]>',
        'ALL'
    );

    // 4. Received: "for" clause — e.g. "for <trap@example.com>;" or
    //    "for trap@example.com;" — redact just the address, keep timestamps
    //    and relay path which are the evidential parts.
    s = reReplaceNoCase(
        s,
        '(\bfor\s+)<[^>]+>',
        '\1<[redacted]>',
        'ALL'
    );
    s = reReplaceNoCase(
        s,
        '(\bfor\s+)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        '\1[redacted]',
        'ALL'
    );

    // 5. Any remaining bare email address anywhere in the text.
    //    This catches addresses in body fragments, log lines, custom fields, etc.
    s = reReplaceNoCase(
        s,
        '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        '[redacted]',
        'ALL'
    );

    return s;
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
