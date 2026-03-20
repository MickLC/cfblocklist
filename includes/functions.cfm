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
// Goal: protect the spamtrap recipient address without hiding anything else.
// Sender addresses, relay hops, authentication results, message body, and
// all other headers are left intact — they are the evidence.
//
// Rules applied in order:
//
//   1. Manual blocks: [REDACT]...[/REDACT] → [redacted]
//      Escape hatch for anything not covered by the rules below.
//
//   2. Headers whose entire value is redacted (recipient-revealing):
//        Delivered-To, X-Original-To, X-Forwarded-To
//        Envelope-To, X-Envelope-To, X-RCPT-To, X-Spam-Rcpt
//        X-Forwarded-Encrypted  — encrypted blob contains recipient domain
//        X-BeenThere            — Google Groups list address, reveals trap
//        X-Spam-Checked-In-Group — explicit trap address
//
//   3. Return-Path: — redact only the <address> inside angle brackets.
//
//   4. Received: continuation lines with (envelope-from <addr>) — redact
//      only the address; the rest of the hop is preserved.
//
//   5. Received: "for <addr>" / "for addr" clause — redact address only.
//
//   6. DKIM-Signature / ARC-* / X-Google-DKIM-Signature: darn= tag —
//      leaks the recipient domain; redact the value after darn=.
//
//   Everything else — From:, To: (spammer's), Subject:, SPF/DKIM/DMARC
//   results, relay IPs, timestamps, message body — is shown as-is.
//
function redactEvidence(required string text) {
    var s = arguments.text;

    // 1. Manual redaction blocks (case-insensitive, spanning newlines)
    s = reReplaceNoCase(s, '\[REDACT\].*?\[/REDACT\]', '[redacted]', 'ALL');

    // 2. Headers whose entire value reveals the recipient — whole line
    //    value replaced. Anchored to start of line.
    var recipientHeaders =
        'Delivered-To' &
        '|X-Original-To' &
        '|X-Forwarded-To' &
        '|Envelope-To' &
        '|X-Envelope-To' &
        '|X-RCPT-To' &
        '|X-Spam-Rcpt' &
        '|X-Forwarded-Encrypted' &
        '|X-BeenThere' &
        '|X-Spam-Checked-In-Group';
    s = reReplaceNoCase(
        s,
        '(?m)^([ \t]*(?:' & recipientHeaders & '):[ \t]*).*$',
        '\1[redacted]',
        'ALL'
    );

    // 3. Return-Path: redact only the <address> portion.
    s = reReplaceNoCase(
        s,
        '(?m)^([ \t]*Return-Path:[ \t]*)<[^>]*>',
        '\1<[redacted]>',
        'ALL'
    );

    // 4. Received: continuation lines — (envelope-from <addr>) clause.
    //    These appear as indented continuation lines inside a Received: block.
    s = reReplaceNoCase(
        s,
        '(\(envelope-from\s+)<[^>]*>(\))',
        '\1<[redacted]>\2',
        'ALL'
    );

    // 5. Received: "for" clause — redact address, preserve rest of line.
    //    Handles both "for <addr>" and bare "for addr" forms.
    s = reReplaceNoCase(s, '(\bfor\s+)<[^>]+>', '\1<[redacted]>', 'ALL');
    s = reReplaceNoCase(
        s,
        '(\bfor\s+)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        '\1[redacted]',
        'ALL'
    );

    // 6. darn= tag in DKIM-Signature and ARC-* headers — value is the
    //    recipient domain (e.g. darn=lexprotego.com). Redact the domain.
    s = reReplaceNoCase(
        s,
        '(\bdarn=)[a-zA-Z0-9.\-]+',
        '\1[redacted]',
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
