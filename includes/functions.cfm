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
//   0. Normalize CRLF → LF.
//
//   1. Manual blocks: [REDACT]...[/REDACT] → [redacted]
//
//   2. Headers whose entire value is redacted (recipient-revealing).
//      Anchored to column 0 (no leading whitespace) to avoid matching
//      folded continuation lines. Folded continuations (lines starting
//      with \t or space) that follow a matched header are also consumed.
//        Delivered-To, X-Original-To, X-Forwarded-To
//        Envelope-To, X-Envelope-To, X-RCPT-To, X-Spam-Rcpt
//        X-Forwarded-Encrypted, X-BeenThere, X-Spam-Checked-In-Group
//        List-Subscribe, List-Unsubscribe
//
//   3. Return-Path: — redact only the <address> inside angle brackets.
//
//   4. Received: (envelope-from <addr>) clause — redact address only.
//
//   5. Received: "for <addr>" clause — redact address only.
//
//   6. darn= tag — leaks recipient domain; redact the value.
//
//   7. From: and To: headers — redact only the local part (before @) of
//      any email address, leaving the @domain visible as evidence.
//      The local part can encode the trap address (e.g. tagged addresses
//      like se999955sdsdeeeedddd@spamrelay.com where the local part is
//      derived from the trap). Display name and domain are preserved.
//
function redactEvidence(required string text) {
    var s = arguments.text;

    // 0. Normalize line endings — CRLF and bare CR → LF.
    s = replace(s, chr(13) & chr(10), chr(10), 'ALL');
    s = replace(s, chr(13), chr(10), 'ALL');

    // 1. Manual redaction blocks
    s = reReplaceNoCase(s, '\[REDACT\].*?\[/REDACT\]', '[redacted]', 'ALL');

    // 2. Recipient-revealing headers — entire value + folded continuations.
    //    Anchored to column 0; uses Java Pattern for reliable multiline handling.
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
        '|X-Spam-Checked-In-Group' &
        '|List-Subscribe' &
        '|List-Unsubscribe';

    var jPattern = createObject('java', 'java.util.regex.Pattern');
    var jMatcher = jPattern.compile(
        '(?im)^(' & recipientHeaders & '):[ \t]*[^\n]*(\n[ \t]+[^\n]*)*'
    );
    var matcher = jMatcher.matcher(s);
    var sb = createObject('java', 'java.lang.StringBuffer').init();
    while (matcher.find()) {
        var matchedName = listFirst(matcher.group(0), ':');
        matcher.appendReplacement(sb, javaCast('string', matchedName & ': [redacted]'));
    }
    matcher.appendTail(sb);
    s = sb.toString();

    // 3. Return-Path: redact only the <address> portion.
    s = reReplaceNoCase(
        s,
        '(?m)^(Return-Path:[ \t]*)<[^>]*>',
        '\1<[redacted]>',
        'ALL'
    );

    // 4. (envelope-from <addr>) clause in Received: lines.
    s = reReplaceNoCase(
        s,
        '(\(envelope-from\s+)<[^>]*>(\))',
        '\1<[redacted]>\2',
        'ALL'
    );

    // 5. "for <addr>" / "for addr" clause in Received: lines.
    s = reReplaceNoCase(s, '(\bfor\s+)<[^>]+>', '\1<[redacted]>', 'ALL');
    s = reReplaceNoCase(
        s,
        '(\bfor\s+)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        '\1[redacted]',
        'ALL'
    );

    // 6. darn= tag — recipient domain.
    s = reReplaceNoCase(s, '(\bdarn=)[a-zA-Z0-9.\-]+', '\1[redacted]', 'ALL');

    // 7. From: and To: — redact only the local part of email addresses.
    //    The local part can encode the trap address via tagged/subaddressed
    //    delivery. The @domain is kept as it identifies the sending infrastructure.
    //    Handles both bare addr@domain and display name <addr@domain> forms.
    //    Applied only to lines starting with From: or To: at column 0.
    var fromToPattern = jPattern.compile(
        '(?im)^((?:From|To):.*?)[a-zA-Z0-9._%+\-]+(@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})'
    );
    var fromToMatcher = fromToPattern.matcher(s);
    var sb2 = createObject('java', 'java.lang.StringBuffer').init();
    while (fromToMatcher.find()) {
        fromToMatcher.appendReplacement(sb2,
            javaCast('string',
                fromToMatcher.group(1).replaceAll('\\$', '\\\$') &
                '[redacted]' &
                fromToMatcher.group(2).replaceAll('\\$', '\\\$')
            )
        );
    }
    fromToMatcher.appendTail(sb2);
    s = sb2.toString();

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
