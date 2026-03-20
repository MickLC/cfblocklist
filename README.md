# cfblocklist

ColdFusion/Lucee front-end for a DNSBL (DNS-based Block List) backed by MariaDB,
served via a PowerDNS pipe backend.

## Features

- **Public site**: Lookup by IPv4, CIDR range, or hostname/domain — shows listing status,
  evidence, and a one-click self-delist button for unlocked entries
- **Admin interface**: Add, edit, lock/unlock, and delete entries; manage evidence records;
  full audit log; user management
- **PowerDNS pipe backend**: `dnsbl-pipe.py` answers DNSBL queries live from MariaDB —
  no zone file regeneration needed; changes are effective immediately
- **Security**: PBKDF2WithHmacSHA256 password hashing with pepper, `cfqueryparam` throughout,
  session-based admin auth, HTML encoding on all output

## Requirements

- Lucee 5.x or 6.x
- MariaDB 10.x or 11.x (the `blocklist` datasource must be configured in Lucee admin)
- PowerDNS Authoritative 4.x running on the same server (port 53)
- Python 3.8+ and `PyMySQL` (`apt install python3-pymysql` or `pip3 install PyMySQL`)
- No root or sudo required for the web application itself

---

## Web server configuration

### Apache

The `config/.htaccess` file included in the project blocks direct HTTP access
to the `config/` directory automatically. No additional configuration needed.

### Nginx

Nginx ignores `.htaccess` files. Add the following to your server block to
block direct access to `config/`:

```nginx
location ^~ /config/ {
    deny all;
    return 403;
}
```

Place these blocks **before** your main `location` block so they take precedence.

---

## Installation

### 1. Deploy web application files

Copy the project to your Lucee web root or a virtual host directory.
The web root should be the directory containing `Application.cfm`.

### 2. Configure the pepper

The pepper is a secret value mixed into every password hash. It must live
**outside the web root** so it cannot be served to a browser.

Generate a value first:

```bash
openssl rand -hex 32
```

Then configure it using **one** of these methods — no root or sudo needed:

#### Option A — Environment variable (preferred)

Add to `{lucee-install}/tomcat/bin/setenv.sh`:

```bash
export BLOCKLIST_PEPPER="your-generated-hex-string"
```

Restart Lucee after editing.

#### Option B — Flat file above the web root

```bash
mkdir -p /var/www/.blocklist
echo "your-generated-hex-string" > /var/www/.blocklist/pepper.txt
chown www-data:www-data /var/www/.blocklist/pepper.txt
chmod 600 /var/www/.blocklist/pepper.txt
```

Then set the path in `config/settings.cfm`:

```coldfusion
application.pepperFile = "/var/www/.blocklist/pepper.txt";
```

The application checks Option A first, then Option B. If neither is configured
it displays a clear setup error page and refuses to start.

### 3. Run the schema migration

```bash
mysql -h <your-db-host> -u <user> -p blocklist < scripts/schema.sql
```

Safe to run against an existing database — all statements are idempotent.

### 4. Configure site settings

Copy the example settings file and edit it:

```bash
cp config/settings.example.cfm config/settings.cfm
```

`config/settings.cfm` is in `.gitignore` — your local values stay local.

| Setting | Description |
|---|---|
| `application.siteName` | Display name shown in headers |
| `application.siteURL` | Canonical base URL (no trailing slash) |
| `application.adminEmail` | Admin contact / delist notification recipient |
| `application.dnsZone` | DNSBL zone name (used in About page examples) |
| `application.delistNotifyAdmin` | `true` to email admin on every self-delist |
| `application.pepperFile` | Full path to pepper file (Option B above); `""` if unused |

### 5. Deploy the pipe backend script

```bash
# Install dependency
apt install python3-pymysql
# or: pip3 install PyMySQL

# Deploy script
cp scripts/dnsbl-pipe.py /opt/blocklist/dnsbl-pipe.py
chmod 755 /opt/blocklist/dnsbl-pipe.py
chown root:pdns /opt/blocklist/dnsbl-pipe.py

# Deploy and fill in the config
cp scripts/blocklist.conf.example /opt/blocklist/blocklist.conf
chmod 640 /opt/blocklist/blocklist.conf
chown root:pdns /opt/blocklist/blocklist.conf
# Edit /opt/blocklist/blocklist.conf — set DB_HOST, DB_USER, DB_PASS, DNSBL_ZONE, etc.
```

Smoke-test the script standalone before touching PowerDNS:

```bash
echo -e "HELO\t1\nQ\t4.3.2.1.dnsbl.whizardries.com\tIN\tA\t1\t10.0.0.1\nQ\tdnsbl.whizardries.com\tIN\tSOA\t2\t10.0.0.1" \
  | /opt/blocklist/dnsbl-pipe.py
# Expected:
#   OK    dnsbl-pipe.py v1 zone=dnsbl.whizardries.com
#   END                   (or DATA ... if 1.2.3.4 is listed)
#   DATA  ... SOA ...
#   END
```

### 6. Configure PowerDNS

The zone `dnsbl.whizardries.com` must exist in PowerDNS so it will forward
queries to the pipe backend. Create it via `pdnsutil` if it doesn't exist yet:

```bash
pdnsutil create-zone dnsbl.whizardries.com ns1.whizardries.com
pdnsutil add-record  dnsbl.whizardries.com @ NS ns1.whizardries.com
pdnsutil add-record  dnsbl.whizardries.com @ NS ns2.whizardries.com
pdnsutil set-kind    dnsbl.whizardries.com NATIVE
```

Then drop in the pipe backend config fragment:

```bash
cp scripts/pdns-pipe.conf /etc/powerdns/pdns.d/pipe-dnsbl.conf
# Review and adjust pipe-instances and pipe-timeout if needed
systemctl restart pdns
```

Verify PowerDNS picked it up:

```bash
journalctl -u pdns --since "1 minute ago" | grep -i pipe
pdnsutil check-zone dnsbl.whizardries.com

# Live test (run from Harry itself):
dig @127.0.0.1 4.3.2.1.dnsbl.whizardries.com A
dig @127.0.0.1 dnsbl.whizardries.com SOA
```

If `4.3.2.1` (`1.2.3.4` reversed) is in the blocklist as active you should get
`127.0.0.2`. Otherwise you should get `NXDOMAIN` with no answer section.

### 7. Set up the expiry cron job

```bash
cp scripts/expire-entries.sh /opt/blocklist/expire-entries.sh
chmod +x /opt/blocklist/expire-entries.sh

# Run daily at 3am
0 3 * * * /opt/blocklist/expire-entries.sh
```

### 8. Create the first admin user

Navigate to `/initialize.cfm` in a browser. This page creates the first admin
user and permanently redirects away once a user exists.

### 9. Log in

Go to `/admin/` and log in with the credentials created in step 8.

---

## How the pipe backend works

PowerDNS forks `dnsbl-pipe.py` as a long-lived child process and communicates
over stdin/stdout using a simple tab-delimited line protocol.

**IP lookups** arrive as reversed-octet queries:

```
4.3.2.1.dnsbl.whizardries.com  →  look up 1.2.3.4
```

The script checks for:
1. Exact IP match (`entry_type = 'ip'`)
2. CIDR containment (Python `ipaddress` library; iterates active CIDR entries)

**Hostname lookups** arrive as forward-format queries:

```
mail.example.com.dnsbl.whizardries.com  →  look up mail.example.com
```

The script checks:
1. Exact hostname match
2. Wildcard walk-up: `.mail.example.com`, `.example.com`, `.com`
   (leading-dot entries in the `ip` table act as wildcards for all subdomains)

A listed entry returns `127.0.0.2` (A record) and a reason string (TXT record).
An unlisted entry returns `NXDOMAIN` (no DATA lines before `END`).

The `last_hit` column is updated on every positive match.

---

## File structure

```
/
├── Application.cfm          # Lucee bootstrap, pepper resolution, auth guard
├── default.cfm              # Public homepage / lookup
├── evidence.cfm             # Public evidence display
├── delist.cfm               # One-click self-delist handler
├── about.cfm                # Public about/policy page
├── initialize.cfm           # First-run admin user creation
├── .gitignore
│
├── config/
│   ├── settings.cfm         # Your local config — gitignored, never committed
│   └── settings.example.cfm # Committed template with neutral defaults
│
├── includes/
│   ├── functions.cfm        # Shared utility functions
│   ├── header_public.cfm    # Public site header
│   ├── footer_public.cfm    # Public site footer
│   ├── header_admin.cfm     # Admin sidebar + header
│   ├── footer_admin.cfm     # Admin footer
│   └── error.cfm            # Global error handler
│
├── admin/
│   ├── default.cfm          # Dashboard
│   ├── login.cfm            # Admin login
│   ├── logout.cfm           # Session destroy
│   ├── entries.cfm          # Entry list + inline lock/unlock/delete
│   ├── entry_add.cfm        # Add entry + initial evidence
│   ├── entry_edit.cfm       # Edit entry: evidence, lock status
│   ├── audit.cfm            # Audit log
│   └── users.cfm            # Admin user management
│
└── scripts/                 # Server-side scripts (web-protected by .htaccess)
    ├── schema.sql            # MariaDB schema + idempotent migrations
    ├── dnsbl-pipe.py         # PowerDNS pipe backend — deploy to /opt/blocklist/
    ├── pdns-pipe.conf        # PowerDNS drop-in config — deploy to /etc/powerdns/pdns.d/
    ├── expire-entries.sh     # Daily cron: deactivates expired entries
    ├── generate-zone.sh      # Legacy: generates rbldnsd zone files (kept for reference)
    ├── reload-rbldnsd.sh     # Legacy: rbldnsd SIGHUP reload (kept for reference)
    └── blocklist.conf.example # Template for /opt/blocklist/blocklist.conf
```

---

## Security notes

- All database queries use `cfqueryparam` — no string interpolation into SQL
- All output uses `encodeForHTML()` — no raw variable output
- Admin session timeout is 4 hours; sessions are stored server-side
- The delist action requires a POST confirmation step before removing any entry
- Locked entries cannot be delisted by any public action
- `/opt/blocklist/blocklist.conf` should be `chmod 640 chown root:pdns` —
  readable by the pdns user, not world-readable

## License

CC0-1.0 (public domain dedication)
