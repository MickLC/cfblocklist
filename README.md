# cfblocklist

ColdFusion/Lucee front-end for a DNSBL (DNS-based Block List) backed by MariaDB and rbldnsd.

## Features

- **Public site**: Lookup by IPv4, CIDR range, or hostname/domain — shows listing status,
  evidence, and a one-click self-delist button for unlocked entries
- **Admin interface**: Add, edit, lock/unlock, and delete entries; manage evidence records;
  full audit log; user management
- **rbldnsd integration**: Automatic zone reload via SIGHUP on every add/edit/delete
- **Security**: PBKDF2WithHmacSHA256 password hashing with pepper, `cfqueryparam` throughout,
  session-based admin auth, HTML encoding on all output

## Requirements

- Lucee 5.x or 6.x
- MariaDB 10.x (the `blocklist` datasource must be configured in Lucee admin)
- rbldnsd running on the same server (or reachable via the reload script)
- No root or sudo required for any part of the setup


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

Place this block **before** your main `location` block so it takes precedence.

## Installation

### 1. Deploy files

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

Restart Lucee after editing. No root needed if you own the Lucee installation.

#### Option B — Flat file above the web root

Create a plain-text file **outside** your web root containing only the pepper value:

```bash
# Example: web root is /home/youruser/public_html
mkdir -p /home/youruser/.blocklist
echo "your-generated-hex-string" > /home/youruser/.blocklist/pepper.txt
chmod 600 /home/youruser/.blocklist/pepper.txt
```

Then set the path in `config/settings.cfm`:

```coldfusion
application.pepperFile = "/home/youruser/.blocklist/pepper.txt";
```

The application checks Option A first, then Option B. If neither is configured
it displays a clear setup error page and refuses to start.

### 3. Run the schema migration

```bash
mysql -h <your-db-host> -u <user> -p blocklist < schema.sql
```

Safe to run against an existing database — all statements are idempotent.

### 4. Configure site settings

Edit `config/settings.cfm` (safe to commit — contains no secrets):

| Setting | Description |
|---|---|
| `application.siteName` | Display name shown in headers |
| `application.siteURL` | Canonical base URL (no trailing slash) |
| `application.adminEmail` | Admin contact / delist notification recipient |
| `application.dnsZone` | Your rbldnsd zone name (used in About page examples) |
| `application.rbldnsdReloadScript` | Path to reload script; `""` to disable |
| `application.delistNotifyAdmin` | `true` to email admin on every self-delist |
| `application.pepperFile` | Full path to pepper file (Option B above); `""` if unused |

### 5. Set up the rbldnsd reload script

```bash
cp reload-rbldnsd.sh /opt/blocklist/reload-rbldnsd.sh
chmod +x /opt/blocklist/reload-rbldnsd.sh
```

No sudo needed if the Lucee service user owns the rbldnsd process.
See the comments inside the script if a sudo rule is required for your setup.

### 6. Create the first admin user

Navigate to `/initialize.cfm` in a browser. This page creates the first admin
user and permanently redirects away once a user exists.

### 7. Log in

Go to `/admin/` and log in with the credentials created in step 6.

## File structure

```
/
├── Application.cfm          # Lucee bootstrap, pepper resolution, auth guard
├── default.cfm              # Public homepage / lookup
├── evidence.cfm             # Public evidence display
├── delist.cfm               # One-click self-delist handler
├── about.cfm                # Public about/policy page
├── initialize.cfm           # First-run admin user creation
├── schema.sql               # MariaDB schema + migration (idempotent)
├── reload-rbldnsd.sh        # rbldnsd SIGHUP reload script
├── .gitignore
│
├── config/
│   └── settings.cfm         # Site configuration (committed, no secrets)
│
├── includes/
│   ├── functions.cfm        # Shared utility functions
│   ├── header_public.cfm    # Public site header
│   ├── footer_public.cfm    # Public site footer
│   ├── header_admin.cfm     # Admin sidebar + header
│   ├── footer_admin.cfm     # Admin footer
│   └── error.cfm            # Global error handler
│
└── admin/
    ├── index.cfm            # Dashboard
    ├── login.cfm            # Admin login
    ├── logout.cfm           # Session destroy
    ├── entries.cfm          # Entry list + inline lock/unlock/delete
    ├── entry_add.cfm        # Add entry + initial evidence
    ├── entry_edit.cfm       # Edit entry: evidence, lock status
    ├── audit.cfm            # Audit log
    └── users.cfm            # Admin user management
```

## Security notes

- All database queries use `cfqueryparam` — no string interpolation into SQL
- All output uses `encodeForHTML()` — no raw variable output
- Admin session timeout is 4 hours; sessions are stored server-side
- The delist action requires a POST confirmation step before removing any entry
- Locked entries cannot be delisted by any public action

## License

CC0-1.0 (public domain dedication)
