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

## Installation

### 1. Deploy files

Copy the project to your Lucee web root or a virtual host directory.
The web root should be the directory containing `Application.cfm`.

### 2. Configure the pepper

```bash
# Generate a random pepper
openssl rand -hex 32
```

Edit `config/pepper.cfm` and replace the placeholder value with your generated string.
**Never commit this file. It is in `.gitignore` by default.**

### 3. Run the schema migration

```bash
mysql -h <your-db-host> -u <user> -p blocklist < schema.sql
```

This is idempotent — safe to run against an existing database.

### 4. Configure site settings

Edit `config/settings.cfm`:

| Setting | Description |
|---|---|
| `application.siteName` | Display name shown in headers |
| `application.siteURL` | Canonical base URL (no trailing slash) |
| `application.adminEmail` | Admin contact / delist notification recipient |
| `application.rbldnsdReloadScript` | Path to reload script; set to `""` to disable |
| `application.delistNotifyAdmin` | `true` to email admin on every self-delist |

### 5. Set up the rbldnsd reload script

```bash
cp reload-rbldnsd.sh /opt/blocklist/reload-rbldnsd.sh
chmod +x /opt/blocklist/reload-rbldnsd.sh
```

Allow the Lucee service user to run it without a password:

```
# /etc/sudoers.d/blocklist
lucee ALL=(root) NOPASSWD: /opt/blocklist/reload-rbldnsd.sh
```

Update `application.rbldnsdReloadScript` in `config/settings.cfm` to:
```
/usr/bin/sudo /opt/blocklist/reload-rbldnsd.sh
```

### 6. Create the first admin user

Navigate to `/initialize.cfm` in a browser.
This page creates the first admin user and then permanently redirects away once
a user exists.

### 7. Log in

Go to `/admin/` and log in with the credentials created in step 6.

## File structure

```
/
├── Application.cfm          # Lucee application bootstrap + auth guard
├── default.cfm              # Public homepage / lookup
├── evidence.cfm             # Public evidence display
├── delist.cfm               # One-click self-delist handler
├── about.cfm                # Public about/policy page
├── initialize.cfm           # First-run admin user creation (keep from original)
├── schema.sql               # MariaDB schema + migration
├── reload-rbldnsd.sh        # rbldnsd SIGHUP reload script
├── .gitignore
│
├── config/
│   ├── settings.cfm         # Site-wide configuration
│   └── pepper.cfm           # Password pepper — NOT in git
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
    ├── index.cfm            # Dashboard (stats, recent entries, recent audit)
    ├── login.cfm            # Admin login form
    ├── logout.cfm           # Session destroy
    ├── entries.cfm          # Paginated entry list + inline lock/unlock/delete
    ├── entry_add.cfm        # Add new entry + initial evidence
    ├── entry_edit.cfm       # Edit entry: evidence records, lock status
    ├── audit.cfm            # Full audit log with filters
    └── users.cfm            # Admin user management
```

## Security notes

- `config/pepper.cfm` must never be committed to version control
- All database queries use `cfqueryparam` — no string interpolation into SQL
- All output uses `encodeForHTML()` — no raw variable output
- Admin session timeout is 4 hours; sessions are stored server-side
- The `Application.cfm` auth guard protects all `/admin/*` routes automatically
- The delist action requires a POST confirmation step before removing any entry
- Locked entries cannot be delisted by any public action regardless of URL manipulation

## License

CC0-1.0 (public domain dedication)
