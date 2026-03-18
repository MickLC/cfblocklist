<!--- includes/header_admin.cfm --->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><cfoutput>#encodeForHTML(attributes.pageTitle & " — " & application.siteName & " Admin")#</cfoutput></title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
          crossorigin="anonymous">
    <style>
        body { background: #f0f2f5; }
        .sidebar {
            min-height: calc(100vh - 56px);
            background: #212529;
        }
        .sidebar .nav-link { color: #adb5bd; padding: .5rem 1rem; }
        .sidebar .nav-link:hover,
        .sidebar .nav-link.active { color: #fff; background: rgba(255,255,255,.1); border-radius: .25rem; }
        .sidebar .nav-section {
            color: #6c757d;
            font-size: .7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .08em;
            padding: 1rem 1rem .25rem;
        }
        .main-content { min-height: calc(100vh - 56px); }
        .table-actions .btn { padding: .2rem .5rem; font-size: .8rem; }
        .badge-locked   { background-color: #dc3545 !important; }
        .badge-unlocked { background-color: #198754 !important; }
        .badge-hostname { background-color: #6f42c1 !important; }
        .badge-cidr     { background-color: #0d6efd !important; }
        .badge-ip       { background-color: #0dcaf0 !important; color: #000 !important; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-md navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="/admin/">
            <cfoutput>#encodeForHTML(application.siteName)#</cfoutput>
            <small class="text-secondary fw-normal fs-6 ms-1">Admin</small>
        </a>
        <div class="ms-auto d-flex align-items-center gap-3">
            <cfif isDefined("session.adminName")>
                <span class="text-secondary small"><cfoutput>#encodeForHTML(session.adminName)#</cfoutput></span>
            </cfif>
            <a href="/admin/logout.cfm" class="btn btn-sm btn-outline-secondary">Log out</a>
        </div>
    </div>
</nav>
<div class="container-fluid">
<div class="row">
    <div class="col-md-2 sidebar pt-3 px-2">
        <ul class="nav flex-column">
            <li class="nav-section">Dashboard</li>
            <li class="nav-item">
                <a class="nav-link <cfif cgi.script_name contains '/admin/default'>active</cfif>" href="/admin/">Overview</a>
            </li>
            <li class="nav-section">Entries</li>
            <li class="nav-item">
                <a class="nav-link <cfif cgi.script_name contains 'entries'>active</cfif>" href="/admin/entries.cfm">All Entries</a>
            </li>
            <li class="nav-item">
                <a class="nav-link <cfif cgi.script_name contains 'entry_add'>active</cfif>" href="/admin/entry_add.cfm">Add Entry</a>
            </li>
            <li class="nav-section">System</li>
            <li class="nav-item">
                <a class="nav-link <cfif cgi.script_name contains 'audit'>active</cfif>" href="/admin/audit.cfm">Audit Log</a>
            </li>
            <li class="nav-item">
                <a class="nav-link <cfif cgi.script_name contains 'users'>active</cfif>" href="/admin/users.cfm">Users</a>
            </li>
            <li class="nav-item mt-2">
                <a class="nav-link" href="/" target="_blank">← Public Site</a>
            </li>
        </ul>
    </div>
    <div class="col-md-10 main-content p-4">
