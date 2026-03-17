<!--- includes/header_public.cfm --->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><cfoutput>#encodeForHTML(attributes.pageTitle & " — " & application.siteName)#</cfoutput></title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
          crossorigin="anonymous">
    <style>
        body { background: #f8f9fa; }
        .navbar-brand { font-weight: 700; letter-spacing: -.5px; }
        .listing-badge-locked   { background: #dc3545; }
        .listing-badge-unlocked { background: #198754; }
        .evidence-box {
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: .375rem;
            padding: 1rem;
            font-family: monospace;
            font-size: .85rem;
            white-space: pre-wrap;
            word-break: break-all;
        }
        footer { border-top: 1px solid #dee2e6; margin-top: 3rem; padding: 1.5rem 0; color: #6c757d; font-size: .875rem; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
    <div class="container">
        <a class="navbar-brand" href="/"><cfoutput>#encodeForHTML(application.siteName)#</cfoutput></a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navMain">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item"><a class="nav-link" href="/">Lookup</a></li>
                <li class="nav-item"><a class="nav-link" href="/about.cfm">About</a></li>
            </ul>
        </div>
    </div>
</nav>
<main class="container pb-4">
