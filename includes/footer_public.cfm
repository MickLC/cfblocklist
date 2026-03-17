<!--- includes/footer_public.cfm --->
</main>
<footer>
    <div class="container">
        <cfoutput>#encodeForHTML(application.siteName)#</cfoutput>
        &mdash; <cfoutput>#encodeForHTML(application.siteTagline)#</cfoutput>
    </div>
</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc4s9bIOgUxi8T/jzmKG0GFqkKqmEdV8V4xn9ZFpFpOlHmNMk"
        crossorigin="anonymous"></script>
</body>
</html>
