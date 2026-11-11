<%@ Page Language="C#" Inherits="Kombit.Samples.CH.WebsiteDemo.EmergencyFeature.EmergencyCompletionPage" %>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Completing sign-in &middot; KOMBIT</title>
<link rel="stylesheet" href="<%: Kombit.Samples.CH.WebsiteDemo.AssetVersion.Url("~/EmergencyAssets/emergency.css") %>" />
<link rel="stylesheet" href="<%: Kombit.Samples.CH.WebsiteDemo.AssetVersion.Url("~/EmergencyAssets/portal.css") %>" />
<script id="demo-scenarios-script" src="<%: Kombit.Samples.CH.WebsiteDemo.AssetVersion.Url("~/EmergencyAssets/scenarios.js") %>" data-root="<%: ResolveUrl("~/") %>"></script>
</head><body class="kombit-emergency"><main class="completion-card" id="emergency-completion"
 data-api="<%: ResolveUrl("~/EmergencyApi.ashx") %>" data-csrf="<%: CsrfToken %>" data-return="<%: ReturnUrl %>">
<span class="eyebrow">KOMBIT &middot; EMERGENCY ACCESS</span><h1>You&#8217;re signed in</h1>
<p id="completion-status" role="status" aria-live="polite">Refreshing your emergency access. No passkey confirmation is needed.</p>
<a id="completion-continue" class="button secondary" href="<%: ReturnUrl %>" hidden="hidden">Continue to the application</a>
<noscript><p>JavaScript is unavailable, so your Passticket has not been renewed.</p><a class="button" href="<%: ReturnUrl %>">Continue to the application</a></noscript>
</main><script src="<%: Kombit.Samples.CH.WebsiteDemo.AssetVersion.Url("~/EmergencyAssets/completion.js") %>" defer></script></body></html>
