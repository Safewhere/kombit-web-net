using System;
using System.Web;
using System.Web.UI;

namespace Kombit.Samples.CH.WebsiteDemo.EmergencyFeature
{
    public class EmergencyCompletionPage : Page
    {
        public string ReturnUrl { get; private set; }
        public string CsrfToken { get; private set; }

        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            EmergencyWeb.Headers(Context);
            ReturnUrl = EmergencyReturnUrl.LocalReturnUrl(Request.QueryString["returnUrl"], Request.Url, Request.ApplicationPath);
            // This page remains usable as a normal-login continuation if the optional feature
            // becomes unavailable. The API independently checks normal login and CSRF.
            CsrfToken = EmergencyWeb.WidgetToken(Context, "renewal_page_unavailable");
        }
    }
}
