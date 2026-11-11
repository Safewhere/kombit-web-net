using System;

namespace Kombit.Samples.CH.WebsiteDemo.EmergencyFeature
{
    public static class EmergencyReturnUrl
    {
        public static string LocalReturnUrl(string value, Uri requestUrl, string applicationPath)
        {
            string root = (applicationPath ?? string.Empty).TrimEnd('/') + "/";
            string fallback = root + "MyPage.aspx";
            if (string.IsNullOrEmpty(value) || value.Length > 4096 || value.IndexOf('\\') >= 0
                || value.IndexOf('\r') >= 0 || value.IndexOf('\n') >= 0 || value.StartsWith("//", StringComparison.Ordinal))
                return fallback;
            Uri target;
            if (!Uri.TryCreate(requestUrl, value, out target)
                || target.Scheme != requestUrl.Scheme || target.Authority != requestUrl.Authority
                || !target.AbsolutePath.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                || target.AbsolutePath.Equals(root + "EmergencyComplete.aspx", StringComparison.OrdinalIgnoreCase))
                return fallback;
            return target.PathAndQuery + target.Fragment;
        }

    }
}
