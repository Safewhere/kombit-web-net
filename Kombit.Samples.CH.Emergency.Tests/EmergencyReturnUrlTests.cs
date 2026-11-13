using System;
using Kombit.Samples.CH.WebsiteDemo.EmergencyFeature;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class EmergencyReturnUrlTests
    {
        [DataTestMethod]
        [DataRow("/app/Other.aspx?x=1#section", "/app/Other.aspx?x=1#section")]
        [DataRow("Other.aspx", "/app/Other.aspx")]
        [DataRow("https://sample.invalid/app/Other.aspx", "/app/Other.aspx")]
        [DataRow("https://other.invalid/app/Other.aspx", "/app/MyPage.aspx")]
        [DataRow("//other.invalid/app/Other.aspx", "/app/MyPage.aspx")]
        [DataRow("/outside/Page.aspx", "/app/MyPage.aspx")]
        [DataRow("/app/../outside/Page.aspx", "/app/MyPage.aspx")]
        [DataRow("/app/EmergencyComplete.aspx", "/app/MyPage.aspx")]
        [DataRow("/app/Other.aspx\r\nLocation: x", "/app/MyPage.aspx")]
        [DataRow("/app\\other.invalid", "/app/MyPage.aspx")]
        [DataRow(null, "/app/MyPage.aspx")]
        public void LocalReturnUrl_ValidatesOriginAndApplicationBoundary(string input, string expected)
        {
            Assert.AreEqual(expected, EmergencyReturnUrl.LocalReturnUrl(input,
                new Uri("https://sample.invalid/app/login.ashx"), "/app"));
        }
    }
}
