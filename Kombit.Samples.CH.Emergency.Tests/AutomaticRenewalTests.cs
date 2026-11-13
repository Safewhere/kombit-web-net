using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class AutomaticRenewalTests
    {
        [TestMethod]
        public async Task RenewAfterLogin_TwoFreshLogins_RenewsBeforeHalfLifeAndDeduplicates()
        {
            using (var fixture = new SamlFixture())
            {
                JObject original = await fixture.Active();
                string previous = (string)original["ec_id"];
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    fixture.Time += TimeSpan.FromSeconds(2);
                    string login = fixture.Login();
                    int calls = fixture.Calls;
                    var gate = new TaskCompletionSource<bool>();
                    fixture.RenewalBarrier = gate.Task;
                    Task<JObject>[] attempts = Enumerable.Range(0, 5).Select(_ =>
                        fixture.Access.RenewAfterLogin(login, fixture.Browser, new[] { fixture.Binding }, CancellationToken.None)).ToArray();
                    gate.SetResult(true);
                    JObject[] results = await Task.WhenAll(attempts);
                    Assert.AreEqual(4, results.Count(result => (string)result["outcome"] == "pending"));
                    Assert.AreEqual(calls + 1, fixture.Calls);
                    JObject renewed = results.First(result => (string)result["outcome"] == "renewed");
                    Assert.AreNotEqual(previous, (string)renewed["ec_id"]);
                    Assert.AreEqual(fixture.Binding, (string)renewed["binding_id"]);
                    Assert.IsFalse(fixture.Access.CanPrepare(login, fixture.Browser));
                    Assert.AreEqual(1, fixture.Access.Readiness(login, fixture.Browser)["credentials"].Count(c => (string)c["status"] == "active"));
                    previous = (string)renewed["ec_id"];
                }
                // Renewal must not reset the counter already raised by enrollment possession.
                JObject challenge = fixture.Access.StartDiscoverableLogin(fixture.Browser, new[] { fixture.Binding });
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => fixture.Access.CompleteDiscoverableLogin(
                    fixture.Browser, (string)challenge["transaction_id"], fixture.Assertion((JObject)challenge["publicKey"], 1)));
                fixture.Offline = true;
                challenge = fixture.Access.StartDiscoverableLogin(fixture.Browser, new[] { fixture.Binding });
                JObject ticket = await fixture.Access.CompleteDiscoverableLogin(fixture.Browser,
                    (string)challenge["transaction_id"], fixture.Assertion((JObject)challenge["publicKey"], 2));
                Assert.IsNotNull(fixture.Access.Authenticate((string)ticket["session"], fixture.Browser));
            }
        }

        [DataTestMethod]
        [DataRow("missing")]
        [DataRow("unknown")]
        [DataRow("foreign")]
        [DataRow("expired")]
        [DataRow("pending")]
        [DataRow("removed")]
        public async Task RenewAfterLogin_IneligibleMarker_PreservesPreparation(string mode)
        {
            using (var fixture = new SamlFixture())
            {
                if (mode == "pending") await fixture.Pending(fixture.Login());
                else await fixture.Active();
                if (mode == "expired") fixture.Time += TimeSpan.FromHours(2);
                if (mode == "removed") await fixture.Access.RemoveKey(fixture.Login(), fixture.Browser, fixture.Binding, CancellationToken.None);
                string login = fixture.Login(mode == "foreign" ? "other-idp" : "normal-idp");
                int calls = fixture.Calls;
                string[] markers = mode == "missing" ? new string[0] : new[] { mode == "unknown" ? "unknown" : fixture.Binding };
                JObject result = await fixture.Access.RenewAfterLogin(login, fixture.Browser, markers, CancellationToken.None);
                Assert.AreEqual("skipped", (string)result["outcome"]);
                Assert.IsTrue(fixture.Access.CanPrepare(login, fixture.Browser));
                Assert.AreEqual(calls, fixture.Calls);
            }
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task RenewAfterLogin_MultipleBindings_SelectsNewestMarkedOnly(bool markNewest)
        {
            using (var fixture = new SamlFixture())
            {
                fixture.SelectKey("binding-a", "credential-a");
                JObject first = await fixture.Active();
                fixture.Time += TimeSpan.FromSeconds(2);
                fixture.SelectKey("binding-b", "credential-b");
                JObject second = await fixture.Active();
                fixture.Time += TimeSpan.FromSeconds(2);
                string selected = markNewest ? "binding-b" : "binding-a";
                fixture.SelectKey(selected, markNewest ? "credential-b" : "credential-a");
                string login = fixture.Login();
                JObject result = await fixture.Access.RenewAfterLogin(login, fixture.Browser,
                    markNewest ? new[] { "binding-a", "binding-b" } : new[] { "binding-a" }, CancellationToken.None);
                Assert.AreEqual(selected, (string)result["binding_id"]);
                JObject untouched = markNewest ? first : second;
                Assert.IsTrue(fixture.Access.IsActiveForLogin((string)untouched["emergency_credential"]));
            }
        }

        [TestMethod]
        public async Task RenewAfterLogin_EqualIssueTimes_UsesOrdinalBindingOrder()
        {
            using (var fixture = new SamlFixture())
            {
                fixture.SelectKey("binding-b", "credential-b");
                JObject untouched = await fixture.Active();
                fixture.SelectKey("binding-a", "credential-a");
                await fixture.Active();
                fixture.Time += TimeSpan.FromSeconds(2);
                JObject result = await fixture.Access.RenewAfterLogin(fixture.Login(), fixture.Browser,
                    new[] { "binding-b", "binding-a" }, CancellationToken.None);
                Assert.AreEqual("binding-a", (string)result["binding_id"]);
                Assert.IsTrue(fixture.Access.IsActiveForLogin((string)untouched["emergency_credential"]));
            }
        }

        [TestMethod]
        public async Task RenewAfterLogin_WrongBrowser_DeniesWithoutIssuerCall()
        {
            using (var fixture = new SamlFixture())
            {
                await fixture.Active();
                string login = fixture.Login();
                int calls = fixture.Calls;
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => fixture.Access.RenewAfterLogin(
                    login, "another-browser", new[] { fixture.Binding }, CancellationToken.None));
                Assert.AreEqual(calls, fixture.Calls);
                Assert.IsTrue(fixture.Access.CanPrepare(login, fixture.Browser));
            }
        }

        [TestMethod]
        public async Task RenewAfterLogin_IssuerFailure_KeepsOldCredentialAndDoesNotRetry()
        {
            using (var fixture = new SamlFixture())
            {
                JObject original = await fixture.Active();
                fixture.Time += TimeSpan.FromSeconds(2);
                string login = fixture.Login();
                fixture.Offline = true;
                await Assert.ThrowsExactlyAsync<System.Net.Http.HttpRequestException>(() => fixture.Access.RenewAfterLogin(
                    login, fixture.Browser, new[] { fixture.Binding }, CancellationToken.None));
                int calls = fixture.Calls;
                fixture.Offline = false;
                JObject repeat = await fixture.Access.RenewAfterLogin(login, fixture.Browser, new[] { fixture.Binding }, CancellationToken.None);
                Assert.AreEqual("failed", (string)repeat["outcome"]);
                Assert.AreEqual(calls, fixture.Calls);
                Assert.IsTrue(fixture.Access.IsActiveForLogin((string)original["emergency_credential"]));
                fixture.Time += TimeSpan.FromSeconds(2);
                Assert.AreEqual("renewed", (string)(await fixture.Access.RenewAfterLogin(fixture.Login(), fixture.Browser,
                    new[] { fixture.Binding }, CancellationToken.None))["outcome"]);
            }
        }

        [TestMethod]
        public async Task RenewAfterLogin_ActivationRejectsSameIssueTime_PreservesActiveCredential()
        {
            using (var fixture = new SamlFixture())
            {
                JObject original = await fixture.Active();
                string login = fixture.Login();
                var failure = await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => fixture.Access.RenewAfterLogin(
                    login, fixture.Browser, new[] { fixture.Binding }, CancellationToken.None));
                Assert.AreEqual("replacement_superseded", failure.ErrorCode);
                Assert.IsTrue(fixture.Access.IsActiveForLogin((string)original["emergency_credential"]));
                Assert.AreEqual("failed", (string)(await fixture.Access.RenewAfterLogin(login, fixture.Browser,
                    new[] { fixture.Binding }, CancellationToken.None))["outcome"]);
            }
        }

        [TestMethod]
        public async Task RenewAfterLogin_PersistenceFailure_PreservesDurableCredentialAndFailsClosed()
        {
            using (var fixture = new SamlFixture())
            {
                JObject original = await fixture.Active();
                fixture.Time += TimeSpan.FromSeconds(2);
                string login = fixture.Login();
                using (var held = fixture.LockDatabase())
                    await Assert.ThrowsExactlyAsync<Microsoft.Data.Sqlite.SqliteException>(() => fixture.Access.RenewAfterLogin(login, fixture.Browser,
                        new[] { fixture.Binding }, CancellationToken.None));
                Assert.AreEqual("state_unavailable", Assert.ThrowsExactly<EmergencyFailure>(() => fixture.Access.Readiness(login, fixture.Browser)).ErrorCode);
                fixture.Restart();
                Assert.IsTrue(fixture.Access.IsActiveForLogin((string)original["emergency_credential"]));
            }
        }
    }
}
