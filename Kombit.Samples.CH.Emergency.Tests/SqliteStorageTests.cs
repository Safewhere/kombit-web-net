using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class SqliteStorageTests
    {
        private static SqliteConnection Open(SamlFixture fixture)
        {
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder {
                DataSource = Path.Combine(fixture.Settings.StateDirectory, "emergency.db"), Pooling = false
            }.ToString());
            connection.Open();
            return connection;
        }

        [TestMethod]
        public async Task NewDatabase_ContainsEncryptedRows_AndSurvivesRestart()
        {
            using (var fixture = new SamlFixture())
            {
                JObject issued = await fixture.Active();
                using (var connection = Open(fixture))
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT COUNT(*) FROM EmergencyRecords WHERE Collection='keys'";
                    Assert.AreEqual(1L, command.ExecuteScalar());
                    command.CommandText = "SELECT Payload FROM EmergencyRecords WHERE Collection='credentials'";
                    var bytes = (byte[])command.ExecuteScalar();
                    Assert.IsFalse(Encoding.UTF8.GetString(bytes).Contains("claims"));
                }
                fixture.Restart();
                Assert.IsTrue(fixture.Access.IsActiveForLogin((string)issued["emergency_credential"]));
                Assert.IsFalse(File.Exists(Path.Combine(fixture.Settings.StateDirectory, "registry.bin")));
            }
        }

        [TestMethod]
        public void UnknownSchema_IsRejectedWithoutResettingDatabase()
        {
            using (var fixture = new SamlFixture())
            {
                fixture.Access.Dispose();
                using (var connection = Open(fixture))
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "PRAGMA user_version=99";
                    command.ExecuteNonQuery();
                }
                Assert.ThrowsExactly<InvalidOperationException>(() => fixture.OpenStore());
                using (var connection = Open(fixture))
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "PRAGMA user_version";
                    Assert.AreEqual(99L, command.ExecuteScalar());
                }
            }
        }
    }
}
