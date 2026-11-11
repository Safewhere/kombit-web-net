using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class PersistenceFailureTests
    {
        [TestMethod]
        public void StateWrite_Fails_DeniesCachedEmergencyAccess()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                using (var held = fixture.LockDatabase())
                {
                    // Act
                    Assert.ThrowsExactly<Microsoft.Data.Sqlite.SqliteException>(() =>
                        fixture.Access.EndSession(Wire.RandomId())
                    );
                    // Assert
                    Assert.AreEqual(
                        503,
                        Assert
                            .ThrowsExactly<EmergencyFailure>(() =>
                                fixture.Access.Authenticate(Wire.RandomId(), fixture.Browser)
                            )
                            .StatusCode
                    );
                }
            }
        }
    }
}
