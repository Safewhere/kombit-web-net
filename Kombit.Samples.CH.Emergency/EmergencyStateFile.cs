using System;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.Data.Sqlite;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class EmergencyStateFile : IDisposable
    {
        private readonly FileStream owner;
        private readonly string filename;
        private readonly Func<byte[], byte[]> protect;
        private readonly SqliteConnection database;
        private JObject current;
        private bool closed;
        private bool faulted;
        public object SyncRoot { get; private set; } = new object();

        public EmergencyStateFile(
            EmergencySettings settings,
            Func<byte[], byte[]> encrypt,
            Func<byte[], byte[]> decrypt,
            CredentialReader reader
        )
        {
            protect = encrypt;
            Directory.CreateDirectory(settings.StateDirectory);
            owner = new FileStream(
                Path.Combine(settings.StateDirectory, "exclusive.lock"),
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None
            );
            filename = Path.Combine(settings.StateDirectory, "emergency.db");
            bool exists = File.Exists(filename);
            try
            {
                database = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = filename,
                    Mode = SqliteOpenMode.ReadWriteCreate,
                    Pooling = false,
                    DefaultTimeout = 2
                }.ToString());
                database.Open();
                using (var command = database.CreateCommand())
                {
                    command.CommandText = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;";
                    command.ExecuteNonQuery();
                    if (!exists)
                    {
                        command.CommandText = "CREATE TABLE EmergencyRecords (Collection TEXT NOT NULL, Id TEXT NOT NULL, Payload BLOB NOT NULL, PRIMARY KEY(Collection, Id)); PRAGMA user_version=1;";
                        command.ExecuteNonQuery();
                    }
                    command.CommandText = "PRAGMA user_version;";
                    if (Convert.ToInt32(command.ExecuteScalar()) != 1) throw new InvalidOperationException("Unsupported emergency database schema.");
                }
                if (exists)
                {
                    if (new FileInfo(filename).Length > 16777216)
                    {
                        throw new InvalidOperationException();
                    }
                    current = Read(decrypt);
                    if (
                        (int?)current["version"] != 1
                        || !(current["keys"] is JObject)
                        || !(current["credentials"] is JObject)
                        || !(current["sessions"] is JObject)
                    )
                    {
                        throw new InvalidOperationException();
                    }
                    current.Remove("identity");
                    CredentialReader.CheckTrust((string)current["trust"]);
                }
                else
                {
                    if (new FileInfo(settings.InitialSigningKeysFile).Length > 65536)
                    {
                        throw new InvalidOperationException();
                    }
                    string trust = File.ReadAllText(settings.InitialSigningKeysFile);
                    CredentialReader.CheckTrust(trust);
                    current = new JObject
                    {
                        ["version"] = 1,
                        ["trust"] = trust,
                        ["cursor"] = 0L,
                        ["keys"] = new JObject(),
                        ["credentials"] = new JObject(),
                        ["sessions"] = new JObject(),
                        ["pending_removals"] = new JArray(),
                        ["events"] = new JArray(),
                    };
                    Write(current);
                }
                string disabled = Path.Combine(settings.StateDirectory, "support-disabled");
                if (File.Exists(disabled))
                {
                    current["sessions"] = new JObject();
                    Write(current);
                    File.Delete(disabled);
                }
            }
            catch
            {
                database?.Dispose();
                owner.Dispose();
                throw;
            }
        }

        public T Inspect<T>(Func<JObject, T> read)
        {
            lock (SyncRoot)
            {
                if (closed)
                {
                    throw new ObjectDisposedException(nameof(EmergencyStateFile));
                }
                if (faulted)
                {
                    throw new EmergencyFailure(503, "state_unavailable");
                }
                return read(current);
            }
        }

        public T Change<T>(Func<JObject, T> apply)
        {
            lock (SyncRoot)
            {
                if (closed)
                {
                    throw new ObjectDisposedException(nameof(EmergencyStateFile));
                }
                if (faulted)
                {
                    throw new EmergencyFailure(503, "state_unavailable");
                }
                JObject next = (JObject)current.DeepClone();
                T result = apply(next);
                try
                {
                    Write(next);
                }
                catch
                {
                    faulted = true;
                    throw;
                }
                current = next;
                return result;
            }
        }

        private JObject Read(Func<byte[], byte[]> decrypt)
        {
            var records = new JObject();
            JObject metadata = null;
            using (var command = database.CreateCommand())
            {
                command.CommandText = "SELECT Collection, Id, Payload FROM EmergencyRecords";
                using (var rows = command.ExecuteReader())
                    while (rows.Read())
                    {
                        string collection = rows.GetString(0), id = rows.GetString(1);
                        var envelope = JObject.Parse(Encoding.UTF8.GetString(decrypt((byte[])rows[2])));
                        if ((string)envelope["collection"] != collection || (string)envelope["id"] != id)
                            throw new InvalidOperationException("Emergency database record mismatch.");
                        if (collection == "metadata" && id == "state") metadata = (JObject)envelope["value"];
                        else
                        {
                            if (collection != "keys" && collection != "credentials" && collection != "sessions")
                                throw new InvalidOperationException("Unknown emergency collection.");
                            if (records[collection] == null) records[collection] = new JObject();
                            records[collection][id] = envelope["value"];
                        }
                    }
            }
            if (metadata == null) throw new InvalidOperationException("Emergency database metadata is missing.");
            foreach (string collection in new[] { "keys", "credentials", "sessions" })
                metadata[collection] = records[collection] ?? new JObject();
            return metadata;
        }

        private void Write(JObject value)
        {
            if (Encoding.UTF8.GetByteCount(value.ToString(Formatting.None)) > 16777216)
                throw new EmergencyFailure(503, "registry_capacity");
            // One transaction commits keys, credentials, counters and sessions together.
            // The bounded, single-worker demo rewrites its small snapshot on each state change.
            using (var transaction = database.BeginTransaction())
            using (var command = database.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = "DELETE FROM EmergencyRecords";
                command.ExecuteNonQuery();
                command.CommandText = "INSERT INTO EmergencyRecords(Collection, Id, Payload) VALUES ($collection, $id, $payload)";
                command.Parameters.Add("$collection", SqliteType.Text);
                command.Parameters.Add("$id", SqliteType.Text);
                command.Parameters.Add("$payload", SqliteType.Blob);
                var metadata = (JObject)value.DeepClone();
                foreach (string collection in new[] { "keys", "credentials", "sessions" })
                {
                    foreach (var record in ((JObject)value[collection]).Properties())
                        Insert(command, collection, record.Name, record.Value);
                    metadata.Remove(collection);
                }
                Insert(command, "metadata", "state", metadata);
                transaction.Commit();
            }
        }

        private void Insert(SqliteCommand command, string collection, string id, JToken value)
        {
            var envelope = new JObject { ["collection"] = collection, ["id"] = id, ["value"] = value.DeepClone() };
            command.Parameters["$collection"].Value = collection;
            command.Parameters["$id"].Value = id;
            command.Parameters["$payload"].Value = protect(Encoding.UTF8.GetBytes(envelope.ToString(Formatting.None)));
            command.ExecuteNonQuery();
        }

        public void Dispose()
        {
            lock (SyncRoot)
            {
                if (!closed)
                {
                    closed = true;
                    database.Dispose();
                    owner.Dispose();
                }
            }
        }
    }
}
