using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet;
using Renci.SshNet.Common;

namespace AutoSSH
{
    internal sealed class SshConnector
    {
        private readonly string backupRoot;
        private readonly Credentials credentials;

        internal SshConnector(string backupRoot, Credentials credentials)
        {
            this.backupRoot = backupRoot;
            this.credentials = credentials;
        }

        internal static void Configure(BaseClient client)
        {
            client.ConnectionInfo.Timeout = AppSettings.ConnectionTimeout;
            client.KeepAliveInterval = AppSettings.KeepAliveInterval;
            if (client is SftpClient sftpClient)
            {
                sftpClient.OperationTimeout = AppSettings.OperationTimeout;
                sftpClient.BufferSize = AppSettings.SftpBufferSize;
            }
        }

        // SSH.NET fixes the socket buffers after connecting, which disables Windows receive-window
        // auto-tuning. There is no public hook, so reach its private socket.
        [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_Session")]
        [return: UnsafeAccessorType("Renci.SshNet.ISession, Renci.SshNet")]
        private static extern object GetSession(BaseClient client);

        [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_socket")]
        private static extern ref Socket GetSocket([UnsafeAccessorType("Renci.SshNet.Session, Renci.SshNet")] object session);

        internal static Socket GetConnectedSocket(BaseClient client) => GetSocket(GetSession(client));

        /// <summary>Raises the socket buffers of a connected client; returns false if SSH.NET internals changed.</summary>
        internal static bool TuneSocket(BaseClient client)
        {
            try
            {
                Socket socket = GetConnectedSocket(client);
                socket.ReceiveBufferSize = AppSettings.SocketBufferSize;
                socket.SendBufferSize = AppSettings.SocketBufferSize;
                return true;
            }
            catch (Exception ex) when (ex is MissingMemberException || ex is TypeLoadException ||
                ex is InvalidCastException || ex is NullReferenceException || ex is SocketException)
            {
                DiagnosticLog.Write($"socket buffer tuning unavailable {ex.GetType().Name}: {ex.Message}");
                return false;
            }
        }

        internal async Task<SshClient> ConnectSshAsync(HostEntry host) =>
            (SshClient)await ConnectAsync(host, ssh: true);

        internal async Task<SftpClient> ConnectSftpAsync(HostEntry host) =>
            (SftpClient)await ConnectAsync(host, ssh: false);

        private async Task<BaseClient> ConnectAsync(HostEntry host, bool ssh)
        {
            Console.WriteLine("Connecting to {0} with type {1}", host, ssh ? "SSH" : "SFTP");
            string op = DiagnosticLog.Begin($"{host} connect {(ssh ? "SSH" : "SFTP")}");
            string hostRoot = Path.Combine(backupRoot, host.Name);
            Directory.CreateDirectory(hostRoot);
            string fingerFile = Path.Combine(hostRoot, "finger.key");
            byte[] fingerprint = File.Exists(fingerFile) ? File.ReadAllBytes(fingerFile) : null;
            string userName = credentials.GetUserName();
            string password = credentials.GetPassword();
            BaseClient client = ssh
                ? new SshClient(host.Host, userName, password)
                : new SftpClient(host.Host, userName, password);
            Configure(client);
            bool fingerMatch = true;
            client.HostKeyReceived += (sender, e) =>
            {
                if (fingerprint != null)
                {
                    if (!e.FingerPrint.SequenceEqual(fingerprint))
                    {
                        e.CanTrust = false;
                        fingerMatch = false;
                    }
                }
                else
                {
                    File.WriteAllBytes(fingerFile, e.FingerPrint);
                    fingerprint = e.FingerPrint.ToArray();
                }
            };
            try
            {
                await client.ConnectAsync(CancellationToken.None);
                if (!client.IsConnected || !client.ConnectionInfo.IsAuthenticated)
                {
                    throw new SshConnectionException($"Failed to connect to {host}, finger match: {fingerMatch}");
                }
                bool tuned = TuneSocket(client);
                DiagnosticLog.End(op, (fingerMatch ? "ok" : "fingerprint-mismatch") +
                    (tuned ? $" socketBuffer={ByteSize.Format(AppSettings.SocketBufferSize)}" : " socketBuffer=default"));
                return client;
            }
            catch (Exception ex)
            {
                DiagnosticLog.Fail(op, ex);
                client.Dispose();
                throw;
            }
        }
    }
}
