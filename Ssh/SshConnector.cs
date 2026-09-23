using System;
using System.IO;
using System.Linq;
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
                DiagnosticLog.End(op, fingerMatch ? "ok" : "fingerprint-mismatch");
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
