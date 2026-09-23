using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Renci.SshNet;

namespace AutoSSH
{
    /// <summary>Runs one host's command list over a root shell plus an SFTP session.</summary>
    internal sealed class HostRunner
    {
        private readonly string backupRoot;
        private readonly Credentials credentials;
        private readonly SshConnector connector;

        internal HostRunner(string backupRoot, Credentials credentials)
        {
            this.backupRoot = backupRoot;
            this.credentials = credentials;
            connector = new SshConnector(backupRoot, credentials);
        }

        internal async Task RunAsync(HostCommands job)
        {
            HostEntry host = job.Host;
            string logFile = Path.Combine(backupRoot, host.Name, "log.txt");
            string backupPath = Path.Combine(backupRoot, host.Name, "backup");
            long backupSize = 0;
            long uploadSize = 0;
            Directory.CreateDirectory(Path.GetDirectoryName(logFile));
            string op = DiagnosticLog.Begin($"{host} host loop commands={job.Commands.Count}");
            try
            {
                using (StreamWriter writer = File.CreateText(logFile))
                using (SshClient ssh = await connector.ConnectSshAsync(host))
                using (ShellStream stream = ssh.CreateShellStream("xterm", 255, 50, 800, 600, 1024, null))
                using (SftpClient sftp = await connector.ConnectSftpAsync(host))
                {
                    EnterShell(host, stream, writer);
                    foreach (string command in job.Commands)
                    {
                        writer.WriteLine(command);
                        DiagnosticLog.Write($"{host} command {command}");
                        if (command.StartsWith("$backup ", StringComparison.OrdinalIgnoreCase))
                        {
                            backupSize += await BackupService.BackupFolderAsync(host, backupPath, command.Substring(8), sftp, writer,
                                async () => await connector.ConnectSftpAsync(host), AppSettings.DownloadWorkers, ssh,
                                AppSettings.DownloadsPerConnection);
                        }
                        else if (command.StartsWith("$upload ", StringComparison.OrdinalIgnoreCase))
                        {
                            uploadSize += await UploadService.UploadFolderAsync(host, command.Substring(8), sftp, writer);
                        }
                        else if (command.StartsWith("$ignore ", StringComparison.OrdinalIgnoreCase))
                        {
                            host.IgnoreRegex = new Regex(command.Substring(8), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        }
                        else if (!command.StartsWith('$'))
                        {
                            RunShellCommand(host, stream, writer, command);
                        }
                    }
                    writer.Write("logout\n");
                }
                DiagnosticLog.End(op, $"backup={ByteSize.Format(backupSize)} upload={ByteSize.Format(uploadSize)}");
                Console.WriteLine("{0} backed up {1}                      ", host, ByteSize.Format(backupSize));
                Console.WriteLine("{0} uploaded {1}                      ", host, ByteSize.Format(uploadSize));
            }
            catch (Exception ex)
            {
                DiagnosticLog.Fail(op, ex);
                throw;
            }
        }

        private void EnterShell(HostEntry host, ShellStream stream, TextWriter writer)
        {
            TimeSpan timeout = AppSettings.ConnectionTimeout;
            ShellPrompt.Expect(stream, host.IsWindows ? ShellPrompt.Windows : ShellPrompt.Login, timeout, writer, "the login prompt");
            if (host.IsWindows)
            {
                return;
            }
            stream.Write("sudo -s\n");
            // sudo may already be authenticated or configured for passwordless access.
            string sudoOutput = ShellPrompt.Expect(stream, ShellPrompt.Sudo, timeout, writer, "the sudo password or root prompt");
            if (!ShellPrompt.Root.IsMatch(sudoOutput))
            {
                credentials.WritePassword(stream);
                ShellPrompt.Expect(stream, ShellPrompt.Root, timeout, writer, "the root prompt");
            }
        }

        private static void RunShellCommand(HostEntry host, ShellStream stream, TextWriter writer, string command)
        {
            Console.WriteLine("Execute command {0}", command);
            stream.Write(command);
            stream.Write("\n");
            ShellPrompt.Expect(stream, host.IsWindows ? ShellPrompt.Windows : ShellPrompt.Root,
                AppSettings.CommandTimeout, writer, $"command completion on {host}: {command}");
        }
    }
}
