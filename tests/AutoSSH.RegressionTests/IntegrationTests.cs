using System.Diagnostics;
using AutoSSH;
using Renci.SshNet;
using Renci.SshNet.Common;

static class IntegrationTests
{
    static long BackupFile(string root, string path, ISftpClient client) =>
        AutoSSHApp.BackupFileAsync(root, path, client).GetAwaiter().GetResult();

    static long BackupFolder(AutoSSHApp.HostEntry host, string root, string path, ISftpClient client,
        TextWriter log, Func<ISftpClient> createClient = null, int workers = 4) =>
        AutoSSHApp.BackupFolderAsync(host, root, path, client, log,
            createClient == null ? null : () => Task.FromResult(createClient()), workers).GetAwaiter().GetResult();

    static long UploadFolder(AutoSSHApp.HostEntry host, string path, ISftpClient client, TextWriter log) =>
        AutoSSHApp.UploadFolderAsync(host, path, client, log).GetAwaiter().GetResult();

    internal static void Run(int port)
    {
        var host = new AutoSSHApp.HostEntry { Host = "127.0.0.1", Name = "test" };
        SftpClient Connect()
        {
            var client = new SftpClient("127.0.0.1", port, "test", "test");
            AutoSSHApp.ConfigureClient(client);
            client.Connect();
            return client;
        }
        using var temp = new TempFolder();
        byte[] contents = Enumerable.Range(0, 300000).Select(i => (byte)(i % 251)).ToArray();
        string uploadDir = Path.Combine(temp.Path, "upload");
        Directory.CreateDirectory(Path.Combine(uploadDir, "nested"));
        File.WriteAllBytes(Path.Combine(uploadDir, "nested/file.bin"), contents);
        string backupDir = Path.Combine(temp.Path, "backup");
        using (var client = Connect())
        {
            long size = UploadFolder(host, uploadDir + ";/target", client, Console.Out);
            Require(size == contents.Length, "Upload byte count mismatch.");
            size = BackupFolder(host, backupDir, "/target", client, Console.Out);
            Require(size == contents.Length, "Backup byte count mismatch.");
            Require(File.ReadAllBytes(Path.Combine(backupDir, "target/nested/file.bin")).SequenceEqual(contents), "Round trip corrupted data.");
        }
        string manyFiles = Path.Combine(temp.Path, "many-files");
        Directory.CreateDirectory(manyFiles);
        for (int i = 0; i < 24; i++) File.WriteAllBytes(Path.Combine(manyFiles, "file" + i), contents[..8192]);
        using (var client = Connect())
        {
            UploadFolder(host, manyFiles + ";/parallel", client, Console.Out);
            var transferTimer = Stopwatch.StartNew();
            long sequentialSize = BackupFolder(host, Path.Combine(temp.Path, "serial"), "/parallel", client, Console.Out);
            double sequentialMs = transferTimer.Elapsed.TotalMilliseconds;
            transferTimer.Restart();
            long parallelSize = BackupFolder(host, backupDir, "/parallel", client, Console.Out, Connect, 4);
            double parallelMs = transferTimer.Elapsed.TotalMilliseconds;
            Require(sequentialSize == 24 * 8192 && parallelSize == sequentialSize, "Concurrent backup byte count mismatch.");
            for (int i = 0; i < 24; i++)
                Require(File.ReadAllBytes(Path.Combine(backupDir, "parallel/file" + i)).SequenceEqual(contents[..8192]), "Concurrent download corrupted data.");
            long skippedSize = BackupFolder(host, backupDir, "/parallel", client, Console.Out,
                () => throw new InvalidOperationException("Unchanged backup opened a worker connection."), 4);
            Require(skippedSize == parallelSize, "Unchanged parallel backup size mismatch.");
            Console.WriteLine($"Local 24-file download: sequential {sequentialMs:F0} ms, four workers {parallelMs:F0} ms (includes worker connections).");
        }
        using (var client = Connect())
        {
            var watch = Stopwatch.StartNew();
            try
            {
                BackupFile(backupDir, "/stall.bin", client);
                throw new InvalidOperationException("Stalled SFTP download did not time out.");
            }
            catch (SshOperationTimeoutException) { }
            Require(watch.Elapsed < TimeSpan.FromSeconds(5), "SFTP download timeout took too long.");
            Require(!Directory.GetFiles(backupDir, "*.__TEMP__", SearchOption.AllDirectories).Any(), "Stalled download left a temporary file.");
        }
        using (var client = Connect())
        {
            var watch = Stopwatch.StartNew();
            try
            {
                BackupFolder(host, backupDir, "/stall-dir", client, Console.Out);
                throw new InvalidOperationException("Stalled directory listing did not time out.");
            }
            catch (SshOperationTimeoutException) { }
            Require(watch.Elapsed < TimeSpan.FromSeconds(5), "Directory timeout took too long.");
        }
        using (var client = Connect())
        {
            var watch = Stopwatch.StartNew();
            try
            {
                UploadFolder(host, uploadDir + ";/stall-upload", client, Console.Out);
                throw new InvalidOperationException("Stalled upload did not time out.");
            }
            catch (SshOperationTimeoutException) { }
            Require(watch.Elapsed < TimeSpan.FromSeconds(5), "Upload timeout took too long.");
        }
        using var ssh = new SshClient("127.0.0.1", port, "test", "test");
        AutoSSHApp.ConfigureClient(ssh);
        ssh.Connect();
        using var shell = ssh.CreateShellStream("xterm", 80, 24, 800, 600, 1024);
        using var log = new StringWriter();
        AutoSSHApp.ExpectPrompt(shell, AutoSSHApp.loginPromptRegex, TimeSpan.FromSeconds(1), log, "login");
        shell.Write("sudo -s\n");
        string sudo = AutoSSHApp.ExpectPrompt(shell, AutoSSHApp.sudoPromptRegex, TimeSpan.FromSeconds(1), log, "sudo");
        Require(AutoSSHApp.rootPromptRegex.IsMatch(sudo), "Passwordless sudo was not recognized.");
        shell.Write("echo test\n");
        AutoSSHApp.ExpectPrompt(shell, AutoSSHApp.rootPromptRegex, TimeSpan.FromSeconds(1), log, "command");
        Require(log.ToString().Contains("test output"), "Command output missing from log.");
        shell.Write("stall\n");
        var timer = Stopwatch.StartNew();
        try
        {
            AutoSSHApp.ExpectPrompt(shell, AutoSSHApp.rootPromptRegex, TimeSpan.FromMilliseconds(200), log, "stalled command");
            throw new InvalidOperationException("Shell prompt did not time out.");
        }
        catch (TimeoutException) { }
        Require(timer.Elapsed < TimeSpan.FromSeconds(3), "Shell timeout took too long.");
    }

    static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
