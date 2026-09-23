using System.Diagnostics;
using AutoSSH;
using Renci.SshNet;
using Renci.SshNet.Common;

static class IntegrationTests
{
    static long BackupFile(string root, string path, ISftpClient client) =>
        BackupService.BackupFileAsync(root, path, client).GetAwaiter().GetResult();

    static long BackupFolder(HostEntry host, string root, string path, ISftpClient client,
        TextWriter log, Func<ISftpClient> createClient = null, int workers = 4, int perConnection = 1) =>
        BackupService.BackupFolderAsync(host, root, path, client, log,
            createClient == null ? null : () => Task.FromResult(createClient()), workers,
            downloadsPerConnection: perConnection).GetAwaiter().GetResult();

    static long UploadFolder(HostEntry host, string path, ISftpClient client, TextWriter log) =>
        UploadService.UploadFolderAsync(host, path, client, log).GetAwaiter().GetResult();

    internal static void Run(int port)
    {
        var host = new HostEntry { Host = "127.0.0.1", Name = "test" };
        SftpClient Connect()
        {
            var client = new SftpClient("127.0.0.1", port, "test", "test");
            SshConnector.Configure(client);
            client.Connect();
            return client;
        }
        using (var tuned = new SftpClient("127.0.0.1", port, "test", "test"))
        {
            SshConnector.Configure(tuned);
            tuned.ConnectAsync(CancellationToken.None).GetAwaiter().GetResult();
            int before = SshConnector.GetConnectedSocket(tuned).ReceiveBufferSize;
            Require(SshConnector.TuneSocket(tuned), "Socket tuning could not reach SSH.NET's socket.");
            int after = SshConnector.GetConnectedSocket(tuned).ReceiveBufferSize;
            Console.WriteLine($"Socket receive buffer: SSH.NET default {before} bytes, tuned {after} bytes.");
            Require(after == 10 * 1024 * 1024, "Socket receive buffer was not raised.");
            Require(tuned.ListDirectory("/").Any(), "Tuned connection stopped working.");
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
            string pipelinedDir = Path.Combine(temp.Path, "pipelined");
            transferTimer.Restart();
            long pipelinedSize = BackupFolder(host, pipelinedDir, "/parallel", client, Console.Out, Connect, 2, 8);
            double pipelinedMs = transferTimer.Elapsed.TotalMilliseconds;
            Require(pipelinedSize == parallelSize, "Pipelined backup byte count mismatch.");
            for (int i = 0; i < 24; i++)
                Require(File.ReadAllBytes(Path.Combine(pipelinedDir, "parallel/file" + i)).SequenceEqual(contents[..8192]), "Pipelined download corrupted data.");
            Console.WriteLine($"Local 24-file download: two connections x8 {pipelinedMs:F0} ms.");
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
        SshConnector.Configure(ssh);
        ssh.Connect();
        using var shell = ssh.CreateShellStream("xterm", 80, 24, 800, 600, 1024);
        using var log = new StringWriter();
        ShellPrompt.Expect(shell, ShellPrompt.Login, TimeSpan.FromSeconds(1), log, "login");
        shell.Write("sudo -s\n");
        string sudo = ShellPrompt.Expect(shell, ShellPrompt.Sudo, TimeSpan.FromSeconds(1), log, "sudo");
        Require(ShellPrompt.Root.IsMatch(sudo), "Passwordless sudo was not recognized.");
        shell.Write("echo test\n");
        ShellPrompt.Expect(shell, ShellPrompt.Root, TimeSpan.FromSeconds(1), log, "command");
        Require(log.ToString().Contains("test output"), "Command output missing from log.");
        shell.Write("stall\n");
        var timer = Stopwatch.StartNew();
        try
        {
            ShellPrompt.Expect(shell, ShellPrompt.Root, TimeSpan.FromMilliseconds(200), log, "stalled command");
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
