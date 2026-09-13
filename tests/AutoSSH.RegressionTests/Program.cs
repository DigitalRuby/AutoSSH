using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using AutoSSH;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

Environment.SetEnvironmentVariable("AUTOSSH_SFTP_TIMEOUT_SECONDS", "1");
Environment.SetEnvironmentVariable("AUTOSSH_COMMAND_TIMEOUT_SECONDS", "1");
var tests = new (string Name, Action Run)[]
{
    ("Recursive backups serialize SFTP requests and preserve sync/ignore behavior", BackupTree),
    ("Concurrent task downloads use independent bounded sessions and skip unchanged files without connections", ParallelBackup),
    ("Downloads start before the directory scan finishes", OverlappingScanAndDownload),
    ("Concurrent task failures propagate and dispose worker sessions", ParallelBackupFailure),
    ("Failed and incomplete downloads preserve the previous backup", FailedDownload),
    ("Downloads that grew after listing still commit the complete file", GrewAfterListing),
    ("Session failures escape every backup stage immediately", BackupSessionFailures),
    ("Uploads retain the remote root, create parents, and truncate existing files", UploadTree),
    ("Session failures escape every upload stage immediately", UploadSessionFailures),
    ("Concurrent, out-of-order progress callbacks count bytes once", Progress),
    ("Clients have finite timeouts and keepalives", ClientSettings)
};
int failures = 0;
foreach (var test in tests)
{
    try { test.Run(); Console.WriteLine("PASS: " + test.Name); }
    catch (Exception ex) { failures++; Console.Error.WriteLine("FAIL: " + test.Name + "\n" + ex); }
}
if (args.Length == 2 && args[0] == "--integration-port")
{
    try { IntegrationTests.Run(int.Parse(args[1])); Console.WriteLine("PASS: Live SSH/SFTP transfers, stalls, and shell prompts"); }
    catch (Exception ex) { failures++; Console.Error.WriteLine("FAIL: Live SSH/SFTP\n" + ex); }
}
return failures == 0 ? 0 : 1;

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void Throws<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException("Expected " + typeof(T).Name);
}

static AutoSSHApp.HostEntry Host(string ignore = null) => new()
{
    Host = "test", Name = "test", IgnoreRegex = ignore == null ? null : new Regex(ignore)
};

static long BackupFile(string root, string path, ISftpClient client) =>
    AutoSSHApp.BackupFileAsync(root, path, client).GetAwaiter().GetResult();

static long BackupFolder(AutoSSHApp.HostEntry host, string root, string path, ISftpClient client,
    TextWriter log, Func<ISftpClient> createClient = null, int workers = 4) =>
    AutoSSHApp.BackupFolderAsync(host, root, path, client, log,
        createClient == null ? null : () => Task.FromResult(createClient()), workers).GetAwaiter().GetResult();

static long UploadFolder(AutoSSHApp.HostEntry host, string path, ISftpClient client, TextWriter log) =>
    AutoSSHApp.UploadFolderAsync(host, path, client, log).GetAwaiter().GetResult();

static void BackupTree()
{
    using var temp = new TempFolder();
    var remote = new FakeSftp();
    remote.AddDirectory("/data");
    long expected = 0;
    for (int folder = 0; folder < 8; folder++)
    {
        string dir = "/data/folder" + folder;
        remote.AddDirectory(dir);
        for (int file = 0; file < 8; file++)
        {
            string contents = $"contents {folder}/{file}";
            remote.AddFile(dir + "/file" + file, contents);
            expected += Encoding.UTF8.GetByteCount(contents);
        }
    }
    remote.AddFile("/data/ignore.txt", "ignore");
    remote.AddDirectory("/data/ignored-dir");
    remote.AddFile("/data/ignored-dir/file", "ignore");
    long size = BackupFolder(Host("ignore"), temp.Path, "/data", remote.Client, TextWriter.Null);
    Check(size == expected, "Wrong backup size or missing files.");
    Check(remote.Downloads == 64 && remote.MaxActive == 1, "SFTP operations must not overlap.");
    Check(Directory.GetFiles(temp.Path, "*", SearchOption.AllDirectories).Length == 64, "Ignore rules failed.");
    Check(File.ReadAllText(System.IO.Path.Combine(temp.Path, "data/folder7/file7")) == "contents 7/7", "Wrong contents.");
    Check(BackupFolder(Host("ignore"), temp.Path, "/data", remote.Client, TextWriter.Null) == expected, "Wrong skipped size.");
    Check(remote.Downloads == 64, "Unchanged files were downloaded again.");
    Check(remote.Gets == 2 && remote.Listings == 18, "Sync performed redundant metadata requests.");

}

static FakeSftp DownloadFixture()
{
    var remote = new FakeSftp();
    remote.AddDirectory("/data");
    for (int i = 0; i < 32; i++) remote.AddFile("/data/file" + i, "contents");
    return remote;
}

static void ParallelBackup()
{
    using var temp = new TempFolder();
    var scanner = DownloadFixture();
    var clients = new System.Collections.Concurrent.ConcurrentBag<FakeSftp>();
    using var overlap = new CountdownEvent(3);
    ISftpClient Connect()
    {
        var worker = DownloadFixture();
        bool first = true;
        worker.Before = method =>
        {
            if (method == "DownloadFile" && first)
            {
                first = false;
                overlap.Signal();
                Check(overlap.Wait(TimeSpan.FromSeconds(5)), "Downloads did not run concurrently.");
            }
        };
        clients.Add(worker);
        return worker.Client;
    }
    long size = BackupFolder(Host(), temp.Path, "/data|/data", scanner.Client, TextWriter.Null, Connect, 3);
    Check(size == 32 * 8, "Overlapping roots duplicated work or lost files.");
    Check(clients.Count == 3 && clients.Sum(c => c.Downloads) == 32, "Wrong worker bound or download count.");
    Check(clients.All(c => c.MaxActive == 1 && c.Disposals == 1 && c.Gets == 0), "Worker sessions overlap, leak, or repeat metadata requests.");
    Check(scanner.Downloads == 0 && scanner.MaxActive == 1, "Scanner session was shared with downloads.");
    Check(Directory.GetFiles(temp.Path, "*", SearchOption.AllDirectories).All(f => File.ReadAllText(f) == "contents"), "Parallel backup corrupted files.");
    size = BackupFolder(Host(), temp.Path, "/data", scanner.Client, TextWriter.Null,
        () => throw new InvalidOperationException("Unchanged sync opened a download connection."), 3);
    Check(size == 32 * 8, "Wrong unchanged backup size.");
}

static FakeSftp NestedDownloadFixture()
{
    var remote = new FakeSftp();
    remote.AddDirectory("/data");
    for (int folder = 0; folder < 4; folder++)
    {
        string dir = "/data/folder" + folder;
        remote.AddDirectory(dir);
        for (int file = 0; file < 4; file++) remote.AddFile(dir + "/file" + file, "contents");
    }
    return remote;
}

static void OverlappingScanAndDownload()
{
    using var temp = new TempFolder();
    var scanner = NestedDownloadFixture();
    using var downloaded = new ManualResetEventSlim(false);
    int listings = 0;
    scanner.Before = method =>
    {
        if (method != "ListDirectory") return;
        if (Interlocked.Increment(ref listings) >= 3)
            Check(downloaded.Wait(TimeSpan.FromSeconds(5)), "Downloads did not overlap directory scanning.");
    };
    ISftpClient Connect()
    {
        var worker = NestedDownloadFixture();
        worker.Before = method =>
        {
            if (method == "DownloadFile") downloaded.Set();
        };
        return worker.Client;
    }
    long size = BackupFolder(Host(), temp.Path, "/data", scanner.Client, TextWriter.Null, Connect, 2);
    Check(size == 16 * 8, "Overlapping scan lost files.");
    Check(downloaded.IsSet, "No files were downloaded.");
}

static void ParallelBackupFailure()
{
    using var temp = new TempFolder();
    var scanner = DownloadFixture();
    var clients = new System.Collections.Concurrent.ConcurrentBag<FakeSftp>();
    ISftpClient Connect()
    {
        var worker = DownloadFixture();
        worker.StallDownload = true;
        clients.Add(worker);
        return worker.Client;
    }
    Throws<SshOperationTimeoutException>(() => BackupFolder(Host(), temp.Path, "/data",
        scanner.Client, TextWriter.Null, Connect, 3));
    Check(clients.Count > 0 && clients.Count <= 3, "Unexpected worker count after failure.");
    Check(clients.All(c => c.Disposals == 1 && c.Downloads <= 1), "Failed session reused or not disposed.");
    Check(!Directory.GetFiles(temp.Path, "*.__TEMP__", SearchOption.AllDirectories).Any(), "Failed parallel download left temporary files.");
    Throws<SshConnectionException>(() => BackupFolder(Host(), temp.Path, "/data",
        scanner.Client, TextWriter.Null, () => throw new SshConnectionException("connect failed"), 3));
}

static void FailedDownload()
{
    foreach (bool stall in new[] { false, true })
    {
        using var temp = new TempFolder();
        var remote = new FakeSftp();
        remote.AddFile("/file", "new complete content");
        string localFile = System.IO.Path.Combine(temp.Path, "file");
        File.WriteAllText(localFile, "previous backup");
        File.SetLastWriteTimeUtc(localFile, remote.Timestamp.AddDays(-1));
        remote.PartialDownload = true;
        remote.StallDownload = stall;
        if (stall)
            Throws<SshOperationTimeoutException>(() => BackupFile(temp.Path, "/file", remote.Client));
        else
            Check(BackupFile(temp.Path, "/file", remote.Client) == 0, "Incomplete download counted as successful.");
        Check(File.ReadAllText(localFile) == "previous backup", "Previous backup was damaged.");
        Check(Directory.GetFiles(temp.Path).Length == 1, "Temporary file was left behind.");
        remote.PartialDownload = remote.StallDownload = false;
        BackupFile(temp.Path, "/file", remote.Client);
        Check(File.ReadAllText(localFile) == "new complete content", "Subsequent sync failed.");
    }
}

static void GrewAfterListing()
{
    using var temp = new TempFolder();
    var remote = new FakeSftp();
    remote.AddDirectory("/data");
    remote.AddFile("/data/live.log", "0123456789");
    remote.ListLengthAdjust = -4;
    long size = BackupFolder(Host(), temp.Path, "/data", remote.Client, TextWriter.Null);
    Check(size == 10, "Grew file was rejected as incomplete.");
    Check(File.ReadAllText(System.IO.Path.Combine(temp.Path, "data/live.log")) == "0123456789", "Grew file was truncated.");
}

static void BackupSessionFailures()
{
    foreach (string operation in new[] { "Get", "ListDirectory", "DownloadFile" })
    foreach (Exception error in new Exception[] { new SshOperationTimeoutException("stalled"), new SshConnectionException("disconnected") })
    {
        using var temp = new TempFolder();
        var remote = new FakeSftp();
        remote.AddDirectory("/data");
        remote.AddDirectory("/data/nested");
        remote.AddFile("/data/nested/a", "a");
        remote.AddFile("/data/nested/b", "b");
        int failures = 0;
        remote.Before = method => { if (method == operation) { failures++; throw error; } };
        Throws<SshException>(() => BackupFolder(Host(), temp.Path, "/data", remote.Client, TextWriter.Null));
        Check(failures == 1, "Kept using the failed SFTP session.");
    }
}

static void UploadTree()
{
    using var temp = new TempFolder();
    Directory.CreateDirectory(System.IO.Path.Combine(temp.Path, "one/two"));
    File.WriteAllText(System.IO.Path.Combine(temp.Path, "one/two/file.txt"), "short");
    File.WriteAllText(System.IO.Path.Combine(temp.Path, "root.txt"), "root");
    File.WriteAllText(System.IO.Path.Combine(temp.Path, "ignore.txt"), "ignore");
    foreach (string destination in new[] { "/target", "relative/target", "/", "/C:/target" })
    {
        var remote = new FakeSftp();
        string root = destination.TrimEnd('/');
        remote.Uploaded[root + "/one/two/file.txt"] = Encoding.UTF8.GetBytes("old, longer contents");
        long size = UploadFolder(Host("ignore"), temp.Path + ";" + destination, remote.Client, TextWriter.Null);
        Check(size == 9, "Wrong upload size.");
        Check(remote.Uploads == 2 && remote.MaxActive == 1, "Uploads overlap or ignore failed.");
        Check(Encoding.UTF8.GetString(remote.Uploaded[root + "/one/two/file.txt"]) == "short", "Upload did not truncate or used wrong path.");
        Check(remote.Uploaded.ContainsKey(root + "/root.txt"), "Lost remote root.");
        Check(remote.Directories.Contains(root + "/one/two"), "Missing remote parent directories.");
    }
}

static void UploadSessionFailures()
{
    foreach (string operation in new[] { "Exists", "CreateDirectory", "UploadFile" })
    {
        using var temp = new TempFolder();
        File.WriteAllText(System.IO.Path.Combine(temp.Path, "a"), "a");
        File.WriteAllText(System.IO.Path.Combine(temp.Path, "b"), "b");
        var remote = new FakeSftp();
        int failures = 0;
        remote.Before = method => { if (method == operation) { failures++; throw new SshOperationTimeoutException("stalled"); } };
        Throws<SshOperationTimeoutException>(() => UploadFolder(Host(), temp.Path + ";/target", remote.Client, TextWriter.Null));
        Check(failures == 1, "Kept uploading on a failed session.");
    }
}

static void Progress()
{
    long count = 0;
    var progress = new AutoSSHApp.TransferProgress(delta => Interlocked.Add(ref count, delta));
    Parallel.For(0, 10000, i => progress.Report((ulong)(10000 - i)));
    progress.Report(10000);
    progress.Report(1);
    Check(count == 10000, "Progress counted bytes more than once or went backwards.");
}

static void ClientSettings()
{
    using var client = new SftpClient("localhost", "test", "test");
    AutoSSHApp.ConfigureClient(client);
    Check(client.OperationTimeout == TimeSpan.FromSeconds(1), "SFTP timeout override was not applied.");
    Check(client.BufferSize == 65536, "SFTP buffer size missing.");
    Check(client.ConnectionInfo.Timeout == TimeSpan.FromSeconds(30), "Connection timeout missing.");
    Check(client.KeepAliveInterval == TimeSpan.FromSeconds(15), "Keepalive missing.");
}

public class StubProxy : DispatchProxy
{
    public Func<MethodInfo, object[], object> Handler { get; set; }
    protected override object Invoke(MethodInfo method, object[] args) => Handler(method, args);
    public static T Make<T>(Func<MethodInfo, object[], object> handler) where T : class
    {
        T proxy = Create<T, StubProxy>();
        ((StubProxy)(object)proxy).Handler = handler;
        return proxy;
    }
}

sealed class FakeSftp
{
    readonly Dictionary<string, ISftpFile> files = new();
    readonly Dictionary<string, byte[]> content = new();
    public readonly HashSet<string> Directories = new() { "/", ".", "/C:" };
    public readonly Dictionary<string, byte[]> Uploaded = new();
    public readonly DateTime Timestamp = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    public readonly ISftpClient Client;
    public Action<string> Before;
    public bool PartialDownload, StallDownload;
    public int Downloads, Uploads, MaxActive, Gets, Listings, Disposals;
    public int ListLengthAdjust;
    int active;

    public FakeSftp() => Client = StubProxy.Make<ISftpClient>(Invoke);
    public void AddDirectory(string path) { Directories.Add(path); Add(path, null); }
    public void AddFile(string path, string value) => Add(path, Encoding.UTF8.GetBytes(value));
    void Add(string path, byte[] bytes)
    {
        content[path] = bytes;
        files[path] = StubProxy.Make<ISftpFile>((method, args) => method.Name switch
        {
            "get_FullName" => path,
            "get_Name" => path[(path.LastIndexOf('/') + 1)..],
            "get_IsDirectory" => bytes == null,
            "get_IsRegularFile" => bytes != null,
            "get_Length" => (long)((bytes?.Length ?? 0) + ListLengthAdjust),
            "get_LastWriteTimeUtc" => Timestamp,
            _ => throw new NotSupportedException(method.Name)
        });
    }

    async IAsyncEnumerable<ISftpFile> ListDirectoryAsync(string path)
    {
        await Task.Yield();
        Before?.Invoke("ListDirectory");
        string prefix = path + "/";
        foreach (var file in files.Where(pair => pair.Key.StartsWith(prefix) &&
            !pair.Key[prefix.Length..].Contains('/')).Select(pair => pair.Value))
        {
            yield return file;
        }
    }

    async Task DownloadFileAsync(string path, Stream output)
    {
        await Task.Yield();
        Before?.Invoke("DownloadFile");
        Interlocked.Increment(ref Downloads);
        byte[] bytes = content[path];
        await output.WriteAsync(bytes.AsMemory(0, PartialDownload ? 1 : bytes.Length));
        if (StallDownload) throw new SshOperationTimeoutException("stalled download");
    }

    async Task<bool> ExistsAsync(string path)
    {
        await Task.Yield();
        Before?.Invoke("Exists");
        return files.ContainsKey(path) || Directories.Contains(path);
    }

    async Task<SftpFileAttributes> GetAttributesAsync(string path)
    {
        await Task.Yield();
        Before?.Invoke("Get");
        if (!content.TryGetValue(path, out byte[] bytes)) throw new SftpPathNotFoundException(path);
        uint permissions = bytes == null ? 16877u : 33188u;
        var constructor = typeof(SftpFileAttributes).GetConstructors(
            BindingFlags.Instance | BindingFlags.NonPublic).Single();
        return (SftpFileAttributes)constructor.Invoke(new object[]
        {
            Timestamp, Timestamp, (long)(bytes?.Length ?? 0), 0, 0, permissions,
            new Dictionary<string, string>()
        });
    }

    async Task CreateDirectoryAsync(string directory)
    {
        await Task.Yield();
        Before?.Invoke("CreateDirectory");
        int slash = directory.LastIndexOf('/');
        string parent = slash <= 0 ? "/" : directory[..slash];
        if (!Directories.Contains(parent)) throw new SftpPathNotFoundException("Missing parent " + parent);
        Directories.Add(directory);
    }

    async Task UploadFileAsync(Stream input, string path, bool overwrite)
    {
        await Task.Yield();
        Before?.Invoke("UploadFile");
        Interlocked.Increment(ref Uploads);
        if (!overwrite) throw new InvalidOperationException("Expected overwrite.");
        using var data = new MemoryStream();
        await input.CopyToAsync(data);
        Uploaded[path] = data.ToArray();
    }

    object Invoke(MethodInfo method, object[] args)
    {
        int current = Interlocked.Increment(ref active);
        int previous;
        do { previous = MaxActive; } while (current > previous && Interlocked.CompareExchange(ref MaxActive, current, previous) != previous);
        try
        {
            string operation = method.Name.EndsWith("Async") ? method.Name[..^5] : method.Name;
            if (!method.Name.EndsWith("Async")) Before?.Invoke(operation);
            switch (method.Name)
            {
                case "Exists": return files.ContainsKey((string)args[0]) || Directories.Contains((string)args[0]);
                case "ExistsAsync": return ExistsAsync((string)args[0]);
                case "Dispose": Disposals++; return null;
                case "Get": Gets++; return files[(string)args[0]];
                case "GetAttributesAsync": Gets++; return GetAttributesAsync((string)args[0]);
                case "ListDirectory":
                    Listings++;
                    string prefix = (string)args[0] + "/";
                    return files.Where(pair => pair.Key.StartsWith(prefix) && !pair.Key[prefix.Length..].Contains('/')).Select(pair => pair.Value).ToArray();
                case "ListDirectoryAsync":
                    Listings++;
                    return ListDirectoryAsync((string)args[0]);
                case "DownloadFile":
                    Interlocked.Increment(ref Downloads);
                    Thread.Sleep(2); // Expose accidental parallel use of this session.
                    byte[] bytes = content[(string)args[0]];
                    var output = (Stream)args[1];
                    output.Write(bytes, 0, PartialDownload ? 1 : bytes.Length);
                    if (StallDownload) throw new SshOperationTimeoutException("stalled download");
                    ((Action<ulong>)args[2])?.Invoke((ulong)output.Length);
                    return null;
                case "DownloadFileAsync":
                    return DownloadFileAsync((string)args[0], (Stream)args[1]);
                case "CreateDirectory":
                    string dir = (string)args[0];
                    int slash = dir.LastIndexOf('/');
                    string parent = slash <= 0 ? "/" : dir[..slash];
                    if (!Directories.Contains(parent)) throw new SftpPathNotFoundException("Missing parent " + parent);
                    Directories.Add(dir);
                    return null;
                case "CreateDirectoryAsync": return CreateDirectoryAsync((string)args[0]);
                case "UploadFile":
                    Interlocked.Increment(ref Uploads);
                    Thread.Sleep(2);
                    if (!(bool)args[2]) throw new InvalidOperationException("Expected overwrite.");
                    using (var data = new MemoryStream())
                    {
                        ((Stream)args[0]).CopyTo(data);
                        Uploaded[(string)args[1]] = data.ToArray();
                        ((Action<ulong>)args[3])?.Invoke((ulong)data.Length);
                    }
                    return null;
                case "UploadFileAsync":
                    return UploadFileAsync((Stream)args[0], (string)args[1], (bool)args[2]);
                default: throw new NotSupportedException(method.Name);
            }
        }
        finally { Interlocked.Decrement(ref active); }
    }
}

sealed class TempFolder : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AutoSSH-tests-" + Guid.NewGuid().ToString("N"));
    public TempFolder() => Directory.CreateDirectory(Path);
    public void Dispose() => Directory.Delete(Path, recursive: true);
}
