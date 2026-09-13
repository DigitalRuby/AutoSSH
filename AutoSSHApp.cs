#region Imports

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Threading;

using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

#endregion Imports

namespace AutoSSH
{
    public static class AutoSSHApp
    {
        internal class HostEntry
        {
            public string Host { get; set; }
            public string Name { get; set; }
            public bool IsWindows { get; set; }
            public Regex IgnoreRegex { get; set; }

            public override string ToString()
            {
                return Name + " : " + Host;
            }
        }

        // Each host owns its clients. Never run concurrent operations on one SFTP session.
        private static readonly int hostWorkers = GetWorkerCount("AUTOSSH_HOST_WORKERS", 8, 64);
        private static readonly int downloadWorkers = GetWorkerCount("AUTOSSH_DOWNLOAD_WORKERS", 8, 16);
        private static readonly TimeSpan connectionTimeout = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan operationTimeout = GetTimeout("AUTOSSH_SFTP_TIMEOUT_SECONDS", 60);
        private static readonly TimeSpan commandTimeout = GetTimeout("AUTOSSH_COMMAND_TIMEOUT_SECONDS", 1800);
        private const int transferBufferSize = 128 * 1024;
        private const uint sftpBufferSize = 64 * 1024;
        private static readonly Regex windowsDrivePrefixRegex = new(@"^\/[A-Za-z]\:[/\\]", RegexOptions.Compiled);

        private static int GetWorkerCount(string name, int defaultWorkers, int maxWorkers)
        {
            string value = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrWhiteSpace(value)) return defaultWorkers;
            if (int.TryParse(value, out int workers) && workers >= 1 && workers <= maxWorkers) return workers;
            throw new ArgumentException($"{name} must be a whole number from 1 to {maxWorkers}.");
        }

        private static TimeSpan GetTimeout(string name, int defaultSeconds)
        {
            string value = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrWhiteSpace(value))
            {
                return TimeSpan.FromSeconds(defaultSeconds);
            }
            if (!int.TryParse(value, out int seconds) || seconds <= 0 || seconds > int.MaxValue / 1000)
            {
                throw new ArgumentException($"{name} must be a positive number of seconds no greater than {int.MaxValue / 1000}.");
            }
            return TimeSpan.FromSeconds(seconds);
        }

        internal static void ConfigureClient(BaseClient client)
        {
            client.ConnectionInfo.Timeout = connectionTimeout;
            client.KeepAliveInterval = TimeSpan.FromSeconds(15);
            if (client is SftpClient sftpClient)
            {
                sftpClient.OperationTimeout = operationTimeout;
                sftpClient.BufferSize = sftpBufferSize;
            }
        }

        private static class Diag
        {
            private static readonly ConcurrentDictionary<string, (string Op, long Start)> inflight = new();
            private static readonly object gate = new();
            private static StreamWriter writer;
            private static Stopwatch clock;
            private static long nextId;

            internal static string Path { get; private set; }

            internal static void Start()
            {
                string dir = System.IO.Path.GetDirectoryName(Environment.ProcessPath);
                if (string.IsNullOrEmpty(dir)) dir = AppContext.BaseDirectory;
                Directory.CreateDirectory(dir);
                Path = System.IO.Path.Combine(dir, "AutoSSH.log");
                clock = Stopwatch.StartNew();
                var stream = new FileStream(Path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                lock (gate)
                {
                    writer = new StreamWriter(stream) { AutoFlush = true };
                }
                Write($"==== AutoSSH {DateTime.Now:yyyy-MM-dd HH:mm:ss} pid={Environment.ProcessId} ====");
                Write("exe=" + (Environment.ProcessPath ?? "(unknown)"));
                Write("log=" + Path);
                Write($"hosts={hostWorkers} downloadWorkers={downloadWorkers} sftpTimeout={operationTimeout.TotalSeconds}s commandTimeout={commandTimeout.TotalSeconds}s");
            }

            internal static void Stop()
            {
                Write("==== finished ====");
                lock (gate)
                {
                    writer?.Dispose();
                    writer = null;
                }
            }

            internal static void Write(string message)
            {
                lock (gate)
                {
                    if (writer == null) return;
                    writer.WriteLine($"{DateTime.Now:HH:mm:ss.fff} +{clock.Elapsed:hh\\:mm\\:ss\\.fff} t{Environment.CurrentManagedThreadId} {message}");
                }
            }

            internal static string Begin(string op)
            {
                if (writer == null) return null;
                string key = Interlocked.Increment(ref nextId).ToString();
                inflight[key] = (op, Stopwatch.GetTimestamp());
                Write($"BEGIN [{key}] {op}");
                return key;
            }

            internal static void End(string key, string extra = null)
            {
                if (key == null) return;
                string suffix = extra == null ? "" : " " + extra;
                if (inflight.TryRemove(key, out var a))
                {
                    double ms = (Stopwatch.GetTimestamp() - a.Start) * 1000.0 / Stopwatch.Frequency;
                    Write($"END   [{key}] {a.Op} {ms:0}ms{suffix}");
                }
                else
                {
                    Write($"END   [{key}]{suffix}");
                }
            }

            internal static void Fail(string key, Exception ex)
            {
                Write($"FAIL  [{key ?? "?"}] {ex.GetType().Name}: {ex.Message}");
                End(key, "FAILED");
            }

            internal static void Heartbeat()
            {
                if (writer == null) return;
                var ops = inflight.Select(kv =>
                {
                    double sec = (Stopwatch.GetTimestamp() - kv.Value.Start) / (double)Stopwatch.Frequency;
                    return $"{kv.Value.Op} ({sec:0.0}s)";
                }).OrderByDescending(s => s).ToArray();
                Write($"HEART down={BytesToString(Interlocked.Read(ref bytesDownloaded))} up={BytesToString(Interlocked.Read(ref bytesUploaded))} skip={BytesToString(Interlocked.Read(ref bytesSkipped))} inflight={ops.Length}");
                foreach (string op in ops)
                {
                    Write("  ... " + op);
                }
            }
        }
        // Accept trailing terminal color/reset sequences as well as plain prompts.
        private const string promptSuffix = @"(?:[ \t]|\x1b\[[0-?]*[ -/]*[@-~])*\r?$";
        internal static readonly Regex loginPromptRegex = new Regex(@"(?m)[$#>]" + promptSuffix);
        internal static readonly Regex rootPromptRegex = new Regex(@"(?m)#" + promptSuffix);
        internal static readonly Regex windowsPromptRegex = new Regex(@"(?m)>" + promptSuffix);
        internal static readonly Regex sudoPromptRegex = new Regex(@"(?m)[Pp]assword[^\r\n]*:" + promptSuffix + "|" + rootPromptRegex);

        private static SecureString userName;
        private static SecureString password;
        private static long bytesDownloaded;
        private static long bytesUploaded;
        private static long bytesSkipped;

        private static void WriteSecure(SecureString secureString, ShellStream writer)
        {
            IntPtr unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                byte[] buf = new byte[2];
                for (int i = 0; i < secureString.Length * 2; )
                {
                    buf[0] = Marshal.ReadByte(unmanagedString, i++);
                    buf[1] = Marshal.ReadByte(unmanagedString, i++);
                    writer.Write(BitConverter.ToChar(buf).ToString());
                }
                writer.Write("\n");
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        private static string SecureStringToString(SecureString secureString)
        {
            StringBuilder b = new StringBuilder();
            IntPtr unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                byte[] buf = new byte[2];
                for (int i = 0; i < secureString.Length * 2;)
                {
                    buf[0] = Marshal.ReadByte(unmanagedString, i++);
                    buf[1] = Marshal.ReadByte(unmanagedString, i++);
                    b.Append(BitConverter.ToChar(buf));
                }
                return b.ToString();
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        private static void SecureStringFromString(ref SecureString secureString, string text)
        {
            secureString = new SecureString();
            foreach (char c in text)
            {
                secureString.AppendChar(c);
            }
        }

        private static List<KeyValuePair<HostEntry, List<string>>> LoadCommands(string commandFile)
        {
            List<KeyValuePair<HostEntry, List<string>>> commands = new List<KeyValuePair<HostEntry, List<string>>>();
            List<string> lines = new List<string>();
            List<string> inheritedLines = new List<string>();
            HostEntry currentEntry = null;
            string cleanedLine;
            bool isHostLine = false;
            int lineIndex = 0;
            Dictionary<string, string> replacers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (string line in File.ReadAllLines(commandFile))
            {
                // clean and trim
                cleanedLine = line.Trim();
                int pos = cleanedLine.IndexOf('#');
                if (pos >= 0)
                {
                    cleanedLine = cleanedLine.Substring(0, pos).Trim();
                }

                // replace any find and replace directives
                foreach (var kv in replacers)
                {
                    cleanedLine = cleanedLine.Replace(kv.Key, kv.Value, StringComparison.OrdinalIgnoreCase);
                }

                // look for defines ($...$=value)
                Match replacer = Regex.Match(cleanedLine, @"(?<name>\$[^\$]+\$)\s*=\s*(?<value>.+)", RegexOptions.IgnoreCase | RegexOptions.Singleline);
                if (replacer.Success)
                {
                    replacers[replacer.Groups["name"].Value] = replacer.Groups["value"].Value;
                    continue;
                }

                // check if this is a host
                isHostLine = cleanedLine.StartsWith("$host", StringComparison.OrdinalIgnoreCase);
                if (currentEntry != null && (cleanedLine.Length == 0 || isHostLine))
                {
                    if (currentEntry.Name != "*" && currentEntry.Host != "*")
                    {
                        lines.AddRange(inheritedLines);
                        commands.Add(new KeyValuePair<HostEntry, List<string>>(currentEntry, lines));
                        lines = new List<string>();
                        currentEntry = null;
                    }
                }
                if (isHostLine)
                {
                    // found a host, set the current entry
                    string[] pieces = cleanedLine.Split(' ');
                    if (pieces.Length < 3)
                    {
                        throw new InvalidOperationException("Host line format is $host name dns_or_address, line: " + lineIndex);
                    }
                    if (pieces[1] == "*" && pieces[2] == "*")
                    {
                        currentEntry = new HostEntry { Name = "*", Host = "*" };
                        inheritedLines.Clear();
                    }
                    else
                    {
                        currentEntry = new HostEntry { Name = pieces[1], Host = pieces[2],
                            IsWindows = (pieces.Length < 4 ? false : pieces[3].Equals("windows", StringComparison.OrdinalIgnoreCase)) };
                    }
                }
                else if (cleanedLine.Length != 0)
                {
                    if (currentEntry == null)
                    {
                        throw new InvalidOperationException("Must define a $host before commands, line: " + lineIndex);
                    }
                    else if (currentEntry.Name == "*" && currentEntry.Host == "*")
                    {
                        inheritedLines.Add(cleanedLine);
                    }
                    else
                    {
                        lines.Add(cleanedLine);
                    }
                }
                lineIndex++;
            }
            lines.AddRange(inheritedLines);
            if (currentEntry != null && lines.Count != 0)
            {
                // add commands for this host
                commands.Add(new KeyValuePair<HostEntry, List<string>>(currentEntry, lines));
            }
            return commands;
        }

        private static List<KeyValuePair<HostEntry, List<string>>> Initialize(string commandFile, string backupRoot)
        {
            string loginPath = Path.Combine(backupRoot, "login.key");
            if (!File.Exists(loginPath))
            {
                Console.Write("Enter user name: ");
                string userName = Console.ReadLine();
                Console.Write("Enter password: ");
                string password = string.Empty;
                while (true)
                {
                    ConsoleKeyInfo key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter)
                    {
                        Console.WriteLine();
                        break;
                    }
                    else
                    {
                        password += key.KeyChar;
                    }
                }
                byte[] bytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(userName + "|" + password), null,
                    DataProtectionScope.CurrentUser);
                File.WriteAllBytes(loginPath, bytes);
            }
            if (!File.Exists(loginPath))
            {
                throw new FileNotFoundException("Missing login.key file");
            }
            {
                byte[] protectedBytes = File.ReadAllBytes(loginPath);
                string unprotectedBytes = Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, null,
                    DataProtectionScope.CurrentUser));
                int pos = unprotectedBytes.IndexOf('|');
                if (pos < 0)
                {
                    throw new ArgumentException("Corrupted login.key file, delete and restart");
                }
                SecureStringFromString(ref userName, unprotectedBytes.Substring(0, pos));
                SecureStringFromString(ref password, unprotectedBytes.Substring(++pos));
                protectedBytes = null;
                unprotectedBytes = null;
                GC.Collect();
            }

            return LoadCommands(commandFile);
        }

        private static async Task<BaseClient> ConnectAsync(string root, HostEntry host, bool ssh)
        {
            Console.WriteLine("Connecting to {0} with type {1}", host, ssh ? "SSH" : "SFTP");
            string op = Diag.Begin($"{host} connect {(ssh ? "SSH" : "SFTP")}");
            root = Path.Combine(root, host.Name);
            Directory.CreateDirectory(root);
            string fingerFile = Path.Combine(root, "finger.key");
            byte[] fingerprint = File.Exists(fingerFile) ? File.ReadAllBytes(fingerFile) : null;
            var insecureUserName = SecureStringToString(userName);
            var insecurePassword = SecureStringToString(password);
            BaseClient client = ssh ? new SshClient(host.Host, insecureUserName, insecurePassword) : new SftpClient(host.Host, insecureUserName, insecurePassword);
            ConfigureClient(client);
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
                Diag.End(op, fingerMatch ? "ok" : "fingerprint-mismatch");
                return client;
            }
            catch (Exception ex)
            {
                Diag.Fail(op, ex);
                client.Dispose();
                throw;
            }
        }

        private static string BytesToString(long byteCount)
        {
            string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
            if (byteCount == 0)
                return "0" + suf[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 2);
            return (Math.Sign(byteCount) * num).ToString() + suf[place];
        }

        // SSH.NET queues progress callbacks on the thread pool, so delivery can be out of order.
        internal sealed class TransferProgress : IProgress<DownloadFileProgressReport>, IProgress<UploadFileProgressReport>
        {
            private long reported;
            private readonly Action<long> addBytes;

            internal TransferProgress(Action<long> addBytes) => this.addBytes = addBytes;

            void IProgress<DownloadFileProgressReport>.Report(DownloadFileProgressReport value) =>
                Report(value.TotalBytesDownloaded);

            void IProgress<UploadFileProgressReport>.Report(UploadFileProgressReport value) =>
                Report(value.TotalBytesUploaded);

            internal void Report(ulong value)
            {
                long progress = checked((long)value);
                long previous;
                do
                {
                    previous = Interlocked.Read(ref reported);
                    if (progress <= previous)
                    {
                        return;
                    }
                }
                while (Interlocked.CompareExchange(ref reported, progress, previous) != previous);
                addBytes(progress - previous);
            }
        }

        private static FileStream OpenLocalTransferStream(string path, FileMode mode, FileAccess access, FileShare share) =>
            new FileStream(path, mode, access, share, transferBufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

        private static async Task WhenAllPreferSessionErrors(params Task[] tasks)
        {
            try
            {
                await Task.WhenAll(tasks);
            }
            catch
            {
                Exception[] errors = tasks.Where(t => t.IsFaulted)
                    .SelectMany(t => t.Exception!.Flatten().InnerExceptions)
                    .ToArray();
                Exception error = Array.Find(errors, static e => e is not OperationCanceledException)
                    ?? errors.FirstOrDefault();
                if (error != null)
                {
                    ExceptionDispatchInfo.Capture(error).Throw();
                }
                throw;
            }
        }

        private static string BackupFileName(string root, string remotePath)
        {
            // trim rooted paths, including drive letters
            string localPath = windowsDrivePrefixRegex.Replace(remotePath, string.Empty).Trim('/', '\\');
            return Path.Combine(root, localPath);
        }

        private static async Task<long> BackupFileAsync(string root, BackupEntry file, ISftpClient client,
            CancellationToken cancellation)
        {
            string fileName = BackupFileName(root, file.FullName);
            long transferred = 0;
            long downloaded = 0;
            bool committed = false;
            string op = Diag.Begin($"download {file.FullName} {BytesToString(file.Length)}");
            try
            {
                string tempFile = fileName + "." + Guid.NewGuid().ToString("N") + ".__TEMP__";
                Directory.CreateDirectory(Path.GetDirectoryName(fileName));
                try
                {
                    await using (FileStream stream = OpenLocalTransferStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        var progress = new TransferProgress(delta =>
                        {
                            Interlocked.Add(ref transferred, delta);
                            Interlocked.Add(ref bytesDownloaded, delta);
                        });
                        await client.DownloadFileAsync(file.FullName, stream, progress, cancellation);
                        await stream.FlushAsync(cancellation);
                        progress.Report((ulong)stream.Length);
                        downloaded = stream.Length;
                    }
                    // Listing/find size is a snapshot. Live sqlite/log files often grow before EOF.
                    // SFTP reads until EOF, so only a short read is actually incomplete.
                    if (downloaded < file.Length)
                    {
                        throw new IOException($"Incomplete download of {file.FullName}; got {downloaded} bytes, expected at least {file.Length}.");
                    }
                    if (downloaded != file.Length)
                    {
                        Diag.Write($"size changed during download {file.FullName} listed={file.Length} got={downloaded}");
                    }
                    File.SetLastWriteTimeUtc(tempFile, file.LastWriteTimeUtc);
                    File.Move(tempFile, fileName, overwrite: true);
                    committed = true;
                    Diag.End(op, BytesToString(downloaded));
                    return downloaded;
                }
                finally
                {
                    try
                    {
                        File.Delete(tempFile);
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        Console.WriteLine("Unable to remove temporary file {0}: {1}", tempFile, ex.Message);
                    }
                }
            }
            catch (SftpPathNotFoundException)
            {
                Diag.End(op, "missing");
                return 0;
            }
            catch (SftpPermissionDeniedException)
            {
                Diag.End(op, "denied");
                return 0;
            }
            catch (Exception ex) when (ex is not SshException && ex is not TimeoutException && ex is not OperationCanceledException)
            {
                Console.WriteLine("Error: {0}         ", ex.Message);
                Diag.Fail(op, ex);
                return 0;
            }
            catch (Exception ex)
            {
                Diag.Fail(op, ex);
                throw;
            }
            finally
            {
                if (!committed && transferred != 0)
                {
                    Interlocked.Add(ref bytesDownloaded, -transferred);
                }
            }
        }

        private sealed record BackupEntry(string FullName, string Name, bool IsRegularFile,
            bool IsDirectory, long Length, DateTime LastWriteTimeUtc);

        private static async Task<BackupEntry> ReadBackupRootAsync(ISftpClient client, string path,
            TextWriter log, CancellationToken cancellation)
        {
            try
            {
                var attributes = await client.GetAttributesAsync(path, cancellation);
                return new BackupEntry(path, Path.GetFileName(path.TrimEnd('/', '\\')),
                    attributes.IsRegularFile, attributes.IsDirectory, attributes.Size, attributes.LastWriteTimeUtc);
            }
            catch (SftpPathNotFoundException)
            {
                Diag.Write("stat missing " + path);
            }
            catch (SftpPermissionDeniedException ex)
            {
                log.WriteLine("Error backing up {0}: {1}", path, ex.Message);
            }
            catch (Exception ex) when (ex is not SshException && ex is not TimeoutException && ex is not OperationCanceledException)
            {
                log.WriteLine("Error backing up {0}: {1}", path, ex);
            }
            return null;
        }

        internal static async Task<long> BackupFileAsync(string root, string remotePath, ISftpClient client,
            CancellationToken cancellation = default)
        {
            var file = await ReadBackupRootAsync(client, remotePath, TextWriter.Null, cancellation);
            if (file == null || !file.IsRegularFile) return 0;
            string localFile = BackupFileName(root, remotePath);
            if (File.Exists(localFile) && file.LastWriteTimeUtc <= File.GetLastWriteTimeUtc(localFile))
            {
                Interlocked.Add(ref bytesSkipped, file.Length);
                return file.Length;
            }
            return await BackupFileAsync(root, file, client, cancellation);
        }

        private static async Task<List<BackupEntry>> ReadBackupEntriesAsync(ISftpClient client, string path,
            TextWriter log, CancellationToken cancellation)
        {
            var entries = new List<BackupEntry>();
            string op = Diag.Begin("list " + path);
            try
            {
                await foreach (var file in client.ListDirectoryAsync(path, cancellation))
                {
                    entries.Add(new BackupEntry(file.FullName, file.Name, file.IsRegularFile,
                        file.IsDirectory, file.Length, file.LastWriteTimeUtc));
                }
                Diag.End(op, entries.Count + " entries");
            }
            catch (SftpPathNotFoundException)
            {
                Diag.End(op, "missing");
            }
            catch (SftpPermissionDeniedException ex)
            {
                Diag.Fail(op, ex);
                log.WriteLine("Error backing up {0}: {1}", path, ex.Message);
            }
            catch (Exception ex) when (ex is not SshException && ex is not TimeoutException && ex is not OperationCanceledException)
            {
                Diag.Fail(op, ex);
                log.WriteLine("Error backing up {0}: {1}", path, ex);
            }
            catch (Exception ex)
            {
                Diag.Fail(op, ex);
                throw;
            }
            return entries;
        }

        private static string QuoteUnix(string value) => "'" + value.Replace("'", "'\\''") + "'";

        private static async Task<List<BackupEntry>> TryFindBackupFilesAsync(HostEntry host, string path,
            SshClient ssh, CancellationToken cancellation)
        {
            string[] roots = path.Split('|').Select(s => s.Trim()).Where(s => s.Length != 0).ToArray();
            if (roots.Length == 0) return new List<BackupEntry>();
            string command = "find " + string.Join(" ", roots.Select(QuoteUnix)) +
                " -name '.*' -type d -prune -o -type f -printf '%T@\\t%s\\t%p\\n'";
            string op = Diag.Begin($"{host} find {path}");
            try
            {
                using SshCommand cmd = ssh.CreateCommand(command);
                cmd.CommandTimeout = commandTimeout;
                await cmd.ExecuteAsync(cancellation);
                string error = cmd.Error ?? string.Empty;
                if (error.Contains("unknown predicate", StringComparison.OrdinalIgnoreCase) ||
                    error.Contains("illegal option", StringComparison.OrdinalIgnoreCase) ||
                    error.Contains("unrecognized", StringComparison.OrdinalIgnoreCase))
                {
                    Diag.End(op, "unsupported find, fallback to SFTP");
                    return null;
                }
                var files = new List<BackupEntry>();
                using StringReader reader = new StringReader(cmd.Result ?? string.Empty);
                for (string line = reader.ReadLine(); line != null; line = reader.ReadLine())
                {
                    int tab1 = line.IndexOf('\t');
                    int tab2 = tab1 < 0 ? -1 : line.IndexOf('\t', tab1 + 1);
                    if (tab2 < 0) continue;
                    if (!double.TryParse(line.AsSpan(0, tab1), NumberStyles.Float, CultureInfo.InvariantCulture, out double unix)) continue;
                    if (!long.TryParse(line.AsSpan(tab1 + 1, tab2 - tab1 - 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out long size)) continue;
                    string fullName = line[(tab2 + 1)..];
                    if (fullName.Length == 0) continue;
                    if (host.IgnoreRegex != null && host.IgnoreRegex.IsMatch(fullName)) continue;
                    string name = fullName[(fullName.LastIndexOf('/') + 1)..];
                    files.Add(new BackupEntry(fullName, name, true, false, size, DateTime.UnixEpoch.AddSeconds(unix)));
                }
                Diag.End(op, $"{files.Count} files exit={cmd.ExitStatus}");
                return files;
            }
            catch (Exception ex)
            {
                Diag.Fail(op, ex);
                return null;
            }
        }

        private static async IAsyncEnumerable<BackupEntry> EnumerateBackupFilesAsync(HostEntry host, string path,
            ISftpClient client, TextWriter log, [EnumeratorCancellation] CancellationToken cancellation)
        {
            foreach (string root in path.Split('|').Select(s => s.Trim()).Where(s => s.Length != 0))
            {
                cancellation.ThrowIfCancellationRequested();
                var rootEntry = await ReadBackupRootAsync(client, root, log, cancellation);
                if (rootEntry == null) continue;
                var pending = new Stack<BackupEntry>();
                pending.Push(rootEntry);
                while (pending.Count != 0)
                {
                    cancellation.ThrowIfCancellationRequested();
                    var entry = pending.Pop();
                    if (entry.IsRegularFile)
                    {
                        yield return entry;
                    }
                    else if (entry.IsDirectory)
                    {
                        foreach (var child in await ReadBackupEntriesAsync(client, entry.FullName, log, cancellation))
                        {
                            if ((child.IsRegularFile || (child.IsDirectory && !child.Name.StartsWith("."))) &&
                                (host.IgnoreRegex == null || !host.IgnoreRegex.IsMatch(child.FullName)))
                            {
                                pending.Push(child);
                            }
                        }
                    }
                }
            }
        }

        internal static async Task<long> BackupFolderAsync(HostEntry host, string root, string path,
            ISftpClient client, TextWriter log, Func<Task<ISftpClient>> createDownloadClient = null, int workers = 4,
            SshClient ssh = null)
        {
            if (workers < 1 || workers > 16) throw new ArgumentOutOfRangeException(nameof(workers));
            long size = 0;
            int queued = 0;
            int skipped = 0;
            using var cancellation = new CancellationTokenSource();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            string scanOp = Diag.Begin($"{host} backup {path} workers={workers}");

            async IAsyncEnumerable<BackupEntry> EnumerateAsync()
            {
                if (ssh != null && !host.IsWindows)
                {
                    List<BackupEntry> found = await TryFindBackupFilesAsync(host, path, ssh, cancellation.Token);
                    if (found != null)
                    {
                        foreach (BackupEntry file in found) yield return file;
                        yield break;
                    }
                    Diag.Write($"{host} falling back to SFTP directory walking");
                }
                await foreach (BackupEntry file in EnumerateBackupFilesAsync(host, path, client, log, cancellation.Token))
                {
                    yield return file;
                }
            }

            async IAsyncEnumerable<BackupEntry> ChangedFilesAsync()
            {
                await foreach (var file in EnumerateAsync())
                {
                    if (!seen.Add(file.FullName)) continue;
                    string localFile = BackupFileName(root, file.FullName);
                    if (File.Exists(localFile) && file.LastWriteTimeUtc <= File.GetLastWriteTimeUtc(localFile))
                    {
                        Interlocked.Add(ref bytesSkipped, file.Length);
                        Interlocked.Add(ref size, file.Length);
                        int n = Interlocked.Increment(ref skipped);
                        if (n == 1 || n % 200 == 0)
                        {
                            Diag.Write($"{host} skipped {n} files (latest {file.FullName})");
                        }
                    }
                    else
                    {
                        yield return file;
                    }
                }
            }

            if (createDownloadClient == null || workers == 1)
            {
                try
                {
                    await foreach (var file in ChangedFilesAsync())
                    {
                        Interlocked.Increment(ref queued);
                        size += await BackupFileAsync(root, file, client, cancellation.Token);
                    }
                    Diag.End(scanOp, $"queued={queued} skipped={skipped} size={BytesToString(size)}");
                    return size;
                }
                catch (Exception ex)
                {
                    Diag.Fail(scanOp, ex);
                    throw;
                }
            }

            // List on the original session while workers download on their own connections.
            // Transfers start as soon as files are found instead of waiting for the whole tree.
            var files = Channel.CreateBounded<BackupEntry>(new BoundedChannelOptions(32)
            {
                SingleWriter = true,
                SingleReader = false,
                FullMode = BoundedChannelFullMode.Wait
            });

            async Task ScanAsync()
            {
                try
                {
                    await foreach (var file in ChangedFilesAsync())
                    {
                        int n = Interlocked.Increment(ref queued);
                        if (n == 1 || n % 50 == 0)
                        {
                            Diag.Write($"{host} queued {n} downloads (latest {file.FullName} {BytesToString(file.Length)})");
                        }
                        var wait = Stopwatch.StartNew();
                        await files.Writer.WriteAsync(file, cancellation.Token);
                        if (wait.ElapsedMilliseconds >= 500)
                        {
                            Diag.Write($"{host} download queue blocked {wait.ElapsedMilliseconds}ms on {file.FullName}");
                        }
                    }
                    files.Writer.TryComplete();
                    Diag.Write($"{host} scan complete queued={queued} skipped={skipped}");
                }
                catch (Exception ex)
                {
                    files.Writer.TryComplete(ex is OperationCanceledException ? null : ex);
                    cancellation.Cancel();
                    throw;
                }
            }

            async Task DownloadWorkerAsync()
            {
                ISftpClient downloadClient = null;
                try
                {
                    await foreach (var file in files.Reader.ReadAllAsync(cancellation.Token))
                    {
                        try
                        {
                            downloadClient ??= await createDownloadClient();
                            Interlocked.Add(ref size,
                                await BackupFileAsync(root, file, downloadClient, cancellation.Token));
                        }
                        catch
                        {
                            cancellation.Cancel();
                            throw;
                        }
                    }
                }
                finally
                {
                    downloadClient?.Dispose();
                }
            }

            var workerTasks = Enumerable.Range(0, workers).Select(_ => DownloadWorkerAsync()).ToArray();
            try
            {
                await WhenAllPreferSessionErrors(new Task[] { ScanAsync() }.Concat(workerTasks).ToArray());
                Diag.End(scanOp, $"queued={queued} skipped={skipped} size={BytesToString(size)}");
                return size;
            }
            catch (Exception ex)
            {
                Diag.Fail(scanOp, ex);
                throw;
            }
        }

        private static async Task EnsureRemoteDirectoryAsync(ISftpClient client, string directory,
            HashSet<string> existing, CancellationToken cancellation)
        {
            if (directory.Length == 0 || directory == "/" || directory == "." || existing.Contains(directory))
            {
                return;
            }
            if (await client.ExistsAsync(directory, cancellation))
            {
                existing.Add(directory);
                return;
            }
            int separator = directory.LastIndexOf('/');
            if (separator > 0)
            {
                await EnsureRemoteDirectoryAsync(client, directory.Substring(0, separator), existing, cancellation);
            }
            await client.CreateDirectoryAsync(directory, cancellation);
            existing.Add(directory);
        }

        internal static async Task<long> UploadFolderAsync(HostEntry host, string pathInfo, ISftpClient client,
            TextWriter log, CancellationToken cancellation = default)
        {
            long uploadSize = 0;
            string[] paths = pathInfo.Split(';', 2);
            if (paths.Length != 2 || string.IsNullOrWhiteSpace(paths[0]) || string.IsNullOrWhiteSpace(paths[1]))
            {
                throw new ArgumentException("Upload format is $upload local_folder;remote_folder.");
            }
            string localDir = Path.GetFullPath(paths[0].Trim());
            string remoteFolder = paths[1].Trim().Replace('\\', '/').TrimEnd('/');
            var existingDirectories = new HashSet<string>(StringComparer.Ordinal);
            string op = Diag.Begin($"{host} upload {localDir} -> {remoteFolder}");
            int uploaded = 0;
            foreach (string file in Directory.EnumerateFiles(localDir, "*", SearchOption.AllDirectories))
            {
                if (host.IgnoreRegex != null && host.IgnoreRegex.IsMatch(file))
                {
                    continue;
                }

                string relativePath = Path.GetRelativePath(localDir, file).Replace('\\', '/');
                string remoteFile = remoteFolder + "/" + relativePath;
                string remoteDir = remoteFile.Substring(0, remoteFile.LastIndexOf('/'));
                string fileOp = Diag.Begin($"upload {file} -> {remoteFile}");
                try
                {
                    await EnsureRemoteDirectoryAsync(client, remoteDir, existingDirectories, cancellation);
                    await using var localStream = OpenLocalTransferStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
                    var progress = new TransferProgress(delta => Interlocked.Add(ref bytesUploaded, delta));
                    await client.UploadFileAsync(localStream, remoteFile, true, progress, cancellation);
                    progress.Report((ulong)localStream.Length);
                    uploadSize += localStream.Length;
                    uploaded++;
                    Diag.End(fileOp, BytesToString(localStream.Length));
                }
                catch (SftpPermissionDeniedException ex)
                {
                    Diag.Fail(fileOp, ex);
                    log.WriteLine("Error uploading file {0} to {1}: {2}", file, remoteFile, ex.Message);
                }
                catch (SftpPathNotFoundException ex)
                {
                    Diag.Fail(fileOp, ex);
                    log.WriteLine("Error uploading file {0} to {1}: {2}", file, remoteFile, ex.Message);
                }
                catch (Exception ex) when (ex is not SshException && ex is not TimeoutException && ex is not OperationCanceledException)
                {
                    Diag.Fail(fileOp, ex);
                    log.WriteLine("Error uploading file {0} to {1}: {2}", file, remoteFile, ex);
                }
                catch (Exception ex)
                {
                    Diag.Fail(fileOp, ex);
                    Diag.Fail(op, ex);
                    throw;
                }
            }
            Diag.End(op, $"files={uploaded} size={BytesToString(uploadSize)}");
            return uploadSize;
        }

        internal static string ExpectPrompt(ShellStream stream, Regex prompt, TimeSpan timeout, TextWriter log, string context)
        {
            string op = Diag.Begin($"wait {context} timeout={timeout.TotalSeconds}s");
            string output = stream.Expect(prompt, timeout);
            if (output == null)
            {
                log.Write(stream.Read());
                log.Flush();
                var ex = new TimeoutException($"Timed out after {timeout.TotalSeconds} seconds waiting for {context}.");
                Diag.Fail(op, ex);
                throw ex;
            }
            log.Write(output);
            log.Flush();
            Diag.End(op, output.Length + " chars");
            return output;
        }

        private static async Task ClientLoopAsync(string root, HostEntry host, List<string> commands)
        {
            string logFile = Path.Combine(root, host.Name, "log.txt");
            string backupPath = Path.Combine(root, host.Name, "backup");
            long backupSize = 0;
            long uploadSize = 0;
            Directory.CreateDirectory(Path.GetDirectoryName(logFile));
            string loopOp = Diag.Begin($"{host} host loop commands={commands.Count}");
            try
            {
            using (StreamWriter writer = File.CreateText(logFile))
            using (SshClient client = (SshClient)await ConnectAsync(root, host, true))
            using (ShellStream stream = client.CreateShellStream("xterm", 255, 50, 800, 600, 1024, null))
            using (SftpClient sftpClient = (SftpClient)await ConnectAsync(root, host, false))
            {
                ExpectPrompt(stream, host.IsWindows ? windowsPromptRegex : loginPromptRegex, connectionTimeout, writer, "the login prompt");
                if (!host.IsWindows)
                {
                    stream.Write("sudo -s\n");
                    // sudo may already be authenticated or configured for passwordless access.
                    string sudoOutput = ExpectPrompt(stream, sudoPromptRegex,
                        connectionTimeout, writer, "the sudo password or root prompt");
                    if (!rootPromptRegex.IsMatch(sudoOutput))
                    {
                        WriteSecure(password, stream);
                        ExpectPrompt(stream, rootPromptRegex, connectionTimeout, writer, "the root prompt");
                    }
                }
                foreach (string command in commands)
                {
                    writer.WriteLine(command);
                    Diag.Write($"{host} command {command}");
                    if (command.StartsWith('$'))
                    {
                        if (command.StartsWith("$backup ", StringComparison.OrdinalIgnoreCase))
                        {
                            backupSize += await BackupFolderAsync(host, backupPath, command.Substring(8), sftpClient, writer,
                                async () => (SftpClient)await ConnectAsync(root, host, false), downloadWorkers, client);
                        }
                        else if (command.StartsWith("$upload ", StringComparison.OrdinalIgnoreCase))
                        {
                            uploadSize += await UploadFolderAsync(host, command.Substring(8), sftpClient, writer);
                        }
                        else if (command.StartsWith("$ignore ", StringComparison.OrdinalIgnoreCase))
                        {
                            host.IgnoreRegex = new Regex(command.Substring(8), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Execute command {0}", command);
                        stream.Write(command);
                        stream.Write("\n");
                        ExpectPrompt(stream, host.IsWindows ? windowsPromptRegex : rootPromptRegex,
                            commandTimeout, writer, $"command completion on {host}: {command}");
                    }
                }
                writer.Write("logout\n");
            }
            Diag.End(loopOp, $"backup={BytesToString(backupSize)} upload={BytesToString(uploadSize)}");
            Console.WriteLine("{0} backed up {1}                      ", host, BytesToString(backupSize));
            Console.WriteLine("{0} uploaded {1}                      ", host, BytesToString(uploadSize));
            }
            catch (Exception ex)
            {
                Diag.Fail(loopOp, ex);
                throw;
            }
        }

        public static async Task Main(string[] args)
        {
            if (args.Length != 2)
            {
                throw new ArgumentException("Usage: AutoSSH [commands file] [backup folder]");
            }

            Console.WriteLine("Process started at {0}", DateTime.Now);
            Diag.Start();
            Console.WriteLine("Diagnostic log: {0}", Diag.Path);
            bytesDownloaded = 0;
            bytesUploaded = 0;
            bytesSkipped = 0;
            Stopwatch stopWatch = Stopwatch.StartNew();
            try
            {
            string commandFile = args.Length > 0 ? args[0] : null;
            string backupFolder = args.Length > 1 ? args[1] : null;
            Diag.Write("commands=" + commandFile);
            Diag.Write("backup=" + backupFolder);
            List<KeyValuePair<HostEntry, List<string>>> commands = Initialize(commandFile, backupFolder);
            Diag.Write("loaded " + commands.Count + " hosts: " + string.Join(", ", commands.Select(kv => kv.Key.ToString())));
            int heartbeatTicks = 0;
            using Timer updateTimer = new Timer(new TimerCallback((state) =>
            {
                Console.Write("Bytes downloaded: {0}, uploaded: {1}, skipped: {2}    \r",
                    BytesToString(Interlocked.Read(ref bytesDownloaded)), BytesToString(Interlocked.Read(ref bytesUploaded)), BytesToString(Interlocked.Read(ref bytesSkipped)));
                if (Interlocked.Increment(ref heartbeatTicks) % 20 == 0)
                {
                    Diag.Heartbeat();
                }
            }));

            // 4x second update rate
            updateTimer.Change(1, 250);
            using var hostGate = new SemaphoreSlim(hostWorkers);
            Task[] hostTasks = commands.Select(async kv =>
            {
                Diag.Write($"{kv.Key} waiting for host slot");
                await hostGate.WaitAsync();
                Diag.Write($"{kv.Key} acquired host slot");
                try
                {
                    await ClientLoopAsync(backupFolder, kv.Key, kv.Value);
                }
                catch (Exception ex)
                {
                    Diag.Write($"{kv.Key} host error {ex}");
                    Console.WriteLine("Error on host {0}: {1}\r\n", kv.Key.Host, ex);
                }
                finally
                {
                    Diag.Write($"{kv.Key} released host slot");
                    hostGate.Release();
                }
            }).ToArray();
            try
            {
                await Task.WhenAll(hostTasks);
            }
            finally
            {
                await updateTimer.DisposeAsync();
            }
            Diag.Heartbeat();
            Console.WriteLine("Bytes downloaded: {0}    ", BytesToString(bytesDownloaded));
            Console.WriteLine("Bytes uploaded: {0}   ", BytesToString(bytesUploaded));
            Console.WriteLine("Bytes skipped: {0}   ", BytesToString(bytesSkipped));
            Console.WriteLine("Process completed at {0}, total time: {1:0.00} minutes.", DateTime.Now, stopWatch.Elapsed.TotalMinutes);
            Diag.Write($"totals down={BytesToString(bytesDownloaded)} up={BytesToString(bytesUploaded)} skip={BytesToString(bytesSkipped)} elapsed={stopWatch.Elapsed.TotalMinutes:0.00}m");
            }
            catch (Exception ex)
            {
                Diag.Write("fatal " + ex);
                throw;
            }
            finally
            {
                Diag.Stop();
            }
        }
    }
}
