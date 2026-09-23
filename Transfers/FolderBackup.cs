using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

using Renci.SshNet;

namespace AutoSSH
{
    /// <summary>
    /// One <c>$backup</c> run: lists remote files (via <c>find</c> on Linux, SFTP walking otherwise),
    /// skips unchanged files, and downloads the rest on independent SFTP sessions.
    /// </summary>
    internal sealed class FolderBackup : IDisposable
    {
        private readonly HostEntry host;
        private readonly string root;
        private readonly string path;
        private readonly ISftpClient client;
        private readonly TextWriter log;
        private readonly Func<Task<ISftpClient>> createDownloadClient;
        private readonly int workers;
        private readonly int downloadsPerConnection;
        private readonly SshClient ssh;
        private readonly CancellationTokenSource cancellation = new();
        private readonly HashSet<string> seen = new(StringComparer.Ordinal);
        private long size;
        private int queued;
        private int skipped;

        internal FolderBackup(HostEntry host, string root, string path, ISftpClient client, TextWriter log,
            Func<Task<ISftpClient>> createDownloadClient, int workers, int downloadsPerConnection, SshClient ssh)
        {
            if (workers < 1 || workers > AppSettings.MaxDownloadWorkers) throw new ArgumentOutOfRangeException(nameof(workers));
            if (downloadsPerConnection < 1 || downloadsPerConnection > AppSettings.MaxDownloadsPerConnection)
                throw new ArgumentOutOfRangeException(nameof(downloadsPerConnection));
            this.host = host;
            this.root = root;
            this.path = path;
            this.client = client;
            this.log = log;
            this.createDownloadClient = createDownloadClient;
            this.workers = workers;
            this.downloadsPerConnection = downloadsPerConnection;
            this.ssh = ssh;
        }

        public void Dispose() => cancellation.Dispose();

        internal async Task<long> RunAsync()
        {
            string op = DiagnosticLog.Begin($"{host} backup {path} workers={workers}x{downloadsPerConnection}");
            try
            {
                List<BackupEntry> found = await FindAsync();
                IAsyncEnumerable<BackupEntry> changed = ChangedFilesAsync(found);
                if (createDownloadClient == null || workers == 1)
                {
                    await DownloadSequentialAsync(changed);
                }
                else
                {
                    await DownloadParallelAsync(changed);
                }
                DiagnosticLog.End(op, $"queued={queued} skipped={skipped} size={ByteSize.Format(size)}");
                return Interlocked.Read(ref size);
            }
            catch (Exception ex)
            {
                DiagnosticLog.Fail(op, ex);
                throw;
            }
        }

        private async Task<List<BackupEntry>> FindAsync()
        {
            if (ssh == null || host.IsWindows) return null;
            List<BackupEntry> found = await RemoteFileLister.TryFindAsync(host, path, ssh, cancellation.Token);
            if (found == null)
            {
                DiagnosticLog.Write($"{host} falling back to SFTP directory walking");
            }
            return found;
        }

        private async IAsyncEnumerable<BackupEntry> ChangedFilesAsync(List<BackupEntry> found)
        {
            IAsyncEnumerable<BackupEntry> source = found != null
                ? found.ToAsyncEnumerable()
                : RemoteFileLister.WalkAsync(host, path, client, log, cancellation.Token);
            await foreach (var file in source)
            {
                if (!seen.Add(file.FullName)) continue;
                if (LocalFiles.IsUpToDate(LocalFiles.BackupPath(root, file.FullName), file.LastWriteTimeUtc))
                {
                    TransferStats.AddSkipped(file.Length);
                    Interlocked.Add(ref size, file.Length);
                    int n = Interlocked.Increment(ref skipped);
                    if (n == 1 || n % 200 == 0)
                    {
                        DiagnosticLog.Write($"{host} skipped {n} files (latest {file.FullName})");
                    }
                }
                else
                {
                    yield return file;
                }
            }
        }

        private void CountQueued(BackupEntry file)
        {
            int n = Interlocked.Increment(ref queued);
            if (n == 1 || n % 50 == 0)
            {
                DiagnosticLog.Write($"{host} queued {n} downloads (latest {file.FullName} {ByteSize.Format(file.Length)})");
            }
        }

        private async Task DownloadSequentialAsync(IAsyncEnumerable<BackupEntry> files)
        {
            await foreach (var file in files)
            {
                CountQueued(file);
                Interlocked.Add(ref size, await FileDownloader.DownloadAsync(root, file, client, cancellation.Token));
            }
        }

        private async Task DownloadParallelAsync(IAsyncEnumerable<BackupEntry> files)
        {
            var queue = Channel.CreateBounded<BackupEntry>(new BoundedChannelOptions(Math.Max(32, workers * downloadsPerConnection * 2))
            {
                SingleWriter = true,
                SingleReader = false,
                FullMode = BoundedChannelFullMode.Wait
            });
            var tasks = new List<Task> { ProduceAsync(files, queue.Writer) };
            tasks.AddRange(Enumerable.Range(0, workers).Select(_ => RunConnectionAsync(queue.Reader)));
            await WhenAllPreferSessionErrors(tasks);
        }

        private async Task ProduceAsync(IAsyncEnumerable<BackupEntry> files, ChannelWriter<BackupEntry> writer)
        {
            try
            {
                await foreach (var file in files)
                {
                    CountQueued(file);
                    var wait = Stopwatch.StartNew();
                    await writer.WriteAsync(file, cancellation.Token);
                    if (wait.ElapsedMilliseconds >= 500)
                    {
                        DiagnosticLog.Write($"{host} download queue blocked {wait.ElapsedMilliseconds}ms on {file.FullName}");
                    }
                }
                writer.TryComplete();
                DiagnosticLog.Write($"{host} scan complete queued={queued} skipped={skipped}");
            }
            catch (Exception ex)
            {
                writer.TryComplete(ex is OperationCanceledException ? null : ex);
                cancellation.Cancel();
                throw;
            }
        }

        // One download connection, opened on first use and shared by its concurrent downloaders.
        private async Task RunConnectionAsync(ChannelReader<BackupEntry> reader)
        {
            var connectGate = new object();
            Task<ISftpClient> connect = null;
            Task<ISftpClient> GetClient()
            {
                lock (connectGate)
                {
                    return connect ??= createDownloadClient();
                }
            }
            try
            {
                await WhenAllPreferSessionErrors(Enumerable.Range(0, downloadsPerConnection)
                    .Select(_ => ConsumeAsync(reader, GetClient)).ToArray());
            }
            finally
            {
                if (connect is { IsCompletedSuccessfully: true })
                {
                    connect.Result.Dispose();
                }
            }
        }

        private async Task ConsumeAsync(ChannelReader<BackupEntry> reader, Func<Task<ISftpClient>> getClient)
        {
            await foreach (var file in reader.ReadAllAsync(cancellation.Token))
            {
                try
                {
                    ISftpClient downloadClient = await getClient();
                    Interlocked.Add(ref size,
                        await FileDownloader.DownloadAsync(root, file, downloadClient, cancellation.Token));
                }
                catch
                {
                    cancellation.Cancel();
                    throw;
                }
            }
        }

        // Cancelled siblings fault with OperationCanceledException; surface the real session error instead.
        private static async Task WhenAllPreferSessionErrors(IReadOnlyCollection<Task> tasks)
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
    }
}
