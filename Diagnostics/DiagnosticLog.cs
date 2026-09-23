using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace AutoSSH
{
    internal static class DiagnosticLog
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
            Write($"hosts={AppSettings.HostWorkers} downloadWorkers={AppSettings.DownloadWorkers} " +
                $"downloadsPerConnection={AppSettings.DownloadsPerConnection} " +
                $"sftpTimeout={AppSettings.OperationTimeout.TotalSeconds}s commandTimeout={AppSettings.CommandTimeout.TotalSeconds}s");
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
            if (inflight.TryRemove(key, out var entry))
            {
                Write($"END   [{key}] {entry.Op} {Stopwatch.GetElapsedTime(entry.Start).TotalMilliseconds:0}ms{suffix}");
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
            var ops = inflight.Values
                .Select(op => $"{op.Op} ({Stopwatch.GetElapsedTime(op.Start).TotalSeconds:0.0}s)")
                .OrderByDescending(s => s)
                .ToArray();
            Write($"HEART {TransferStats.Summary()} inflight={ops.Length}");
            foreach (string op in ops)
            {
                Write("  ... " + op);
            }
        }
    }
}
