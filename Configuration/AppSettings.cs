using System;

namespace AutoSSH
{
    internal static class AppSettings
    {
        internal const int MaxDownloadWorkers = 16;
        internal const int MaxDownloadsPerConnection = 64;
        internal const int TransferBufferSize = 128 * 1024;
        // Bytes in flight per TCP connection; SSH.NET's fixed default (134KB) caps a 175ms link near 0.75MB/s.
        internal const int SocketBufferSize = 10 * 1024 * 1024;
        internal const uint SftpBufferSize = 64 * 1024;

        // Each host owns its clients. Small files cost several round trips each, so each download
        // connection keeps multiple requests in flight; SSH.NET matches SFTP replies by request id.
        internal static readonly int HostWorkers = GetWorkerCount("AUTOSSH_HOST_WORKERS", 8, 64);
        internal static readonly int DownloadWorkers = GetWorkerCount("AUTOSSH_DOWNLOAD_WORKERS", 8, MaxDownloadWorkers);
        internal static readonly int DownloadsPerConnection = GetWorkerCount("AUTOSSH_DOWNLOADS_PER_CONNECTION", 8, MaxDownloadsPerConnection);
        internal static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(30);
        internal static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(15);
        internal static readonly TimeSpan OperationTimeout = GetTimeout("AUTOSSH_SFTP_TIMEOUT_SECONDS", 60);
        internal static readonly TimeSpan CommandTimeout = GetTimeout("AUTOSSH_COMMAND_TIMEOUT_SECONDS", 1800);

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
    }
}
