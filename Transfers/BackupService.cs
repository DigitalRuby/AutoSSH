using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet;

namespace AutoSSH
{
    internal static class BackupService
    {
        internal static async Task<long> BackupFileAsync(string root, string remotePath, ISftpClient client,
            CancellationToken cancellation = default)
        {
            var file = await RemoteFileLister.ReadRootAsync(client, remotePath, TextWriter.Null, cancellation);
            if (file == null || !file.IsRegularFile) return 0;
            if (LocalFiles.IsUpToDate(LocalFiles.BackupPath(root, remotePath), file.LastWriteTimeUtc))
            {
                TransferStats.AddSkipped(file.Length);
                return file.Length;
            }
            return await FileDownloader.DownloadAsync(root, file, client, cancellation);
        }

        internal static async Task<long> BackupFolderAsync(HostEntry host, string root, string path,
            ISftpClient client, TextWriter log, Func<Task<ISftpClient>> createDownloadClient = null, int workers = 4,
            SshClient ssh = null, int downloadsPerConnection = 1)
        {
            using var backup = new FolderBackup(host, root, path, client, log, createDownloadClient, workers,
                downloadsPerConnection, ssh);
            return await backup.RunAsync();
        }
    }
}
