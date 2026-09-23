using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet;
using Renci.SshNet.Common;

namespace AutoSSH
{
    internal static class UploadService
    {
        internal static async Task<long> UploadFolderAsync(HostEntry host, string pathInfo, ISftpClient client,
            TextWriter log, CancellationToken cancellation = default)
        {
            string[] paths = pathInfo.Split(';', 2);
            if (paths.Length != 2 || string.IsNullOrWhiteSpace(paths[0]) || string.IsNullOrWhiteSpace(paths[1]))
            {
                throw new ArgumentException("Upload format is $upload local_folder;remote_folder.");
            }
            string localDir = Path.GetFullPath(paths[0].Trim());
            string remoteFolder = paths[1].Trim().Replace('\\', '/').TrimEnd('/');
            var existingDirectories = new HashSet<string>(StringComparer.Ordinal);
            string op = DiagnosticLog.Begin($"{host} upload {localDir} -> {remoteFolder}");
            long uploadSize = 0;
            int uploaded = 0;
            foreach (string file in Directory.EnumerateFiles(localDir, "*", SearchOption.AllDirectories))
            {
                if (host.IsIgnored(file))
                {
                    continue;
                }

                string relativePath = Path.GetRelativePath(localDir, file).Replace('\\', '/');
                string remoteFile = remoteFolder + "/" + relativePath;
                string remoteDir = remoteFile.Substring(0, remoteFile.LastIndexOf('/'));
                string fileOp = DiagnosticLog.Begin($"upload {file} -> {remoteFile}");
                try
                {
                    await EnsureRemoteDirectoryAsync(client, remoteDir, existingDirectories, cancellation);
                    await using var localStream = LocalFiles.OpenTransferStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
                    var progress = new TransferProgress(TransferStats.AddUploaded);
                    await client.UploadFileAsync(localStream, remoteFile, true, progress, cancellation);
                    progress.Report((ulong)localStream.Length);
                    uploadSize += localStream.Length;
                    uploaded++;
                    DiagnosticLog.End(fileOp, ByteSize.Format(localStream.Length));
                }
                catch (Exception ex) when (ex is SftpPermissionDeniedException || ex is SftpPathNotFoundException)
                {
                    DiagnosticLog.Fail(fileOp, ex);
                    log.WriteLine("Error uploading file {0} to {1}: {2}", file, remoteFile, ex.Message);
                }
                catch (Exception ex) when (!RemoteFileLister.IsSessionFailure(ex))
                {
                    DiagnosticLog.Fail(fileOp, ex);
                    log.WriteLine("Error uploading file {0} to {1}: {2}", file, remoteFile, ex);
                }
                catch (Exception ex)
                {
                    DiagnosticLog.Fail(fileOp, ex);
                    DiagnosticLog.Fail(op, ex);
                    throw;
                }
            }
            DiagnosticLog.End(op, $"files={uploaded} size={ByteSize.Format(uploadSize)}");
            return uploadSize;
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
    }
}
