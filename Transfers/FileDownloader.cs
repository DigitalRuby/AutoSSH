using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet;
using Renci.SshNet.Common;

namespace AutoSSH
{
    /// <summary>Downloads one file to a temp file and only replaces the backup once the transfer completes.</summary>
    internal static class FileDownloader
    {
        internal static async Task<long> DownloadAsync(string root, BackupEntry file, ISftpClient client,
            CancellationToken cancellation)
        {
            string fileName = LocalFiles.BackupPath(root, file.FullName);
            long transferred = 0;
            bool committed = false;
            string op = DiagnosticLog.Begin($"download {file.FullName} {ByteSize.Format(file.Length)}");
            try
            {
                string tempFile = LocalFiles.TempPathFor(fileName);
                Directory.CreateDirectory(Path.GetDirectoryName(fileName));
                try
                {
                    long downloaded;
                    await using (FileStream stream = LocalFiles.OpenTransferStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        var progress = new TransferProgress(delta =>
                        {
                            Interlocked.Add(ref transferred, delta);
                            TransferStats.AddDownloaded(delta);
                        });
                        await client.DownloadFileAsync(file.FullName, stream, progress, cancellation);
                        await stream.FlushAsync(cancellation);
                        progress.Report((ulong)stream.Length);
                        downloaded = stream.Length;
                    }
                    // Listing/find size is a snapshot. Live json/sqlite/log files grow and shrink.
                    // SFTP reads until EOF, so a finished transfer is complete even if the size moved.
                    if (downloaded != file.Length)
                    {
                        DiagnosticLog.Write($"size changed during download {file.FullName} listed={file.Length} got={downloaded}");
                    }
                    File.SetLastWriteTimeUtc(tempFile, file.LastWriteTimeUtc);
                    File.Move(tempFile, fileName, overwrite: true);
                    committed = true;
                    DiagnosticLog.End(op, ByteSize.Format(downloaded));
                    return downloaded;
                }
                finally
                {
                    DeleteTempFile(tempFile);
                }
            }
            catch (SftpPathNotFoundException)
            {
                DiagnosticLog.End(op, "missing");
                return 0;
            }
            catch (SftpPermissionDeniedException)
            {
                DiagnosticLog.End(op, "denied");
                return 0;
            }
            catch (Exception ex) when (!RemoteFileLister.IsSessionFailure(ex))
            {
                Console.WriteLine("Error: {0}         ", ex.Message);
                DiagnosticLog.Fail(op, ex);
                return 0;
            }
            catch (Exception ex)
            {
                DiagnosticLog.Fail(op, ex);
                throw;
            }
            finally
            {
                if (!committed && transferred != 0)
                {
                    TransferStats.AddDownloaded(-transferred);
                }
            }
        }

        private static void DeleteTempFile(string tempFile)
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
}
