using System;
using System.IO;
using System.Text.RegularExpressions;

namespace AutoSSH
{
    internal static class LocalFiles
    {
        private static readonly Regex windowsDrivePrefixRegex = new(@"^\/[A-Za-z]\:[/\\]", RegexOptions.Compiled);

        internal static string BackupPath(string root, string remotePath)
        {
            // trim rooted paths, including drive letters
            string localPath = windowsDrivePrefixRegex.Replace(remotePath, string.Empty).Trim('/', '\\');
            return Path.Combine(root, localPath);
        }

        // Whole seconds: remote listings may carry sub-second times the local file system can't store.
        internal static bool IsUpToDate(string localFile, DateTime remoteWriteTimeUtc) =>
            File.Exists(localFile) &&
            WholeSeconds(remoteWriteTimeUtc) <= WholeSeconds(File.GetLastWriteTimeUtc(localFile));

        internal static FileStream OpenTransferStream(string path, FileMode mode, FileAccess access, FileShare share) =>
            new(path, mode, access, share, AppSettings.TransferBufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

        internal static string TempPathFor(string fileName) =>
            fileName + "." + Guid.NewGuid().ToString("N") + ".__TEMP__";

        private static long WholeSeconds(DateTime time) => time.Ticks / TimeSpan.TicksPerSecond;
    }
}
