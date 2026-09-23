using System;

namespace AutoSSH
{
    internal sealed record BackupEntry(string FullName, string Name, bool IsRegularFile,
        bool IsDirectory, long Length, DateTime LastWriteTimeUtc);
}
