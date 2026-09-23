using System;
using System.Threading;

using Renci.SshNet;

namespace AutoSSH
{
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
}
