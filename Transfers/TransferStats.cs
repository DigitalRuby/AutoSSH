using System.Threading;

namespace AutoSSH
{
    internal static class TransferStats
    {
        private static long downloaded;
        private static long uploaded;
        private static long skipped;

        internal static long Downloaded => Interlocked.Read(ref downloaded);
        internal static long Uploaded => Interlocked.Read(ref uploaded);
        internal static long Skipped => Interlocked.Read(ref skipped);

        internal static void AddDownloaded(long bytes) => Interlocked.Add(ref downloaded, bytes);
        internal static void AddUploaded(long bytes) => Interlocked.Add(ref uploaded, bytes);
        internal static void AddSkipped(long bytes) => Interlocked.Add(ref skipped, bytes);

        internal static void Reset()
        {
            Interlocked.Exchange(ref downloaded, 0);
            Interlocked.Exchange(ref uploaded, 0);
            Interlocked.Exchange(ref skipped, 0);
        }

        internal static string Summary() =>
            $"down={ByteSize.Format(Downloaded)} up={ByteSize.Format(Uploaded)} skip={ByteSize.Format(Skipped)}";
    }
}
