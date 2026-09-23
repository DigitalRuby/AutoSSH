using System;

namespace AutoSSH
{
    internal static class ByteSize
    {
        private static readonly string[] suffixes = { "B", "KB", "MB", "GB", "TB", "PB", "EB" };

        internal static string Format(long byteCount)
        {
            if (byteCount == 0)
                return "0" + suffixes[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 2);
            return (Math.Sign(byteCount) * num).ToString() + suffixes[place];
        }
    }
}
