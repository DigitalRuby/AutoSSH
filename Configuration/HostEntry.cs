using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace AutoSSH
{
    internal sealed class HostEntry
    {
        public string Host { get; set; }
        public string Name { get; set; }
        public bool IsWindows { get; set; }
        public Regex IgnoreRegex { get; set; }

        public bool IsIgnored(string path) => IgnoreRegex != null && IgnoreRegex.IsMatch(path);

        public override string ToString()
        {
            return Name + " : " + Host;
        }
    }

    internal sealed record HostCommands(HostEntry Host, List<string> Commands);
}
