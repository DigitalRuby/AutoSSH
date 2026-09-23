using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace AutoSSH
{
    internal static class CommandFileParser
    {
        private static readonly Regex replacerRegex = new(@"(?<name>\$[^\$]+\$)\s*=\s*(?<value>.+)",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

        internal static List<HostCommands> Parse(string commandFile)
        {
            var commands = new List<HostCommands>();
            var lines = new List<string>();
            var inheritedLines = new List<string>();
            HostEntry currentEntry = null;
            int lineIndex = 0;
            var replacers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (string line in File.ReadAllLines(commandFile))
            {
                // clean and trim
                string cleanedLine = line.Trim();
                int pos = cleanedLine.IndexOf('#');
                if (pos >= 0)
                {
                    cleanedLine = cleanedLine.Substring(0, pos).Trim();
                }

                // replace any find and replace directives
                foreach (var kv in replacers)
                {
                    cleanedLine = cleanedLine.Replace(kv.Key, kv.Value, StringComparison.OrdinalIgnoreCase);
                }

                // look for defines ($...$=value)
                Match replacer = replacerRegex.Match(cleanedLine);
                if (replacer.Success)
                {
                    replacers[replacer.Groups["name"].Value] = replacer.Groups["value"].Value;
                    continue;
                }

                bool isHostLine = cleanedLine.StartsWith("$host", StringComparison.OrdinalIgnoreCase);
                if (currentEntry != null && (cleanedLine.Length == 0 || isHostLine) && !IsGlobal(currentEntry))
                {
                    lines.AddRange(inheritedLines);
                    commands.Add(new HostCommands(currentEntry, lines));
                    lines = new List<string>();
                    currentEntry = null;
                }
                if (isHostLine)
                {
                    currentEntry = ParseHostLine(cleanedLine, lineIndex);
                    if (IsGlobal(currentEntry))
                    {
                        inheritedLines.Clear();
                    }
                }
                else if (cleanedLine.Length != 0)
                {
                    if (currentEntry == null)
                    {
                        throw new InvalidOperationException("Must define a $host before commands, line: " + lineIndex);
                    }
                    (IsGlobal(currentEntry) ? inheritedLines : lines).Add(cleanedLine);
                }
                lineIndex++;
            }
            lines.AddRange(inheritedLines);
            if (currentEntry != null && lines.Count != 0)
            {
                commands.Add(new HostCommands(currentEntry, lines));
            }
            return commands;
        }

        private static bool IsGlobal(HostEntry entry) => entry.Name == "*" && entry.Host == "*";

        private static HostEntry ParseHostLine(string line, int lineIndex)
        {
            string[] pieces = line.Split(' ');
            if (pieces.Length < 3)
            {
                throw new InvalidOperationException("Host line format is $host name dns_or_address, line: " + lineIndex);
            }
            if (pieces[1] == "*" && pieces[2] == "*")
            {
                return new HostEntry { Name = "*", Host = "*" };
            }
            return new HostEntry
            {
                Name = pieces[1],
                Host = pieces[2],
                IsWindows = pieces.Length >= 4 && pieces[3].Equals("windows", StringComparison.OrdinalIgnoreCase)
            };
        }
    }
}
