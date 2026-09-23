using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet;
using Renci.SshNet.Common;

namespace AutoSSH
{
    internal static class RemoteFileLister
    {
        internal static string[] SplitRoots(string path) =>
            path.Split('|').Select(s => s.Trim()).Where(s => s.Length != 0).ToArray();

        internal static async Task<BackupEntry> ReadRootAsync(ISftpClient client, string path,
            TextWriter log, CancellationToken cancellation)
        {
            try
            {
                var attributes = await client.GetAttributesAsync(path, cancellation);
                return new BackupEntry(path, Path.GetFileName(path.TrimEnd('/', '\\')),
                    attributes.IsRegularFile, attributes.IsDirectory, attributes.Size, attributes.LastWriteTimeUtc);
            }
            catch (SftpPathNotFoundException)
            {
                DiagnosticLog.Write("stat missing " + path);
            }
            catch (SftpPermissionDeniedException ex)
            {
                log.WriteLine("Error backing up {0}: {1}", path, ex.Message);
            }
            catch (Exception ex) when (!IsSessionFailure(ex))
            {
                log.WriteLine("Error backing up {0}: {1}", path, ex);
            }
            return null;
        }

        /// <summary>Lists files with one remote <c>find</c>; returns null when find is unusable.</summary>
        internal static async Task<List<BackupEntry>> TryFindAsync(HostEntry host, string path,
            SshClient ssh, CancellationToken cancellation)
        {
            string[] roots = SplitRoots(path);
            if (roots.Length == 0) return new List<BackupEntry>();
            string command = "find " + string.Join(" ", roots.Select(QuoteUnix)) +
                " -name '.*' -type d -prune -o -type f -printf '%T@\\t%s\\t%p\\n'";
            string op = DiagnosticLog.Begin($"{host} find {path}");
            try
            {
                using SshCommand cmd = ssh.CreateCommand(command);
                cmd.CommandTimeout = AppSettings.CommandTimeout;
                await cmd.ExecuteAsync(cancellation);
                string error = cmd.Error ?? string.Empty;
                if (error.Contains("unknown predicate", StringComparison.OrdinalIgnoreCase) ||
                    error.Contains("illegal option", StringComparison.OrdinalIgnoreCase) ||
                    error.Contains("unrecognized", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticLog.End(op, "unsupported find, fallback to SFTP");
                    return null;
                }
                var files = new List<BackupEntry>();
                using var reader = new StringReader(cmd.Result ?? string.Empty);
                for (string line = reader.ReadLine(); line != null; line = reader.ReadLine())
                {
                    if (TryParseFindLine(line, out BackupEntry file) && !host.IsIgnored(file.FullName))
                    {
                        files.Add(file);
                    }
                }
                DiagnosticLog.End(op, $"{files.Count} files exit={cmd.ExitStatus}");
                return files;
            }
            catch (Exception ex)
            {
                DiagnosticLog.Fail(op, ex);
                return null;
            }
        }

        /// <summary>Walks directories over SFTP, skipping hidden folders and ignored paths.</summary>
        internal static async IAsyncEnumerable<BackupEntry> WalkAsync(HostEntry host, string path,
            ISftpClient client, TextWriter log, [EnumeratorCancellation] CancellationToken cancellation)
        {
            foreach (string root in SplitRoots(path))
            {
                cancellation.ThrowIfCancellationRequested();
                var rootEntry = await ReadRootAsync(client, root, log, cancellation);
                if (rootEntry == null) continue;
                var pending = new Stack<BackupEntry>();
                pending.Push(rootEntry);
                while (pending.Count != 0)
                {
                    cancellation.ThrowIfCancellationRequested();
                    var entry = pending.Pop();
                    if (entry.IsRegularFile)
                    {
                        yield return entry;
                    }
                    else if (entry.IsDirectory)
                    {
                        foreach (var child in await ReadDirectoryAsync(client, entry.FullName, log, cancellation))
                        {
                            if ((child.IsRegularFile || (child.IsDirectory && !child.Name.StartsWith("."))) &&
                                !host.IsIgnored(child.FullName))
                            {
                                pending.Push(child);
                            }
                        }
                    }
                }
            }
        }

        internal static bool IsSessionFailure(Exception ex) =>
            ex is SshException || ex is TimeoutException || ex is OperationCanceledException;

        private static async Task<List<BackupEntry>> ReadDirectoryAsync(ISftpClient client, string path,
            TextWriter log, CancellationToken cancellation)
        {
            var entries = new List<BackupEntry>();
            string op = DiagnosticLog.Begin("list " + path);
            try
            {
                await foreach (var file in client.ListDirectoryAsync(path, cancellation))
                {
                    entries.Add(new BackupEntry(file.FullName, file.Name, file.IsRegularFile,
                        file.IsDirectory, file.Length, file.LastWriteTimeUtc));
                }
                DiagnosticLog.End(op, entries.Count + " entries");
            }
            catch (SftpPathNotFoundException)
            {
                DiagnosticLog.End(op, "missing");
            }
            catch (SftpPermissionDeniedException ex)
            {
                DiagnosticLog.Fail(op, ex);
                log.WriteLine("Error backing up {0}: {1}", path, ex.Message);
            }
            catch (Exception ex) when (!IsSessionFailure(ex))
            {
                DiagnosticLog.Fail(op, ex);
                log.WriteLine("Error backing up {0}: {1}", path, ex);
            }
            catch (Exception ex)
            {
                DiagnosticLog.Fail(op, ex);
                throw;
            }
            return entries;
        }

        private static bool TryParseFindLine(string line, out BackupEntry file)
        {
            file = null;
            int tab1 = line.IndexOf('\t');
            int tab2 = tab1 < 0 ? -1 : line.IndexOf('\t', tab1 + 1);
            if (tab2 < 0) return false;
            if (!double.TryParse(line.AsSpan(0, tab1), NumberStyles.Float, CultureInfo.InvariantCulture, out double unix)) return false;
            if (!long.TryParse(line.AsSpan(tab1 + 1, tab2 - tab1 - 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out long size)) return false;
            string fullName = line[(tab2 + 1)..];
            if (fullName.Length == 0) return false;
            string name = fullName[(fullName.LastIndexOf('/') + 1)..];
            file = new BackupEntry(fullName, name, true, false, size, DateTime.UnixEpoch.AddSeconds(unix));
            return true;
        }

        private static string QuoteUnix(string value) => "'" + value.Replace("'", "'\\''") + "'";
    }
}
