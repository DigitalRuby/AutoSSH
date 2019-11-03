#region Imports

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;

using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

#endregion Imports

namespace AutoSSH
{
    public static class AutoSSHApp
    {
        private class HostEntry
        {
            public string Host { get; set; }
            public string Name { get; set; }
            public bool IsWindows { get; set; }
            public Regex IgnoreRegex { get; set; }

            public override string ToString()
            {
                return Name + " : " + Host;
            }
        }

        private static readonly ParallelOptions parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = 16 };
        private static readonly ParallelOptions parallelOptions2 = new ParallelOptions { MaxDegreeOfParallelism = 4 };
        private static SecureString userName;
        private static SecureString password;
        private static long bytesDownloaded;
        private static long bytesSkipped;

        private static void WriteSecure(SecureString secureString, ShellStream writer)
        {
            IntPtr unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                byte[] buf = new byte[2];
                for (int i = 0; i < secureString.Length * 2; )
                {
                    buf[0] = Marshal.ReadByte(unmanagedString, i++);
                    buf[1] = Marshal.ReadByte(unmanagedString, i++);
                    writer.Write(BitConverter.ToChar(buf).ToString());
                }
                writer.Write("\n");
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        private static string SecureStringToString(SecureString secureString)
        {
            StringBuilder b = new StringBuilder();
            IntPtr unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                byte[] buf = new byte[2];
                for (int i = 0; i < secureString.Length * 2;)
                {
                    buf[0] = Marshal.ReadByte(unmanagedString, i++);
                    buf[1] = Marshal.ReadByte(unmanagedString, i++);
                    b.Append(BitConverter.ToChar(buf));
                }
                return b.ToString();
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        private static void SecureStringFromString(ref SecureString secureString, string text)
        {
            secureString = new SecureString();
            foreach (char c in text)
            {
                secureString.AppendChar(c);
            }
        }

        private static List<KeyValuePair<HostEntry, List<string>>> LoadCommands(string commandFile)
        {
            List<KeyValuePair<HostEntry, List<string>>> commands = new List<KeyValuePair<HostEntry, List<string>>>();
            List<string> lines = new List<string>();
            List<string> inheritedLines = new List<string>();
            HostEntry currentEntry = null;
            string cleanedLine;
            bool isHostLine = false;
            int lineIndex = 0;
            foreach (string line in File.ReadAllLines(commandFile))
            {
                cleanedLine = line.Trim();
                int pos = cleanedLine.IndexOf('#');
                if (pos >= 0)
                {
                    cleanedLine = cleanedLine.Substring(0, pos).Trim();
                }
                isHostLine = cleanedLine.StartsWith("$host", StringComparison.OrdinalIgnoreCase);
                if (currentEntry != null && (cleanedLine.Length == 0 || isHostLine))
                {
                    if (currentEntry.Name != "*" && currentEntry.Host != "*")
                    {
                        lines.AddRange(inheritedLines);
                        commands.Add(new KeyValuePair<HostEntry, List<string>>(currentEntry, lines));
                        lines = new List<string>();
                        currentEntry = null;
                    }
                }
                if (isHostLine)
                {
                    string[] pieces = cleanedLine.Split(' ');
                    if (pieces.Length < 3)
                    {
                        throw new InvalidOperationException("Host line format is $host name dns_or_address, line: " + lineIndex);
                    }
                    if (pieces[1] == "*" && pieces[2] == "*")
                    {
                        currentEntry = new HostEntry { Name = "*", Host = "*" };
                        inheritedLines.Clear();
                    }
                    else
                    {
                        currentEntry = new HostEntry { Name = pieces[1], Host = pieces[2],
                            IsWindows = (pieces.Length < 4 ? false : pieces[3].Equals("windows", StringComparison.OrdinalIgnoreCase)) };
                    }
                }
                else if (cleanedLine.Length != 0)
                {
                    if (currentEntry == null)
                    {
                        throw new InvalidOperationException("Must define a $host before commands, line: " + lineIndex);
                    }
                    else if (currentEntry.Name == "*" && currentEntry.Host == "*")
                    {
                        inheritedLines.Add(cleanedLine);
                    }
                    else
                    {
                        lines.Add(cleanedLine);
                    }
                }
                lineIndex++;
            }
            lines.AddRange(inheritedLines);
            if (currentEntry != null && lines.Count != 0)
            {
                commands.Add(new KeyValuePair<HostEntry, List<string>>(currentEntry, lines));
            }
            return commands;
        }

        private static List<KeyValuePair<HostEntry, List<string>>> Initialize(string commandFile, string root)
        {
            string loginPath = Path.Combine(root, "login.key");
            if (!File.Exists(loginPath))
            {
                Console.Write("Enter user name: ");
                string userName = Console.ReadLine();
                Console.Write("Enter password: ");
                string password = string.Empty;
                while (true)
                {
                    ConsoleKeyInfo key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter)
                    {
                        Console.WriteLine();
                        break;
                    }
                    else
                    {
                        password += key.KeyChar;
                    }
                }
                byte[] bytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(userName + "|" + password), null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(loginPath, bytes);
            }
            if (!File.Exists(loginPath))
            {
                throw new FileNotFoundException("Missing login.key file");
            }
            {
                byte[] protectedBytes = File.ReadAllBytes(loginPath);
                string unprotectedBytes = Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser));
                int pos = unprotectedBytes.IndexOf('|');
                if (pos < 0)
                {
                    throw new ArgumentException("Corrupted login.key file, delete and restart");
                }
                SecureStringFromString(ref userName, unprotectedBytes.Substring(0, pos));
                SecureStringFromString(ref password, unprotectedBytes.Substring(++pos));
                protectedBytes = null;
                unprotectedBytes = null;
                GC.Collect();
            }

            return LoadCommands(commandFile);
        }

        private static T Connect<T>(string root, HostEntry host) where T : BaseClient
        {
            Console.WriteLine("Connecting to {0} with type {1}", host, typeof(T).Name);
            root = Path.Combine(root, host.Name);
            Directory.CreateDirectory(root);
            MemoryStream finger = new MemoryStream();
            bool hasFinger = false;
            string fingerFile = Path.Combine(root, "finger.key");
            if (File.Exists(fingerFile))
            {
                hasFinger = true;
                using (Stream fs = File.OpenRead(fingerFile))
                {
                    fs.CopyTo(finger);
                }
            }
            T client = Activator.CreateInstance(typeof(T), new object[] { host.Host, SecureStringToString(userName), SecureStringToString(password) }) as T;
            bool fingerMatch = true;
            client.HostKeyReceived += (sender, e) =>
            {
                if (hasFinger)
                {
                    if (!e.FingerPrint.SequenceEqual(finger.GetBuffer().AsSpan(0, e.FingerPrint.Length).ToArray()))
                    {
                        e.CanTrust = false;
                        fingerMatch = false;
                    }
                }
                else
                {
                    finger.Write(e.FingerPrint);
                    File.WriteAllBytes(fingerFile, e.FingerPrint);
                }
            };
            client.Connect();
            if (!client.IsConnected || !client.ConnectionInfo.IsAuthenticated)
            {
                Console.WriteLine("Failed to connect, finger match: {0}", fingerMatch);
                return null;
            }
            GC.Collect();
            return client;
        }

        private static string BytesToString(long byteCount)
        {
            string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
            if (byteCount == 0)
                return "0" + suf[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 2);
            return (Math.Sign(byteCount) * num).ToString() + suf[place];
        }

        private static long BackupFile(string root, string remotePath, SftpClient client)
        {
            string name = Path.GetFileName(remotePath);

            // trim rooted paths, including drive letters
            string localPath = Regex.Replace(remotePath, @"^\/[A-Za-z]\:[/\\]", string.Empty).Trim('/', '\\');
            string fileName = Path.Combine(root, localPath);

            try
            {
                SftpFile file = client.Get(remotePath);
                Directory.CreateDirectory(Path.GetDirectoryName(fileName));
                if (!File.Exists(fileName) || file.LastWriteTimeUtc > File.GetLastWriteTimeUtc(fileName))
                {
                    string tempFile = fileName + ".__TEMP__";
                    using (FileStream stream = File.Create(tempFile))
                    {
                        long prevProgress = 0;
                        client.DownloadFile(remotePath, stream, (progress) =>
                        {
                            Interlocked.Add(ref bytesDownloaded, ((long)progress - prevProgress));
                            prevProgress = (long)progress;
                        });
                    }
                    if (File.Exists(tempFile) && new FileInfo(tempFile).Length == file.Length)
                    {
                        if (File.Exists(fileName))
                        {
                            File.Delete(fileName);
                        }
                        File.Move(tempFile, fileName);
                        File.SetLastWriteTimeUtc(fileName, file.LastWriteTimeUtc);
                    }
                }
                else
                {
                    Interlocked.Add(ref bytesSkipped, file.Length);
                }
                return file.Length;
            }
            catch (SftpPathNotFoundException)
            {
                // OK
            }
            catch (SftpPermissionDeniedException)
            {
                // OK
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}         ", ex.Message);
            }
            return 0;
        }

        private static long BackupFolder(HostEntry host, string root, string path, SftpClient client, StreamWriter log)
        {
            long size = 0;
            foreach (string fileOrFolder in path.Split('|').Select(s => s.Trim()).Where(s => s.Length != 0))
            {
                SftpFile file;
                try
                {
                    file = client.Get(fileOrFolder);
                }
                catch (SftpPathNotFoundException)
                {
                    continue;
                }
                catch (Exception ex)
                {
                    log.WriteLine("Error backing up folder {0}: {1}", fileOrFolder, ex);
                    continue;
                }
                if (file.IsRegularFile)
                {
                    Interlocked.Add(ref size, BackupFile(root, file.FullName, client));
                }
                else
                {
                    try
                    {
                        SftpFile[] files = client.ListDirectory(fileOrFolder).Where(f => f.IsRegularFile || (f.IsDirectory && !f.Name.StartsWith("."))).ToArray();
                        Parallel.ForEach(files.Where(f => f.IsRegularFile && (host.IgnoreRegex == null || !host.IgnoreRegex.IsMatch(f.FullName))), parallelOptions, (_file) =>
                        {
                            Interlocked.Add(ref size, BackupFile(root, _file.FullName, client));
                        });
                        Parallel.ForEach(files.Where(f => f.IsDirectory), parallelOptions2, (folder) =>
                        {
                            Interlocked.Add(ref size, BackupFolder(host, root, folder.FullName, client, log));
                        });
                    }
                    catch (Exception ex)
                    {
                        log.WriteLine("Failed to backup file or folder {0}, error: {1}", fileOrFolder, ex.Message);
                    }
                }
            }
            return size;
        }

        private static void ClientLoop(string root, HostEntry host, List<string> commands)
        {
            bytesDownloaded = 0;
            string logFile = Path.Combine(root, host.Name, "log.txt");
            string backupPath = Path.Combine(root, host.Name, "backup");
            long backupSize = 0;
            Directory.CreateDirectory(Path.GetDirectoryName(logFile));
            Regex promptRegex = new Regex(@"[$>]");
            //Regex userRegex = new Regex(@"[$>]");
            //Regex passwordRegex = new Regex(@"([$#>:])");
            using (StreamWriter writer = File.CreateText(logFile))
            using (SshClient client = Connect<SshClient>(root, host))
            using (ShellStream stream = client.CreateShellStream("xterm", 255, 50, 800, 600, 1024, null))
            using (SftpClient sftpClient = Connect<SftpClient>(root, host))
            {
                if (host.IsWindows)
                {
                    stream.Expect(">");
                    while (stream.DataAvailable)
                    {
                        writer.Write(stream.Read());
                    }
                }
                else
                {
                    stream.Expect(promptRegex);
                    while (stream.DataAvailable)
                    {
                        writer.Write(stream.Read());
                    }
                    stream.Write("sudo -s\n");
                    stream.Expect("password");
                    WriteSecure(password, stream);
                    stream.Expect("#");
                    while (stream.DataAvailable)
                    {
                        writer.Write(stream.Read());
                    }
                }
                foreach (string command in commands)
                {
                    writer.WriteLine(command);
                    if (command.StartsWith('$'))
                    {
                        if (command.StartsWith("$backup ", StringComparison.OrdinalIgnoreCase))
                        {
                            backupSize += BackupFolder(host, backupPath, command.Substring(8), sftpClient, writer);
                        }
                        else if (command.StartsWith("$ignore ", StringComparison.OrdinalIgnoreCase))
                        {
                            host.IgnoreRegex = new Regex(command.Substring(8), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Execute command {0}", command);
                        stream.Write(command);
                        stream.Write("\n");
                        if (host.IsWindows)
                        {
                            stream.Expect(">");
                        }
                        else
                        {
                            stream.Expect("#");
                        }
                        while (stream.DataAvailable)
                        {
                            writer.Write(stream.Read());
                        }
                    }
                }
                writer.Write("logout\n");
            }
            Console.WriteLine("{0} backed up {1}                         ", host, BytesToString(backupSize));
        }

        public static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                throw new ArgumentException("Usage: AutoSSH [commands file] [backup folder]");
            }

            Console.WriteLine("Process started at {0}", DateTime.Now);
            Stopwatch stopWatch = Stopwatch.StartNew();
            string commandFile = args[0];
            string backupFolder = args[1];
            List<KeyValuePair<HostEntry, List<string>>> commands = Initialize(commandFile, backupFolder);
            Timer updateTimer = new Timer(new TimerCallback((state) =>
            {
                Console.Write("Bytes downloaded: {0}, skipped: {1}    \r", BytesToString(bytesDownloaded), BytesToString(bytesSkipped));
            }));

            // 10x second update rate
            updateTimer.Change(1, 100);
            Parallel.ForEach(commands, (kv) =>
            {
                ClientLoop(backupFolder, kv.Key, kv.Value);
            });
            Console.WriteLine("Bytes downloaded: {0}, skipped: {1}    ", BytesToString(bytesDownloaded), BytesToString(bytesSkipped));
            Console.WriteLine("Process completed at {0}, total time: {1:0.00} minutes.", DateTime.Now, stopWatch.Elapsed.TotalMinutes);
        }
    }
}
