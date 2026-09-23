using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AutoSSH
{
    public static class AutoSSHApp
    {
        public static async Task Main(string[] args)
        {
            if (args.Length != 2)
            {
                throw new ArgumentException("Usage: AutoSSH [commands file] [backup folder]");
            }

            Console.WriteLine("Process started at {0}", DateTime.Now);
            DiagnosticLog.Start();
            Console.WriteLine("Diagnostic log: {0}", DiagnosticLog.Path);
            TransferStats.Reset();
            Stopwatch stopWatch = Stopwatch.StartNew();
            try
            {
                string commandFile = args[0];
                string backupFolder = args[1];
                DiagnosticLog.Write("commands=" + commandFile);
                DiagnosticLog.Write("backup=" + backupFolder);
                var credentials = Credentials.LoadOrPrompt(backupFolder);
                List<HostCommands> jobs = CommandFileParser.Parse(commandFile);
                DiagnosticLog.Write("loaded " + jobs.Count + " hosts: " + string.Join(", ", jobs.Select(job => job.Host.ToString())));

                await using (StartProgressTimer())
                {
                    await RunHostsAsync(new HostRunner(backupFolder, credentials), jobs);
                }

                DiagnosticLog.Heartbeat();
                Console.WriteLine("Bytes downloaded: {0}    ", ByteSize.Format(TransferStats.Downloaded));
                Console.WriteLine("Bytes uploaded: {0}   ", ByteSize.Format(TransferStats.Uploaded));
                Console.WriteLine("Bytes skipped: {0}   ", ByteSize.Format(TransferStats.Skipped));
                Console.WriteLine("Process completed at {0}, total time: {1:0.00} minutes.", DateTime.Now, stopWatch.Elapsed.TotalMinutes);
                DiagnosticLog.Write($"totals {TransferStats.Summary()} elapsed={stopWatch.Elapsed.TotalMinutes:0.00}m");
            }
            catch (Exception ex)
            {
                DiagnosticLog.Write("fatal " + ex);
                throw;
            }
            finally
            {
                DiagnosticLog.Stop();
            }
        }

        private static async Task RunHostsAsync(HostRunner runner, List<HostCommands> jobs)
        {
            using var hostGate = new SemaphoreSlim(AppSettings.HostWorkers);
            await Task.WhenAll(jobs.Select(async job =>
            {
                DiagnosticLog.Write($"{job.Host} waiting for host slot");
                await hostGate.WaitAsync();
                DiagnosticLog.Write($"{job.Host} acquired host slot");
                try
                {
                    await runner.RunAsync(job);
                }
                catch (Exception ex)
                {
                    DiagnosticLog.Write($"{job.Host} host error {ex}");
                    Console.WriteLine("Error on host {0}: {1}\r\n", job.Host.Host, ex);
                }
                finally
                {
                    DiagnosticLog.Write($"{job.Host} released host slot");
                    hostGate.Release();
                }
            }));
        }

        private static Timer StartProgressTimer()
        {
            int ticks = 0;
            // 4x second console updates, diagnostic heartbeat every 5 seconds
            return new Timer(_ =>
            {
                Console.Write("Bytes downloaded: {0}, uploaded: {1}, skipped: {2}    \r",
                    ByteSize.Format(TransferStats.Downloaded), ByteSize.Format(TransferStats.Uploaded), ByteSize.Format(TransferStats.Skipped));
                if (Interlocked.Increment(ref ticks) % 20 == 0)
                {
                    DiagnosticLog.Heartbeat();
                }
            }, null, 1, 250);
        }
    }
}
