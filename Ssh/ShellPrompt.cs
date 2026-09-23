using System;
using System.IO;
using System.Text.RegularExpressions;

using Renci.SshNet;

namespace AutoSSH
{
    internal static class ShellPrompt
    {
        // Accept trailing terminal color/reset sequences as well as plain prompts.
        private const string promptSuffix = @"(?:[ \t]|\x1b\[[0-?]*[ -/]*[@-~])*\r?$";

        internal static readonly Regex Login = new(@"(?m)[$#>]" + promptSuffix);
        internal static readonly Regex Root = new(@"(?m)#" + promptSuffix);
        internal static readonly Regex Windows = new(@"(?m)>" + promptSuffix);
        internal static readonly Regex Sudo = new(@"(?m)[Pp]assword[^\r\n]*:" + promptSuffix + "|" + Root);

        internal static string Expect(ShellStream stream, Regex prompt, TimeSpan timeout, TextWriter log, string context)
        {
            string op = DiagnosticLog.Begin($"wait {context} timeout={timeout.TotalSeconds}s");
            string output = stream.Expect(prompt, timeout);
            if (output == null)
            {
                log.Write(stream.Read());
                log.Flush();
                var ex = new TimeoutException($"Timed out after {timeout.TotalSeconds} seconds waiting for {context}.");
                DiagnosticLog.Fail(op, ex);
                throw ex;
            }
            log.Write(output);
            log.Flush();
            DiagnosticLog.End(op, output.Length + " chars");
            return output;
        }
    }
}
