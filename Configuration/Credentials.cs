using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

using Renci.SshNet;

namespace AutoSSH
{
    internal sealed class Credentials
    {
        private const string fileName = "login.key";

        private readonly SecureString userName;
        private readonly SecureString password;

        private Credentials(string userName, string password)
        {
            this.userName = ToSecureString(userName);
            this.password = ToSecureString(password);
        }

        internal static Credentials LoadOrPrompt(string backupRoot)
        {
            string loginPath = Path.Combine(backupRoot, fileName);
            if (!File.Exists(loginPath))
            {
                Prompt(loginPath);
            }
            if (!File.Exists(loginPath))
            {
                throw new FileNotFoundException("Missing login.key file");
            }

            byte[] protectedBytes = File.ReadAllBytes(loginPath);
            string unprotected = Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, null,
                DataProtectionScope.CurrentUser));
            int pos = unprotected.IndexOf('|');
            if (pos < 0)
            {
                throw new ArgumentException("Corrupted login.key file, delete and restart");
            }
            var credentials = new Credentials(unprotected.Substring(0, pos), unprotected.Substring(pos + 1));
            protectedBytes = null;
            unprotected = null;
            GC.Collect();
            return credentials;
        }

        internal string GetUserName() => ToInsecureString(userName);

        internal string GetPassword() => ToInsecureString(password);

        internal void WritePassword(ShellStream stream)
        {
            stream.Write(ToInsecureString(password));
            stream.Write("\n");
        }

        private static void Prompt(string loginPath)
        {
            Console.Write("Enter user name: ");
            string userName = Console.ReadLine();
            Console.Write("Enter password: ");
            var password = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                password.Append(key.KeyChar);
            }
            byte[] bytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(userName + "|" + password), null,
                DataProtectionScope.CurrentUser);
            File.WriteAllBytes(loginPath, bytes);
        }

        private static SecureString ToSecureString(string text)
        {
            var secureString = new SecureString();
            foreach (char c in text)
            {
                secureString.AppendChar(c);
            }
            secureString.MakeReadOnly();
            return secureString;
        }

        private static string ToInsecureString(SecureString secureString)
        {
            IntPtr unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                return Marshal.PtrToStringUni(unmanagedString, secureString.Length);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }
    }
}
