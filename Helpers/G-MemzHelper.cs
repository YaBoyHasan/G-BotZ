using System.Diagnostics;
using System.Text;

namespace G_BotZ.Helpers
{
    public class G_MemzHelper
    {
        public static string RunGMemzAndGetRc4Hex()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "G-MemZ.exe",
                Arguments = "flash",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var rc4DumpBuilder = new StringBuilder();

            using var process = new Process { StartInfo = psi };

            process.OutputDataReceived += (sender, args) =>
            {
                if (!string.IsNullOrWhiteSpace(args.Data))
                {
                    if (args.Data.Contains("Found potential RC4 table at:"))
                        Console.WriteLine("[G-MemZ] " + args.Data);

                    if (args.Data.Length > 500) // likely the RC4 dump
                    {
                        rc4DumpBuilder.AppendLine(args.Data.Trim());
                    }
                }
            };

            process.ErrorDataReceived += (sender, args) =>
            {
                if (!string.IsNullOrWhiteSpace(args.Data))
                {
                    Console.WriteLine("[G-MemZ-ERR] " + args.Data);

                    if (args.Data.Length > 500) // could be the RC4 table hex
                    {
                        rc4DumpBuilder.AppendLine(args.Data.Trim());
                    }
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.WaitForExit();

            string rc4Hex = rc4DumpBuilder.ToString().Replace("\r", "").Replace("\n", "").Trim();
            return rc4Hex;
        }
        public static (int i, int j, byte[] decrypted)? BruteforceRC4(string rc4Hex, byte[] encrypted)
        {
            if (rc4Hex.Length != 512)
                throw new Exception("Invalid RC4 hex");

            byte[] sBox = Enumerable.Range(0, 256)
                .Select(x => Convert.ToByte(rc4Hex.Substring(x * 2, 2), 16))
                .ToArray();

            for (int iTry = 0; iTry < 256; iTry++)
            {
                for (int jTry = 0; jTry < 256; jTry++)
                {
                    // Clone S-box
                    int[] table = new int[256];
                    for (int x = 0; x < 256; x++)
                        table[x] = sBox[x];

                    // Setup state
                    var rc4 = new RC4Dummy(table, iTry, jTry); // See below for RC4Dummy

                    // Copy encrypted buffer
                    byte[] decrypted = (byte[])encrypted.Clone();

                    // Peek-parse without mutating state
                    rc4.RefParse(decrypted, 0, decrypted.Length, isPeeking: true);

                    if (decrypted.Length < 6) continue;

                    int len = (decrypted[0] << 24) | (decrypted[1] << 16) | (decrypted[2] << 8) | decrypted[3];
                    if (len <= 0 || len > 4096) continue;

                    ushort header = (ushort)((decrypted[4] << 8) | decrypted[5]);
                    if (header >= 1 && header <= 5000)
                    {
                        // Return decrypted chunk
                        byte[] clean = decrypted.Take(len + 4).ToArray();
                        return (iTry, jTry, clean);
                    }
                }
            }

            Console.WriteLine("❌ RC4 Bruteforce Failed.");
            return null;
        }

    }
}
