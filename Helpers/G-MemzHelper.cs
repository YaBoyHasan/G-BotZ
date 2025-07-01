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
                    byte[] S = (byte[])sBox.Clone();
                    int i = iTry, j = jTry;
                    byte[] keystream = new byte[encrypted.Length];
                    for (int k = 0; k < encrypted.Length; k++)
                    {
                        i = (i + 1) & 0xFF;
                        j = (j + S[i]) & 0xFF;
                        (S[i], S[j]) = (S[j], S[i]);
                        keystream[k] = S[(S[i] + S[j]) & 0xFF];
                    }

                    byte[] decrypted = encrypted.Zip(keystream, (e, k) => (byte)(e ^ k)).ToArray();

                    // check length field
                    if (decrypted.Length < 6) continue;
                    int len = (decrypted[0] << 24) | (decrypted[1] << 16) | (decrypted[2] << 8) | decrypted[3];
                    if (len > 4096 || len <= 0) continue;

                    short header = (short)((decrypted[4] << 8) | decrypted[5]);
                    if (header >= 1000 && header < 6000)
                    {
                        byte[] decryptedClean = decrypted.Take(len + 4).ToArray();
                        return (iTry, jTry, decryptedClean);
                    }
                }
            }

            Console.WriteLine("❌ Failed to bruteforce RC4.");
            return null;
        }

    }
}
