using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Google.Authenticator;
using System.Security.Cryptography;

namespace authenticator
{
    class Program
    {
        public static readonly DateTime UNIX_EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        static void Main(string[] args)
        {
            if (args.Length == 0)
                return;

            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator(true, true);

            Console.WriteLine("key: " + args[0]);

            //string[] pins = tfa.GetCurrentPINs(args[0]);

            //foreach (var s in pins)
            //    Console.WriteLine(s);

            Console.WriteLine(tfa.GetCurrentPIN(args[0]));

            //Console.ReadKey();

            //long counter = (long)(DateTime.UtcNow - UNIX_EPOCH).TotalSeconds / 30;
            //Console.WriteLine(GeneratePassword(args[0], counter));
            //Console.WriteLine(GeneratePassword(args[0].ToUpper(), counter));
            //Console.WriteLine(GeneratePassword(args[0].ToLower(), counter));
        }

        public static string GeneratePassword(string secret, long iterationNumber, int digits = 6)
        {
            byte[] counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            byte[] key = Encoding.ASCII.GetBytes(secret);

            HMACSHA1 hmac = new HMACSHA1(key, true);

            byte[] hash = hmac.ComputeHash(counter);

            int offset = hash[hash.Length - 1] & 0xf;

            int binary =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

            int password = binary % (int)Math.Pow(10, digits); // 6 digits

            return password.ToString(new string('0', digits));
        }
    }
}
