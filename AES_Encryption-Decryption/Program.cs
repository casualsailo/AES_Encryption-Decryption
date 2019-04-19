using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES_Encryption_Decryption
{
    class Program
    {
        static void Main(string[] args)
        {
            // https://msdn.microsoft.com/en-us/library/system.security.cryptography.aes(v=vs.110).aspx
            // https://www.codeproject.com/Articles/769741/Csharp-AES-bits-Encryption-Library-with-Salt
            var password = "encryptionPassword";
            var saltBytes = GenerateSalt(32); // Convert.FromBase64String("7tL0JPvjhZ5YHKgC+AUXDhf3FNBSsAIq3zkwXIulbhE=");
            var encryptedFile = Directory.GetCurrentDirectory() + @"\connections.ini";

            var temp = @"[Dev_Connection_String=Driver=SQL Server;Server=\\localhost;UID=admin;PWD=password;Database=development]" + Environment.NewLine;
            temp += @"[Prod_Connection_String=Driver=SQL Server;Server=\\localhost;UID=admin;PWD=password;Database=production]";
            EncryptStringToFile(encryptedFile, temp, password, saltBytes);
            Console.WriteLine(DecryptFileToString(encryptedFile, password, saltBytes));
        }

        static public void EncryptStringToFile(string filePath, string plainText, string password, byte[] salt)
        {
            var textBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptedBytes = AES_Encrypt(textBytes, password, salt);
            File.WriteAllBytes(filePath, encryptedBytes);
        }

        static public string DecryptFileToString(string filePath, string password, byte[] salt)
        {
            var encryptedBytes = File.ReadAllBytes(filePath);
            var decryptedBytes = AES_Decrypt(encryptedBytes, password, salt);
            return Encoding.UTF8.GetString(decryptedBytes);

        }

        // Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
        // https://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider(v=vs.110).aspx
        static public byte[] GenerateSalt(int saltSize)
        {
            var salt = new byte[saltSize];
            using (var rngCsp = new RNGCryptoServiceProvider()) {
                rngCsp.GetBytes(salt);
            }
            return salt;
        }

        static public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, string password, byte[] saltBytes)
        {
            byte[] encryptedBytes;
            using (var aesAlg = Aes.Create()) {
                var key = new Rfc2898DeriveBytes(password, saltBytes, 10000, HashAlgorithmName.SHA512);
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

                using (var msEncrypt = new MemoryStream()) {
                    using (var csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write)) {
                        csEncrypt.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }
            }
            return encryptedBytes;
        }

        static public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, string password, byte[] saltBytes)
        {
            byte[] decryptedBytes;
            using (var aesAlg = Aes.Create()) {
                var key = new Rfc2898DeriveBytes(password, saltBytes, 10000, HashAlgorithmName.SHA512);
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

                using (var msDecrypt = new MemoryStream()) {
                    using (var csDecrypt = new CryptoStream(msDecrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Write)) {
                        csDecrypt.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                    }
                    decryptedBytes = msDecrypt.ToArray();
                }
            }
            return decryptedBytes;
        }

    }
}
