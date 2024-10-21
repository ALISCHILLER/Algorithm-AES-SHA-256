using System;
using System.Text;
using System.Security.Cryptography;
using BCrypt.Net;

class Program
{
    // تولید کلید با استفاده از SHA-256
    static byte[] GenerateSHA256Key(string input)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        }
    }

    static string EncryptAES(string data, byte[] secretKey)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = secretKey;
            aes.IV = new byte[16]; // IV ثابت (صفر شده)

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (var ms = new System.IO.MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (var sw = new System.IO.StreamWriter(cs))
                    {
                        sw.Write(data);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }
    }

    static string DecryptAES(string encryptedData, byte[] secretKey)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = secretKey;
            aes.IV = new byte[16]; // IV ثابت (صفر شده)

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (var ms = new System.IO.MemoryStream(Convert.FromBase64String(encryptedData)))
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (var sr = new System.IO.StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }

    static string HashUsername(string username)
    {
        return BCrypt.Net.BCrypt.HashPassword(username, workFactor: 10);
    }

    static bool CheckUsernameHash(string username, string hashed)
    {
        return BCrypt.Net.BCrypt.Verify(username, hashed);
    }

    static void Main(string[] args)
    {
        var secretKey = GenerateSHA256Key("2024-10-21");
        Console.WriteLine("Secret Key: " + Convert.ToBase64String(secretKey));

        string username = "user123";
        string encryptedUsername = EncryptAES(username, secretKey);
        Console.WriteLine("Encrypted Username: " + encryptedUsername);

        string decryptedUsername = DecryptAES(encryptedUsername, secretKey);
        Console.WriteLine("Decrypted Username: " + decryptedUsername);

        string hashedUsername = HashUsername(username);
        Console.WriteLine("Hashed Username: " + hashedUsername);

        bool isValid = CheckUsernameHash(username, hashedUsername);
        Console.WriteLine("Is valid: " + isValid);
    }
}
