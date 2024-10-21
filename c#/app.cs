using System;
using System.Security.Cryptography;
using System.Text;
using BCrypt.Net;

// تولید کلید با استفاده از SHA-256
byte[] GenerateSHA256Key(string input)
{
    using (SHA256 sha256 = SHA256.Create())
    {
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
    }
}

// ثابت کردن IV
byte[] iv = new byte[16]; // IV ثابت (صفر شده)

string EncryptAES(string data, byte[] secretKey)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = secretKey;
        aes.IV = iv;

        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using (var ms = new System.IO.MemoryStream())
        {
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                using (var sw = new StreamWriter(cs))
                {
                    sw.Write(data);
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }
}

string DecryptAES(string encryptedData, byte[] secretKey)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = secretKey;
        aes.IV = iv;

        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using (var ms = new System.IO.MemoryStream(Convert.FromBase64String(encryptedData)))
        {
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            {
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }
    }
}

string HashUsername(string username)
{
    // هزینه را به 10 تنظیم کنید
    return BCrypt.Net.BCrypt.HashPassword(username, BCrypt.Net.BCrypt.GenerateSalt(10));
}

bool CheckUsernameHash(string username, string hashed)
{
    return BCrypt.Net.BCrypt.Verify(username, hashed);
}

class Program
{
    static void Main(string[] args)
    {
        string secretKeyInput = "2024-10-21";
        byte[] secretKey = GenerateSHA256Key(secretKeyInput);
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
