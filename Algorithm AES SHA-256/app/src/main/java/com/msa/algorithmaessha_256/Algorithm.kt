package com.msa.algorithmaessha_256

//import android.util.Base64   //استفاده در اندروید
import java.util.Base64
import at.favre.lib.crypto.bcrypt.BCrypt
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import java.security.MessageDigest

// تولید کلید با استفاده از SHA-256
fun generateSHA256Key(input: String): String {
    val bytes = input.toByteArray()
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(bytes)
    return digest.fold("", { str, it -> str + "%02x".format(it) }).substring(0, 32)

}

// رمزنگاری با AES
fun encryptAES(data: String, secretKey: String): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(secretKey.toByteArray(), "AES")
    val iv = ByteArray(16) // مقدار IV که به صورت صفر پر می‌شود
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
   // return Base64.encodeToString(encrypted, Base64.DEFAULT) //استفاده در اندروید
    return Base64.getEncoder().encodeToString(encrypted) // استفاده از java.util.Base64
}

// رمزگشایی با AES
fun decryptAES(encryptedData: String, secretKey: String): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(secretKey.toByteArray(), "AES")
    val iv = ByteArray(16) // مقدار IV که به صورت صفر پر می‌شود
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
   // val decodedEncryptedData = Base64.decode(encryptedData, Base64.DEFAULT) //استفاده در اندروید
    val decodedEncryptedData = Base64.getDecoder().decode(encryptedData) // استفاده از java.util.Base64
    val decrypted = cipher.doFinal(decodedEncryptedData)
    return String(decrypted, Charsets.UTF_8)
}



// هش کردن نام کاربری با bcrypt
fun hashUsername(username: String): String {
    val bcryptHashString = BCrypt.withDefaults().hashToString(12, username.toCharArray())
    return bcryptHashString
}

// بررسی نام کاربری هش شده
fun checkUsernameHash(username: String, hashed: String): Boolean {
    val result = BCrypt.verifyer().verify(username.toCharArray(), hashed)
    return result.verified
}

// استفاده از این توابع
fun main() {
    // تولید کلید از تاریخ (مثلاً)
    val secretKey = com.msa.algorithmaessha_256.a.generateSHA256Key("2024-10-21")
    println("secretKey: $secretKey")
    // رمزنگاری نام کاربری
    val username = "user123"
    val encryptedUsername = com.msa.algorithmaessha_256.a.encryptAES(username, secretKey)
    println("Encrypted Username: $encryptedUsername")

    // رمزگشایی نام کاربری
    val decryptedUsername = com.msa.algorithmaessha_256.a.decryptAES(encryptedUsername, secretKey)
    println("Decrypted Username: $decryptedUsername")

    // هش کردن نام کاربری
    val hashedUsername = com.msa.algorithmaessha_256.a.hashUsername(username)
    println("Hashed Username: $hashedUsername")

    // بررسی صحت هش
    val isValid = com.msa.algorithmaessha_256.a.checkUsernameHash(username, hashedUsername)
    println("Is valid: $isValid")
}
