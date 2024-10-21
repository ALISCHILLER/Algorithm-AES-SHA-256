package com.msa.algorithmaessha_256 // نام بسته یا پکیج برنامه

import java.util.Base64 // وارد کردن کلاس Base64 برای تبدیل به رشته Base64
import at.favre.lib.crypto.bcrypt.BCrypt // وارد کردن کتابخانه BCrypt برای هش کردن رمز عبور
import javax.crypto.Cipher // وارد کردن کلاس Cipher برای رمزنگاری
import javax.crypto.spec.IvParameterSpec // وارد کردن کلاس IvParameterSpec برای تعریف IV
import javax.crypto.spec.SecretKeySpec // وارد کردن کلاس SecretKeySpec برای تعریف کلید رمزنگاری
import java.security.MessageDigest // وارد کردن کلاس MessageDigest برای تولید هش

// تابعی برای تولید کلید با استفاده از SHA-256
fun generateSHA256Key(input: String): ByteArray {
    val bytes = input.toByteArray() // تبدیل رشته ورودی به آرایه بایت
    val md = MessageDigest.getInstance("SHA-256") // ایجاد شیء MessageDigest برای SHA-256
    return md.digest(bytes) // تولید هش SHA-256 و بازگشت به عنوان آرایه بایت
}

// ثابت کردن IV (مقدار اولیه برای رمزنگاری)
val iv = ByteArray(16) // IV ثابت (صفر شده) به طول 16 بایت برای AES

// تابعی برای رمزنگاری داده‌ها با استفاده از AES
fun encryptAES(data: String, secretKey: ByteArray): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") // تعیین نوع رمزنگاری (AES با حالت CBC و padding)
    val keySpec = SecretKeySpec(secretKey, "AES") // ایجاد شیء SecretKeySpec با کلید
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(iv)) // تنظیم حالت رمزنگاری
    val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8)) // رمزنگاری داده‌ها
    // return Base64.encodeToString(encrypted, Base64.DEFAULT) //استفاده در اندروید
    return Base64.getEncoder().encodeToString(encrypted) // تبدیل داده‌های رمزنگاری شده به رشته Base64
}

// تابعی برای رمزگشایی داده‌های رمزنگاری شده با AES
fun decryptAES(encryptedData: String, secretKey: ByteArray): String {
    // val decodedEncryptedData = Base64.decode(encryptedData, Base64.DEFAULT) //استفاده در اندروید
    val decodedData = Base64.getDecoder().decode(encryptedData) // تبدیل رشته Base64 به آرایه بایت
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") // تعیین نوع رمزنگاری
    val keySpec = SecretKeySpec(secretKey, "AES") // ایجاد شیء SecretKeySpec با کلید
    cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv)) // تنظیم حالت رمزگشایی
    val decrypted = cipher.doFinal(decodedData) // رمزگشایی داده‌ها
    return String(decrypted, Charsets.UTF_8) // تبدیل آرایه بایت به رشته UTF-8
}

// تابعی برای هش کردن نام کاربری با استفاده از bcrypt
fun hashUsername(username: String): String {

    val salt = "$2a$10$" + "abcdefghijklmno" //  ثابت
    return BCrypt.withDefaults().hashToString(10, username.toCharArray() + salt.toCharArray())

//    // هزینه را به 10 تنظیم کنید
//    return BCrypt.withDefaults().hashToString(10, username.toCharArray()) // هش کردن نام کاربری
}

// تابعی برای بررسی صحت نام کاربری هش شده
fun checkUsernameHash(username: String, hashed: String): Boolean {
    val result = BCrypt.verifyer().verify(username.toCharArray(), hashed) // بررسی صحت هش
    return result.verified // بازگشت نتیجه صحت
}

// تابع اصلی برای آزمایش توابع
fun main() {
    val secretKey = generateSHA256Key("2024-10-21") // تولید کلید از تاریخ
    println("Secret Key: ${Base64.getEncoder().encodeToString(secretKey)}") // چاپ کلید

    val username = "user123" // نام کاربری
    val encryptedUsername = encryptAES(username, secretKey) // رمزنگاری نام کاربری
    println("Encrypted Username: $encryptedUsername") // چاپ نام کاربری رمزنگاری شده

    val decryptedUsername = decryptAES(encryptedUsername, secretKey) // رمزگشایی نام کاربری
    println("Decrypted Username: $decryptedUsername") // چاپ نام کاربری رمزگشایی شده

    val hashedUsername = hashUsername(username) // هش کردن نام کاربری
    println("Hashed Username: $hashedUsername") // چاپ نام کاربری هش شده

    val isValid = checkUsernameHash(username, hashedUsername) // بررسی صحت هش
    println("Is valid: $isValid") // چاپ نتیجه صحت
}
