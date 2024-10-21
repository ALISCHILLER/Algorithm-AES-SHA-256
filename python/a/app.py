import base64  # وارد کردن کتابخانه base64 برای رمزگذاری و رمزگشایی
import hashlib  # وارد کردن کتابخانه hashlib برای تولید هش
from Crypto.Cipher import AES  # وارد کردن کلاس AES از کتابخانه Crypto برای رمزنگاری
from Crypto.Util.Padding import pad, unpad  # وارد کردن توابع pad و unpad برای مدیریت پر کردن
import bcrypt  # وارد کردن کتابخانه bcrypt برای هش کردن رمز عبور

# تولید کلید با استفاده از SHA-256
def generate_sha256_key(input_str):
    return hashlib.sha256(input_str.encode()).digest()  # تولید و بازگشت هش SHA-256 از ورودی

# ثابت کردن IV (Initialization Vector) که برای رمزنگاری استفاده می‌شود
iv = bytes(16)  # مقدار IV که به صورت صفر پر می‌شود (16 بایت برای AES)

# تابعی برای رمزنگاری داده‌ها با استفاده از AES
def encrypt_aes(data, secret_key):
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)  # ایجاد شیء AES با حالت CBC و IV مشخص شده
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))  # رمزنگاری داده‌ها و پر کردن آن‌ها
    return base64.b64encode(encrypted).decode()  # تبدیل داده‌های رمزنگاری شده به رشته Base64

# تابعی برای رمزگشایی داده‌های رمزنگاری شده با AES
def decrypt_aes(encrypted_data, secret_key):
    decoded_data = base64.b64decode(encrypted_data.encode())  # تبدیل رشته Base64 به آرایه بایت
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)  # ایجاد شیء AES با حالت CBC و IV مشخص شده
    decrypted = unpad(cipher.decrypt(decoded_data), AES.block_size).decode()  # رمزنگاری و حذف پر کردن
    return decrypted  # بازگشت داده‌های رمزگشایی شده

# تابعی برای هش کردن نام کاربری با استفاده از bcrypt
def hash_username(username):
     # استفاده از نمک ثابت
    salt = "$2a$10$abcdefghijklmno"  # نمک ثابت
    return bcrypt.hashpw(username.encode() + salt.encode(), bcrypt.gensalt(10)).decode()
    
    # return bcrypt.hashpw(username.encode(), bcrypt.gensalt(10)).decode()  # هش کردن نام کاربری

# تابعی برای بررسی صحت نام کاربری هش شده
def check_username_hash(username, hashed):
    return bcrypt.checkpw(username.encode(), hashed.encode())  # بررسی صحت هش

# تابع اصلی برای آزمایش توابع
if __name__ == "__main__":
    secret_key = generate_sha256_key("2024-10-21")  # تولید کلید از تاریخ
    print("Secret Key:", base64.b64encode(secret_key).decode())  # چاپ کلید به صورت Base64

    username = "user123"  # نام کاربری
    encrypted_username = encrypt_aes(username, secret_key)  # رمزنگاری نام کاربری
    print("Encrypted Username:", encrypted_username)  # چاپ نام کاربری رمزنگاری شده

    decrypted_username = decrypt_aes(encrypted_username, secret_key)  # رمزگشایی نام کاربری
    print("Decrypted Username:", decrypted_username)  # چاپ نام کاربری رمزگشایی شده

    hashed_username = hash_username(username)  # هش کردن نام کاربری
    print("Hashed Username:", hashed_username)  # چاپ نام کاربری هش شده

    is_valid = check_username_hash(username, hashed_username)  # بررسی صحت هش
    print("Is valid:", is_valid)  # چاپ نتیجه صحت
