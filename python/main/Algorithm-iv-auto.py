import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import bcrypt

# تولید کلید با استفاده از SHA-256
def generate_sha256_key(input_string: str) -> str:
    sha256 = hashlib.sha256()
    sha256.update(input_string.encode())
    return sha256.hexdigest()[:32]

# رمزنگاری با AES
def encrypt_aes(data: str, secret_key: str) -> str:
    backend = default_backend()
    key = secret_key.encode()
    iv = b'\x00' * 16  # IV ثابت با مقدار صفر
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padded_data = data.encode('utf-8')
    while len(padded_data) % 16 != 0:
        padded_data += b' '  # پد کردن داده برای تطابق با اندازه بلوک

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

# رمزگشایی با AES
def decrypt_aes(encrypted_data: str, secret_key: str) -> str:
    backend = default_backend()
    key = secret_key.encode()
    iv = b'\x00' * 16  # IV ثابت با مقدار صفر
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decoded_encrypted_data = base64.b64decode(encrypted_data)
    decrypted = decryptor.update(decoded_encrypted_data) + decryptor.finalize()

    return decrypted.decode('utf-8').rstrip()  # حذف پدینگ‌ها

# هش کردن نام کاربری با bcrypt
def hash_username(username: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(username.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# بررسی نام کاربری هش شده
def check_username_hash(username: str, hashed: str) -> bool:
    return bcrypt.checkpw(username.encode('utf-8'), hashed.encode('utf-8'))

# استفاده از این توابع
if __name__ == "__main__":
    # تولید کلید از تاریخ
    secret_key = generate_sha256_key("2024-10-21")
    print(f"Secret Key: {secret_key}")

    # رمزنگاری نام کاربری
    username = "user123"
    encrypted_username = encrypt_aes(username, secret_key)
    print(f"Encrypted Username: {encrypted_username}")

    # رمزگشایی نام کاربری
    decrypted_username = decrypt_aes(encrypted_username, secret_key)
    print(f"Decrypted Username: {decrypted_username}")

    # هش کردن نام کاربری
    hashed_username = hash_username(username)
    print(f"Hashed Username: {hashed_username}")

    # بررسی صحت هش
    is_valid = check_username_hash(username, hashed_username)
    print(f"Is valid: {is_valid}")
