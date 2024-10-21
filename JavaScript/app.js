const crypto = require('crypto');
const bcrypt = require('bcrypt');

// تولید کلید با استفاده از SHA-256
function generateSHA256Key(input) {
    return crypto.createHash('sha256').update(input).digest();
}

// ثابت کردن IV
const iv = Buffer.alloc(16); // IV ثابت (صفر شده)

function encryptAES(data, secretKey) {
    const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

function decryptAES(encryptedData, secretKey) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function hashUsername(username) {
    const saltRounds = 10; // هزینه را به 10 تنظیم کنید
    return bcrypt.hashSync(username, saltRounds);
}

function checkUsernameHash(username, hashed) {
    return bcrypt.compareSync(username, hashed);
}

const secretKey = generateSHA256Key("2024-10-21");
console.log("Secret Key:", secretKey.toString('base64'));

const username = "user123";
const encryptedUsername = encryptAES(username, secretKey);
console.log("Encrypted Username:", encryptedUsername);

const decryptedUsername = decryptAES(encryptedUsername, secretKey);
console.log("Decrypted Username:", decryptedUsername);

const hashedUsername = hashUsername(username);
console.log("Hashed Username:", hashedUsername);

const isValid = checkUsernameHash(username, hashedUsername);
console.log("Is valid:", isValid);
