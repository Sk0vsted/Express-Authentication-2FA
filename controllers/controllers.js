const sqlite3 = require('better-sqlite3');
const db = new sqlite3('db/sampleAPI.db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const algorithm = 'aes-256-gcm';
require('dotenv').config();
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const secretKey = Buffer.from(process.env.SECRET_CRYPTO, 'hex');
if (secretKey.length !== 32) {
    throw new Error("SECRET_KEY skal være 32 bytes lang!");
}

const JWT_SECRET = process.env.SECRET || 'fakeKey';

// ✅ Generer JWT token
function generateToken(user) {
    return jwt.sign(
        { email: user.email, admin: user.admin },
        JWT_SECRET,
        { expiresIn: '1h' }
    );
}

async function enableTwoFactor(req, res) {
    const { email } = req.user;

    const secret = speakeasy.generateSecret({ length: 20 });

    const stmt = db.prepare('UPDATE user SET two_factor_secret = ?, two_factor_enabled = 1 WHERE email = ?');
    stmt.run(secret.base32, email);

    QRCode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to generate QR code' });
        }
        res.json({ qrCodeUrl, secret: secret.base32 });
    });
}

async function verifyTwoFactor(req, res) {
    const { email } = req.user;
    const { token } = req.body;

    const stmt = db.prepare('SELECT two_factor_secret FROM user WHERE email = ?');
    const user = stmt.get(email);

    if (!user || !user.two_factor_secret) {
        return res.status(400).json({ error: "2FA not set up for this user" });
    }

    const verified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: 'base32',
        token,
        window: 1,
    });

    if (!verified) {
        return res.status(400).json({ error: "Invalid OTP" });
    }

    res.json({ message: "2FA setup verified!" });
}


// ✅ Middleware: Verificér JWT token
function authenticateUser(req, res, next) {
    const token = req.cookies.jwt;
    if (!token) {
        return res.status(401).json({ error: 'Access Denied: No Token Provided!' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(400).json({ error: 'Invalid Token' });
    }
}

// ✅ Registrér en ny bruger
async function register(req, res) {
    const { email, password, bio } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO user (email, password, bio, admin) VALUES (?, ?, ?, ?)');
    stmt.run(email, hashedPassword, bio, 0);

    res.status(201).json({ message: 'User registered successfully!' });
}

// ✅ Log brugeren ind
async function login(req, res) {
    const { email, password, otp } = req.body;

    const stmt = db.prepare('SELECT * FROM user WHERE email = ?');
    const user = stmt.get(email);

    if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.two_factor_enabled) {
        if (!otp) {
            return res.status(401).json({ error: '2FA required! Please enter your OTP.' });
        }

        const verified = speakeasy.totp.verify({
            secret: user.two_factor_secret,
            encoding: 'base32',
            token: otp
        });

        if (!verified) {
            return res.status(401).json({ error: 'Invalid OTP' });
        }
    }

    const token = generateToken(user);

    res.cookie('jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 3600000
    });

    res.json({ message: "Login successful", redirect: "/users/profile" });
}

// ✅ Hent brugerprofil
function getProfile(req, res) {
    const stmt = db.prepare('SELECT email, bio, admin FROM user WHERE email = ?');
    const user = stmt.get(req.user.email);

    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    res.render('profile', {
        title: 'Profile',
        subtitle: 'Your profile',
        user
    });
}

function encryptBio(text) {
    const iv = Buffer.alloc(16, 0); // Fast IV (mindre sikkerhed, men simpelt)
    const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted; // Gem kun dette i databasen
}

function decryptBio(encryptedData) {
    try {
        const iv = Buffer.alloc(16, 0); // Samme IV som ved kryptering
        const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);

        let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
        decrypted += decipher.final('utf-8');

        return decrypted;
    } catch (error) {
        console.error("Fejl ved dekryptering af bio:", error);
        return null;
    }
}


module.exports = {
    authenticateUser,
    register,
    login,
    getProfile,
    encryptBio,
    decryptBio,
    enableTwoFactor,
    verifyTwoFactor
};
