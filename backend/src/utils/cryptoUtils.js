/**
 * Cryptographic Utilities
 * क्रिप्टोग्राफिक उपकरण
 * 
 * This module provides secure cryptographic functions for:
 * - AES-256-GCM file encryption/decryption (authenticated encryption)
 * - RSA-OAEP key wrapping/unwrapping for CEK protection
 * - HMAC-SHA256 for deterministic indexing
 * - Argon2id for password-based key derivation
 * - Secure random number generation
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const argon2 = require('argon2');
const { logger } = require('./logger');

/**
 * AES-256-GCM Encryption Functions
 * AES-256-GCM एन्क्रिप्शन फ़ंक्शन
 */

/**
 * Generate a random Content Encryption Key (CEK)
 * रैंडम कंटेंट एन्क्रिप्शन की (CEK) जेनरेट करें
 * 
 * @returns {Buffer} 256-bit random key
 */
const generateCEK = () => {
    return crypto.randomBytes(32); // 256 bits for AES-256
};

/**
 * Generate a random Initialization Vector (IV)
 * रैंडम इनिशियलाइज़ेशन वेक्टर (IV) जेनरेट करें
 * 
 * @returns {Buffer} 96-bit random IV for GCM mode
 */
const generateIV = () => {
    return crypto.randomBytes(12); // 96 bits recommended for GCM
};

/**
 * Encrypt data using AES-256-GCM (Authenticated Encryption)
 * AES-256-GCM का उपयोग करके डेटा एन्क्रिप्ट करें
 * 
 * @param {Buffer} cek - Content Encryption Key (32 bytes)
 * @param {Buffer} plaintext - Data to encrypt
 * @param {Buffer} [additionalData] - Optional additional authenticated data
 * @returns {Object} Encryption result with ciphertext, iv, and authTag
 */
const encryptAESGCM = (cek, plaintext, additionalData = null) => {
    try {
        const iv = generateIV();
        const cipher = crypto.createCipher('aes-256-gcm');

        // Set the IV
        cipher.setAAD(iv);

        // Add additional authenticated data if provided
        if (additionalData) {
            cipher.setAAD(additionalData);
        }

        // Encrypt the plaintext
        let ciphertext = cipher.update(plaintext);
        cipher.final();

        // Get the authentication tag
        const authTag = cipher.getAuthTag();

        logger.debug('AES-GCM encryption completed', {
            plaintextSize: plaintext.length,
            ciphertextSize: ciphertext.length,
            ivLength: iv.length,
            tagLength: authTag.length
        });

        return {
            ciphertext: Buffer.concat([ciphertext]),
            iv: iv,
            authTag: authTag
        };

    } catch (error) {
        logger.error('AES-GCM encryption failed:', error);
        throw new Error('Encryption failed: ' + error.message);
    }
};

/**
 * Decrypt data using AES-256-GCM
 * AES-256-GCM का उपयोग करके डेटा डिक्रिप्ट करें
 * 
 * @param {Buffer} cek - Content Encryption Key (32 bytes)
 * @param {Buffer} ciphertext - Encrypted data
 * @param {Buffer} iv - Initialization Vector
 * @param {Buffer} authTag - Authentication tag
 * @param {Buffer} [additionalData] - Optional additional authenticated data
 * @returns {Buffer} Decrypted plaintext
 */
const decryptAESGCM = (cek, ciphertext, iv, authTag, additionalData = null) => {
    try {
        const decipher = crypto.createDecipher('aes-256-gcm');

        // Set the IV and auth tag
        decipher.setAAD(iv);
        decipher.setAuthTag(authTag);

        // Add additional authenticated data if provided
        if (additionalData) {
            decipher.setAAD(additionalData);
        }

        // Decrypt the ciphertext
        let plaintext = decipher.update(ciphertext);
        decipher.final(); // This will throw if authentication fails

        logger.debug('AES-GCM decryption completed', {
            ciphertextSize: ciphertext.length,
            plaintextSize: plaintext.length
        });

        return Buffer.concat([plaintext]);

    } catch (error) {
        logger.error('AES-GCM decryption failed:', error);
        throw new Error('Decryption failed - data may be corrupted or tampered');
    }
};

/**
 * RSA-OAEP Key Wrapping Functions
 * RSA-OAEP की रैपिंग फ़ंक्शन
 */

/**
 * Load RSA public key from PEM file
 * PEM फाइल से RSA पब्लिक की लोड करें
 * 
 * @param {string} keyPath - Path to public key file
 * @returns {string} PEM formatted public key
 */
const loadPublicKey = (keyPath) => {
    try {
        const fullPath = path.resolve(keyPath);
        if (!fs.existsSync(fullPath)) {
            throw new Error(`Public key file not found: ${fullPath}`);
        }

        const keyData = fs.readFileSync(fullPath, 'utf8');
        logger.debug('Public key loaded successfully', { keyPath: fullPath });
        return keyData;

    } catch (error) {
        logger.error('Failed to load public key:', error);
        throw new Error('Public key loading failed: ' + error.message);
    }
};

/**
 * Load RSA private key from PEM file
 * PEM फाइल से RSA प्राइवेट की लोड करें
 * 
 * @param {string} keyPath - Path to private key file
 * @returns {string} PEM formatted private key
 */
const loadPrivateKey = (keyPath) => {
    try {
        const fullPath = path.resolve(keyPath);
        if (!fs.existsSync(fullPath)) {
            throw new Error(`Private key file not found: ${fullPath}`);
        }

        const keyData = fs.readFileSync(fullPath, 'utf8');
        logger.debug('Private key loaded successfully', { keyPath: fullPath });
        return keyData;

    } catch (error) {
        logger.error('Failed to load private key:', error);
        throw new Error('Private key loading failed: ' + error.message);
    }
};

/**
 * Wrap (encrypt) CEK using RSA-OAEP public key
 * RSA-OAEP पब्लिक की का उपयोग करके CEK को रैप (एन्क्रिप्ट) करें
 * 
 * @param {Buffer} cek - Content Encryption Key to wrap
 * @param {string} publicKeyPEM - RSA public key in PEM format
 * @returns {Buffer} Wrapped (encrypted) CEK
 */
const wrapKeyRSA = (cek, publicKeyPEM) => {
    try {
        // Convert PEM to forge public key
        const publicKey = forge.pki.publicKeyFromPem(publicKeyPEM);

        // Encrypt CEK using RSA-OAEP
        const wrappedKey = publicKey.encrypt(cek.toString('binary'), 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: {
                md: forge.md.sha256.create()
            }
        });

        const wrappedBuffer = Buffer.from(wrappedKey, 'binary');

        logger.debug('RSA key wrapping completed', {
            cekLength: cek.length,
            wrappedLength: wrappedBuffer.length
        });

        return wrappedBuffer;

    } catch (error) {
        logger.error('RSA key wrapping failed:', error);
        throw new Error('Key wrapping failed: ' + error.message);
    }
};

/**
 * Unwrap (decrypt) CEK using RSA-OAEP private key
 * RSA-OAEP प्राइवेट की का उपयोग करके CEK को अनरैप (डिक्रिप्ट) करें
 * 
 * @param {Buffer} wrappedKey - Wrapped (encrypted) CEK
 * @param {string} privateKeyPEM - RSA private key in PEM format
 * @returns {Buffer} Unwrapped (decrypted) CEK
 */
const unwrapKeyRSA = (wrappedKey, privateKeyPEM) => {
    try {
        // Convert PEM to forge private key
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPEM);

        // Decrypt wrapped CEK using RSA-OAEP
        const cek = privateKey.decrypt(wrappedKey.toString('binary'), 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: {
                md: forge.md.sha256.create()
            }
        });

        const cekBuffer = Buffer.from(cek, 'binary');

        logger.debug('RSA key unwrapping completed', {
            wrappedLength: wrappedKey.length,
            cekLength: cekBuffer.length
        });

        return cekBuffer;

    } catch (error) {
        logger.error('RSA key unwrapping failed:', error);
        throw new Error('Key unwrapping failed: ' + error.message);
    }
};

/**
 * HMAC Functions for Deterministic Indexing
 * निर्धारक अनुक्रमण के लिए HMAC फ़ंक्शन
 */

/**
 * Generate HMAC-SHA256 for deterministic indexing
 * निर्धारक अनुक्रमण के लिए HMAC-SHA256 जेनरेट करें
 * 
 * @param {string} value - Value to hash
 * @param {string} key - HMAC key
 * @returns {string} Base64 encoded HMAC
 */
const generateHMACIndex = (value, key) => {
    try {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(value);
        const hash = hmac.digest('base64');

        logger.debug('HMAC index generated', {
            valueLength: value.length,
            hashLength: hash.length
        });

        return hash;

    } catch (error) {
        logger.error('HMAC generation failed:', error);
        throw new Error('HMAC generation failed: ' + error.message);
    }
};

/**
 * Generate SHA-256 fingerprint for data integrity
 * डेटा अखंडता के लिए SHA-256 फिंगरप्रिंट जेनरेट करें
 * 
 * @param {Buffer} data - Data to fingerprint
 * @returns {string} Hex encoded SHA-256 hash
 */
const generateFingerprint = (data) => {
    try {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        const fingerprint = hash.digest('hex');

        logger.debug('Data fingerprint generated', {
            dataSize: data.length,
            fingerprint: fingerprint.substring(0, 16) + '...'
        });

        return fingerprint;

    } catch (error) {
        logger.error('Fingerprint generation failed:', error);
        throw new Error('Fingerprint generation failed: ' + error.message);
    }
};

/**
 * Password-Based Key Derivation
 * पासवर्ड-आधारित की व्युत्पत्ति
 */

/**
 * Derive key from passphrase using Argon2id
 * Argon2id का उपयोग करके पासफ़्रेज़ से की प्राप्त करें
 * 
 * @param {string} passphrase - User passphrase
 * @param {Buffer} [salt] - Salt (generated if not provided)
 * @param {number} [keyLength=32] - Desired key length in bytes
 * @returns {Object} Derived key and salt
 */
const deriveKeyFromPassphrase = async (passphrase, salt = null, keyLength = 32) => {
    try {
        // Generate salt if not provided
        if (!salt) {
            salt = crypto.randomBytes(16); // 128-bit salt
        }

        // Derive key using Argon2id with secure parameters
        const derivedKey = await argon2.hash(passphrase, {
            type: argon2.argon2id,
            memoryCost: 2 ** 16, // 64 MB
            timeCost: 3,         // 3 iterations
            parallelism: 1,      // 1 thread
            raw: true,           // Return raw bytes
            salt: salt,
            hashLength: keyLength
        });

        logger.debug('Key derivation completed', {
            passphraseLength: passphrase.length,
            saltLength: salt.length,
            keyLength: derivedKey.length
        });

        return {
            key: Buffer.from(derivedKey),
            salt: salt
        };

    } catch (error) {
        logger.error('Key derivation failed:', error);
        throw new Error('Key derivation failed: ' + error.message);
    }
};

/**
 * Secure Memory Operations
 * सुरक्षित मेमोरी ऑपरेशन
 */

/**
 * Securely zero out sensitive data in memory
 * मेमोरी में संवेदनशील डेटा को सुरक्षित रूप से शून्य करें
 * 
 * @param {Buffer} buffer - Buffer to zero out
 */
const zeroizeBuffer = (buffer) => {
    if (Buffer.isBuffer(buffer)) {
        buffer.fill(0);
    }
};

/**
 * Generate secure random bytes
 * सुरक्षित रैंडम बाइट्स जेनरेट करें
 * 
 * @param {number} size - Number of bytes to generate
 * @returns {Buffer} Random bytes
 */
const generateSecureRandom = (size) => {
    try {
        return crypto.randomBytes(size);
    } catch (error) {
        logger.error('Secure random generation failed:', error);
        throw new Error('Random generation failed: ' + error.message);
    }
};

/**
 * Utility Functions
 * उपयोगिता फ़ंक्शन
 */

/**
 * Convert buffer to base64 URL-safe string
 * बफर को base64 URL-सुरक्षित स्ट्रिंग में बदलें
 * 
 * @param {Buffer} buffer - Buffer to convert
 * @returns {string} Base64 URL-safe string
 */
const bufferToBase64URL = (buffer) => {
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
};

/**
 * Convert base64 URL-safe string to buffer
 * Base64 URL-सुरक्षित स्ट्रिंग को बफर में बदलें
 * 
 * @param {string} base64url - Base64 URL-safe string
 * @returns {Buffer} Converted buffer
 */
const base64URLToBuffer = (base64url) => {
    const base64 = base64url
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    // Add padding if necessary
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);

    return Buffer.from(padded, 'base64');
};

module.exports = {
    // AES-GCM functions
    generateCEK,
    generateIV,
    encryptAESGCM,
    decryptAESGCM,

    // RSA-OAEP functions
    loadPublicKey,
    loadPrivateKey,
    wrapKeyRSA,
    unwrapKeyRSA,

    // HMAC and hashing
    generateHMACIndex,
    generateFingerprint,

    // Key derivation
    deriveKeyFromPassphrase,

    // Utility functions
    zeroizeBuffer,
    generateSecureRandom,
    bufferToBase64URL,
    base64URLToBuffer
};