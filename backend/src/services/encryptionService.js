/**
 * Encryption Service
 * एन्क्रिप्शन सेवा
 * 
 * This service provides high-level encryption and decryption operations
 * for secure financial data processing. It implements envelope encryption
 * pattern using AES-256-GCM for content and RSA-OAEP for key wrapping.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
    generateCEK,
    encryptAESGCM,
    decryptAESGCM,
    wrapKeyRSA,
    unwrapKeyRSA,
    loadPublicKey,
    loadPrivateKey,
    generateFingerprint,
    bufferToBase64URL,
    base64URLToBuffer,
    zeroizeBuffer
} = require('../utils/cryptoUtils');
const { logger, logKeyOperation, logSecurityEvent } = require('../utils/logger');

class EncryptionService {
    constructor() {
        // Key paths - in production, these should be in secure key management
        this.publicKeyPath = process.env.RSA_PUBLIC_KEY_PATH || './keys/public.pem';
        this.privateKeyPath = process.env.RSA_PRIVATE_KEY_PATH || './keys/private.pem';

        // Cache for loaded keys (in production, use secure key caching)
        this.keyCache = new Map();

        // Initialize service
        this.initialize();
    }

    /**
     * Initialize encryption service
     * एन्क्रिप्शन सेवा को प्रारंभ करें
     */
    async initialize() {
        try {
            // Verify key files exist
            await this.verifyKeyFiles();

            logger.info('Encryption service initialized successfully', {
                publicKeyPath: this.publicKeyPath,
                privateKeyPath: this.privateKeyPath
            });

        } catch (error) {
            logger.error('Failed to initialize encryption service:', error);
            throw new Error('Encryption service initialization failed');
        }
    }

    /**
     * Verify RSA key files exist and are valid
     * RSA की फाइलों की जांच करें और सत्यापित करें
     */
    async verifyKeyFiles() {
        try {
            // Check if key files exist
            if (!fs.existsSync(this.publicKeyPath)) {
                throw new Error(`Public key file not found: ${this.publicKeyPath}`);
            }

            if (!fs.existsSync(this.privateKeyPath)) {
                throw new Error(`Private key file not found: ${this.privateKeyPath}`);
            }

            // Load and validate keys
            const publicKey = loadPublicKey(this.publicKeyPath);
            const privateKey = loadPrivateKey(this.privateKeyPath);

            // Test key pair by encrypting and decrypting a test message
            const testMessage = Buffer.from('test-key-validation', 'utf8');
            const testCEK = generateCEK();

            const wrappedKey = wrapKeyRSA(testCEK, publicKey);
            const unwrappedKey = unwrapKeyRSA(wrappedKey, privateKey);

            if (!testCEK.equals(unwrappedKey)) {
                throw new Error('Key pair validation failed - keys do not match');
            }

            // Cache validated keys
            this.keyCache.set('public', publicKey);
            this.keyCache.set('private', privateKey);

            logger.info('RSA key pair validation successful');

        } catch (error) {
            logger.error('Key file verification failed:', error);
            throw error;
        }
    }

    /**
     * Get public key (from cache or load)
     * पब्लिक की प्राप्त करें (कैश से या लोड करें)
     */
    getPublicKey() {
        if (this.keyCache.has('public')) {
            return this.keyCache.get('public');
        }

        const publicKey = loadPublicKey(this.publicKeyPath);
        this.keyCache.set('public', publicKey);
        return publicKey;
    }

    /**
     * Get private key (from cache or load)
     * प्राइवेट की प्राप्त करें (कैश से या लोड करें)
     */
    getPrivateKey() {
        if (this.keyCache.has('private')) {
            return this.keyCache.get('private');
        }

        const privateKey = loadPrivateKey(this.privateKeyPath);
        this.keyCache.set('private', privateKey);
        return privateKey;
    }

    /**
     * Encrypt file data using envelope encryption
     * एनवलप एन्क्रिप्शन का उपयोग करके फाइल डेटा एन्क्रिप्ट करें
     * 
     * @param {Buffer} fileData - File data to encrypt
     * @param {Object} metadata - File metadata (name, type, etc.)
     * @param {Object} [user] - User information for audit logging
     * @returns {Object} Encryption result with wrapped key and metadata
     */
    async encryptFile(fileData, metadata, user = null) {
        let cek = null;

        try {
            const startTime = Date.now();

            // Generate a new Content Encryption Key (CEK)
            cek = generateCEK();

            logKeyOperation('GENERATE_CEK', {
                keyType: 'AES-256',
                algorithm: 'AES-256-GCM',
                success: true
            }, user);

            // Encrypt file data with AES-256-GCM
            const encryptionResult = encryptAESGCM(cek, fileData);

            // Wrap (encrypt) CEK with RSA public key
            const publicKey = this.getPublicKey();
            const wrappedCEK = wrapKeyRSA(cek, publicKey);

            logKeyOperation('WRAP_CEK', {
                keyType: 'RSA-OAEP',
                algorithm: 'RSA-OAEP-2048',
                success: true
            }, user);

            // Generate data fingerprint for integrity
            const fingerprint = generateFingerprint(fileData);

            // Create encryption metadata
            const encryptedMetadata = {
                algorithm: 'AES-256-GCM',
                keyAlgorithm: 'RSA-OAEP',
                wrappedCEK: bufferToBase64URL(wrappedCEK),
                iv: bufferToBase64URL(encryptionResult.iv),
                authTag: bufferToBase64URL(encryptionResult.authTag),
                fingerprint: fingerprint,
                originalSize: fileData.length,
                encryptedSize: encryptionResult.ciphertext.length,
                timestamp: new Date().toISOString(),
                version: '1.0'
            };

            // Include original metadata
            if (metadata) {
                encryptedMetadata.originalMetadata = {
                    fileName: metadata.fileName,
                    fileType: metadata.fileType,
                    mimeType: metadata.mimeType
                };
            }

            const processingTime = Date.now() - startTime;

            logSecurityEvent('FILE_ENCRYPTION', {
                fileSize: fileData.length,
                algorithm: 'AES-256-GCM',
                processingTime: `${processingTime}ms`,
                success: true
            }, user);

            logger.info('File encryption completed successfully', {
                originalSize: fileData.length,
                encryptedSize: encryptionResult.ciphertext.length,
                processingTime: `${processingTime}ms`,
                fingerprint: fingerprint.substring(0, 16) + '...'
            });

            return {
                ciphertext: encryptionResult.ciphertext,
                metadata: encryptedMetadata
            };

        } catch (error) {
            logger.error('File encryption failed:', error);

            logSecurityEvent('FILE_ENCRYPTION_FAILED', {
                error: error.message,
                fileSize: fileData ? fileData.length : 0
            }, user);

            throw new Error(`Encryption failed: ${error.message}`);

        } finally {
            // Securely zero out CEK from memory
            if (cek) {
                zeroizeBuffer(cek);
            }
        }
    }

    /**
     * Decrypt file data using envelope decryption
     * एनवलप डिक्रिप्शन का उपयोग करके फाइल डेटा डिक्रिप्ट करें
     * 
     * @param {Buffer} encryptedData - Encrypted file data
     * @param {Object} encryptionMetadata - Encryption metadata
     * @param {Object} [user] - User information for audit logging
     * @returns {Object} Decryption result with original file data
     */
    async decryptFile(encryptedData, encryptionMetadata, user = null) {
        let cek = null;

        try {
            const startTime = Date.now();

            // Validate encryption metadata
            this.validateEncryptionMetadata(encryptionMetadata);

            // Convert base64URL encoded values back to buffers
            const wrappedCEK = base64URLToBuffer(encryptionMetadata.wrappedCEK);
            const iv = base64URLToBuffer(encryptionMetadata.iv);
            const authTag = base64URLToBuffer(encryptionMetadata.authTag);

            // Unwrap (decrypt) CEK with RSA private key
            const privateKey = this.getPrivateKey();
            cek = unwrapKeyRSA(wrappedCEK, privateKey);

            logKeyOperation('UNWRAP_CEK', {
                keyType: 'RSA-OAEP',
                algorithm: 'RSA-OAEP-2048',
                success: true
            }, user);

            // Decrypt file data with AES-256-GCM
            const decryptedData = decryptAESGCM(cek, encryptedData, iv, authTag);

            // Verify data integrity using fingerprint
            const calculatedFingerprint = generateFingerprint(decryptedData);
            if (calculatedFingerprint !== encryptionMetadata.fingerprint) {
                throw new Error('Data integrity verification failed - fingerprint mismatch');
            }

            // Verify original file size
            if (decryptedData.length !== encryptionMetadata.originalSize) {
                throw new Error('Data integrity verification failed - size mismatch');
            }

            const processingTime = Date.now() - startTime;

            logSecurityEvent('FILE_DECRYPTION', {
                encryptedSize: encryptedData.length,
                decryptedSize: decryptedData.length,
                algorithm: 'AES-256-GCM',
                processingTime: `${processingTime}ms`,
                success: true
            }, user);

            logger.info('File decryption completed successfully', {
                encryptedSize: encryptedData.length,
                decryptedSize: decryptedData.length,
                processingTime: `${processingTime}ms`,
                fingerprintVerified: true
            });

            return {
                data: decryptedData,
                metadata: encryptionMetadata.originalMetadata || {},
                verified: true
            };

        } catch (error) {
            logger.error('File decryption failed:', error);

            logSecurityEvent('FILE_DECRYPTION_FAILED', {
                error: error.message,
                encryptedSize: encryptedData ? encryptedData.length : 0
            }, user);

            throw new Error(`Decryption failed: ${error.message}`);

        } finally {
            // Securely zero out CEK from memory
            if (cek) {
                zeroizeBuffer(cek);
            }
        }
    }

    /**
     * Validate encryption metadata
     * एन्क्रिप्शन मेटाडेटा को मान्य करें
     * 
     * @param {Object} metadata - Encryption metadata to validate
     */
    validateEncryptionMetadata(metadata) {
        const requiredFields = [
            'algorithm', 'keyAlgorithm', 'wrappedCEK',
            'iv', 'authTag', 'fingerprint', 'originalSize'
        ];

        for (const field of requiredFields) {
            if (!metadata[field]) {
                throw new Error(`Missing required encryption metadata field: ${field}`);
            }
        }

        // Validate algorithms
        if (metadata.algorithm !== 'AES-256-GCM') {
            throw new Error(`Unsupported encryption algorithm: ${metadata.algorithm}`);
        }

        if (metadata.keyAlgorithm !== 'RSA-OAEP') {
            throw new Error(`Unsupported key wrapping algorithm: ${metadata.keyAlgorithm}`);
        }

        // Validate metadata version compatibility
        if (metadata.version && metadata.version !== '1.0') {
            logger.warn('Encryption metadata version mismatch', {
                expected: '1.0',
                received: metadata.version
            });
        }
    }

    /**
     * Create a secure file bundle with encryption metadata
     * एन्क्रिप्शन मेटाडेटा के साथ सुरक्षित फाइल बंडल बनाएं
     * 
     * @param {Buffer} encryptedData - Encrypted file data
     * @param {Object} metadata - Encryption metadata
     * @returns {Object} Secure file bundle
     */
    createSecureBundle(encryptedData, metadata) {
        try {
            const bundle = {
                version: '1.0',
                type: 'secure-financial-data',
                timestamp: new Date().toISOString(),
                encryptedData: bufferToBase64URL(encryptedData),
                metadata: metadata
            };

            // Add bundle checksum for additional integrity
            const bundleJSON = JSON.stringify(bundle);
            const checksum = crypto.createHash('sha256')
                .update(bundleJSON)
                .digest('hex');

            bundle.checksum = checksum;

            logger.debug('Secure bundle created', {
                bundleSize: bundleJSON.length,
                checksum: checksum.substring(0, 16) + '...'
            });

            return bundle;

        } catch (error) {
            logger.error('Failed to create secure bundle:', error);
            throw new Error(`Bundle creation failed: ${error.message}`);
        }
    }

    /**
     * Verify and extract secure file bundle
     * सुरक्षित फाइल बंडल को सत्यापित और निकालें
     * 
     * @param {Object} bundle - Secure file bundle
     * @returns {Object} Extracted encrypted data and metadata
     */
    extractSecureBundle(bundle) {
        try {
            // Validate bundle structure
            if (!bundle.version || !bundle.type || !bundle.encryptedData || !bundle.metadata) {
                throw new Error('Invalid secure bundle structure');
            }

            if (bundle.type !== 'secure-financial-data') {
                throw new Error('Invalid bundle type');
            }

            // Verify bundle checksum if present
            if (bundle.checksum) {
                const { checksum, ...bundleForVerification } = bundle;
                const calculatedChecksum = crypto.createHash('sha256')
                    .update(JSON.stringify(bundleForVerification))
                    .digest('hex');

                if (checksum !== calculatedChecksum) {
                    throw new Error('Bundle integrity verification failed');
                }
            }

            // Extract encrypted data
            const encryptedData = base64URLToBuffer(bundle.encryptedData);

            logger.debug('Secure bundle extracted successfully', {
                bundleVersion: bundle.version,
                dataSize: encryptedData.length
            });

            return {
                encryptedData,
                metadata: bundle.metadata
            };

        } catch (error) {
            logger.error('Failed to extract secure bundle:', error);
            throw new Error(`Bundle extraction failed: ${error.message}`);
        }
    }

    /**
     * Rotate encryption keys (for key management)
     * एन्क्रिप्शन की घुमाएं (की प्रबंधन के लिए)
     */
    async rotateKeys() {
        try {
            logger.info('Key rotation initiated');

            // Clear key cache to force reload
            this.keyCache.clear();

            // Re-verify new keys
            await this.verifyKeyFiles();

            logSecurityEvent('KEY_ROTATION', {
                success: true,
                timestamp: new Date().toISOString()
            });

            logger.info('Key rotation completed successfully');

        } catch (error) {
            logger.error('Key rotation failed:', error);

            logSecurityEvent('KEY_ROTATION_FAILED', {
                error: error.message,
                timestamp: new Date().toISOString()
            });

            throw new Error(`Key rotation failed: ${error.message}`);
        }
    }

    /**
     * Get encryption service health status
     * एन्क्रिप्शन सेवा स्वास्थ्य स्थिति प्राप्त करें
     */
    async getHealthStatus() {
        try {
            const status = {
                status: 'healthy',
                keyFilesPresent: {
                    public: fs.existsSync(this.publicKeyPath),
                    private: fs.existsSync(this.privateKeyPath)
                },
                keysLoaded: {
                    public: this.keyCache.has('public'),
                    private: this.keyCache.has('private')
                },
                algorithms: {
                    symmetric: 'AES-256-GCM',
                    asymmetric: 'RSA-OAEP',
                    hash: 'SHA-256',
                    kdf: 'Argon2id'
                },
                lastHealthCheck: new Date().toISOString()
            };

            // Test encryption/decryption capability
            const testData = Buffer.from('health-check-test', 'utf8');
            const encrypted = await this.encryptFile(testData, { fileName: 'health-test' });
            const decrypted = await this.decryptFile(encrypted.ciphertext, encrypted.metadata);

            status.operationalTest = testData.equals(decrypted.data);

            return status;

        } catch (error) {
            return {
                status: 'unhealthy',
                error: error.message,
                lastHealthCheck: new Date().toISOString()
            };
        }
    }
}

module.exports = EncryptionService;