/**
 * Key Store Utility
 * की स्टोर उपयोगिता
 * 
 * DEMO IMPLEMENTATION ONLY - Do not use in production!
 * डेमो कार्यान्वयन केवल - उत्पादन में उपयोग न करें!
 * 
 * This module provides a simple in-memory key store for demo purposes.
 * In production, integrate with AWS KMS, Azure Key Vault, HashiCorp Vault, 
 * or another secure key management system.
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { logger, logSecurityEvent } = require('./logger');

class DemoKeyStore {
    constructor() {
        // WARNING: In-memory storage for DEMO ONLY
        // चेतावनी: डेमो के लिए केवल इन-मेमोरी स्टोरेज
        this.keys = new Map();
        this.keyMetadata = new Map();

        // Key store configuration
        this.config = {
            keyDirectory: process.env.KEY_STORE_DIR || './keys/store',
            encryptionKey: this.deriveStoreEncryptionKey(),
            maxKeyAge: 365 * 24 * 60 * 60 * 1000, // 365 days in milliseconds
            rotationInterval: 90 * 24 * 60 * 60 * 1000 // 90 days in milliseconds
        };

        this.initializeKeyStore();
    }

    /**
     * Initialize key store
     * की स्टोर को प्रारंभ करें
     */
    async initializeKeyStore() {
        try {
            // Ensure key directory exists
            await fs.mkdir(this.config.keyDirectory, { recursive: true });

            // Load existing keys (if any)
            await this.loadExistingKeys();

            logger.info('Demo key store initialized', {
                keyDirectory: this.config.keyDirectory,
                loadedKeys: this.keys.size
            });

        } catch (error) {
            logger.error('Key store initialization failed:', error);
            throw new Error(`Key store initialization failed: ${error.message}`);
        }
    }

    /**
     * Store encryption key
     * एन्क्रिप्शन की स्टोर करें
     * 
     * @param {string} keyId - Unique key identifier
     * @param {Buffer} keyData - Key data to store
     * @param {Object} [metadata] - Additional key metadata
     */
    async storeKey(keyId, keyData, metadata = {}) {
        try {
            logger.debug('Storing key', { keyId });

            // Validate inputs
            if (!keyId || typeof keyId !== 'string') {
                throw new Error('Invalid key ID');
            }

            if (!Buffer.isBuffer(keyData)) {
                throw new Error('Key data must be a Buffer');
            }

            // Encrypt key data for storage
            const encryptedKey = this.encryptKeyForStorage(keyData);

            // Create key metadata
            const keyMetadata = {
                keyId,
                createdAt: new Date().toISOString(),
                algorithm: 'AES-256-GCM',
                keySize: keyData.length,
                version: '1.0',
                ...metadata
            };

            // Store in memory (DEMO ONLY)
            this.keys.set(keyId, encryptedKey);
            this.keyMetadata.set(keyId, keyMetadata);

            // Persist to disk for demo persistence
            await this.persistKeyToDisk(keyId, encryptedKey, keyMetadata);

            logSecurityEvent('KEY_STORED', {
                keyId,
                keySize: keyData.length,
                algorithm: keyMetadata.algorithm
            });

            logger.info('Key stored successfully', { keyId });

        } catch (error) {
            logger.error('Key storage failed:', error);
            throw new Error(`Key storage failed: ${error.message}`);
        }
    }

    /**
     * Retrieve encryption key
     * एन्क्रिप्शन की प्राप्त करें
     * 
     * @param {string} keyId - Key identifier
     * @returns {Buffer} Decrypted key data
     */
    async retrieveKey(keyId) {
        try {
            logger.debug('Retrieving key', { keyId });

            if (!keyId || typeof keyId !== 'string') {
                throw new Error('Invalid key ID');
            }

            // Check if key exists in memory
            const encryptedKey = this.keys.get(keyId);
            if (!encryptedKey) {
                // Try to load from disk
                await this.loadKeyFromDisk(keyId);
                const retryEncryptedKey = this.keys.get(keyId);

                if (!retryEncryptedKey) {
                    throw new Error('Key not found');
                }
            }

            // Decrypt key data
            const keyData = this.decryptKeyFromStorage(this.keys.get(keyId));

            // Get key metadata for logging
            const metadata = this.keyMetadata.get(keyId);

            logSecurityEvent('KEY_RETRIEVED', {
                keyId,
                keyAge: metadata ? Date.now() - new Date(metadata.createdAt).getTime() : 0
            });

            logger.debug('Key retrieved successfully', { keyId });

            return keyData;

        } catch (error) {
            logger.error('Key retrieval failed:', error);
            throw new Error(`Key retrieval failed: ${error.message}`);
        }
    }

    /**
     * Delete encryption key
     * एन्क्रिप्शन की हटाएं
     * 
     * @param {string} keyId - Key identifier
     */
    async deleteKey(keyId) {
        try {
            logger.debug('Deleting key', { keyId });

            if (!this.keys.has(keyId)) {
                throw new Error('Key not found');
            }

            // Remove from memory
            this.keys.delete(keyId);
            this.keyMetadata.delete(keyId);

            // Remove from disk
            await this.deleteKeyFromDisk(keyId);

            logSecurityEvent('KEY_DELETED', { keyId });

            logger.info('Key deleted successfully', { keyId });

        } catch (error) {
            logger.error('Key deletion failed:', error);
            throw new Error(`Key deletion failed: ${error.message}`);
        }
    }

    /**
     * List stored keys
     * संग्रहीत कीज़ की सूची बनाएं
     * 
     * @returns {Array} List of key metadata
     */
    async listKeys() {
        try {
            const keyList = [];

            for (const [keyId, metadata] of this.keyMetadata.entries()) {
                keyList.push({
                    keyId,
                    createdAt: metadata.createdAt,
                    algorithm: metadata.algorithm,
                    keySize: metadata.keySize,
                    age: Date.now() - new Date(metadata.createdAt).getTime(),
                    version: metadata.version
                });
            }

            return keyList.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        } catch (error) {
            logger.error('Key listing failed:', error);
            throw new Error(`Key listing failed: ${error.message}`);
        }
    }

    /**
     * Check if key exists
     * जांचें कि की मौजूद है या नहीं
     * 
     * @param {string} keyId - Key identifier
     * @returns {boolean} True if key exists
     */
    async keyExists(keyId) {
        return this.keys.has(keyId);
    }

    /**
     * Rotate old keys
     * पुरानी कीज़ घुमाएं
     */
    async rotateKeys() {
        try {
            logger.info('Starting key rotation');

            const now = Date.now();
            const keysToRotate = [];

            // Find keys older than rotation interval
            for (const [keyId, metadata] of this.keyMetadata.entries()) {
                const keyAge = now - new Date(metadata.createdAt).getTime();
                if (keyAge > this.config.rotationInterval) {
                    keysToRotate.push(keyId);
                }
            }

            if (keysToRotate.length === 0) {
                logger.info('No keys require rotation');
                return { rotated: 0, message: 'No keys require rotation' };
            }

            logger.warn('Keys scheduled for rotation', {
                count: keysToRotate.length,
                keyIds: keysToRotate
            });

            // In production, this would:
            // 1. Generate new keys
            // 2. Re-encrypt data with new keys
            // 3. Safely delete old keys
            // For demo, we just log the requirement

            logSecurityEvent('KEY_ROTATION_REQUIRED', {
                keysToRotate: keysToRotate.length,
                keyIds: keysToRotate
            });

            return {
                rotated: 0,
                message: `${keysToRotate.length} keys require rotation (not implemented in demo)`,
                keyIds: keysToRotate
            };

        } catch (error) {
            logger.error('Key rotation failed:', error);
            throw new Error(`Key rotation failed: ${error.message}`);
        }
    }

    /**
     * Private helper methods
     * निजी सहायक विधियां
     */

    /**
     * Derive encryption key for key store
     * की स्टोर के लिए एन्क्रिप्शन की डेराइव करें
     */
    deriveStoreEncryptionKey() {
        // DEMO ONLY - Use environment variable or secure key derivation
        const keyMaterial = process.env.KEY_STORE_SECRET || 'demo-key-store-secret-change-in-production';
        return crypto.createHash('sha256').update(keyMaterial).digest();
    }

    /**
     * Encrypt key for storage
     * भंडारण के लिए की एन्क्रिप्ट करें
     */
    encryptKeyForStorage(keyData) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipher('aes-256-gcm');
        cipher.setAAD(iv);

        let encrypted = cipher.update(keyData);
        cipher.final();

        const authTag = cipher.getAuthTag();

        return {
            encrypted: Buffer.concat([encrypted]),
            iv: iv,
            authTag: authTag,
            algorithm: 'aes-256-gcm'
        };
    }

    /**
     * Decrypt key from storage
     * भंडारण से की डिक्रिप्ट करें
     */
    decryptKeyFromStorage(encryptedKeyData) {
        const decipher = crypto.createDecipher('aes-256-gcm');
        decipher.setAAD(encryptedKeyData.iv);
        decipher.setAuthTag(encryptedKeyData.authTag);

        let decrypted = decipher.update(encryptedKeyData.encrypted);
        decipher.final();

        return Buffer.concat([decrypted]);
    }

    /**
     * Persist key to disk
     * की को डिस्क पर स्थायी करें
     */
    async persistKeyToDisk(keyId, encryptedKey, metadata) {
        const keyFile = path.join(this.config.keyDirectory, `${keyId}.json`);

        const keyRecord = {
            keyId,
            encryptedKey: {
                encrypted: encryptedKey.encrypted.toString('base64'),
                iv: encryptedKey.iv.toString('base64'),
                authTag: encryptedKey.authTag.toString('base64'),
                algorithm: encryptedKey.algorithm
            },
            metadata
        };

        await fs.writeFile(keyFile, JSON.stringify(keyRecord, null, 2), 'utf8');
    }

    /**
     * Load key from disk
     * डिस्क से की लोड करें
     */
    async loadKeyFromDisk(keyId) {
        const keyFile = path.join(this.config.keyDirectory, `${keyId}.json`);

        try {
            const keyRecord = JSON.parse(await fs.readFile(keyFile, 'utf8'));

            const encryptedKey = {
                encrypted: Buffer.from(keyRecord.encryptedKey.encrypted, 'base64'),
                iv: Buffer.from(keyRecord.encryptedKey.iv, 'base64'),
                authTag: Buffer.from(keyRecord.encryptedKey.authTag, 'base64'),
                algorithm: keyRecord.encryptedKey.algorithm
            };

            this.keys.set(keyId, encryptedKey);
            this.keyMetadata.set(keyId, keyRecord.metadata);

        } catch (error) {
            if (error.code !== 'ENOENT') {
                throw error;
            }
            // File doesn't exist, key not found
        }
    }

    /**
     * Delete key from disk
     * डिस्क से की हटाएं
     */
    async deleteKeyFromDisk(keyId) {
        const keyFile = path.join(this.config.keyDirectory, `${keyId}.json`);

        try {
            await fs.unlink(keyFile);
        } catch (error) {
            if (error.code !== 'ENOENT') {
                throw error;
            }
            // File doesn't exist, already deleted
        }
    }

    /**
     * Load existing keys from disk
     * डिस्क से मौजूदा कीज़ लोड करें
     */
    async loadExistingKeys() {
        try {
            const files = await fs.readdir(this.config.keyDirectory);
            const keyFiles = files.filter(file => file.endsWith('.json'));

            for (const file of keyFiles) {
                const keyId = path.basename(file, '.json');
                await this.loadKeyFromDisk(keyId);
            }

            logger.info('Loaded existing keys from disk', { count: keyFiles.length });

        } catch (error) {
            if (error.code !== 'ENOENT') {
                logger.warn('Failed to load existing keys:', error);
            }
        }
    }

    /**
     * Get key store health status
     * की स्टोर स्वास्थ्य स्थिति प्राप्त करें
     */
    async getHealthStatus() {
        try {
            return {
                status: 'healthy',
                type: 'demo-key-store',
                keysStored: this.keys.size,
                keyDirectory: this.config.keyDirectory,
                rotationInterval: this.config.rotationInterval,
                maxKeyAge: this.config.maxKeyAge,
                warning: 'DEMO ONLY - Replace with secure KMS in production'
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                error: error.message
            };
        }
    }
}

// Export singleton instance
module.exports = new DemoKeyStore();