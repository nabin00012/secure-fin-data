/**
 * Encrypted Result Model
 * एन्क्रिप्टेड रिजल्ट मॉडल
 * 
 * This model stores encrypted financial analysis results in MongoDB.
 * All sensitive data is encrypted before storage using AES-256-GCM.
 * Searchable fields use HMAC-SHA256 for deterministic indexing.
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const {
    encryptAESGCM,
    decryptAESGCM,
    generateHMACIndex,
    generateCEK,
    generateFingerprint
} = require('../utils/cryptoUtils');
const { logger } = require('../utils/logger');

// Schema for storing encrypted financial analysis results
const encryptedResultSchema = new mongoose.Schema({
    // Unique identifier for the result
    resultId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },

    // HMAC-based searchable indexes (deterministic but secure)
    fileNameIndex: {
        type: String,
        index: true,
        required: true
    },

    userIdIndex: {
        type: String,
        index: true,
        sparse: true
    },

    fileTypeIndex: {
        type: String,
        index: true,
        required: true
    },

    // Encrypted file metadata
    encryptedMetadata: {
        // AES-256-GCM encrypted JSON string
        ciphertext: {
            type: Buffer,
            required: true
        },
        iv: {
            type: Buffer,
            required: true
        },
        authTag: {
            type: Buffer,
            required: true
        },
        algorithm: {
            type: String,
            default: 'AES-256-GCM'
        }
    },

    // Encrypted financial metrics data
    encryptedMetrics: {
        // AES-256-GCM encrypted JSON string
        ciphertext: {
            type: Buffer,
            required: true
        },
        iv: {
            type: Buffer,
            required: true
        },
        authTag: {
            type: Buffer,
            required: true
        },
        algorithm: {
            type: String,
            default: 'AES-256-GCM'
        }
    },

    // Encrypted original file data (optional, for audit purposes)
    encryptedFileData: {
        ciphertext: {
            type: Buffer,
            sparse: true
        },
        iv: {
            type: Buffer,
            sparse: true
        },
        authTag: {
            type: Buffer,
            sparse: true
        },
        algorithm: {
            type: String,
            default: 'AES-256-GCM'
        }
    },

    // Key management information
    keyManagement: {
        // ID of the key used for encryption (for key rotation)
        keyId: {
            type: String,
            required: true
        },
        keyVersion: {
            type: String,
            default: '1.0'
        },
        algorithm: {
            type: String,
            default: 'AES-256-GCM'
        }
    },

    // Data integrity and audit fields
    dataIntegrity: {
        // SHA-256 fingerprint of original data
        originalDataFingerprint: {
            type: String,
            required: true
        },
        // SHA-256 fingerprint of encrypted data
        encryptedDataFingerprint: {
            type: String,
            required: true
        },
        // Checksum for additional verification
        checksum: {
            type: String,
            required: true
        }
    },

    // Processing information
    processingInfo: {
        processingTime: {
            type: Number, // milliseconds
            required: true
        },
        processingVersion: {
            type: String,
            default: '1.0'
        },
        metricsCount: {
            type: Number,
            required: true
        },
        extractionMethod: {
            type: String,
            enum: ['excel', 'pdf', 'manual'],
            required: true
        }
    },

    // Status and lifecycle
    status: {
        type: String,
        enum: ['processing', 'completed', 'failed', 'archived'],
        default: 'processing',
        index: true
    },

    // Access control
    accessControl: {
        ownerId: {
            type: String,
            required: true,
            index: true
        },
        allowedUsers: [{
            userId: String,
            permissions: {
                type: [String],
                enum: ['read', 'decrypt', 'delete', 'share'],
                default: ['read']
            }
        }],
        isPublic: {
            type: Boolean,
            default: false
        }
    },

    // Audit trail
    auditTrail: {
        createdAt: {
            type: Date,
            default: Date.now,
            index: true
        },
        updatedAt: {
            type: Date,
            default: Date.now
        },
        accessCount: {
            type: Number,
            default: 0
        },
        lastAccessedAt: {
            type: Date,
            default: Date.now
        },
        lastAccessedBy: {
            type: String
        }
    },

    // Retention policy
    retention: {
        expiresAt: {
            type: Date,
            index: { expireAfterSeconds: 0 }
        },
        retentionPeriod: {
            type: Number, // days
            default: 365
        }
    }
}, {
    timestamps: true,
    collection: 'encryptedResults'
});

/**
 * Static methods for encryption operations
 */
encryptedResultSchema.statics = {

    /**
     * Create encrypted result with all data encrypted
     * सभी डेटा एन्क्रिप्टेड के साथ एन्क्रिप्टेड रिजल्ट बनाएं
     * 
     * @param {Object} resultData - Result data to encrypt and store
     * @param {Object} user - User information
     * @returns {Object} Created encrypted result
     */
    async createEncryptedResult(resultData, user) {
        try {
            logger.info('Creating encrypted result', {
                userId: user?.id,
                fileName: resultData.fileMetadata?.fileName
            });

            // Generate encryption key for this result
            const encryptionKey = generateCEK();
            const keyId = crypto.randomUUID();

            // Generate HMAC indices for searchability
            const hmacKey = process.env.HMAC_SECRET || 'default-hmac-key';

            const fileNameIndex = generateHMACIndex(
                resultData.fileMetadata?.fileName || 'unknown',
                hmacKey
            );
            const userIdIndex = user?.id ? generateHMACIndex(user.id, hmacKey) : null;
            const fileTypeIndex = generateHMACIndex(
                resultData.fileMetadata?.fileType || 'unknown',
                hmacKey
            );

            // Encrypt metadata
            const metadataJSON = JSON.stringify(resultData.fileMetadata || {});
            const encryptedMetadata = encryptAESGCM(
                encryptionKey,
                Buffer.from(metadataJSON, 'utf8')
            );

            // Encrypt metrics
            const metricsJSON = JSON.stringify(resultData.metrics || {});
            const encryptedMetrics = encryptAESGCM(
                encryptionKey,
                Buffer.from(metricsJSON, 'utf8')
            );

            // Encrypt original file data if provided
            let encryptedFileData = null;
            if (resultData.originalFileData) {
                encryptedFileData = encryptAESGCM(encryptionKey, resultData.originalFileData);
            }

            // Generate fingerprints and checksums
            const originalDataFingerprint = generateFingerprint(
                Buffer.from(metadataJSON + metricsJSON, 'utf8')
            );

            const encryptedDataBuffer = Buffer.concat([
                encryptedMetadata.ciphertext,
                encryptedMetrics.ciphertext
            ]);
            const encryptedDataFingerprint = generateFingerprint(encryptedDataBuffer);

            const checksum = crypto.createHash('sha256')
                .update(originalDataFingerprint + encryptedDataFingerprint)
                .digest('hex');

            // Calculate retention expiry
            const retentionPeriod = resultData.retentionDays || 365;
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + retentionPeriod);

            // Create the encrypted result document
            const encryptedResult = new this({
                resultId: crypto.randomUUID(),
                fileNameIndex,
                userIdIndex,
                fileTypeIndex,

                encryptedMetadata: {
                    ciphertext: encryptedMetadata.ciphertext,
                    iv: encryptedMetadata.iv,
                    authTag: encryptedMetadata.authTag
                },

                encryptedMetrics: {
                    ciphertext: encryptedMetrics.ciphertext,
                    iv: encryptedMetrics.iv,
                    authTag: encryptedMetrics.authTag
                },

                encryptedFileData: encryptedFileData ? {
                    ciphertext: encryptedFileData.ciphertext,
                    iv: encryptedFileData.iv,
                    authTag: encryptedFileData.authTag
                } : undefined,

                keyManagement: {
                    keyId: keyId,
                    keyVersion: '1.0',
                    algorithm: 'AES-256-GCM'
                },

                dataIntegrity: {
                    originalDataFingerprint,
                    encryptedDataFingerprint,
                    checksum
                },

                processingInfo: {
                    processingTime: resultData.processingInfo?.processingTime || 0,
                    metricsCount: Object.keys(resultData.metrics || {}).length,
                    extractionMethod: resultData.processingInfo?.extractionMethod || 'unknown'
                },

                status: 'completed',

                accessControl: {
                    ownerId: user?.id || 'system',
                    allowedUsers: [],
                    isPublic: false
                },

                retention: {
                    expiresAt,
                    retentionPeriod
                }
            });

            // Save to database
            const saved = await encryptedResult.save();

            // Store encryption key securely (in production, use KMS)
            await this.storeEncryptionKey(keyId, encryptionKey);

            logger.info('Encrypted result created successfully', {
                resultId: saved.resultId,
                keyId: keyId,
                metricsCount: saved.processingInfo.metricsCount
            });

            return {
                resultId: saved.resultId,
                keyId: keyId,
                status: saved.status,
                createdAt: saved.auditTrail.createdAt
            };

        } catch (error) {
            logger.error('Failed to create encrypted result:', error);
            throw new Error(`Encrypted result creation failed: ${error.message}`);
        }
    },

    /**
     * Retrieve and decrypt result
     * रिजल्ट को प्राप्त और डिक्रिप्ट करें
     * 
     * @param {string} resultId - Result ID to retrieve
     * @param {Object} user - User requesting the data
     * @returns {Object} Decrypted result data
     */
    async getDecryptedResult(resultId, user) {
        try {
            logger.info('Retrieving encrypted result', { resultId, userId: user?.id });

            // Find the encrypted result
            const encryptedResult = await this.findOne({ resultId });

            if (!encryptedResult) {
                throw new Error('Result not found');
            }

            // Check access permissions
            if (!this.checkAccess(encryptedResult, user)) {
                throw new Error('Access denied');
            }

            // Retrieve encryption key (in production, use KMS)
            const encryptionKey = await this.retrieveEncryptionKey(
                encryptedResult.keyManagement.keyId
            );

            // Decrypt metadata
            const decryptedMetadata = decryptAESGCM(
                encryptionKey,
                encryptedResult.encryptedMetadata.ciphertext,
                encryptedResult.encryptedMetadata.iv,
                encryptedResult.encryptedMetadata.authTag
            );
            const metadata = JSON.parse(decryptedMetadata.toString('utf8'));

            // Decrypt metrics
            const decryptedMetrics = decryptAESGCM(
                encryptionKey,
                encryptedResult.encryptedMetrics.ciphertext,
                encryptedResult.encryptedMetrics.iv,
                encryptedResult.encryptedMetrics.authTag
            );
            const metrics = JSON.parse(decryptedMetrics.toString('utf8'));

            // Update access tracking
            await this.updateOne(
                { resultId },
                {
                    $inc: { 'auditTrail.accessCount': 1 },
                    $set: {
                        'auditTrail.lastAccessedAt': new Date(),
                        'auditTrail.lastAccessedBy': user?.id || 'anonymous'
                    }
                }
            );

            logger.info('Result decrypted successfully', {
                resultId,
                userId: user?.id,
                accessCount: encryptedResult.auditTrail.accessCount + 1
            });

            return {
                resultId: encryptedResult.resultId,
                metadata,
                metrics,
                processingInfo: encryptedResult.processingInfo,
                status: encryptedResult.status,
                auditTrail: encryptedResult.auditTrail
            };

        } catch (error) {
            logger.error('Failed to retrieve encrypted result:', error);
            throw new Error(`Result retrieval failed: ${error.message}`);
        }
    },

    /**
     * Search encrypted results using HMAC indices
     * HMAC इंडेक्स का उपयोग करके एन्क्रिप्टेड रिजल्ट खोजें
     * 
     * @param {Object} searchCriteria - Search criteria
     * @param {Object} user - User performing search
     * @returns {Array} Search results
     */
    async searchEncryptedResults(searchCriteria, user) {
        try {
            const hmacKey = process.env.HMAC_SECRET || 'default-hmac-key';
            const query = {};

            // Build searchable query using HMAC indices
            if (searchCriteria.fileName) {
                query.fileNameIndex = generateHMACIndex(searchCriteria.fileName, hmacKey);
            }

            if (searchCriteria.fileType) {
                query.fileTypeIndex = generateHMACIndex(searchCriteria.fileType, hmacKey);
            }

            if (user?.id) {
                query.$or = [
                    { 'accessControl.ownerId': user.id },
                    { userIdIndex: generateHMACIndex(user.id, hmacKey) },
                    { 'accessControl.isPublic': true }
                ];
            }

            if (searchCriteria.status) {
                query.status = searchCriteria.status;
            }

            // Add date range if specified
            if (searchCriteria.dateFrom || searchCriteria.dateTo) {
                query['auditTrail.createdAt'] = {};
                if (searchCriteria.dateFrom) {
                    query['auditTrail.createdAt'].$gte = new Date(searchCriteria.dateFrom);
                }
                if (searchCriteria.dateTo) {
                    query['auditTrail.createdAt'].$lte = new Date(searchCriteria.dateTo);
                }
            }

            // Execute search with pagination
            const page = parseInt(searchCriteria.page) || 1;
            const limit = parseInt(searchCriteria.limit) || 20;
            const skip = (page - 1) * limit;

            const results = await this.find(query)
                .select('resultId status processingInfo auditTrail accessControl keyManagement')
                .sort({ 'auditTrail.createdAt': -1 })
                .skip(skip)
                .limit(limit)
                .lean();

            const total = await this.countDocuments(query);

            logger.info('Search completed', {
                userId: user?.id,
                resultsFound: results.length,
                totalResults: total,
                searchCriteria: Object.keys(searchCriteria)
            });

            return {
                results: results.map(result => ({
                    resultId: result.resultId,
                    status: result.status,
                    createdAt: result.auditTrail.createdAt,
                    metricsCount: result.processingInfo.metricsCount,
                    extractionMethod: result.processingInfo.extractionMethod,
                    isOwner: result.accessControl.ownerId === user?.id
                })),
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            };

        } catch (error) {
            logger.error('Search failed:', error);
            throw new Error(`Search failed: ${error.message}`);
        }
    },

    /**
     * Check if user has access to result
     * जांचें कि उपयोगकर्ता के पास रिजल्ट तक पहुंच है या नहीं
     * 
     * @param {Object} encryptedResult - Encrypted result document
     * @param {Object} user - User to check access for
     * @returns {boolean} True if user has access
     */
    checkAccess(encryptedResult, user) {
        if (!user) return false;

        // Owner has full access
        if (encryptedResult.accessControl.ownerId === user.id) {
            return true;
        }

        // Check if public
        if (encryptedResult.accessControl.isPublic) {
            return true;
        }

        // Check allowed users list
        const allowedUser = encryptedResult.accessControl.allowedUsers.find(
            u => u.userId === user.id
        );

        return !!allowedUser;
    },

    /**
     * Store encryption key securely
     * एन्क्रिप्शन की को सुरक्षित रूप से संग्रहीत करें
     * 
     * In production, this should integrate with a proper KMS
     * प्रोडक्शन में, यह उचित KMS के साथ एकीकृत होना चाहिए
     * 
     * @param {string} keyId - Key identifier
     * @param {Buffer} key - Encryption key
     */
    async storeEncryptionKey(keyId, key) {
        // DEMO ONLY - In production, use AWS KMS, Azure Key Vault, or HashiCorp Vault
        // डेमो केवल - प्रोडक्शन में AWS KMS, Azure Key Vault, या HashiCorp Vault का उपयोग करें

        const keyStore = require('../utils/keyStore');
        await keyStore.storeKey(keyId, key);
    },

    /**
     * Retrieve encryption key securely
     * एन्क्रिप्शन की को सुरक्षित रूप से प्राप्त करें
     * 
     * @param {string} keyId - Key identifier
     * @returns {Buffer} Encryption key
     */
    async retrieveEncryptionKey(keyId) {
        // DEMO ONLY - In production, use proper KMS
        // डेमो केवल - प्रोडक्शन में उचित KMS का उपयोग करें

        const keyStore = require('../utils/keyStore');
        return await keyStore.retrieveKey(keyId);
    }
};

// Indexes for performance and security
encryptedResultSchema.index({ resultId: 1 }, { unique: true });
encryptedResultSchema.index({ fileNameIndex: 1, userIdIndex: 1 });
encryptedResultSchema.index({ 'accessControl.ownerId': 1, 'auditTrail.createdAt': -1 });
encryptedResultSchema.index({ status: 1, 'auditTrail.createdAt': -1 });
encryptedResultSchema.index({ 'retention.expiresAt': 1 }, { expireAfterSeconds: 0 });

// Middleware for audit logging
encryptedResultSchema.pre('save', function (next) {
    if (this.isModified() && !this.isNew) {
        this.auditTrail.updatedAt = new Date();
    }
    next();
});

encryptedResultSchema.pre('findOneAndUpdate', function (next) {
    this.set({ 'auditTrail.updatedAt': new Date() });
    next();
});

const EncryptedResult = mongoose.model('EncryptedResult', encryptedResultSchema);

module.exports = EncryptedResult;