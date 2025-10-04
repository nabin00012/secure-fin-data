/**
 * File Controller
 * फाइल कंट्रोलर
 * 
 * This controller handles file encryption, decryption, processing,
 * and secure storage operations for financial data files.
 */

const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const EncryptionService = require('../services/encryptionService');
const MetricService = require('../services/metricService');
const EncryptedResult = require('../models/EncryptedResult');
const { logger, logFileOperation } = require('../utils/logger');
const { catchAsync, AppError } = require('../middleware/errorMiddleware');

// Initialize services
const encryptionService = new EncryptionService();
const metricService = new MetricService();

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB default
        files: 1
    },
    fileFilter: (req, file, cb) => {
        // Check allowed file types
        const allowedTypes = (process.env.ALLOWED_FILE_TYPES || '.xlsx,.pdf').split(',');
        const fileExt = path.extname(file.originalname).toLowerCase();

        if (allowedTypes.includes(fileExt)) {
            cb(null, true);
        } else {
            cb(new AppError(`File type ${fileExt} not allowed. Allowed types: ${allowedTypes.join(', ')}`, 400, 'INVALID_FILE_TYPE'));
        }
    }
}).single('file');

/**
 * Upload and encrypt file
 * फाइल अपलोड और एन्क्रिप्ट करें
 * 
 * POST /api/files/encrypt
 * Accepts a file, encrypts it, and returns encryption metadata
 */
const encryptFile = catchAsync(async (req, res) => {
    // Handle file upload
    upload(req, res, async (err) => {
        if (err) {
            if (err instanceof multer.MulterError) {
                if (err.code === 'LIMIT_FILE_SIZE') {
                    throw new AppError('File size too large', 413, 'FILE_TOO_LARGE');
                }
                throw new AppError(`Upload error: ${err.message}`, 400, 'UPLOAD_ERROR');
            }
            throw err;
        }

        if (!req.file) {
            throw new AppError('No file provided', 400, 'NO_FILE');
        }

        const startTime = Date.now();

        // Prepare file metadata
        const fileMetadata = {
            fileName: req.file.originalname,
            fileType: path.extname(req.file.originalname).toLowerCase(),
            mimeType: req.file.mimetype,
            fileSize: req.file.size,
            uploadedAt: new Date().toISOString()
        };

        logger.info('Starting file encryption', {
            fileName: fileMetadata.fileName,
            fileSize: fileMetadata.fileSize,
            user: req.user?.email
        });

        try {
            // Encrypt the file
            const encryptionResult = await encryptionService.encryptFile(
                req.file.buffer,
                fileMetadata,
                req.user
            );

            // Create secure bundle
            const secureBundle = encryptionService.createSecureBundle(
                encryptionResult.ciphertext,
                encryptionResult.metadata
            );

            const processingTime = Date.now() - startTime;

            // Log file operation
            logFileOperation('ENCRYPT_FILE', fileMetadata.fileName, {
                fileSize: fileMetadata.fileSize,
                fileType: fileMetadata.fileType,
                processingTime,
                encrypted: true,
                success: true
            }, req.user);

            logger.info('File encrypted successfully', {
                fileName: fileMetadata.fileName,
                processingTime: `${processingTime}ms`,
                bundleSize: JSON.stringify(secureBundle).length
            });

            res.status(200).json({
                status: 'success',
                message: 'File encrypted successfully',
                data: {
                    fileId: encryptionResult.metadata.fingerprint,
                    encryptionMetadata: {
                        algorithm: encryptionResult.metadata.algorithm,
                        keyAlgorithm: encryptionResult.metadata.keyAlgorithm,
                        originalSize: encryptionResult.metadata.originalSize,
                        encryptedSize: encryptionResult.metadata.encryptedSize,
                        timestamp: encryptionResult.metadata.timestamp
                    },
                    secureBundle: secureBundle,
                    processingTime: `${processingTime}ms`
                }
            });

        } catch (error) {
            logFileOperation('ENCRYPT_FILE_FAILED', fileMetadata.fileName, {
                fileSize: fileMetadata.fileSize,
                fileType: fileMetadata.fileType,
                error: error.message,
                success: false
            }, req.user);

            throw new AppError(`File encryption failed: ${error.message}`, 500, 'ENCRYPTION_FAILED');
        }
    });
});

/**
 * Decrypt file
 * फाइल डिक्रिप्ट करें
 * 
 * POST /api/files/decrypt
 * Accepts encrypted bundle and returns decrypted file
 */
const decryptFile = catchAsync(async (req, res) => {
    const { secureBundle } = req.body;

    if (!secureBundle) {
        throw new AppError('Secure bundle is required', 400, 'NO_BUNDLE');
    }

    const startTime = Date.now();

    try {
        logger.info('Starting file decryption', {
            bundleType: secureBundle.type,
            user: req.user?.email
        });

        // Extract encrypted data from bundle
        const { encryptedData, metadata } = encryptionService.extractSecureBundle(secureBundle);

        // Decrypt the file
        const decryptionResult = await encryptionService.decryptFile(
            encryptedData,
            metadata,
            req.user
        );

        const processingTime = Date.now() - startTime;

        // Log file operation
        logFileOperation('DECRYPT_FILE', metadata.originalMetadata?.fileName || 'unknown', {
            fileSize: decryptionResult.data.length,
            fileType: metadata.originalMetadata?.fileType,
            processingTime,
            encrypted: false,
            success: true
        }, req.user);

        logger.info('File decrypted successfully', {
            fileName: metadata.originalMetadata?.fileName,
            processingTime: `${processingTime}ms`,
            decryptedSize: decryptionResult.data.length
        });

        // Set appropriate headers for file download
        const fileName = metadata.originalMetadata?.fileName || 'decrypted-file';
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.setHeader('Content-Type', metadata.originalMetadata?.mimeType || 'application/octet-stream');
        res.setHeader('Content-Length', decryptionResult.data.length);

        res.status(200).send(decryptionResult.data);

    } catch (error) {
        logFileOperation('DECRYPT_FILE_FAILED', 'unknown', {
            error: error.message,
            success: false
        }, req.user);

        throw new AppError(`File decryption failed: ${error.message}`, 500, 'DECRYPTION_FAILED');
    }
});

/**
 * Process file and extract metrics
 * फाइल प्रोसेस करें और मेट्रिक्स निकालें
 * 
 * POST /api/files/process
 * Decrypts file, extracts financial metrics, and stores encrypted results
 */
const processFile = catchAsync(async (req, res) => {
    const { secureBundle, storeResults = true } = req.body;

    if (!secureBundle) {
        throw new AppError('Secure bundle is required', 400, 'NO_BUNDLE');
    }

    const startTime = Date.now();

    try {
        logger.info('Starting file processing', {
            bundleType: secureBundle.type,
            user: req.user?.email
        });

        // Step 1: Extract and decrypt file
        const { encryptedData, metadata } = encryptionService.extractSecureBundle(secureBundle);
        const decryptionResult = await encryptionService.decryptFile(
            encryptedData,
            metadata,
            req.user
        );

        // Step 2: Process file and extract metrics
        const processingResult = await metricService.processFinancialFile(
            decryptionResult.data,
            metadata.originalMetadata,
            req.user
        );

        const processingTime = Date.now() - startTime;

        let resultId = null;

        // Step 3: Store encrypted results if requested
        if (storeResults) {
            const resultData = {
                fileMetadata: metadata.originalMetadata,
                metrics: processingResult.metrics,
                originalFileData: req.body.includeOriginalFile ? decryptionResult.data : null,
                processingInfo: {
                    processingTime,
                    extractionMethod: metadata.originalMetadata?.fileType?.includes('xlsx') ? 'excel' : 'pdf'
                }
            };

            const storageResult = await EncryptedResult.createEncryptedResult(resultData, req.user);
            resultId = storageResult.resultId;
        }

        // Log processing operation
        logFileOperation('PROCESS_FILE', metadata.originalMetadata?.fileName || 'unknown', {
            fileSize: decryptionResult.data.length,
            fileType: metadata.originalMetadata?.fileType,
            processingTime,
            metricsCalculated: Object.keys(processingResult.metrics).length,
            stored: storeResults,
            resultId,
            success: true
        }, req.user);

        logger.info('File processing completed', {
            fileName: metadata.originalMetadata?.fileName,
            processingTime: `${processingTime}ms`,
            metricsCount: Object.keys(processingResult.metrics).length,
            resultId
        });

        // Return processing results
        res.status(200).json({
            status: 'success',
            message: 'File processed successfully',
            data: {
                resultId,
                fileMetadata: processingResult.fileMetadata,
                metrics: processingResult.metrics,
                processingInfo: {
                    ...processingResult.processingInfo,
                    totalProcessingTime: `${processingTime}ms`
                },
                summary: generateProcessingSummary(processingResult.metrics)
            }
        });

    } catch (error) {
        logFileOperation('PROCESS_FILE_FAILED', 'unknown', {
            error: error.message,
            success: false
        }, req.user);

        throw new AppError(`File processing failed: ${error.message}`, 500, 'PROCESSING_FAILED');
    }
});

/**
 * Get processed result
 * प्रोसेस्ड रिजल्ट प्राप्त करें
 * 
 * GET /api/files/result/:resultId
 * Retrieves and decrypts stored financial analysis results
 */
const getResult = catchAsync(async (req, res) => {
    const { resultId } = req.params;
    const { decrypt = false } = req.query;

    if (!resultId) {
        throw new AppError('Result ID is required', 400, 'NO_RESULT_ID');
    }

    try {
        logger.info('Retrieving result', { resultId, user: req.user?.email });

        if (decrypt) {
            // Decrypt and return full result
            const result = await EncryptedResult.getDecryptedResult(resultId, req.user);

            res.status(200).json({
                status: 'success',
                message: 'Result retrieved and decrypted successfully',
                data: result
            });
        } else {
            // Return metadata only (no decryption)
            const encryptedResult = await EncryptedResult.findOne({ resultId });

            if (!encryptedResult) {
                throw new AppError('Result not found', 404, 'RESULT_NOT_FOUND');
            }

            // Check access permissions
            if (!EncryptedResult.checkAccess(encryptedResult, req.user)) {
                throw new AppError('Access denied to this result', 403, 'ACCESS_DENIED');
            }

            res.status(200).json({
                status: 'success',
                message: 'Result metadata retrieved successfully',
                data: {
                    resultId: encryptedResult.resultId,
                    status: encryptedResult.status,
                    processingInfo: encryptedResult.processingInfo,
                    auditTrail: encryptedResult.auditTrail,
                    accessControl: {
                        isOwner: encryptedResult.accessControl.ownerId === req.user?._id?.toString(),
                        isPublic: encryptedResult.accessControl.isPublic
                    }
                }
            });
        }

    } catch (error) {
        throw new AppError(`Result retrieval failed: ${error.message}`, 500, 'RETRIEVAL_FAILED');
    }
});

/**
 * Search results
 * रिजल्ट खोजें
 * 
 * GET /api/files/search
 * Search encrypted results using HMAC indices
 */
const searchResults = catchAsync(async (req, res) => {
    const searchCriteria = {
        fileName: req.query.fileName,
        fileType: req.query.fileType,
        status: req.query.status,
        dateFrom: req.query.dateFrom,
        dateTo: req.query.dateTo,
        page: req.query.page || 1,
        limit: req.query.limit || 20
    };

    try {
        logger.info('Searching results', {
            searchCriteria: Object.keys(searchCriteria).filter(k => searchCriteria[k]),
            user: req.user?.email
        });

        const searchResults = await EncryptedResult.searchEncryptedResults(searchCriteria, req.user);

        res.status(200).json({
            status: 'success',
            message: 'Search completed successfully',
            data: searchResults
        });

    } catch (error) {
        throw new AppError(`Search failed: ${error.message}`, 500, 'SEARCH_FAILED');
    }
});

/**
 * Delete result
 * रिजल्ट हटाएं
 * 
 * DELETE /api/files/result/:resultId
 * Securely delete stored analysis result
 */
const deleteResult = catchAsync(async (req, res) => {
    const { resultId } = req.params;

    if (!resultId) {
        throw new AppError('Result ID is required', 400, 'NO_RESULT_ID');
    }

    try {
        const encryptedResult = await EncryptedResult.findOne({ resultId });

        if (!encryptedResult) {
            throw new AppError('Result not found', 404, 'RESULT_NOT_FOUND');
        }

        // Check if user can delete (owner or admin)
        const canDelete = encryptedResult.accessControl.ownerId === req.user?._id?.toString() ||
            req.user?.role === 'admin';

        if (!canDelete) {
            throw new AppError('Permission denied - you can only delete your own results', 403, 'DELETE_DENIED');
        }

        // Securely delete the result
        await EncryptedResult.deleteOne({ resultId });

        // Log deletion operation
        logFileOperation('DELETE_RESULT', resultId, {
            deletedBy: req.user._id,
            success: true
        }, req.user);

        logger.info('Result deleted successfully', {
            resultId,
            deletedBy: req.user?.email
        });

        res.status(200).json({
            status: 'success',
            message: 'Result deleted successfully',
            data: { resultId }
        });

    } catch (error) {
        throw new AppError(`Result deletion failed: ${error.message}`, 500, 'DELETION_FAILED');
    }
});

/**
 * Get file processing status
 * फाइल प्रोसेसिंग स्थिति प्राप्त करें
 * 
 * GET /api/files/status
 * Returns service health and processing capabilities
 */
const getStatus = catchAsync(async (req, res) => {
    try {
        const encryptionStatus = await encryptionService.getHealthStatus();
        const metricStatus = metricService.getHealthStatus();

        res.status(200).json({
            status: 'success',
            message: 'Service status retrieved successfully',
            data: {
                encryption: encryptionStatus,
                metrics: metricStatus,
                supportedFileTypes: ['.xlsx', '.pdf'],
                maxFileSize: process.env.MAX_FILE_SIZE || '10MB',
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        throw new AppError(`Status check failed: ${error.message}`, 500, 'STATUS_CHECK_FAILED');
    }
});

/**
 * Utility Functions
 * उपकरण कार्य
 */

/**
 * Generate processing summary
 * प्रोसेसिंग सारांश जेनरेट करें
 */
const generateProcessingSummary = (metrics) => {
    const summary = {
        totalMetrics: 0,
        categories: [],
        keyFindings: []
    };

    Object.keys(metrics).forEach(category => {
        if (typeof metrics[category] === 'object') {
            const categoryMetrics = Object.keys(metrics[category]).length;
            summary.totalMetrics += categoryMetrics;
            summary.categories.push({
                category,
                metricsCount: categoryMetrics
            });
        }
    });

    // Add key findings from summary if available
    if (metrics.summary && metrics.summary.keyInsights) {
        summary.keyFindings = metrics.summary.keyInsights.slice(0, 3);
    }

    return summary;
};

module.exports = {
    encryptFile,
    decryptFile,
    processFile,
    getResult,
    searchResults,
    deleteResult,
    getStatus
};