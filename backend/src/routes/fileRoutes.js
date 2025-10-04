/**
 * File Routes
 * फाइल रूट्स
 * 
 * Defines API routes for file encryption, decryption, processing,
 * and secure financial data handling operations.
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const {
    authenticate,
    authorize,
    requirePermission,
    sanitizeRequest,
    securityHeaders
} = require('../middleware/authMiddleware');
const { handleValidationErrors } = require('../middleware/errorMiddleware');
const { body, param, query } = require('express-validator');
const {
    encryptFile,
    decryptFile,
    processFile,
    getResult,
    searchResults,
    deleteResult,
    getStatus
} = require('../controllers/fileController');

const router = express.Router();

// Apply security headers to all routes
router.use(securityHeaders);

// Apply request sanitization
router.use(sanitizeRequest);

/**
 * Rate limiting for different operations
 * विभिन्न ऑपरेशन्स के लिए दर सीमा
 */

// File upload rate limiting (stricter)
const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 uploads per 15 minutes
    message: {
        error: 'Too many file uploads',
        message: 'Please wait before uploading more files'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Processing rate limiting
const processLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 processing requests per 15 minutes
    message: {
        error: 'Too many processing requests',
        message: 'Please wait before processing more files'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Search rate limiting
const searchLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 searches per 5 minutes
    message: {
        error: 'Too many search requests',
        message: 'Please wait before searching again'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

/**
 * Validation middleware
 * सत्यापन मिडलवेयर
 */

const validateEncryptRequest = [
    // File validation is handled in multer configuration
    body('description')
        .optional()
        .isLength({ max: 500 })
        .withMessage('Description must be less than 500 characters'),
    handleValidationErrors
];

const validateDecryptRequest = [
    body('secureBundle')
        .notEmpty()
        .withMessage('Secure bundle is required')
        .isObject()
        .withMessage('Secure bundle must be a valid object'),
    body('secureBundle.type')
        .equals('secure-financial-data')
        .withMessage('Invalid bundle type'),
    body('secureBundle.version')
        .notEmpty()
        .withMessage('Bundle version is required'),
    handleValidationErrors
];

const validateProcessRequest = [
    body('secureBundle')
        .notEmpty()
        .withMessage('Secure bundle is required')
        .isObject()
        .withMessage('Secure bundle must be a valid object'),
    body('storeResults')
        .optional()
        .isBoolean()
        .withMessage('storeResults must be boolean'),
    body('includeOriginalFile')
        .optional()
        .isBoolean()
        .withMessage('includeOriginalFile must be boolean'),
    handleValidationErrors
];

const validateResultId = [
    param('resultId')
        .isUUID()
        .withMessage('Invalid result ID format'),
    handleValidationErrors
];

const validateSearchQuery = [
    query('fileName')
        .optional()
        .isLength({ min: 1, max: 255 })
        .withMessage('File name must be between 1-255 characters'),
    query('fileType')
        .optional()
        .isIn(['.xlsx', '.pdf'])
        .withMessage('File type must be .xlsx or .pdf'),
    query('status')
        .optional()
        .isIn(['processing', 'completed', 'failed', 'archived'])
        .withMessage('Invalid status'),
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1-100'),
    query('dateFrom')
        .optional()
        .isISO8601()
        .withMessage('dateFrom must be a valid ISO date'),
    query('dateTo')
        .optional()
        .isISO8601()
        .withMessage('dateTo must be a valid ISO date'),
    handleValidationErrors
];

/**
 * File encryption routes
 * फाइल एन्क्रिप्शन रूट्स
 */

/**
 * @route   POST /api/files/encrypt
 * @desc    Upload and encrypt a financial file
 * @access  Private (uploader, processor, admin)
 * @rateLimit 10 uploads per 15 minutes
 */
router.post('/encrypt',
    uploadLimiter,
    authenticate,
    requirePermission('files', 'create'),
    validateEncryptRequest,
    encryptFile
);

/**
 * @route   POST /api/files/decrypt
 * @desc    Decrypt an encrypted file bundle
 * @access  Private (processor, admin)
 * @rateLimit Standard rate limiting
 */
router.post('/decrypt',
    authenticate,
    requirePermission('files', 'decrypt'),
    validateDecryptRequest,
    decryptFile
);

/**
 * File processing routes
 * फाइल प्रोसेसिंग रूट्स
 */

/**
 * @route   POST /api/files/process
 * @desc    Process encrypted file and extract financial metrics
 * @access  Private (processor, admin)
 * @rateLimit 20 requests per 15 minutes
 */
router.post('/process',
    processLimiter,
    authenticate,
    requirePermission('metrics', 'create'),
    validateProcessRequest,
    processFile
);

/**
 * Result management routes
 * रिजल्ट प्रबंधन रूट्स
 */

/**
 * @route   GET /api/files/result/:resultId
 * @desc    Get processed financial analysis result
 * @access  Private (owner, processor, auditor, admin)
 * @query   decrypt=true to return decrypted data
 */
router.get('/result/:resultId',
    authenticate,
    validateResultId,
    getResult
);

/**
 * @route   DELETE /api/files/result/:resultId
 * @desc    Delete stored analysis result
 * @access  Private (owner, admin)
 */
router.delete('/result/:resultId',
    authenticate,
    validateResultId,
    deleteResult
);

/**
 * Search and discovery routes
 * खोज और खोज रूट्स
 */

/**
 * @route   GET /api/files/search
 * @desc    Search encrypted results using HMAC indices
 * @access  Private (authenticated users)
 * @rateLimit 50 searches per 5 minutes
 */
router.get('/search',
    searchLimiter,
    authenticate,
    validateSearchQuery,
    searchResults
);

/**
 * Service status and health routes
 * सेवा स्थिति और स्वास्थ्य रूट्स
 */

/**
 * @route   GET /api/files/status
 * @desc    Get file processing service status
 * @access  Public (for health checks)
 */
router.get('/status', getStatus);

/**
 * Batch operations (Future enhancement)
 * बैच ऑपरेशन्स (भविष्य में सुधार)
 */

/**
 * @route   POST /api/files/batch/encrypt
 * @desc    Encrypt multiple files in batch
 * @access  Private (processor, admin)
 * @note    Future enhancement for bulk operations
 */
router.post('/batch/encrypt',
    authenticate,
    authorize('processor', 'admin'),
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Batch encryption not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * @route   POST /api/files/batch/process
 * @desc    Process multiple files in batch
 * @access  Private (processor, admin)
 * @note    Future enhancement for bulk operations
 */
router.post('/batch/process',
    authenticate,
    authorize('processor', 'admin'),
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Batch processing not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * Analytics and reporting routes
 * एनालिटिक्स और रिपोर्टिंग रूट्स
 */

/**
 * @route   GET /api/files/analytics
 * @desc    Get file processing analytics
 * @access  Private (auditor, admin)
 */
router.get('/analytics',
    authenticate,
    authorize('auditor', 'admin'),
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Analytics endpoint not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * Export functionality
 * एक्सपोर्ट कार्यक्षमता
 */

/**
 * @route   GET /api/files/export/:resultId
 * @desc    Export analysis results in various formats
 * @access  Private (owner, processor, admin)
 */
router.get('/export/:resultId',
    authenticate,
    validateResultId,
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Export functionality not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * Error handling for this router
 * इस राउटर के लिए त्रुटि प्रबंधन
 */
router.use((err, req, res, next) => {
    // Log route-specific errors
    const { logger } = require('../utils/logger');
    logger.error('File route error', {
        error: err.message,
        route: req.originalUrl,
        method: req.method,
        user: req.user?._id
    });

    next(err);
});

module.exports = router;