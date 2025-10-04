/**
 * Error Handling Middleware
 * त्रुटि प्रबंधन मिडलवेयर
 * 
 * This middleware provides centralized error handling for the application
 * with proper logging, sanitization, and user-friendly error responses.
 */

const { logger, logSecurityEvent } = require('../utils/logger');

/**
 * Development Error Response
 * डेवलपमेंट त्रुटि प्रतिक्रिया
 * 
 * Detailed error information for development environment
 */
const sendErrorDev = (err, req, res) => {
    const errorResponse = {
        status: 'error',
        error: {
            name: err.name,
            message: err.message,
            stack: err.stack,
            statusCode: err.statusCode || 500
        },
        request: {
            method: req.method,
            url: req.originalUrl,
            headers: sanitizeHeaders(req.headers),
            body: sanitizeRequestBody(req.body),
            user: req.user ? {
                id: req.user._id,
                email: req.user.email,
                role: req.user.role
            } : null
        },
        timestamp: new Date().toISOString()
    };

    // Log detailed error in development
    logger.error('Development Error Details', errorResponse);

    res.status(err.statusCode || 500).json(errorResponse);
};

/**
 * Production Error Response
 * प्रोडक्शन त्रुटि प्रतिक्रिया
 * 
 * Sanitized error information for production environment
 */
const sendErrorProd = (err, req, res) => {
    // Operational errors: send message to client
    if (err.isOperational) {
        const errorResponse = {
            status: 'error',
            message: err.message,
            code: err.code || 'OPERATIONAL_ERROR',
            timestamp: new Date().toISOString()
        };

        res.status(err.statusCode || 500).json(errorResponse);
    }
    // Programming errors: don't leak error details
    else {
        // Log error for internal monitoring
        logger.error('Programming Error', {
            name: err.name,
            message: err.message,
            stack: err.stack,
            url: req.originalUrl,
            method: req.method,
            user: req.user?._id,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        // Send generic message to client
        const errorResponse = {
            status: 'error',
            message: 'Something went wrong on our end. Please try again later.',
            code: 'INTERNAL_ERROR',
            timestamp: new Date().toISOString(),
            requestId: req.id || generateRequestId()
        };

        res.status(500).json(errorResponse);
    }
};

/**
 * Main Error Handling Middleware
 * मुख्य त्रुटि प्रबंधन मिडलवेयर
 */
const errorHandler = (err, req, res, next) => {
    // Set default error properties
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    // Log security-related errors
    if (isSecurityError(err)) {
        logSecurityEvent('SECURITY_ERROR', {
            error: err.name,
            message: sanitizeErrorMessage(err.message),
            url: req.originalUrl,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            statusCode: err.statusCode
        }, req.user);
    }

    // Handle different types of errors
    let error = { ...err };
    error.message = err.message;

    // MongoDB cast error
    if (err.name === 'CastError') {
        error = handleCastErrorDB(error);
    }

    // MongoDB duplicate key error
    if (err.code === 11000) {
        error = handleDuplicateFieldsDB(error);
    }

    // MongoDB validation error
    if (err.name === 'ValidationError') {
        error = handleValidationErrorDB(error);
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        error = handleJWTError();
    }

    if (err.name === 'TokenExpiredError') {
        error = handleJWTExpiredError();
    }

    // Multer file upload errors
    if (err.code === 'LIMIT_FILE_SIZE') {
        error = handleFileUploadError(error);
    }

    // Rate limiting errors
    if (err.statusCode === 429) {
        error = handleRateLimitError(error);
    }

    // Encryption/Decryption errors
    if (err.message.includes('Encryption') || err.message.includes('Decryption')) {
        error = handleCryptoError(error);
    }

    // Send error response based on environment
    if (process.env.NODE_ENV === 'development') {
        sendErrorDev(error, req, res);
    } else {
        sendErrorProd(error, req, res);
    }
};

/**
 * 404 Not Found Handler
 * 404 नहीं मिला हैंडलर
 */
const notFound = (req, res, next) => {
    const error = new Error(`Route ${req.originalUrl} not found`);
    error.statusCode = 404;
    error.isOperational = true;
    error.code = 'ROUTE_NOT_FOUND';

    // Log 404 errors for monitoring
    logger.warn('Route not found', {
        url: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        user: req.user?._id
    });

    next(error);
};

/**
 * Specific Error Handlers
 * विशिष्ट त्रुटि हैंडलर
 */

/**
 * Handle MongoDB cast errors
 */
const handleCastErrorDB = (err) => {
    const message = `Invalid ${err.path}: ${err.value}`;
    const error = new Error(message);
    error.statusCode = 400;
    error.isOperational = true;
    error.code = 'INVALID_DATA_FORMAT';
    return error;
};

/**
 * Handle MongoDB duplicate field errors
 */
const handleDuplicateFieldsDB = (err) => {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    const message = `${field} '${value}' already exists`;

    const error = new Error(message);
    error.statusCode = 400;
    error.isOperational = true;
    error.code = 'DUPLICATE_FIELD';
    return error;
};

/**
 * Handle MongoDB validation errors
 */
const handleValidationErrorDB = (err) => {
    const errors = Object.values(err.errors).map(el => el.message);
    const message = `Invalid input data: ${errors.join('. ')}`;

    const error = new Error(message);
    error.statusCode = 400;
    error.isOperational = true;
    error.code = 'VALIDATION_ERROR';
    return error;
};

/**
 * Handle JWT errors
 */
const handleJWTError = () => {
    const error = new Error('Invalid token. Please log in again.');
    error.statusCode = 401;
    error.isOperational = true;
    error.code = 'INVALID_TOKEN';
    return error;
};

/**
 * Handle JWT expired errors
 */
const handleJWTExpiredError = () => {
    const error = new Error('Your token has expired. Please log in again.');
    error.statusCode = 401;
    error.isOperational = true;
    error.code = 'TOKEN_EXPIRED';
    return error;
};

/**
 * Handle file upload errors
 */
const handleFileUploadError = (err) => {
    const message = `File too large. Maximum size allowed: ${process.env.MAX_FILE_SIZE || '10MB'}`;
    const error = new Error(message);
    error.statusCode = 413;
    error.isOperational = true;
    error.code = 'FILE_TOO_LARGE';
    return error;
};

/**
 * Handle rate limiting errors
 */
const handleRateLimitError = (err) => {
    const message = 'Too many requests from this IP. Please try again later.';
    const error = new Error(message);
    error.statusCode = 429;
    error.isOperational = true;
    error.code = 'RATE_LIMIT_EXCEEDED';
    return error;
};

/**
 * Handle cryptographic errors
 */
const handleCryptoError = (err) => {
    const message = 'Cryptographic operation failed. Please try again or contact support.';
    const error = new Error(message);
    error.statusCode = 500;
    error.isOperational = true;
    error.code = 'CRYPTO_ERROR';
    return error;
};

/**
 * Utility Functions
 * उपकरण कार्य
 */

/**
 * Check if error is security-related
 */
const isSecurityError = (err) => {
    const securityErrorCodes = [
        'INVALID_TOKEN', 'TOKEN_EXPIRED', 'ACCESS_DENIED',
        'PERMISSION_DENIED', 'AUTHENTICATION_FAILED',
        'CRYPTO_ERROR', 'INVALID_SIGNATURE'
    ];

    const securityErrorNames = [
        'JsonWebTokenError', 'TokenExpiredError', 'UnauthorizedError'
    ];

    return securityErrorCodes.includes(err.code) ||
        securityErrorNames.includes(err.name) ||
        err.statusCode === 401 ||
        err.statusCode === 403;
};

/**
 * Sanitize error message for logging
 */
const sanitizeErrorMessage = (message) => {
    if (!message) return 'Unknown error';

    // Remove potentially sensitive information
    return message
        .replace(/password/gi, '[REDACTED]')
        .replace(/token/gi, '[REDACTED]')
        .replace(/key/gi, '[REDACTED]')
        .replace(/secret/gi, '[REDACTED]');
};

/**
 * Sanitize request headers for logging
 */
const sanitizeHeaders = (headers) => {
    const sanitized = { ...headers };

    // Remove sensitive headers
    delete sanitized.authorization;
    delete sanitized.cookie;
    delete sanitized['x-api-key'];

    return sanitized;
};

/**
 * Sanitize request body for logging
 */
const sanitizeRequestBody = (body) => {
    if (!body || typeof body !== 'object') return body;

    const sanitized = { ...body };

    // Remove sensitive fields
    const sensitiveFields = ['password', 'token', 'key', 'secret'];
    sensitiveFields.forEach(field => {
        if (sanitized[field]) {
            sanitized[field] = '[REDACTED]';
        }
    });

    return sanitized;
};

/**
 * Generate unique request ID
 */
const generateRequestId = () => {
    return require('crypto').randomUUID();
};

/**
 * Async Error Wrapper
 * async त्रुटि रैपर
 * 
 * Wrapper for async route handlers to catch unhandled promise rejections
 */
const catchAsync = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

/**
 * Validation Error Handler
 * सत्यापन त्रुटि हैंडलर
 * 
 * Handle validation errors from express-validator
 */
const handleValidationErrors = (req, res, next) => {
    const { validationResult } = require('express-validator');
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const formattedErrors = errors.array().map(error => ({
            field: error.param,
            message: error.msg,
            value: error.value
        }));

        logger.warn('Validation errors', {
            url: req.originalUrl,
            method: req.method,
            errors: formattedErrors,
            user: req.user?._id
        });

        return res.status(400).json({
            status: 'error',
            message: 'Validation failed',
            code: 'VALIDATION_ERROR',
            errors: formattedErrors,
            timestamp: new Date().toISOString()
        });
    }

    next();
};

/**
 * Operational Error Class
 * परिचालन त्रुटि वर्ग
 * 
 * Custom error class for operational errors
 */
class AppError extends Error {
    constructor(message, statusCode, code = null) {
        super(message);

        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        this.code = code;

        Error.captureStackTrace(this, this.constructor);
    }
}

module.exports = {
    errorHandler,
    notFound,
    catchAsync,
    handleValidationErrors,
    AppError
};