/**
 * Logging Configuration and Utilities
 * लॉगिंग कॉन्फ़िगरेशन और उपकरण
 * 
 * This module provides structured logging with different levels,
 * audit trail capabilities, and secure handling of sensitive data.
 * All logs are sanitized to prevent sensitive information leakage.
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Custom log format for structured logging
 * संरचित लॉगिंग के लिए कस्टम लॉग प्रारूप
 */
const customFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss.SSS'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        // Sanitize sensitive data from logs
        const sanitizedMeta = sanitizeLogData(meta);

        return JSON.stringify({
            timestamp,
            level: level.toUpperCase(),
            message,
            ...sanitizedMeta
        });
    })
);

/**
 * Sanitize sensitive data from log entries
 * लॉग एंट्री से संवेदनशील डेटा को साफ़ करें
 * 
 * @param {Object} data - Data to sanitize
 * @returns {Object} Sanitized data
 */
const sanitizeLogData = (data) => {
    const sensitiveFields = [
        'password', 'token', 'key', 'secret', 'authorization', 'cookie',
        'cek', 'privateKey', 'publicKey', 'hmacKey', 'wrappedKey',
        'plaintext', 'ciphertext', 'authTag', 'iv', 'salt'
    ];

    const sanitized = { ...data };

    const sanitizeObject = (obj, path = '') => {
        for (const [key, value] of Object.entries(obj)) {
            const currentPath = path ? `${path}.${key}` : key;

            // Check if field name contains sensitive keywords
            if (sensitiveFields.some(field =>
                key.toLowerCase().includes(field.toLowerCase()))) {
                obj[key] = '[REDACTED]';
            } else if (typeof value === 'object' && value !== null && !Buffer.isBuffer(value)) {
                sanitizeObject(value, currentPath);
            } else if (Buffer.isBuffer(value)) {
                obj[key] = `[BUFFER:${value.length}bytes]`;
            } else if (typeof value === 'string' && value.length > 1000) {
                // Truncate very long strings that might contain sensitive data
                obj[key] = `[TRUNCATED:${value.length}chars]`;
            }
        }
    };

    if (typeof sanitized === 'object' && sanitized !== null) {
        sanitizeObject(sanitized);
    }

    return sanitized;
};

/**
 * Logger Configuration
 * लॉगर कॉन्फ़िगरेशन
 */
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: customFormat,
    defaultMeta: {
        service: 'secure-fin-data',
        pid: process.pid,
        environment: process.env.NODE_ENV || 'development'
    },
    transports: [
        // Console output for development
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            ),
            silent: process.env.NODE_ENV === 'test'
        }),

        // Application logs
        new winston.transports.File({
            filename: path.join(logsDir, 'app.log'),
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 5,
            tailable: true
        }),

        // Error logs
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 5,
            tailable: true
        }),

        // Security audit logs (append-only)
        new winston.transports.File({
            filename: path.join(logsDir, 'audit.log'),
            maxsize: 50 * 1024 * 1024, // 50MB
            maxFiles: 10,
            tailable: true
        })
    ],

    // Handle uncaught exceptions
    exceptionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'exceptions.log')
        })
    ],

    // Handle unhandled promise rejections
    rejectionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'rejections.log')
        })
    ]
});

/**
 * Security Audit Logger
 * सुरक्षा ऑडिट लॉगर
 */
const auditLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: {
        type: 'SECURITY_AUDIT',
        service: 'secure-fin-data'
    },
    transports: [
        new winston.transports.File({
            filename: path.join(logsDir, 'security-audit.log'),
            maxsize: 100 * 1024 * 1024, // 100MB
            maxFiles: 20,
            tailable: true
        })
    ]
});

/**
 * Audit logging functions
 * ऑडिट लॉगिंग फ़ंक्शन
 */

/**
 * Log security events for audit trail
 * ऑडिट ट्रेल के लिए सुरक्षा घटनाओं को लॉग करें
 * 
 * @param {string} action - Action performed
 * @param {Object} details - Event details
 * @param {Object} [user] - User information
 */
const logSecurityEvent = (action, details, user = null) => {
    const auditEntry = {
        action,
        timestamp: new Date().toISOString(),
        user: user ? {
            id: user.id ? user.id.toString() : user._id ? user._id.toString() : null,
            email: user.email,
            role: user.role,
            ip: user.ip
        } : null,
        details: sanitizeLogData(details),
        sessionId: details.sessionId || null,
        requestId: details.requestId || null
    };

    auditLogger.info('Security Event', auditEntry);
};

/**
 * Log file operations
 * फाइल ऑपरेशन लॉग करें
 * 
 * @param {string} operation - File operation type
 * @param {string} fileName - File name (sanitized)
 * @param {Object} metadata - Additional metadata
 * @param {Object} [user] - User information
 */
const logFileOperation = (operation, fileName, metadata, user = null) => {
    logSecurityEvent('FILE_OPERATION', {
        operation,
        fileName: sanitizeFileName(fileName),
        fileSize: metadata.fileSize,
        fileType: metadata.fileType,
        encrypted: metadata.encrypted || false,
        processingTime: metadata.processingTime,
        success: metadata.success || false
    }, user);
};

/**
 * Log authentication events
 * प्रमाणीकरण घटनाओं को लॉग करें
 * 
 * @param {string} event - Authentication event type
 * @param {Object} details - Event details
 */
const logAuthEvent = (event, details) => {
    logSecurityEvent('AUTHENTICATION', {
        event,
        userAgent: details.userAgent,
        ip: details.ip,
        success: details.success || false,
        reason: details.reason || null,
        timestamp: new Date().toISOString()
    });
};

/**
 * Log key management events
 * की प्रबंधन घटनाओं को लॉग करें
 * 
 * @param {string} operation - Key operation
 * @param {Object} details - Operation details
 * @param {Object} [user] - User information
 */
const logKeyOperation = (operation, details, user = null) => {
    logSecurityEvent('KEY_MANAGEMENT', {
        operation,
        keyType: details.keyType,
        keyId: details.keyId || '[GENERATED]',
        algorithm: details.algorithm,
        success: details.success || false
    }, user);
};

/**
 * Sanitize file name for logging
 * लॉगिंग के लिए फाइल नाम को साफ़ करें
 * 
 * @param {string} fileName - Original file name
 * @returns {string} Sanitized file name
 */
const sanitizeFileName = (fileName) => {
    if (!fileName) return '[UNKNOWN]';

    // Remove path components and keep only the basename
    const baseName = path.basename(fileName);

    // Replace potentially sensitive patterns
    return baseName
        .replace(/[0-9]{10,}/g, '[NUMBERS]') // Long numbers (IDs, timestamps)
        .replace(/[a-f0-9]{32,}/g, '[HASH]') // Hash-like strings
        .substring(0, 100); // Limit length
};

/**
 * Performance logging
 * प्रदर्शन लॉगिंग
 */

/**
 * Create a performance timer
 * प्रदर्शन टाइमर बनाएं
 * 
 * @param {string} operation - Operation name
 * @returns {Object} Timer object with stop function
 */
const createTimer = (operation) => {
    const startTime = process.hrtime.bigint();

    return {
        stop: () => {
            const endTime = process.hrtime.bigint();
            const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds

            logger.debug('Performance Measurement', {
                operation,
                duration: `${duration.toFixed(2)}ms`,
                timestamp: new Date().toISOString()
            });

            return duration;
        }
    };
};

/**
 * HTTP request logging middleware helper
 * HTTP अनुरोध लॉगिंग मिडलवेयर सहायक
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {number} duration - Request duration in ms
 */
const logHttpRequest = (req, res, duration) => {
    const logData = {
        method: req.method,
        url: req.originalUrl || req.url,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
        referer: req.get('Referer'),
        contentLength: res.get('Content-Length'),
        userId: req.user ? req.user.id : null
    };

    if (res.statusCode >= 400) {
        logger.warn('HTTP Request Error', logData);
    } else {
        logger.info('HTTP Request', logData);
    }
};

module.exports = {
    logger,
    auditLogger,
    logSecurityEvent,
    logFileOperation,
    logAuthEvent,
    logKeyOperation,
    sanitizeLogData,
    sanitizeFileName,
    createTimer,
    logHttpRequest
};