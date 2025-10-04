/**
 * Audit Middleware
 * ऑडिट मिडलवेयर
 * 
 * This middleware provides comprehensive audit logging for all API requests,
 * tracking user actions, security events, and system operations for compliance.
 */

const { logHttpRequest, logSecurityEvent, createTimer } = require('../utils/logger');
const crypto = require('crypto');

/**
 * Main Audit Middleware
 * मुख्य ऑडिट मिडलवेयर
 * 
 * Logs all HTTP requests with timing, user information, and security context
 */
const auditMiddleware = (req, res, next) => {
    // Generate unique request ID for tracing
    req.requestId = crypto.randomUUID();
    req.startTime = Date.now();

    // Create performance timer
    const timer = createTimer(`${req.method} ${req.originalUrl}`);

    // Extract client information
    const clientInfo = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        origin: req.get('Origin'),
        contentType: req.get('Content-Type'),
        contentLength: req.get('Content-Length')
    };

    // Store client info in request for later use
    req.clientInfo = clientInfo;

    // Log request start
    const requestStartData = {
        requestId: req.requestId,
        method: req.method,
        url: req.originalUrl,
        query: sanitizeQuery(req.query),
        headers: sanitizeHeaders(req.headers),
        clientInfo,
        timestamp: new Date().toISOString()
    };

    // Don't log sensitive routes in detail
    if (!isSensitiveRoute(req.originalUrl)) {
        requestStartData.body = sanitizeRequestBody(req.body);
    }

    // Override res.json to capture response data
    const originalJson = res.json;
    res.json = function (data) {
        // Store response data for audit logging
        res.responseData = sanitizeResponseData(data);
        return originalJson.call(this, data);
    };

    // Override res.send to capture response
    const originalSend = res.send;
    res.send = function (data) {
        if (!res.responseData && data) {
            try {
                res.responseData = typeof data === 'string' ?
                    sanitizeResponseData(JSON.parse(data)) :
                    sanitizeResponseData(data);
            } catch (e) {
                res.responseData = { type: 'non-json', length: data?.length || 0 };
            }
        }
        return originalSend.call(this, data);
    };

    // Log response when request finishes
    const onFinished = () => {
        const duration = timer.stop();

        const auditData = {
            ...requestStartData,
            response: {
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                headers: sanitizeResponseHeaders(res.getHeaders()),
                data: res.responseData || null,
                size: res.get('Content-Length') || 0
            },
            performance: {
                duration: Math.round(duration),
                timestamp: new Date().toISOString()
            },
            user: req.user ? {
                id: req.user._id,
                email: req.user.email,
                role: req.user.role
            } : null
        };

        // Determine audit severity based on response
        const severity = getAuditSeverity(req, res);

        // Log based on severity
        if (severity === 'high') {
            logSecurityEvent('HIGH_SEVERITY_REQUEST', auditData, req.user);
        } else if (severity === 'medium') {
            logSecurityEvent('MEDIUM_SEVERITY_REQUEST', auditData, req.user);
        }

        // Always log HTTP request for general audit
        logHttpRequest(req, res, duration);

        // Log specific operations
        logOperationSpecificAudit(req, res, auditData);
    };

    // Attach listeners for when response finishes
    res.on('finish', onFinished);
    res.on('close', onFinished);

    next();
};

/**
 * Determine audit severity based on request/response
 * अनुरोध/प्रतिक्रिया के आधार पर ऑडिट गंभीरता निर्धारित करें
 */
const getAuditSeverity = (req, res) => {
    // High severity conditions
    if (res.statusCode >= 400) return 'high';
    if (isSecuritySensitiveRoute(req.originalUrl)) return 'high';
    if (req.method === 'DELETE') return 'high';
    if (isAuthRoute(req.originalUrl)) return 'high';

    // Medium severity conditions
    if (req.method === 'POST' || req.method === 'PUT') return 'medium';
    if (isDataModificationRoute(req.originalUrl)) return 'medium';

    return 'low';
};

/**
 * Log operation-specific audit events
 * ऑपरेशन-विशिष्ट ऑडिट घटनाओं को लॉग करें
 */
const logOperationSpecificAudit = (req, res, auditData) => {
    const url = req.originalUrl;
    const method = req.method;

    // File operations
    if (url.includes('/files') || url.includes('/upload') || url.includes('/encrypt')) {
        logSecurityEvent('FILE_OPERATION_AUDIT', {
            operation: `${method} ${url}`,
            fileInfo: extractFileInfo(req, res),
            statusCode: res.statusCode,
            duration: auditData.performance.duration
        }, req.user);
    }

    // Authentication operations
    if (url.includes('/auth')) {
        logSecurityEvent('AUTH_OPERATION_AUDIT', {
            operation: `${method} ${url}`,
            success: res.statusCode < 400,
            clientInfo: req.clientInfo,
            statusCode: res.statusCode
        }, req.user);
    }

    // Admin operations
    if (url.includes('/admin')) {
        logSecurityEvent('ADMIN_OPERATION_AUDIT', {
            operation: `${method} ${url}`,
            adminUser: req.user ? {
                id: req.user._id,
                email: req.user.email
            } : null,
            statusCode: res.statusCode,
            targetResource: extractTargetResource(url)
        }, req.user);
    }

    // Key management operations
    if (url.includes('/keys') || url.includes('/kms')) {
        logSecurityEvent('KEY_MANAGEMENT_AUDIT', {
            operation: `${method} ${url}`,
            keyOperation: extractKeyOperation(req),
            success: res.statusCode < 400,
            statusCode: res.statusCode
        }, req.user);
    }

    // Data access operations
    if (method === 'GET' && isDataAccessRoute(url)) {
        logSecurityEvent('DATA_ACCESS_AUDIT', {
            operation: `${method} ${url}`,
            dataType: extractDataType(url),
            accessPattern: extractAccessPattern(req),
            statusCode: res.statusCode
        }, req.user);
    }
};

/**
 * Sanitization functions for audit data
 * ऑडिट डेटा के लिए स्वच्छता कार्य
 */

const sanitizeQuery = (query) => {
    if (!query || typeof query !== 'object') return query;

    const sanitized = { ...query };
    const sensitiveParams = ['password', 'token', 'key', 'secret'];

    sensitiveParams.forEach(param => {
        if (sanitized[param]) {
            sanitized[param] = '[REDACTED]';
        }
    });

    return sanitized;
};

const sanitizeHeaders = (headers) => {
    const sanitized = { ...headers };

    // Remove sensitive headers
    const sensitiveHeaders = [
        'authorization', 'cookie', 'x-api-key',
        'x-auth-token', 'x-access-token'
    ];

    sensitiveHeaders.forEach(header => {
        if (sanitized[header]) {
            sanitized[header] = '[REDACTED]';
        }
    });

    return sanitized;
};

const sanitizeRequestBody = (body) => {
    if (!body || typeof body !== 'object') return body;

    const sanitized = JSON.parse(JSON.stringify(body));

    // Remove sensitive fields
    const sensitiveFields = [
        'password', 'token', 'key', 'secret', 'privateKey',
        'apiKey', 'authToken', 'refreshToken'
    ];

    const sanitizeObject = (obj) => {
        if (!obj || typeof obj !== 'object') return obj;

        for (const key in obj) {
            if (sensitiveFields.some(field => key.toLowerCase().includes(field.toLowerCase()))) {
                obj[key] = '[REDACTED]';
            } else if (typeof obj[key] === 'object') {
                sanitizeObject(obj[key]);
            } else if (typeof obj[key] === 'string' && obj[key].length > 1000) {
                // Truncate very long strings that might contain sensitive data
                obj[key] = `[TRUNCATED:${obj[key].length}chars]`;
            }
        }
    };

    sanitizeObject(sanitized);
    return sanitized;
};

const sanitizeResponseData = (data) => {
    if (!data || typeof data !== 'object') return data;

    // Don't log large response bodies in detail
    const responseSize = JSON.stringify(data).length;
    if (responseSize > 10000) {
        return {
            type: 'large-response',
            size: responseSize,
            structure: Object.keys(data)
        };
    }

    return sanitizeRequestBody(data);
};

const sanitizeResponseHeaders = (headers) => {
    const sanitized = { ...headers };

    // Remove sensitive response headers
    delete sanitized['set-cookie'];
    delete sanitized['x-auth-token'];

    return sanitized;
};

/**
 * Route classification functions
 * रूट वर्गीकरण कार्य
 */

const isSensitiveRoute = (url) => {
    const sensitivePatterns = [
        '/auth', '/login', '/register', '/password',
        '/keys', '/kms', '/decrypt', '/admin/users'
    ];

    return sensitivePatterns.some(pattern => url.includes(pattern));
};

const isSecuritySensitiveRoute = (url) => {
    const securityPatterns = [
        '/encrypt', '/decrypt', '/keys', '/kms',
        '/admin', '/auth', '/users'
    ];

    return securityPatterns.some(pattern => url.includes(pattern));
};

const isAuthRoute = (url) => {
    return url.includes('/auth') || url.includes('/login') || url.includes('/register');
};

const isDataModificationRoute = (url) => {
    const modificationPatterns = [
        '/upload', '/process', '/create', '/update', '/delete'
    ];

    return modificationPatterns.some(pattern => url.includes(pattern));
};

const isDataAccessRoute = (url) => {
    const accessPatterns = [
        '/results', '/metrics', '/files', '/reports'
    ];

    return accessPatterns.some(pattern => url.includes(pattern));
};

/**
 * Information extraction functions
 * सूचना निष्कर्षण कार्य
 */

const extractFileInfo = (req, res) => {
    const fileInfo = {};

    // From multer file upload
    if (req.file) {
        fileInfo.originalName = req.file.originalname;
        fileInfo.mimetype = req.file.mimetype;
        fileInfo.size = req.file.size;
    }

    // From request body
    if (req.body && req.body.fileName) {
        fileInfo.fileName = req.body.fileName;
    }

    // From response
    if (res.responseData && res.responseData.fileId) {
        fileInfo.fileId = res.responseData.fileId;
    }

    return Object.keys(fileInfo).length > 0 ? fileInfo : null;
};

const extractKeyOperation = (req) => {
    const operations = {
        'POST': 'create',
        'GET': 'read',
        'PUT': 'update',
        'DELETE': 'delete'
    };

    const operation = operations[req.method] || 'unknown';

    if (req.originalUrl.includes('rotate')) return 'rotate';
    if (req.originalUrl.includes('wrap')) return 'wrap';
    if (req.originalUrl.includes('unwrap')) return 'unwrap';

    return operation;
};

const extractTargetResource = (url) => {
    if (url.includes('/users')) return 'users';
    if (url.includes('/keys')) return 'keys';
    if (url.includes('/audit')) return 'audit';
    if (url.includes('/config')) return 'config';

    return 'unknown';
};

const extractDataType = (url) => {
    if (url.includes('/results')) return 'financial-results';
    if (url.includes('/metrics')) return 'financial-metrics';
    if (url.includes('/files')) return 'encrypted-files';
    if (url.includes('/audit')) return 'audit-logs';

    return 'unknown';
};

const extractAccessPattern = (req) => {
    const patterns = [];

    if (req.query.search) patterns.push('search');
    if (req.query.filter) patterns.push('filter');
    if (req.query.sort) patterns.push('sort');
    if (req.query.page) patterns.push('paginated');
    if (req.params.id) patterns.push('by-id');

    return patterns.length > 0 ? patterns : ['direct-access'];
};

/**
 * Compliance audit middleware
 * अनुपालन ऑडिट मिडलवेयर
 * 
 * Additional middleware for compliance requirements (GDPR, SOX, etc.)
 */
const complianceAudit = (req, res, next) => {
    // Track data subject access for GDPR compliance
    if (isPersonalDataAccess(req)) {
        logSecurityEvent('PERSONAL_DATA_ACCESS', {
            dataSubject: extractDataSubject(req),
            purpose: req.headers['x-processing-purpose'] || 'not-specified',
            legalBasis: req.headers['x-legal-basis'] || 'not-specified',
            requestId: req.requestId
        }, req.user);
    }

    // Track financial data access for SOX compliance
    if (isFinancialDataAccess(req)) {
        logSecurityEvent('FINANCIAL_DATA_ACCESS', {
            financialPeriod: extractFinancialPeriod(req),
            accessReason: req.headers['x-access-reason'] || 'not-specified',
            requestId: req.requestId
        }, req.user);
    }

    next();
};

const isPersonalDataAccess = (req) => {
    return req.originalUrl.includes('/users') ||
        req.originalUrl.includes('/profile') ||
        (req.originalUrl.includes('/results') && req.query.userId);
};

const isFinancialDataAccess = (req) => {
    return req.originalUrl.includes('/metrics') ||
        req.originalUrl.includes('/results') ||
        req.originalUrl.includes('/reports');
};

const extractDataSubject = (req) => {
    return req.params.userId || req.query.userId || req.user?._id || 'unknown';
};

const extractFinancialPeriod = (req) => {
    return req.query.period || req.body.period || 'unknown';
};

module.exports = {
    auditMiddleware,
    complianceAudit
};