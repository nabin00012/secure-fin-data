/**
 * Authentication and Authorization Middleware
 * प्रमाणीकरण और प्राधिकरण मिडलवेयर
 * 
 * This middleware handles JWT token validation, user authentication,
 * and role-based access control for API endpoints.
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { logger, logAuthEvent, logSecurityEvent } = require('../utils/logger');

/**
 * JWT Authentication Middleware
 * JWT प्रमाणीकरण मिडलवेयर
 * 
 * Validates JWT tokens and attaches user information to request
 */
const authenticate = async (req, res, next) => {
    try {
        // Extract token from Authorization header
        const authHeader = req.header('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Access denied',
                message: 'No valid authorization token provided',
                code: 'NO_TOKEN'
            });
        }

        const token = authHeader.substring(7); // Remove 'Bearer ' prefix

        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Find user in database
        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            logAuthEvent('TOKEN_INVALID_USER', {
                userId: decoded.id,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                success: false,
                reason: 'User not found'
            });

            return res.status(401).json({
                error: 'Invalid token',
                message: 'User associated with token not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Check if user account is active
        if (!user.security.isActive) {
            logAuthEvent('TOKEN_INACTIVE_USER', {
                userId: user._id,
                email: user.email,
                ip: req.ip,
                success: false,
                reason: 'Account inactive'
            });

            return res.status(401).json({
                error: 'Access denied',
                message: 'User account is inactive',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        // Check if account is locked
        if (user.isLocked()) {
            logAuthEvent('TOKEN_LOCKED_USER', {
                userId: user._id,
                email: user.email,
                ip: req.ip,
                success: false,
                reason: 'Account locked'
            });

            return res.status(401).json({
                error: 'Access denied',
                message: 'Account is temporarily locked',
                code: 'ACCOUNT_LOCKED'
            });
        }

        // Check if password was changed after token was issued
        const tokenIssuedAt = new Date(decoded.iat * 1000);
        if (user.security.passwordChangedAt > tokenIssuedAt) {
            logAuthEvent('TOKEN_EXPIRED_PASSWORD', {
                userId: user._id,
                email: user.email,
                ip: req.ip,
                success: false,
                reason: 'Password changed after token issued'
            });

            return res.status(401).json({
                error: 'Token expired',
                message: 'Please log in again due to password change',
                code: 'PASSWORD_CHANGED'
            });
        }

        // Attach user to request
        req.user = user;

        // Log successful authentication
        logAuthEvent('TOKEN_VALIDATED', {
            userId: user._id,
            email: user.email,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            success: true
        });

        next();

    } catch (error) {
        logger.error('Authentication middleware error:', error);

        let errorCode = 'TOKEN_ERROR';
        let errorMessage = 'Authentication failed';

        if (error.name === 'JsonWebTokenError') {
            errorCode = 'INVALID_TOKEN';
            errorMessage = 'Invalid token format';
        } else if (error.name === 'TokenExpiredError') {
            errorCode = 'TOKEN_EXPIRED';
            errorMessage = 'Token has expired';
        }

        logAuthEvent('AUTHENTICATION_FAILED', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            error: error.message,
            success: false,
            reason: errorCode
        });

        return res.status(401).json({
            error: 'Authentication failed',
            message: errorMessage,
            code: errorCode
        });
    }
};

/**
 * Optional Authentication Middleware
 * वैकल्पिक प्रमाणीकरण मिडलवेयर
 * 
 * Validates token if present, but doesn't require authentication
 */
const optionalAuth = async (req, res, next) => {
    const authHeader = req.header('Authorization');

    if (authHeader && authHeader.startsWith('Bearer ')) {
        // If token is present, validate it
        return authenticate(req, res, next);
    } else {
        // No token present, continue without user
        req.user = null;
        next();
    }
};

/**
 * Role-based Authorization Middleware
 * भूमिका-आधारित प्राधिकरण मिडलवेयर
 * 
 * Checks if user has required role
 */
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please log in to access this resource',
                code: 'AUTH_REQUIRED'
            });
        }

        if (!roles.includes(req.user.role)) {
            logSecurityEvent('AUTHORIZATION_FAILED', {
                userId: req.user._id,
                email: req.user.email,
                role: req.user.role,
                requiredRoles: roles,
                resource: req.originalUrl,
                method: req.method,
                ip: req.ip
            }, req.user);

            return res.status(403).json({
                error: 'Access forbidden',
                message: `Required role: ${roles.join(' or ')}. Your role: ${req.user.role}`,
                code: 'INSUFFICIENT_ROLE'
            });
        }

        next();
    };
};

/**
 * Permission-based Authorization Middleware
 * अनुमति-आधारित प्राधिकरण मिडलवेयर
 * 
 * Checks if user has specific permission
 */
const requirePermission = (resource, action) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please log in to access this resource',
                code: 'AUTH_REQUIRED'
            });
        }

        if (!req.user.hasPermission(resource, action)) {
            logSecurityEvent('PERMISSION_DENIED', {
                userId: req.user._id,
                email: req.user.email,
                role: req.user.role,
                requiredPermission: { resource, action },
                resource: req.originalUrl,
                method: req.method,
                ip: req.ip
            }, req.user);

            return res.status(403).json({
                error: 'Permission denied',
                message: `Required permission: ${action} on ${resource}`,
                code: 'INSUFFICIENT_PERMISSION'
            });
        }

        next();
    };
};

/**
 * API Key Authentication Middleware
 * API की प्रमाणीकरण मिडलवेयर
 * 
 * Alternative authentication using API keys
 */
const authenticateApiKey = async (req, res, next) => {
    try {
        // Extract API key from header
        const apiKey = req.header('X-API-Key');
        if (!apiKey) {
            return res.status(401).json({
                error: 'API key required',
                message: 'X-API-Key header is required for this endpoint',
                code: 'NO_API_KEY'
            });
        }

        // Find user with matching API key hash
        // Note: This is simplified - in production, use proper key lookup
        const users = await User.find({
            'apiAccess.enabled': true,
            'security.isActive': true
        }).select('+apiAccess.apiKeyHash');

        let authenticatedUser = null;

        for (const user of users) {
            if (await user.validateApiKey(apiKey)) {
                authenticatedUser = user;
                break;
            }
        }

        if (!authenticatedUser) {
            logAuthEvent('API_KEY_INVALID', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                success: false,
                reason: 'Invalid API key'
            });

            return res.status(401).json({
                error: 'Invalid API key',
                message: 'The provided API key is not valid',
                code: 'INVALID_API_KEY'
            });
        }

        // Attach user to request (without password)
        req.user = await User.findById(authenticatedUser._id).select('-password');

        logAuthEvent('API_KEY_VALIDATED', {
            userId: req.user._id,
            email: req.user.email,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            success: true
        });

        next();

    } catch (error) {
        logger.error('API key authentication error:', error);

        logAuthEvent('API_KEY_ERROR', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            error: error.message,
            success: false
        });

        return res.status(500).json({
            error: 'Authentication error',
            message: 'Internal server error during API key validation',
            code: 'AUTH_ERROR'
        });
    }
};

/**
 * Rate Limiting by User
 * उपयोगकर्ता द्वारा दर सीमा
 * 
 * Apply rate limiting based on user tier
 */
const userRateLimit = (req, res, next) => {
    if (!req.user) {
        return next();
    }

    // Rate limits based on user tier
    const rateLimits = {
        basic: { requests: 100, window: 60 * 60 * 1000 }, // 100 requests per hour
        premium: { requests: 500, window: 60 * 60 * 1000 }, // 500 requests per hour
        enterprise: { requests: 2000, window: 60 * 60 * 1000 } // 2000 requests per hour
    };

    const userTier = req.user.apiAccess?.rateLimitTier || 'basic';
    const limit = rateLimits[userTier];

    // Implement user-specific rate limiting logic here
    // This is a simplified version - use Redis or similar for production

    next();
};

/**
 * Owner or Admin Access Middleware
 * स्वामी या व्यवस्थापक पहुंच मिडलवेयर
 * 
 * Allows access to resource owner or admin
 */
const ownerOrAdmin = (getOwnerId) => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        // Admin always has access
        if (req.user.role === 'admin') {
            return next();
        }

        try {
            // Get resource owner ID
            const ownerId = await getOwnerId(req);

            if (req.user._id.toString() === ownerId?.toString()) {
                return next();
            }

            logSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', {
                userId: req.user._id,
                email: req.user.email,
                resource: req.originalUrl,
                method: req.method,
                reason: 'Not owner or admin',
                ip: req.ip
            }, req.user);

            return res.status(403).json({
                error: 'Access forbidden',
                message: 'You can only access your own resources',
                code: 'NOT_OWNER'
            });

        } catch (error) {
            logger.error('Owner check error:', error);
            return res.status(500).json({
                error: 'Authorization error',
                code: 'AUTH_CHECK_ERROR'
            });
        }
    };
};

/**
 * Security Headers Middleware
 * सुरक्षा हेडर मिडलवेयर
 * 
 * Add security headers to all responses
 */
const securityHeaders = (req, res, next) => {
    // Add security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    // Remove server information
    res.removeHeader('X-Powered-By');

    next();
};

/**
 * Request Sanitization Middleware
 * अनुरोध स्वच्छता मिडलवेयर
 * 
 * Sanitize request data to prevent injection attacks
 */
const sanitizeRequest = (req, res, next) => {
    // Basic XSS protection for string inputs
    const sanitizeString = (str) => {
        if (typeof str !== 'string') return str;
        return str
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+\s*=/gi, '');
    };

    // Sanitize request body
    if (req.body && typeof req.body === 'object') {
        const sanitizeObject = (obj) => {
            for (const key in obj) {
                if (typeof obj[key] === 'string') {
                    obj[key] = sanitizeString(obj[key]);
                } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                    sanitizeObject(obj[key]);
                }
            }
        };
        sanitizeObject(req.body);
    }

    // Sanitize query parameters
    if (req.query && typeof req.query === 'object') {
        for (const key in req.query) {
            if (typeof req.query[key] === 'string') {
                req.query[key] = sanitizeString(req.query[key]);
            }
        }
    }

    next();
};

module.exports = {
    authenticate,
    optionalAuth,
    authorize,
    requirePermission,
    authenticateApiKey,
    userRateLimit,
    ownerOrAdmin,
    securityHeaders,
    sanitizeRequest
};