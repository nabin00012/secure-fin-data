/**
 * Admin Routes
 * एडमिन रूट्स
 * 
 * Administrative API endpoints for system management
 * सिस्टम प्रबंधन के लिए प्रशासनिक एपीआई एंडपॉइंट्स
 */

const express = require('express');
const { body, param, query } = require('express-validator');
const rateLimit = require('express-rate-limit');

const {
    getDashboard,
    getUsers,
    getUserById,
    updateUser,
    deleteUser,
    resetUserPassword,
    getLogs,
    getAnalytics,
    manageKeys
} = require('../controllers/adminController');

const { authenticate: authenticateToken, authorize: requireRole } = require('../middleware/authMiddleware');
const { auditMiddleware } = require('../middleware/auditMiddleware');

const router = express.Router();

/**
 * Rate limiting for admin operations
 * एडमिन ऑपरेशन के लिए दर सीमा
 */

// General admin rate limit
const adminRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many admin requests, please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Sensitive operations rate limit
const sensitiveRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // limit each IP to 10 sensitive operations per hour
    message: {
        success: false,
        message: 'Too many sensitive operations, please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Key management rate limit
const keyManagementRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // limit each IP to 5 key operations per hour
    message: {
        success: false,
        message: 'Too many key management operations, please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

/**
 * Middleware chain for admin routes
 * एडमिन रूट्स के लिए मिडलवेयर श्रृंखला
 */
const adminAuth = [
    authenticateToken,
    requireRole('admin', 'super_admin'),
    auditMiddleware
];

const superAdminAuth = [
    authenticateToken,
    requireRole('super_admin'),
    auditMiddleware
];

/**
 * Validation schemas
 * सत्यापन स्कीमा
 */

const userUpdateValidation = [
    param('userId')
        .isMongoId()
        .withMessage('Invalid user ID format'),

    body('username')
        .optional()
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be 3-30 characters')
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),

    body('email')
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid email required'),

    body('role')
        .optional()
        .isIn(['user', 'analyst', 'admin', 'super_admin'])
        .withMessage('Invalid role specified'),

    body('isActive')
        .optional()
        .isBoolean()
        .withMessage('isActive must be a boolean value')
];

const passwordResetValidation = [
    param('userId')
        .isMongoId()
        .withMessage('Invalid user ID format'),

    body('newPassword')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be 8-128 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];

const paginationValidation = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),

    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100'),

    query('sortBy')
        .optional()
        .isIn(['createdAt', 'username', 'email', 'role', 'lastLogin'])
        .withMessage('Invalid sort field'),

    query('sortOrder')
        .optional()
        .isIn(['asc', 'desc'])
        .withMessage('Sort order must be asc or desc')
];

const analyticsValidation = [
    query('period')
        .optional()
        .isIn(['24h', '7d', '30d', '90d'])
        .withMessage('Invalid period. Use: 24h, 7d, 30d, or 90d')
];

const logsValidation = [
    ...paginationValidation,
    query('level')
        .optional()
        .isIn(['error', 'warn', 'info', 'debug'])
        .withMessage('Invalid log level'),

    query('startDate')
        .optional()
        .isISO8601()
        .withMessage('Start date must be in ISO 8601 format'),

    query('endDate')
        .optional()
        .isISO8601()
        .withMessage('End date must be in ISO 8601 format')
];

/**
 * Dashboard Routes
 * डैशबोर्ड रूट्स
 */

// GET /api/admin/dashboard - Get system dashboard
router.get('/dashboard',
    adminRateLimit,
    authenticateToken,
    requireRole('admin', 'super_admin'),
    auditMiddleware,
    getDashboard
);

/**
 * User Management Routes
 * उपयोगकर्ता प्रबंधन रूट्स
 */

// GET /api/admin/users - Get all users with pagination and filtering
router.get('/users',
    adminRateLimit,
    ...adminAuth,
    paginationValidation,
    query('role')
        .optional()
        .isIn(['user', 'analyst', 'admin', 'super_admin'])
        .withMessage('Invalid role filter'),
    query('search')
        .optional()
        .isLength({ min: 1, max: 100 })
        .withMessage('Search term must be 1-100 characters'),
    getUsers
);

// GET /api/admin/users/:userId - Get user by ID
router.get('/users/:userId',
    adminRateLimit,
    ...adminAuth,
    param('userId')
        .isMongoId()
        .withMessage('Invalid user ID format'),
    getUserById
);

// PUT /api/admin/users/:userId - Update user
router.put('/users/:userId',
    adminRateLimit,
    ...adminAuth,
    userUpdateValidation,
    updateUser
);

// DELETE /api/admin/users/:userId - Delete user
router.delete('/users/:userId',
    sensitiveRateLimit,
    ...superAdminAuth, // Only super admin can delete users
    param('userId')
        .isMongoId()
        .withMessage('Invalid user ID format'),
    deleteUser
);

// POST /api/admin/users/:userId/reset-password - Reset user password
router.post('/users/:userId/reset-password',
    sensitiveRateLimit,
    ...adminAuth,
    passwordResetValidation,
    resetUserPassword
);

/**
 * System Management Routes
 * सिस्टम प्रबंधन रूट्स
 */

// GET /api/admin/logs - Get system logs
router.get('/logs',
    adminRateLimit,
    ...adminAuth,
    logsValidation,
    getLogs
);

// GET /api/admin/analytics - Get system analytics
router.get('/analytics',
    adminRateLimit,
    ...adminAuth,
    analyticsValidation,
    getAnalytics
);

/**
 * Key Management Routes
 * की प्रबंधन रूट्स
 */

// GET /api/admin/keys/:action - Manage encryption keys
router.get('/keys/:action',
    keyManagementRateLimit,
    ...superAdminAuth, // Only super admin for key operations
    param('action')
        .isIn(['list', 'rotate', 'health'])
        .withMessage('Invalid action. Use: list, rotate, or health'),
    manageKeys
);

/**
 * System Health Routes
 * सिस्टम स्वास्थ्य रूट्स
 */

// GET /api/admin/health/detailed - Get detailed system health
router.get('/health/detailed',
    adminRateLimit,
    ...adminAuth,
    async (req, res) => {
        try {
            const { logger } = require('../utils/logger');
            const keyStore = require('../utils/keyStore');
            const mongoose = require('mongoose');

            // Check database connection
            const dbHealth = {
                status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
                readyState: mongoose.connection.readyState,
                host: mongoose.connection.host,
                port: mongoose.connection.port,
                name: mongoose.connection.name
            };

            // Check key store health
            const keyStoreHealth = await keyStore.getHealthStatus();

            // System metrics
            const systemMetrics = {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
                nodeVersion: process.version,
                platform: process.platform,
                arch: process.arch
            };

            // Service status
            const serviceStatus = {
                api: 'operational',
                database: dbHealth.status === 'connected' ? 'operational' : 'degraded',
                keyStore: keyStoreHealth.status === 'healthy' ? 'operational' : 'degraded',
                logging: 'operational'
            };

            const overallHealth = Object.values(serviceStatus).every(status => status === 'operational')
                ? 'healthy'
                : Object.values(serviceStatus).some(status => status === 'degraded')
                    ? 'degraded'
                    : 'unhealthy';

            logger.info('Admin system health check', {
                adminId: req.user.id,
                overallHealth
            });

            res.json({
                success: true,
                data: {
                    status: overallHealth,
                    timestamp: new Date().toISOString(),
                    services: serviceStatus,
                    database: dbHealth,
                    keyStore: keyStoreHealth,
                    system: systemMetrics,
                    version: process.env.npm_package_version || '1.0.0'
                }
            });

        } catch (error) {
            const { logger } = require('../utils/logger');
            logger.error('Admin health check failed:', error);

            res.status(500).json({
                success: false,
                message: 'Health check failed',
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }
);

/**
 * System Configuration Routes
 * सिस्टम कॉन्फ़िगरेशन रूट्स
 */

// GET /api/admin/config - Get system configuration (safe values only)
router.get('/config',
    adminRateLimit,
    ...adminAuth,
    async (req, res) => {
        try {
            const { logger } = require('../utils/logger');

            // Return safe configuration values (no secrets)
            const safeConfig = {
                environment: process.env.NODE_ENV || 'development',
                port: process.env.PORT || 5000,
                corsOrigin: process.env.CORS_ORIGIN || '*',
                jwtExpiration: process.env.JWT_EXPIRES_IN || '24h',
                maxFileSize: process.env.MAX_FILE_SIZE || '10MB',
                rateLimiting: {
                    windowMs: 15 * 60 * 1000,
                    maxRequests: 100
                },
                features: {
                    encryption: true,
                    audit: true,
                    rateLimit: true,
                    cors: true
                },
                database: {
                    name: process.env.DB_NAME || 'secure_fin_data',
                    // Don't expose connection details
                }
            };

            logger.info('Admin config accessed', {
                adminId: req.user.id
            });

            res.json({
                success: true,
                data: safeConfig,
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            const { logger } = require('../utils/logger');
            logger.error('Admin config access failed:', error);

            res.status(500).json({
                success: false,
                message: 'Failed to fetch configuration'
            });
        }
    }
);

/**
 * Error handling middleware
 * त्रुटि हैंडलिंग मिडलवेयर
 */
router.use((error, req, res, next) => {
    const { logger } = require('../utils/logger');

    logger.error('Admin route error:', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        adminId: req.user?.id
    });

    res.status(500).json({
        success: false,
        message: 'Internal server error in admin operation',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

module.exports = router;