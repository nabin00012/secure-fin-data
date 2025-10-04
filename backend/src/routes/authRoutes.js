/**
 * Authentication Routes
 * प्रमाणीकरण रूट्स
 * 
 * Defines API routes for user authentication, registration,
 * login, logout, and profile management operations.
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const {
    authenticate,
    optionalAuth,
    sanitizeRequest,
    securityHeaders
} = require('../middleware/authMiddleware');
const { handleValidationErrors } = require('../middleware/errorMiddleware');
const {
    register,
    login,
    logout,
    getProfile,
    updateProfile,
    changePassword,
    generateApiKey,
    refreshToken,
    verifyToken
} = require('../controllers/authController');

const router = express.Router();

// Apply security headers to all routes
router.use(securityHeaders);

// Apply request sanitization
router.use(sanitizeRequest);

/**
 * Rate limiting for authentication endpoints
 * प्रमाणीकरण एंडपॉइंट्स के लिए दर सीमा
 */

// Strict rate limiting for registration (prevent spam accounts)
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 registrations per hour per IP
    message: {
        error: 'Too many registration attempts',
        message: 'Please wait an hour before creating another account',
        code: 'REGISTRATION_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true // Don't count successful registrations
});

// Strict rate limiting for login attempts (prevent brute force)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 login attempts per 15 minutes per IP
    message: {
        error: 'Too many login attempts',
        message: 'Please wait 15 minutes before trying again',
        code: 'LOGIN_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true // Don't count successful logins
});

// Rate limiting for password changes (prevent abuse)
const passwordLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 password changes per hour per IP
    message: {
        error: 'Too many password change attempts',
        message: 'Please wait an hour before changing password again',
        code: 'PASSWORD_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Rate limiting for API key generation
const apiKeyLimiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 3, // 3 API key generations per day per IP
    message: {
        error: 'Too many API key generation requests',
        message: 'Please wait 24 hours before generating another API key',
        code: 'API_KEY_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false
});

/**
 * Public authentication routes (no authentication required)
 * सार्वजनिक प्रमाणीकरण रूट्स (प्रमाणीकरण की आवश्यकता नहीं)
 */

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user account
 * @access  Public
 * @rateLimit 5 registrations per hour
 */
router.post('/register',
    registerLimiter,
    register
);

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and return JWT token
 * @access  Public
 * @rateLimit 5 login attempts per 15 minutes
 */
router.post('/login',
    loginLimiter,
    login
);

/**
 * Protected authentication routes (authentication required)
 * संरक्षित प्रमाणीकरण रूट्स (प्रमाणीकरण आवश्यक)
 */

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user and invalidate session
 * @access  Private
 */
router.post('/logout',
    authenticate,
    logout
);

/**
 * @route   GET /api/auth/profile
 * @desc    Get current user profile information
 * @access  Private
 */
router.get('/profile',
    authenticate,
    getProfile
);

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile information
 * @access  Private
 */
router.put('/profile',
    authenticate,
    updateProfile
);

/**
 * @route   PUT /api/auth/password
 * @desc    Change user password
 * @access  Private
 * @rateLimit 3 password changes per hour
 */
router.put('/password',
    passwordLimiter,
    authenticate,
    changePassword
);

/**
 * @route   POST /api/auth/api-key
 * @desc    Generate new API key for programmatic access
 * @access  Private
 * @rateLimit 3 API key generations per day
 */
router.post('/api-key',
    apiKeyLimiter,
    authenticate,
    generateApiKey
);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh JWT token
 * @access  Private
 */
router.post('/refresh',
    authenticate,
    refreshToken
);

/**
 * @route   GET /api/auth/verify
 * @desc    Verify JWT token validity
 * @access  Private
 */
router.get('/verify',
    authenticate,
    verifyToken
);

/**
 * Optional authentication routes
 * वैकल्पिक प्रमाणीकरण रूट्स
 */

/**
 * @route   GET /api/auth/status
 * @desc    Get authentication service status
 * @access  Public/Private (optional auth)
 */
router.get('/status',
    optionalAuth,
    (req, res) => {
        res.status(200).json({
            status: 'success',
            message: 'Authentication service is operational',
            data: {
                service: 'auth',
                version: '1.0.0',
                authenticated: !!req.user,
                user: req.user ? {
                    id: req.user._id,
                    email: req.user.email,
                    role: req.user.role
                } : null,
                features: {
                    jwtAuth: true,
                    apiKeyAuth: true,
                    roleBasedAccess: true,
                    rateLimiting: true,
                    auditLogging: true
                },
                timestamp: new Date().toISOString()
            }
        });
    }
);

/**
 * Password reset routes (Future enhancement)
 * पासवर्ड रीसेट रूट्स (भविष्य में सुधार)
 */

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset email
 * @access  Public
 * @note    Future enhancement for password recovery
 */
router.post('/forgot-password',
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Password reset functionality not yet implemented',
            code: 'FEATURE_COMING_SOON',
            recommendation: 'Contact administrator for password reset'
        });
    }
);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password using reset token
 * @access  Public
 * @note    Future enhancement for password recovery
 */
router.post('/reset-password',
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Password reset functionality not yet implemented',
            code: 'FEATURE_COMING_SOON',
            recommendation: 'Contact administrator for password reset'
        });
    }
);

/**
 * Two-factor authentication routes (Future enhancement)
 * द्विकारक प्रमाणीकरण रूट्स (भविष्य में सुधार)
 */

/**
 * @route   POST /api/auth/2fa/enable
 * @desc    Enable two-factor authentication
 * @access  Private
 * @note    Future enhancement for additional security
 */
router.post('/2fa/enable',
    authenticate,
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Two-factor authentication not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * @route   POST /api/auth/2fa/verify
 * @desc    Verify two-factor authentication code
 * @access  Private
 * @note    Future enhancement for additional security
 */
router.post('/2fa/verify',
    authenticate,
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Two-factor authentication not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * Session management routes
 * सत्र प्रबंधन रूट्स
 */

/**
 * @route   GET /api/auth/sessions
 * @desc    Get active user sessions
 * @access  Private
 * @note    Future enhancement for session management
 */
router.get('/sessions',
    authenticate,
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Session management not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * @route   DELETE /api/auth/sessions/:sessionId
 * @desc    Revoke specific user session
 * @access  Private
 * @note    Future enhancement for session management
 */
router.delete('/sessions/:sessionId',
    authenticate,
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Session revocation not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * Account security routes
 * खाता सुरक्षा रूट्स
 */

/**
 * @route   GET /api/auth/security-log
 * @desc    Get user's security activity log
 * @access  Private
 */
router.get('/security-log',
    authenticate,
    (req, res) => {
        // This would return filtered security events for the current user
        res.status(501).json({
            status: 'info',
            message: 'Security log endpoint not yet implemented',
            code: 'FEATURE_COMING_SOON'
        });
    }
);

/**
 * @route   POST /api/auth/deactivate
 * @desc    Deactivate user account
 * @access  Private
 */
router.post('/deactivate',
    authenticate,
    (req, res) => {
        res.status(501).json({
            status: 'info',
            message: 'Account deactivation not yet implemented',
            code: 'FEATURE_COMING_SOON',
            recommendation: 'Contact administrator to deactivate account'
        });
    }
);

/**
 * Error handling for authentication routes
 * प्रमाणीकरण रूट्स के लिए त्रुटि प्रबंधन
 */
router.use((err, req, res, next) => {
    // Log authentication-specific errors
    const { logger } = require('../utils/logger');
    logger.error('Authentication route error', {
        error: err.message,
        route: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });

    next(err);
});

module.exports = router;