/**
 * Authentication Controller
 * प्रमाणीकरण नियंत्रक
 * 
 * This controller handles user authentication, registration,
 * login, logout, and JWT token management.
 */

const User = require('../models/User');
const { logger, logAuthEvent, logSecurityEvent } = require('../utils/logger');
const { catchAsync, AppError } = require('../middleware/errorMiddleware');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

/**
 * User Registration
 * उपयोगकर्ता पंजीकरण
 * 
 * POST /api/auth/register
 * Creates a new user account with encrypted password
 */
const register = catchAsync(async (req, res) => {
    // Validation rules
    await Promise.all([
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Please provide a valid email address')
            .run(req),
        body('username')
            .isLength({ min: 3, max: 30 })
            .matches(/^[a-zA-Z0-9_-]+$/)
            .withMessage('Username must be 3-30 characters long and contain only letters, numbers, underscore, or dash')
            .run(req),
        body('password')
            .isLength({ min: 8 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
            .withMessage('Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one number, and one special character')
            .run(req),
        body('firstName')
            .isLength({ min: 1, max: 50 })
            .trim()
            .escape()
            .withMessage('First name is required and must be less than 50 characters')
            .run(req),
        body('lastName')
            .isLength({ min: 1, max: 50 })
            .trim()
            .escape()
            .withMessage('Last name is required and must be less than 50 characters')
            .run(req),
        body('role')
            .optional()
            .isIn(['uploader', 'processor', 'auditor'])
            .withMessage('Invalid role specified')
            .run(req)
    ]);

    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const formattedErrors = errors.array().map(error => ({
            field: error.param,
            message: error.msg
        }));

        logAuthEvent('REGISTRATION_VALIDATION_FAILED', {
            email: req.body.email,
            errors: formattedErrors,
            ip: req.ip,
            success: false
        });

        return res.status(400).json({
            status: 'fail',
            message: 'Validation failed',
            errors: formattedErrors
        });
    }

    const { email, username, password, firstName, lastName, role = 'uploader', organization, department } = req.body;

    try {
        logger.info('User registration attempt', {
            email,
            username,
            role,
            ip: req.ip
        });

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existingUser) {
            logAuthEvent('REGISTRATION_DUPLICATE_USER', {
                email,
                username,
                existingField: existingUser.email === email ? 'email' : 'username',
                ip: req.ip,
                success: false
            });

            throw new AppError(
                existingUser.email === email ? 'Email already registered' : 'Username already taken',
                409,
                'USER_EXISTS'
            );
        }

        // Create new user
        const userData = {
            email,
            username,
            password,
            profile: {
                firstName,
                lastName,
                organization: organization || '',
                department: department || ''
            },
            role,
            security: {
                isActive: true,
                isVerified: false // In production, implement email verification
            }
        };

        const user = await User.createWithPermissions(userData);

        // Generate JWT token
        const token = user.generateJWT();

        // Generate API key
        const apiKey = await user.generateApiKey();

        logAuthEvent('REGISTRATION_SUCCESS', {
            userId: user._id,
            email: user.email,
            username: user.username,
            role: user.role,
            ip: req.ip,
            success: true
        });

        logger.info('User registered successfully', {
            userId: user._id,
            email: user.email,
            role: user.role
        });

        // Return user data without sensitive information
        res.status(201).json({
            status: 'success',
            message: 'User registered successfully',
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    username: user.username,
                    fullName: user.fullName,
                    role: user.role,
                    permissions: user.permissions,
                    isActive: user.security.isActive,
                    createdAt: user.createdAt
                },
                token,
                apiKey, // Only provided once during registration
                expiresIn: process.env.JWT_EXPIRES_IN || '7d'
            }
        });

    } catch (error) {
        logAuthEvent('REGISTRATION_FAILED', {
            email,
            username,
            error: error.message,
            ip: req.ip,
            success: false
        });

        throw error;
    }
});

/**
 * User Login
 * उपयोगकर्ता लॉगिन
 * 
 * POST /api/auth/login
 * Authenticates user credentials and returns JWT token
 */
const login = catchAsync(async (req, res) => {
    // Validation rules
    await Promise.all([
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Please provide a valid email address')
            .run(req),
        body('password')
            .isLength({ min: 1 })
            .withMessage('Password is required')
            .run(req)
    ]);

    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            status: 'fail',
            message: 'Please provide valid email and password'
        });
    }

    const { email, password, rememberMe = false } = req.body;
    const clientIP = req.ip;

    try {
        logger.info('Login attempt', { email, ip: clientIP });

        // Find user and check credentials
        const user = await User.findByCredentials(email, password);

        // Handle login attempt tracking
        await user.handleLoginAttempt(true, clientIP);

        // Generate JWT token with appropriate expiration
        const tokenExpiry = rememberMe ? '30d' : (process.env.JWT_EXPIRES_IN || '7d');
        const token = jwt.sign(
            {
                id: user._id,
                email: user.email,
                role: user.role,
                permissions: user.permissions
            },
            process.env.JWT_SECRET,
            {
                expiresIn: tokenExpiry,
                issuer: 'secure-fin-data',
                audience: 'api-users'
            }
        );

        logAuthEvent('LOGIN_SUCCESS', {
            userId: user._id,
            email: user.email,
            role: user.role,
            ip: clientIP,
            userAgent: req.get('User-Agent'),
            rememberMe,
            success: true
        });

        logger.info('User logged in successfully', {
            userId: user._id,
            email: user.email,
            role: user.role,
            ip: clientIP
        });

        // Set secure cookie with token (optional, for web clients)
        if (req.headers.origin) {
            res.cookie('authToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000
            });
        }

        res.status(200).json({
            status: 'success',
            message: 'Login successful',
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    username: user.username,
                    fullName: user.fullName,
                    role: user.role,
                    permissions: user.permissions,
                    lastLoginAt: user.security.lastLoginAt,
                    isVerified: user.security.isVerified
                },
                token,
                expiresIn: tokenExpiry
            }
        });

    } catch (error) {
        // Handle failed login attempt
        if (error.message.includes('Invalid credentials') || error.message.includes('Account locked')) {
            const user = await User.findOne({ email });
            if (user) {
                await user.handleLoginAttempt(false, clientIP);
            }

            logAuthEvent('LOGIN_FAILED', {
                email,
                ip: clientIP,
                userAgent: req.get('User-Agent'),
                reason: error.message,
                success: false
            });
        }

        // Return generic error message for security
        throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }
});

/**
 * User Logout
 * उपयोगकर्ता लॉगआउट
 * 
 * POST /api/auth/logout
 * Invalidates user session and clears cookies
 */
const logout = catchAsync(async (req, res) => {
    try {
        logAuthEvent('LOGOUT', {
            userId: req.user?._id,
            email: req.user?.email,
            ip: req.ip,
            success: true
        });

        // Clear auth cookie if present
        res.clearCookie('authToken');

        logger.info('User logged out', {
            userId: req.user?._id,
            email: req.user?.email
        });

        res.status(200).json({
            status: 'success',
            message: 'Logout successful'
        });

    } catch (error) {
        throw new AppError('Logout failed', 500, 'LOGOUT_FAILED');
    }
});

/**
 * Get Current User Profile
 * वर्तमान उपयोगकर्ता प्रोफ़ाइल प्राप्त करें
 * 
 * GET /api/auth/profile
 * Returns current authenticated user's profile information
 */
const getProfile = catchAsync(async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');

        if (!user) {
            throw new AppError('User not found', 404, 'USER_NOT_FOUND');
        }

        res.status(200).json({
            status: 'success',
            message: 'Profile retrieved successfully',
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    username: user.username,
                    fullName: user.fullName,
                    profile: user.profile,
                    role: user.role,
                    permissions: user.permissions,
                    security: {
                        isActive: user.security.isActive,
                        isVerified: user.security.isVerified,
                        twoFactorEnabled: user.security.twoFactorEnabled,
                        lastLoginAt: user.security.lastLoginAt,
                        lastLoginIP: user.security.lastLoginIP
                    },
                    apiAccess: {
                        enabled: user.apiAccess.enabled,
                        rateLimitTier: user.apiAccess.rateLimitTier,
                        apiKeyCreatedAt: user.apiAccess.apiKeyCreatedAt
                    },
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt
                }
            }
        });

    } catch (error) {
        throw new AppError('Profile retrieval failed', 500, 'PROFILE_FAILED');
    }
});

/**
 * Update User Profile
 * उपयोगकर्ता प्रोफ़ाइल अपडेट करें
 * 
 * PUT /api/auth/profile
 * Updates user profile information
 */
const updateProfile = catchAsync(async (req, res) => {
    // Validation rules for profile update
    await Promise.all([
        body('firstName')
            .optional()
            .isLength({ min: 1, max: 50 })
            .trim()
            .escape()
            .run(req),
        body('lastName')
            .optional()
            .isLength({ min: 1, max: 50 })
            .trim()
            .escape()
            .run(req),
        body('organization')
            .optional()
            .isLength({ max: 100 })
            .trim()
            .escape()
            .run(req),
        body('department')
            .optional()
            .isLength({ max: 50 })
            .trim()
            .escape()
            .run(req)
    ]);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            status: 'fail',
            message: 'Validation failed',
            errors: errors.array()
        });
    }

    try {
        const { firstName, lastName, organization, department } = req.body;

        const updateData = {};
        if (firstName) updateData['profile.firstName'] = firstName;
        if (lastName) updateData['profile.lastName'] = lastName;
        if (organization !== undefined) updateData['profile.organization'] = organization;
        if (department !== undefined) updateData['profile.department'] = department;

        const user = await User.findByIdAndUpdate(
            req.user._id,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');

        logSecurityEvent('PROFILE_UPDATED', {
            userId: user._id,
            updatedFields: Object.keys(updateData)
        }, req.user);

        logger.info('User profile updated', {
            userId: user._id,
            email: user.email,
            updatedFields: Object.keys(updateData)
        });

        res.status(200).json({
            status: 'success',
            message: 'Profile updated successfully',
            data: { user }
        });

    } catch (error) {
        throw new AppError('Profile update failed', 500, 'UPDATE_FAILED');
    }
});

/**
 * Change Password
 * पासवर्ड बदलें
 * 
 * PUT /api/auth/password
 * Changes user password with current password verification
 */
const changePassword = catchAsync(async (req, res) => {
    await Promise.all([
        body('currentPassword')
            .isLength({ min: 1 })
            .withMessage('Current password is required')
            .run(req),
        body('newPassword')
            .isLength({ min: 8 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
            .withMessage('New password must meet security requirements')
            .run(req)
    ]);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            status: 'fail',
            message: 'Password validation failed',
            errors: errors.array()
        });
    }

    const { currentPassword, newPassword } = req.body;

    try {
        const user = await User.findById(req.user._id);

        // Verify current password
        const isCurrentPasswordValid = await user.checkPassword(currentPassword);
        if (!isCurrentPasswordValid) {
            logSecurityEvent('PASSWORD_CHANGE_FAILED', {
                userId: user._id,
                reason: 'Invalid current password'
            }, req.user);

            throw new AppError('Current password is incorrect', 401, 'INVALID_CURRENT_PASSWORD');
        }

        // Update password
        user.password = newPassword;
        await user.save();

        logSecurityEvent('PASSWORD_CHANGED', {
            userId: user._id,
            timestamp: new Date().toISOString()
        }, req.user);

        logger.info('Password changed successfully', {
            userId: user._id,
            email: user.email
        });

        res.status(200).json({
            status: 'success',
            message: 'Password changed successfully'
        });

    } catch (error) {
        throw error;
    }
});

/**
 * Generate New API Key
 * नई API की जेनरेट करें
 * 
 * POST /api/auth/api-key
 * Generates a new API key for programmatic access
 */
const generateApiKey = catchAsync(async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        const apiKey = await user.generateApiKey();

        logSecurityEvent('API_KEY_GENERATED', {
            userId: user._id,
            timestamp: new Date().toISOString()
        }, req.user);

        logger.info('New API key generated', {
            userId: user._id,
            email: user.email
        });

        res.status(200).json({
            status: 'success',
            message: 'API key generated successfully',
            data: {
                apiKey: apiKey, // This is the only time the plaintext key is returned
                createdAt: user.apiAccess.apiKeyCreatedAt,
                warning: 'Store this key securely. It will not be shown again.'
            }
        });

    } catch (error) {
        throw new AppError('API key generation failed', 500, 'API_KEY_FAILED');
    }
});

/**
 * Refresh Token
 * टोकन रीफ्रेश करें
 * 
 * POST /api/auth/refresh
 * Refreshes JWT token before expiration
 */
const refreshToken = catchAsync(async (req, res) => {
    try {
        // Generate new token with same expiration time
        const newToken = req.user.generateJWT();

        logAuthEvent('TOKEN_REFRESHED', {
            userId: req.user._id,
            email: req.user.email,
            ip: req.ip
        });

        res.status(200).json({
            status: 'success',
            message: 'Token refreshed successfully',
            data: {
                token: newToken,
                expiresIn: process.env.JWT_EXPIRES_IN || '7d'
            }
        });

    } catch (error) {
        throw new AppError('Token refresh failed', 500, 'REFRESH_FAILED');
    }
});

/**
 * Verify Token
 * टोकन सत्यापित करें
 * 
 * GET /api/auth/verify
 * Verifies if current token is valid
 */
const verifyToken = catchAsync(async (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Token is valid',
        data: {
            user: {
                id: req.user._id,
                email: req.user.email,
                role: req.user.role
            },
            isValid: true
        }
    });
});

module.exports = {
    register,
    login,
    logout,
    getProfile,
    updateProfile,
    changePassword,
    generateApiKey,
    refreshToken,
    verifyToken
};