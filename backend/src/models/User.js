/**
 * User Model
 * उपयोगकर्ता मॉडल
 * 
 * This model handles user authentication and authorization
 * with secure password hashing and role-based access control.
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { logger, logAuthEvent } = require('../utils/logger');

const userSchema = new mongoose.Schema({
    // User identification
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },

    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },

    // Encrypted password (never store plaintext)
    password: {
        type: String,
        required: true,
        minlength: 8
    },

    // User profile
    profile: {
        firstName: {
            type: String,
            required: true,
            trim: true,
            maxlength: 50
        },
        lastName: {
            type: String,
            required: true,
            trim: true,
            maxlength: 50
        },
        organization: {
            type: String,
            trim: true,
            maxlength: 100
        },
        department: {
            type: String,
            trim: true,
            maxlength: 50
        }
    },

    // Role-based access control
    role: {
        type: String,
        enum: ['uploader', 'processor', 'auditor', 'admin'],
        default: 'uploader'
    },

    permissions: [{
        resource: {
            type: String,
            enum: ['files', 'metrics', 'audit', 'users', 'keys']
        },
        actions: [{
            type: String,
            enum: ['create', 'read', 'update', 'delete', 'decrypt']
        }]
    }],

    // Account security
    security: {
        isActive: {
            type: Boolean,
            default: true
        },
        isVerified: {
            type: Boolean,
            default: false
        },
        twoFactorEnabled: {
            type: Boolean,
            default: false
        },
        passwordChangedAt: {
            type: Date,
            default: Date.now
        },
        loginAttempts: {
            type: Number,
            default: 0
        },
        lockUntil: Date,
        lastLoginAt: Date,
        lastLoginIP: String
    },

    // API access
    apiAccess: {
        enabled: {
            type: Boolean,
            default: true
        },
        rateLimitTier: {
            type: String,
            enum: ['basic', 'premium', 'enterprise'],
            default: 'basic'
        },
        apiKeyHash: String, // Hashed API key
        apiKeyCreatedAt: Date
    }
}, {
    timestamps: true,
    collection: 'users'
});

/**
 * Password hashing middleware
 * पासवर्ड हैशिंग मिडलवेयर
 */
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        // Hash password with bcrypt (cost factor 12)
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);

        // Update password changed timestamp
        this.security.passwordChangedAt = new Date();

        logger.debug('Password hashed successfully', { userId: this._id });
        next();
    } catch (error) {
        logger.error('Password hashing failed:', error);
        next(error);
    }
});

/**
 * Instance methods
 */

/**
 * Check password validity
 * पासवर्ड वैधता की जांच करें
 */
userSchema.methods.checkPassword = async function (candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        logger.error('Password comparison failed:', error);
        return false;
    }
};

/**
 * Generate JWT token
 * JWT टोकन जेनरेट करें
 */
userSchema.methods.generateJWT = function () {
    const payload = {
        id: this._id,
        email: this.email,
        role: this.role,
        permissions: this.permissions
    };

    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN || '7d',
        issuer: 'secure-fin-data',
        audience: 'api-users'
    });
};

/**
 * Check if user has permission
 * जांचें कि उपयोगकर्ता के पास अनुमति है या नहीं
 */
userSchema.methods.hasPermission = function (resource, action) {
    // Admin has all permissions
    if (this.role === 'admin') return true;

    // Check specific permissions
    const permission = this.permissions.find(p => p.resource === resource);
    return permission && permission.actions.includes(action);
};

/**
 * Generate API key
 * API की जेनरेट करें
 */
userSchema.methods.generateApiKey = async function () {
    const crypto = require('crypto');

    // Generate random API key
    const apiKey = crypto.randomBytes(32).toString('hex');

    // Hash and store
    const salt = await bcrypt.genSalt(10);
    this.apiAccess.apiKeyHash = await bcrypt.hash(apiKey, salt);
    this.apiAccess.apiKeyCreatedAt = new Date();

    await this.save();

    logger.info('API key generated', { userId: this._id });

    // Return unhashed key (only time it's available in plaintext)
    return apiKey;
};

/**
 * Validate API key
 * API की को मान्य करें
 */
userSchema.methods.validateApiKey = async function (candidateKey) {
    if (!this.apiAccess.apiKeyHash) return false;

    try {
        return await bcrypt.compare(candidateKey, this.apiAccess.apiKeyHash);
    } catch (error) {
        logger.error('API key validation failed:', error);
        return false;
    }
};

/**
 * Handle login attempt
 * लॉगिन प्रयास को संभालें
 */
userSchema.methods.handleLoginAttempt = async function (success, ipAddress) {
    if (success) {
        // Reset failed attempts on successful login
        if (this.security.loginAttempts > 0) {
            this.security.loginAttempts = 0;
            this.security.lockUntil = undefined;
        }

        this.security.lastLoginAt = new Date();
        this.security.lastLoginIP = ipAddress;

        logAuthEvent('LOGIN_SUCCESS', {
            userId: this._id,
            email: this.email,
            ip: ipAddress,
            success: true
        });

    } else {
        // Increment failed attempts
        this.security.loginAttempts += 1;

        // Lock account after 5 failed attempts
        if (this.security.loginAttempts >= 5) {
            this.security.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        }

        logAuthEvent('LOGIN_FAILED', {
            userId: this._id,
            email: this.email,
            ip: ipAddress,
            success: false,
            attempts: this.security.loginAttempts
        });
    }

    await this.save();
};

/**
 * Check if account is locked
 * जांचें कि खाता बंद है या नहीं
 */
userSchema.methods.isLocked = function () {
    return this.security.lockUntil && this.security.lockUntil > Date.now();
};

/**
 * Static methods
 */

/**
 * Find by credentials
 * क्रेडेंशियल्स द्वारा खोजें
 */
userSchema.statics.findByCredentials = async function (email, password) {
    try {
        const user = await this.findOne({
            email: email.toLowerCase(),
            'security.isActive': true
        });

        if (!user) {
            throw new Error('Invalid credentials');
        }

        if (user.isLocked()) {
            throw new Error('Account locked due to too many failed login attempts');
        }

        const isMatch = await user.checkPassword(password);
        if (!isMatch) {
            throw new Error('Invalid credentials');
        }

        return user;
    } catch (error) {
        logger.error('Authentication failed:', error);
        throw error;
    }
};

/**
 * Create user with default permissions
 * डिफ़ॉल्ट अनुमतियों के साथ उपयोगकर्ता बनाएं
 */
userSchema.statics.createWithPermissions = async function (userData) {
    try {
        // Set default permissions based on role
        const defaultPermissions = this.getDefaultPermissions(userData.role);
        userData.permissions = defaultPermissions;

        const user = new this(userData);
        await user.save();

        logger.info('User created successfully', {
            userId: user._id,
            email: user.email,
            role: user.role
        });

        return user;
    } catch (error) {
        logger.error('User creation failed:', error);
        throw error;
    }
};

/**
 * Get default permissions for role
 * भूमिका के लिए डिफ़ॉल्ट अनुमतियां प्राप्त करें
 */
userSchema.statics.getDefaultPermissions = function (role) {
    const permissions = {
        uploader: [
            { resource: 'files', actions: ['create', 'read'] }
        ],
        processor: [
            { resource: 'files', actions: ['create', 'read', 'decrypt'] },
            { resource: 'metrics', actions: ['create', 'read'] }
        ],
        auditor: [
            { resource: 'files', actions: ['read'] },
            { resource: 'metrics', actions: ['read'] },
            { resource: 'audit', actions: ['read'] }
        ],
        admin: [
            { resource: 'files', actions: ['create', 'read', 'update', 'delete', 'decrypt'] },
            { resource: 'metrics', actions: ['create', 'read', 'update', 'delete'] },
            { resource: 'audit', actions: ['create', 'read', 'update', 'delete'] },
            { resource: 'users', actions: ['create', 'read', 'update', 'delete'] },
            { resource: 'keys', actions: ['create', 'read', 'update', 'delete'] }
        ]
    };

    return permissions[role] || permissions.uploader;
};

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ role: 1 });
userSchema.index({ 'security.isActive': 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function () {
    return `${this.profile.firstName} ${this.profile.lastName}`;
});

// Transform output (remove sensitive fields)
userSchema.methods.toJSON = function () {
    const user = this.toObject();
    delete user.password;
    delete user.security.loginAttempts;
    delete user.security.lockUntil;
    delete user.apiAccess.apiKeyHash;
    return user;
};

const User = mongoose.model('User', userSchema);

module.exports = User;