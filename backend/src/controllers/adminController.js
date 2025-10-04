/**
 * Admin Controller
 * एडमिन कंट्रोलर
 * 
 * Handles administrative operations for the secure financial data platform
 * सुरक्षित वित्तीय डेटा प्लेटफॉर्म के लिए प्रशासनिक कार्यों को संभालता है
 */

const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const EncryptedResult = require('../models/EncryptedResult');
const { logger, logSecurityEvent } = require('../utils/logger');
const keyStore = require('../utils/keyStore');

/**
 * Get system dashboard
 * सिस्टम डैशबोर्ड प्राप्त करें
 */
const getDashboard = async (req, res) => {
    try {
        logger.info('Admin dashboard accessed', {
            adminId: req.user.id,
            userAgent: req.get('User-Agent'),
            ip: req.ip
        });

        // Get system statistics
        const [userCount, resultCount, keyStoreHealth] = await Promise.all([
            User.countDocuments(),
            EncryptedResult.countDocuments(),
            keyStore.getHealthStatus()
        ]);

        // Get recent activity
        const recentUsers = await User.find({})
            .select('username email role createdAt lastLogin')
            .sort({ createdAt: -1 })
            .limit(10);

        const recentResults = await EncryptedResult.find({})
            .select('fileName userId createdAt metrics.summary')
            .populate('userId', 'username email')
            .sort({ createdAt: -1 })
            .limit(10);

        // Get user role distribution
        const roleDistribution = await User.aggregate([
            {
                $group: {
                    _id: '$role',
                    count: { $sum: 1 }
                }
            }
        ]);

        // Get processing statistics
        const processingStats = await EncryptedResult.aggregate([
            {
                $group: {
                    _id: {
                        $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
                    },
                    count: { $sum: 1 },
                    totalSize: { $sum: '$fileSize' }
                }
            },
            {
                $sort: { '_id': -1 }
            },
            {
                $limit: 30
            }
        ]);

        const dashboardData = {
            summary: {
                totalUsers: userCount,
                totalResults: resultCount,
                keyStoreStatus: keyStoreHealth.status,
                systemHealth: 'operational'
            },
            recentActivity: {
                users: recentUsers,
                results: recentResults
            },
            analytics: {
                roleDistribution,
                processingStats
            },
            keyStore: keyStoreHealth
        };

        res.json({
            success: true,
            data: dashboardData,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        logger.error('Admin dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch dashboard data',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Get all users (with pagination and filtering)
 * सभी उपयोगकर्ता प्राप्त करें (पेजिनेशन और फ़िल्टरिंग के साथ)
 */
const getUsers = async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            role,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        logger.info('Admin users list accessed', {
            adminId: req.user.id,
            filters: { page, limit, role, search, sortBy, sortOrder }
        });

        // Build query
        const query = {};
        if (role) {
            query.role = role;
        }
        if (search) {
            query.$or = [
                { username: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }

        // Build sort
        const sort = {};
        sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Execute query with pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [users, total] = await Promise.all([
            User.find(query)
                .select('-password')
                .sort(sort)
                .skip(skip)
                .limit(parseInt(limit)),
            User.countDocuments(query)
        ]);

        // Get processing statistics for each user
        const userIds = users.map(user => user._id);
        const userStats = await EncryptedResult.aggregate([
            {
                $match: { userId: { $in: userIds } }
            },
            {
                $group: {
                    _id: '$userId',
                    totalFiles: { $sum: 1 },
                    totalSize: { $sum: '$fileSize' },
                    lastActivity: { $max: '$createdAt' }
                }
            }
        ]);

        // Merge user data with statistics
        const usersWithStats = users.map(user => {
            const stats = userStats.find(stat => stat._id.equals(user._id));
            return {
                ...user.toObject(),
                stats: stats ? {
                    totalFiles: stats.totalFiles,
                    totalSize: stats.totalSize,
                    lastActivity: stats.lastActivity
                } : {
                    totalFiles: 0,
                    totalSize: 0,
                    lastActivity: null
                }
            };
        });

        res.json({
            success: true,
            data: {
                users: usersWithStats,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalUsers: total,
                    hasNextPage: skip + parseInt(limit) < total,
                    hasPrevPage: parseInt(page) > 1
                }
            }
        });

    } catch (error) {
        logger.error('Admin get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Get user by ID
 * ID द्वारा उपयोगकर्ता प्राप्त करें
 */
const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;

        logger.info('Admin user detail accessed', {
            adminId: req.user.id,
            targetUserId: userId
        });

        // Find user
        const user = await User.findById(userId).select('-password');
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Get user's processing history
        const processingHistory = await EncryptedResult.find({ userId })
            .select('fileName fileSize createdAt metrics.summary')
            .sort({ createdAt: -1 })
            .limit(50);

        // Get user statistics
        const stats = await EncryptedResult.aggregate([
            {
                $match: { userId: user._id }
            },
            {
                $group: {
                    _id: null,
                    totalFiles: { $sum: 1 },
                    totalSize: { $sum: '$fileSize' },
                    firstActivity: { $min: '$createdAt' },
                    lastActivity: { $max: '$createdAt' }
                }
            }
        ]);

        const userDetail = {
            ...user.toObject(),
            processingHistory,
            stats: stats[0] || {
                totalFiles: 0,
                totalSize: 0,
                firstActivity: null,
                lastActivity: null
            }
        };

        res.json({
            success: true,
            data: userDetail
        });

    } catch (error) {
        logger.error('Admin get user by ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user details',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Update user
 * उपयोगकर्ता अपडेट करें
 */
const updateUser = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { userId } = req.params;
        const { username, email, role, isActive } = req.body;

        logger.info('Admin user update initiated', {
            adminId: req.user.id,
            targetUserId: userId,
            updates: { username, email, role, isActive }
        });

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Prevent admin from modifying their own role
        if (user._id.equals(req.user.id) && role && role !== user.role) {
            return res.status(400).json({
                success: false,
                message: 'Cannot modify your own role'
            });
        }

        // Check for email uniqueness if email is being changed
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already registered'
                });
            }
        }

        // Check for username uniqueness if username is being changed
        if (username && username !== user.username) {
            const existingUser = await User.findOne({ username, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Username already taken'
                });
            }
        }

        // Update user
        const updateData = {};
        if (username !== undefined) updateData.username = username;
        if (email !== undefined) updateData.email = email;
        if (role !== undefined) updateData.role = role;
        if (isActive !== undefined) updateData.isActive = isActive;

        updateData.updatedAt = new Date();

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');

        logSecurityEvent('USER_UPDATED_BY_ADMIN', {
            adminId: req.user.id,
            targetUserId: userId,
            updates: Object.keys(updateData)
        });

        logger.info('User updated by admin', {
            adminId: req.user.id,
            targetUserId: userId,
            updates: Object.keys(updateData)
        });

        res.json({
            success: true,
            message: 'User updated successfully',
            data: updatedUser
        });

    } catch (error) {
        logger.error('Admin update user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Delete user
 * उपयोगकर्ता हटाएं
 */
const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;

        logger.info('Admin user deletion initiated', {
            adminId: req.user.id,
            targetUserId: userId
        });

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Prevent admin from deleting themselves
        if (user._id.equals(req.user.id)) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete your own account'
            });
        }

        // Check if user has processed files
        const userFiles = await EncryptedResult.countDocuments({ userId });

        if (userFiles > 0) {
            // In production, you might want to:
            // 1. Transfer ownership to another user
            // 2. Archive the data
            // 3. Provide option to cascade delete

            return res.status(400).json({
                success: false,
                message: `Cannot delete user with ${userFiles} processed files. Please transfer or delete their data first.`,
                details: {
                    processedFiles: userFiles
                }
            });
        }

        // Delete user
        await User.findByIdAndDelete(userId);

        logSecurityEvent('USER_DELETED_BY_ADMIN', {
            adminId: req.user.id,
            targetUserId: userId,
            deletedUser: {
                username: user.username,
                email: user.email,
                role: user.role
            }
        });

        logger.info('User deleted by admin', {
            adminId: req.user.id,
            targetUserId: userId
        });

        res.json({
            success: true,
            message: 'User deleted successfully'
        });

    } catch (error) {
        logger.error('Admin delete user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Reset user password
 * उपयोगकर्ता पासवर्ड रीसेट करें
 */
const resetUserPassword = async (req, res) => {
    try {
        const { userId } = req.params;
        const { newPassword } = req.body;

        if (!newPassword || newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }

        logger.info('Admin password reset initiated', {
            adminId: req.user.id,
            targetUserId: userId
        });

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Hash new password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update password
        await User.findByIdAndUpdate(userId, {
            password: hashedPassword,
            updatedAt: new Date()
        });

        logSecurityEvent('PASSWORD_RESET_BY_ADMIN', {
            adminId: req.user.id,
            targetUserId: userId
        });

        logger.info('User password reset by admin', {
            adminId: req.user.id,
            targetUserId: userId
        });

        res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        logger.error('Admin reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Get system logs
 * सिस्टम लॉग प्राप्त करें
 */
const getLogs = async (req, res) => {
    try {
        const {
            page = 1,
            limit = 100,
            level,
            startDate,
            endDate,
            search
        } = req.query;

        logger.info('Admin logs accessed', {
            adminId: req.user.id,
            filters: { page, limit, level, startDate, endDate, search }
        });

        // In a production system, you would query your log storage
        // (e.g., Elasticsearch, MongoDB, log files, etc.)
        // For this demo, we'll return a mock response

        const mockLogs = [
            {
                timestamp: new Date().toISOString(),
                level: 'info',
                message: 'User authentication successful',
                userId: 'user123',
                ip: '192.168.1.100'
            },
            {
                timestamp: new Date(Date.now() - 60000).toISOString(),
                level: 'warn',
                message: 'Multiple failed login attempts',
                ip: '192.168.1.105',
                attempts: 3
            },
            {
                timestamp: new Date(Date.now() - 120000).toISOString(),
                level: 'error',
                message: 'File encryption failed',
                userId: 'user456',
                fileName: 'financial-data.xlsx',
                error: 'Invalid file format'
            }
        ];

        // Apply filters (mock implementation)
        let filteredLogs = [...mockLogs];

        if (level) {
            filteredLogs = filteredLogs.filter(log => log.level === level);
        }

        if (search) {
            filteredLogs = filteredLogs.filter(log =>
                log.message.toLowerCase().includes(search.toLowerCase())
            );
        }

        // Apply pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const paginatedLogs = filteredLogs.slice(skip, skip + parseInt(limit));

        res.json({
            success: true,
            data: {
                logs: paginatedLogs,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(filteredLogs.length / parseInt(limit)),
                    totalLogs: filteredLogs.length,
                    hasNextPage: skip + parseInt(limit) < filteredLogs.length,
                    hasPrevPage: parseInt(page) > 1
                }
            },
            notice: 'This is a demo implementation. In production, integrate with your log storage system.'
        });

    } catch (error) {
        logger.error('Admin get logs error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch logs',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Get system analytics
 * सिस्टम एनालिटिक्स प्राप्त करें
 */
const getAnalytics = async (req, res) => {
    try {
        const { period = '7d' } = req.query;

        logger.info('Admin analytics accessed', {
            adminId: req.user.id,
            period
        });

        // Calculate date range
        const now = new Date();
        let startDate;

        switch (period) {
            case '24h':
                startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                break;
            case '7d':
                startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                break;
            case '30d':
                startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                break;
            case '90d':
                startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
                break;
            default:
                startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        }

        // Get analytics data
        const [
            userGrowth,
            fileProcessingTrends,
            errorRates,
            systemUsage
        ] = await Promise.all([
            // User growth
            User.aggregate([
                {
                    $match: { createdAt: { $gte: startDate } }
                },
                {
                    $group: {
                        _id: {
                            $dateToString: {
                                format: period === '24h' ? '%H' : '%Y-%m-%d',
                                date: '$createdAt'
                            }
                        },
                        count: { $sum: 1 }
                    }
                },
                {
                    $sort: { '_id': 1 }
                }
            ]),

            // File processing trends
            EncryptedResult.aggregate([
                {
                    $match: { createdAt: { $gte: startDate } }
                },
                {
                    $group: {
                        _id: {
                            $dateToString: {
                                format: period === '24h' ? '%H' : '%Y-%m-%d',
                                date: '$createdAt'
                            }
                        },
                        filesProcessed: { $sum: 1 },
                        totalSize: { $sum: '$fileSize' }
                    }
                },
                {
                    $sort: { '_id': 1 }
                }
            ]),

            // Mock error rates (in production, query from logs)
            Promise.resolve([
                { _id: '2023-12-01', errors: 2, total: 100 },
                { _id: '2023-12-02', errors: 1, total: 150 },
                { _id: '2023-12-03', errors: 3, total: 200 }
            ]),

            // System usage statistics
            EncryptedResult.aggregate([
                {
                    $match: { createdAt: { $gte: startDate } }
                },
                {
                    $group: {
                        _id: null,
                        totalFiles: { $sum: 1 },
                        totalSize: { $sum: '$fileSize' },
                        avgFileSize: { $avg: '$fileSize' },
                        uniqueUsers: { $addToSet: '$userId' }
                    }
                }
            ])
        ]);

        const analytics = {
            period,
            dateRange: {
                start: startDate.toISOString(),
                end: now.toISOString()
            },
            userGrowth: userGrowth.map(item => ({
                period: item._id,
                newUsers: item.count
            })),
            fileProcessing: fileProcessingTrends.map(item => ({
                period: item._id,
                filesProcessed: item.filesProcessed,
                totalSize: item.totalSize
            })),
            errorRates: errorRates.map(item => ({
                date: item._id,
                errorRate: item.total > 0 ? (item.errors / item.total * 100).toFixed(2) : 0,
                errors: item.errors,
                total: item.total
            })),
            systemUsage: systemUsage[0] || {
                totalFiles: 0,
                totalSize: 0,
                avgFileSize: 0,
                uniqueUsers: []
            }
        };

        res.json({
            success: true,
            data: analytics
        });

    } catch (error) {
        logger.error('Admin get analytics error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch analytics',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * Manage keys
 * कीज़ प्रबंधित करें
 */
const manageKeys = async (req, res) => {
    try {
        const { action } = req.params;

        logger.info('Admin key management accessed', {
            adminId: req.user.id,
            action
        });

        let result;

        switch (action) {
            case 'list':
                result = await keyStore.listKeys();
                break;

            case 'rotate':
                result = await keyStore.rotateKeys();
                break;

            case 'health':
                result = await keyStore.getHealthStatus();
                break;

            default:
                return res.status(400).json({
                    success: false,
                    message: 'Invalid action. Supported: list, rotate, health'
                });
        }

        logSecurityEvent('KEY_MANAGEMENT_ACTION', {
            adminId: req.user.id,
            action
        });

        res.json({
            success: true,
            action,
            data: result
        });

    } catch (error) {
        logger.error('Admin key management error:', error);
        res.status(500).json({
            success: false,
            message: 'Key management operation failed',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

module.exports = {
    getDashboard,
    getUsers,
    getUserById,
    updateUser,
    deleteUser,
    resetUserPassword,
    getLogs,
    getAnalytics,
    manageKeys
};