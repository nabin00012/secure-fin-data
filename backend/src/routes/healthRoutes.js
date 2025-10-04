/**
 * Health Check Routes
 * स्वास्थ्य जांच रूट्स
 * 
 * Provides health check endpoints for monitoring service availability,
 * dependencies, and system status for deployment and monitoring tools.
 */

const express = require('express');
const mongoose = require('mongoose');
const { logger } = require('../utils/logger');
const EncryptionService = require('../services/encryptionService');
const MetricService = require('../services/metricService');
const { optionalAuth } = require('../middleware/authMiddleware');

const router = express.Router();

// Services will be initialized on-demand for health checks

/**
 * Basic Health Check
 * बुनियादी स्वास्थ्य जांच
 * 
 * @route   GET /api/health
 * @desc    Basic health check endpoint
 * @access  Public
 */
router.get('/', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        message: 'Secure Financial Data Processing API is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    });
});

/**
 * Comprehensive Health Check with Service Status
 * सेवा स्थिति के साथ व्यापक स्वास्थ्य जांच
 * 
 * Returns detailed health information about all system components
 */
router.get('/detailed',
    optionalAuth, // User authentication optional for detailed health
    async (req, res) => {
        try {
            const healthData = {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                system: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    arch: process.arch,
                    memory: process.memoryUsage(),
                    pid: process.pid
                },
                services: {}
            };

            // Check MongoDB connection
            try {
                const dbState = mongoose.connection.readyState;
                const dbStates = {
                    0: 'disconnected',
                    1: 'connected',
                    2: 'connecting',
                    3: 'disconnecting'
                };

                healthData.services.database = {
                    status: dbState === 1 ? 'healthy' : 'unhealthy',
                    state: dbStates[dbState],
                    host: mongoose.connection.host,
                    name: mongoose.connection.name,
                    collections: mongoose.connection.db ?
                        Object.keys(mongoose.connection.db.collections || {}).length : 0
                };
            } catch (error) {
                healthData.services.database = {
                    status: 'unhealthy',
                    error: error.message
                };
            }

            // Check Encryption Service (create instance on demand)
            try {
                const encryptionService = new EncryptionService();
                healthData.services.encryption = await encryptionService.healthCheck();
            } catch (error) {
                healthData.services.encryption = {
                    status: 'unhealthy',
                    error: error.message
                };
            }

            // Check Metrics Service (create instance on demand)
            try {
                const metricService = new MetricService();
                healthData.services.metrics = await metricService.healthCheck();
            } catch (error) {
                healthData.services.metrics = {
                    status: 'unhealthy',
                    error: error.message
                };
            }

            // Determine overall health status
            const unhealthyServices = Object.values(healthData.services)
                .filter(service => service.status === 'unhealthy');

            if (unhealthyServices.length > 0) {
                healthData.status = 'degraded';
                res.status(503);
            }

            // Add user context if authenticated
            if (req.user) {
                healthData.user = {
                    authenticated: true,
                    role: req.user.role,
                    permissions: req.user.permissions
                };
            }

            logger.info('Detailed health check completed', {
                status: healthData.status,
                services: Object.keys(healthData.services),
                requestId: req.requestId
            });

            res.json(healthData);

        } catch (error) {
            logger.error('Health check failed:', error);
            res.status(503).json({
                status: 'unhealthy',
                error: 'Health check failed',
                timestamp: new Date().toISOString()
            });
        }
    }
);

/**
 * Readiness Check
 * तैयारी जांच
 * 
 * @route   GET /api/health/ready
 * @desc    Kubernetes readiness probe endpoint
 * @access  Public
 */
router.get('/ready', async (req, res) => {
    try {
        // Check if all critical services are ready
        const dbReady = await isDatabaseReady();
        const encryptionReady = await isEncryptionServiceReady();

        if (dbReady && encryptionReady) {
            res.status(200).json({
                status: 'ready',
                message: 'Service is ready to handle requests',
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                status: 'not-ready',
                message: 'Service is not ready to handle requests',
                dependencies: {
                    database: dbReady,
                    encryption: encryptionReady
                },
                timestamp: new Date().toISOString()
            });
        }

    } catch (error) {
        logger.error('Readiness check failed:', error);

        res.status(503).json({
            status: 'not-ready',
            message: 'Readiness check failed',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * Liveness Check
 * जीवंतता जांच
 * 
 * @route   GET /api/health/live
 * @desc    Kubernetes liveness probe endpoint
 * @access  Public
 */
router.get('/live', (req, res) => {
    // Basic liveness check - if we can respond, we're alive
    res.status(200).json({
        status: 'alive',
        message: 'Service is alive',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        pid: process.pid
    });
});

/**
 * Metrics Endpoint
 * मेट्रिक्स एंडपॉइंट
 * 
 * @route   GET /api/health/metrics
 * @desc    Application metrics for monitoring
 * @access  Private (optional auth - limited info for unauthenticated)
 */
router.get('/metrics', optionalAuth, (req, res) => {
    const metrics = {
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    };

    // Add detailed metrics for authenticated users
    if (req.user) {
        metrics.detailed = {
            activeHandles: process._getActiveHandles().length,
            activeRequests: process._getActiveRequests().length,
            eventLoopDelay: getEventLoopDelay(),
            gc: getGCStats()
        };
    }

    res.status(200).json({
        status: 'success',
        message: 'Metrics retrieved successfully',
        data: metrics
    });
});

/**
 * Service-specific health check functions
 * सेवा-विशिष्ट स्वास्थ्य जांच कार्य
 */

/**
 * Check database connectivity and health
 */
async function checkDatabaseHealth() {
    try {
        // Check if mongoose is connected
        if (mongoose.connection.readyState !== 1) {
            return {
                status: 'unhealthy',
                error: 'Database not connected',
                readyState: mongoose.connection.readyState
            };
        }

        // Perform a simple database operation
        await mongoose.connection.db.admin().ping();

        // Get database stats
        const stats = await mongoose.connection.db.stats();

        return {
            status: 'healthy',
            connection: mongoose.connection.readyState,
            host: mongoose.connection.host,
            name: mongoose.connection.name,
            collections: stats.collections,
            dataSize: stats.dataSize,
            indexSize: stats.indexSize
        };

    } catch (error) {
        return {
            status: 'unhealthy',
            error: error.message
        };
    }
}

/**
 * Check encryption service health
 */
async function checkEncryptionService() {
    try {
        const status = await encryptionService.getHealthStatus();
        return status;
    } catch (error) {
        return {
            status: 'unhealthy',
            error: error.message
        };
    }
}

/**
 * Check metric service health
 */
function checkMetricService() {
    try {
        const status = metricService.getHealthStatus();
        return status;
    } catch (error) {
        return {
            status: 'unhealthy',
            error: error.message
        };
    }
}

/**
 * Check Redis connectivity (if configured)
 */
async function checkRedisHealth() {
    try {
        // This would be implemented if Redis is used
        // For now, return a placeholder
        return {
            status: 'not-configured',
            message: 'Redis not configured'
        };
    } catch (error) {
        return {
            status: 'unhealthy',
            error: error.message
        };
    }
}

/**
 * Get system health information
 */
function getSystemHealth() {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    return {
        memory: {
            used: memUsage.heapUsed,
            total: memUsage.heapTotal,
            external: memUsage.external,
            rss: memUsage.rss,
            usage: ((memUsage.heapUsed / memUsage.heapTotal) * 100).toFixed(2) + '%'
        },
        cpu: {
            user: cpuUsage.user,
            system: cpuUsage.system
        },
        uptime: process.uptime(),
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        pid: process.pid
    };
}

/**
 * Readiness check functions
 */
async function isDatabaseReady() {
    try {
        return mongoose.connection.readyState === 1;
    } catch (error) {
        return false;
    }
}

async function isEncryptionServiceReady() {
    try {
        const status = await encryptionService.getHealthStatus();
        return status.status === 'healthy' && status.operationalTest === true;
    } catch (error) {
        return false;
    }
}

/**
 * Get event loop delay (for performance monitoring)
 */
function getEventLoopDelay() {
    const start = process.hrtime.bigint();
    setImmediate(() => {
        const delta = process.hrtime.bigint() - start;
        return Number(delta / BigInt(1000000)); // Convert to milliseconds
    });
    return 0; // Placeholder - would need async implementation
}

/**
 * Get garbage collection stats
 */
function getGCStats() {
    // This would require additional monitoring setup
    // For now, return basic info
    return {
        enabled: typeof global.gc === 'function',
        manual: false // Whether manual GC is available
    };
}

/**
 * Startup Health Check
 * स्टार्टअप स्वास्थ्य जांच
 * 
 * @route   GET /api/health/startup
 * @desc    Health check for application startup verification
 * @access  Public
 */
router.get('/startup', async (req, res) => {
    const startupChecks = {
        timestamp: new Date().toISOString(),
        status: 'checking',
        checks: {}
    };

    try {
        // Check environment variables
        startupChecks.checks.environment = checkEnvironmentVariables();

        // Check database connection
        startupChecks.checks.database = await checkDatabaseHealth();

        // Check encryption service
        startupChecks.checks.encryption = await checkEncryptionService();

        // Check file system permissions
        startupChecks.checks.filesystem = checkFileSystemPermissions();

        // Determine overall startup status
        const allChecksPass = Object.values(startupChecks.checks).every(
            check => check.status === 'healthy' || check.status === 'pass'
        );

        startupChecks.status = allChecksPass ? 'ready' : 'failed';

        const statusCode = allChecksPass ? 200 : 503;
        res.status(statusCode).json(startupChecks);

    } catch (error) {
        logger.error('Startup health check failed:', error);

        startupChecks.status = 'failed';
        startupChecks.error = error.message;

        res.status(503).json(startupChecks);
    }
});

/**
 * Check required environment variables
 */
function checkEnvironmentVariables() {
    const required = [
        'NODE_ENV',
        'MONGODB_URI',
        'JWT_SECRET',
        'HMAC_SECRET'
    ];

    const missing = required.filter(env => !process.env[env]);

    return {
        status: missing.length === 0 ? 'pass' : 'fail',
        required: required.length,
        present: required.length - missing.length,
        missing: missing
    };
}

/**
 * Check file system permissions
 */
function checkFileSystemPermissions() {
    const fs = require('fs');
    const path = require('path');

    try {
        // Check if we can create/write to logs directory
        const logsDir = path.join(__dirname, '../../logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }

        // Test write permission
        const testFile = path.join(logsDir, 'test-write.tmp');
        fs.writeFileSync(testFile, 'test');
        fs.unlinkSync(testFile);

        return {
            status: 'pass',
            logsDirectory: 'writable'
        };

    } catch (error) {
        return {
            status: 'fail',
            error: error.message
        };
    }
}

module.exports = router;