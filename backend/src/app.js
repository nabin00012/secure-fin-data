/**
 * Main Express Application Entry Point
 * सुरक्षित वित्तीय डेटा प्रसंस्करण - मुख्य एप्लिकेशन
 * 
 * This file sets up the Express server with all necessary middleware,
 * security configurations, and route handlers for secure financial data processing.
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

// Import custom modules
const { logger } = require('./utils/logger');
const { errorHandler, notFound } = require('./middleware/errorMiddleware');
const authMiddleware = require('./middleware/authMiddleware');
const { auditMiddleware } = require('./middleware/auditMiddleware');

// Import route handlers
const fileRoutes = require('./routes/fileRoutes');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const healthRoutes = require('./routes/healthRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

/**
 * Security Middleware Configuration
 * सुरक्षा मिडलवेयर कॉन्फ़िगरेशन
 */

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Rate limiting - prevent abuse
// दर सीमा - दुरुपयोग को रोकने के लिए
const limiter = rateLimit({
    windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW) || 15) * 60 * 1000, // 15 minutes default
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // Limit each IP
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: 'Please wait before making more requests.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', limiter);

// CORS configuration for secure cross-origin requests
const corsOptions = {
    origin: process.env.NODE_ENV === 'production'
        ? ['https://yourdomain.com']
        : ['http://localhost:3000', 'https://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));

// Body parsing middleware
app.use(compression()); // Compress responses
app.use(express.json({ limit: '10mb' })); // JSON parsing with size limit
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Audit logging middleware - log all requests
// ऑडिट लॉगिंग - सभी अनुरोधों को लॉग करें
app.use(auditMiddleware);

/**
 * Database Connection
 * डेटाबेस कनेक्शन
 */
const connectDB = async () => {
    try {
        const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-fin-data';

        await mongoose.connect(mongoURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10, // Maximum number of connections
            serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
            socketTimeoutMS: 45000, // Close connections after 45 seconds of inactivity
        });

        logger.info('MongoDB connected successfully', {
            host: mongoose.connection.host,
            database: mongoose.connection.name
        });

        // Handle connection errors after initial connection
        mongoose.connection.on('error', (err) => {
            logger.error('MongoDB connection error:', err);
        });

        mongoose.connection.on('disconnected', () => {
            logger.warn('MongoDB disconnected');
        });

    } catch (error) {
        logger.error('Database connection failed:', error);
        process.exit(1);
    }
};

// Connect to database
connectDB();

/**
 * Route Configuration
 * रूट कॉन्फ़िगरेशन
 */

// Health check endpoint
app.use('/api/health', healthRoutes);

// Authentication routes (no auth required)
app.use('/api/auth', authRoutes);

// File encryption/decryption routes (auth required for some)
app.use('/api/files', fileRoutes);

// Admin routes (admin auth required)
app.use('/api/admin', adminRoutes);

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Secure Financial Data Processing API',
        version: '1.0.0',
        documentation: '/api/docs',
        health: '/api/health'
    });
});

/**
 * Error Handling Middleware
 * त्रुटि प्रबंधन मिडलवेयर
 */
app.use(notFound);
app.use(errorHandler);

/**
 * Graceful Shutdown Handler
 * सुंदर शटडाउन हैंडलर
 */
const gracefulShutdown = (signal) => {
    logger.info(`Received ${signal}, starting graceful shutdown...`);

    server.close(() => {
        logger.info('HTTP server closed');

        mongoose.connection.close(false, () => {
            logger.info('MongoDB connection closed');
            process.exit(0);
        });
    });

    // Force close server after 10 seconds
    setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 10000);
};

// Handle process termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (err, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', err);
    process.exit(1);
});

/**
 * Start Server
 * सर्वर शुरू करें
 */
const server = app.listen(PORT, () => {
    logger.info(`Secure Financial Data API Server running on port ${PORT}`, {
        environment: process.env.NODE_ENV,
        port: PORT,
        mongoURI: process.env.MONGODB_URI ? 'Connected' : 'Local'
    });
});

module.exports = app;