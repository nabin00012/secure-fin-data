#!/usr/bin/env node

/**
 * Demo Script for Secure Financial Data Platform
 * सुरक्षित वित्तीय डेटा प्लेटफॉर्म के लिए डेमो स्क्रिप्ट
 * 
 * This script demonstrates the key features of the secure financial data platform
 * यह स्क्रिप्ट सुरक्षित वित्तीय डेटा प्लेटफॉर्म की मुख्य विशेषताओं का प्रदर्शन करती है
 */

const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const FormData = require('form-data');
let chalk;
try {
    chalk = require('chalk');
} catch (e) {
    // Fallback for ES modules version
    chalk = {
        red: (text) => `\x1b[31m${text}\x1b[0m`,
        green: (text) => `\x1b[32m${text}\x1b[0m`,
        blue: (text) => `\x1b[34m${text}\x1b[0m`,
        yellow: (text) => `\x1b[33m${text}\x1b[0m`,
        magenta: (text) => `\x1b[35m${text}\x1b[0m`,
        cyan: (text) => `\x1b[36m${text}\x1b[0m`,
        bold: (text) => `\x1b[1m${text}\x1b[0m`,
        underline: (text) => `\x1b[4m${text}\x1b[0m`
    };
}

// Demo configuration
const DEMO_CONFIG = {
    baseURL: process.env.DEMO_BASE_URL || 'http://localhost:3001',
    timeout: 30000,
    demoUser: {
        username: 'demo_user',
        email: 'demo@example.com',
        password: 'SecurePass123!',
        role: 'analyst'
    },
    adminUser: {
        username: 'admin_user',
        email: 'admin@example.com',
        password: 'AdminPass123!',
        role: 'admin'
    }
};

class DemoRunner {
    constructor() {
        this.client = axios.create({
            baseURL: DEMO_CONFIG.baseURL,
            timeout: DEMO_CONFIG.timeout,
            validateStatus: () => true // Don't throw on HTTP errors
        });

        this.userToken = null;
        this.adminToken = null;
        this.stepCounter = 1;
    }

    /**
     * Print demo step
     * डेमो चरण प्रिंट करें
     */
    printStep(title, description = '') {
        console.log(chalk.cyan(`\n📋 Step ${this.stepCounter++}: ${title}`));
        if (description) {
            console.log(chalk.gray(`   ${description}`));
        }
        console.log(chalk.gray('   ' + '─'.repeat(60)));
    }

    /**
     * Print success message
     * सफलता संदेश प्रिंट करें
     */
    printSuccess(message, data = null) {
        console.log(chalk.green(`   ✅ ${message}`));
        if (data && typeof data === 'object') {
            console.log(chalk.gray(`   📄 Response: ${JSON.stringify(data, null, 2)}`));
        }
    }

    /**
     * Print error message
     * त्रुटि संदेश प्रिंट करें
     */
    printError(message, error = null) {
        console.log(chalk.red(`   ❌ ${message}`));
        if (error) {
            console.log(chalk.gray(`   🐛 Error: ${error.message || error}`));
        }
    }

    /**
     * Print warning message
     * चेतावनी संदेश प्रिंट करें
     */
    printWarning(message) {
        console.log(chalk.yellow(`   ⚠️  ${message}`));
    }

    /**
     * Wait for user input
     * उपयोगकर्ता इनपुट की प्रतीक्षा करें
     */
    async waitForEnter(message = 'Press Enter to continue...') {
        console.log(chalk.blue(`\n   ${message}`));

        return new Promise((resolve) => {
            process.stdin.once('data', () => {
                resolve();
            });
        });
    }

    /**
     * Check if server is running
     * जांचें कि सर्वर चल रहा है या नहीं
     */
    async checkServerHealth() {
        try {
            this.printStep('Server Health Check', 'Verifying that the backend server is running');

            const response = await this.client.get('/api/health');

            if (response.status === 200) {
                this.printSuccess('Server is running and healthy', {
                    status: response.data.status,
                    version: response.data.version
                });
                return true;
            } else {
                this.printError(`Server returned status ${response.status}`);
                return false;
            }
        } catch (error) {
            this.printError('Failed to connect to server', error);
            console.log(chalk.yellow('\n💡 Make sure to start the server first:'));
            console.log(chalk.white('   cd backend && npm start'));
            return false;
        }
    }

    /**
     * Register demo user
     * डेमो उपयोगकर्ता पंजीकरण करें
     */
    async registerUser() {
        try {
            this.printStep('User Registration', 'Creating a demo user account');

            const response = await this.client.post('/api/auth/register', DEMO_CONFIG.demoUser);

            if (response.status === 201 || response.status === 409) {
                if (response.status === 409) {
                    this.printWarning('User already exists, will proceed with login');
                } else {
                    this.printSuccess('User registered successfully', {
                        username: DEMO_CONFIG.demoUser.username,
                        email: DEMO_CONFIG.demoUser.email
                    });
                }
                return true;
            } else {
                this.printError(`Registration failed with status ${response.status}`, response.data);
                return false;
            }
        } catch (error) {
            this.printError('Registration failed', error);
            return false;
        }
    }

    /**
     * Login user
     * उपयोगकर्ता लॉगिन करें
     */
    async loginUser() {
        try {
            this.printStep('User Login', 'Authenticating the demo user');

            const response = await this.client.post('/api/auth/login', {
                email: DEMO_CONFIG.demoUser.email,
                password: DEMO_CONFIG.demoUser.password
            });

            if (response.status === 200) {
                this.userToken = response.data.data.token;
                this.printSuccess('User login successful', {
                    token: `${this.userToken.substring(0, 20)}...`,
                    user: response.data.data.user.username
                });
                return true;
            } else {
                this.printError(`Login failed with status ${response.status}`, response.data);
                return false;
            }
        } catch (error) {
            this.printError('Login failed', error);
            return false;
        }
    }

    /**
     * Create sample financial file
     * नमूना वित्तीय फाइल बनाएं
     */
    async createSampleFile() {
        try {
            this.printStep('Sample File Creation', 'Creating a sample financial Excel file for demo');

            // Create a simple CSV file (Excel can be complex to generate)
            const sampleData = `Date,Description,Amount,Category,Account
2023-12-01,Salary Deposit,5000.00,Income,Checking
2023-12-02,Rent Payment,-1200.00,Housing,Checking  
2023-12-03,Grocery Shopping,-150.75,Food,Credit Card
2023-12-04,Investment Deposit,-500.00,Investment,Savings
2023-12-05,Utility Bill,-85.50,Utilities,Checking
2023-12-06,Restaurant,-45.20,Food,Credit Card
2023-12-07,Fuel,-60.00,Transportation,Credit Card
2023-12-08,Online Shopping,-120.00,Shopping,Credit Card
2023-12-09,Freelance Income,800.00,Income,Checking
2023-12-10,Insurance,-200.00,Insurance,Checking`;

            const filePath = path.join(__dirname, 'sample_financial_data.csv');
            await fs.writeFile(filePath, sampleData, 'utf8');

            this.printSuccess('Sample file created successfully', {
                path: filePath,
                size: `${sampleData.length} bytes`
            });

            return filePath;
        } catch (error) {
            this.printError('Failed to create sample file', error);
            return null;
        }
    }

    /**
     * Upload and encrypt file
     * फाइल अपलोड और एन्क्रिप्ट करें
     */
    async encryptFile(filePath) {
        try {
            this.printStep('File Encryption', 'Uploading and encrypting the sample file');

            const fileBuffer = await fs.readFile(filePath);
            const form = new FormData();
            form.append('file', fileBuffer, {
                filename: 'sample_financial_data.csv',
                contentType: 'text/csv'
            });

            const response = await this.client.post('/api/files/encrypt', form, {
                headers: {
                    ...form.getHeaders(),
                    'Authorization': `Bearer ${this.userToken}`
                }
            });

            if (response.status === 200) {
                const { encryptedFileId, keyId, fileName } = response.data.data;
                this.printSuccess('File encrypted successfully', {
                    encryptedFileId,
                    keyId: `${keyId.substring(0, 20)}...`,
                    fileName
                });
                return { encryptedFileId, keyId };
            } else {
                this.printError(`File encryption failed with status ${response.status}`, response.data);
                return null;
            }
        } catch (error) {
            this.printError('File encryption failed', error);
            return null;
        }
    }

    /**
     * Process file for metrics
     * मेट्रिक्स के लिए फाइल प्रोसेस करें
     */
    async processFile(filePath) {
        try {
            this.printStep('File Processing', 'Processing file to extract financial metrics');

            const fileBuffer = await fs.readFile(filePath);
            const form = new FormData();
            form.append('file', fileBuffer, {
                filename: 'sample_financial_data.csv',
                contentType: 'text/csv'
            });

            const response = await this.client.post('/api/files/process', form, {
                headers: {
                    ...form.getHeaders(),
                    'Authorization': `Bearer ${this.userToken}`
                }
            });

            if (response.status === 200) {
                const { resultId, metrics } = response.data.data;
                this.printSuccess('File processed successfully', {
                    resultId,
                    totalTransactions: metrics.summary?.totalTransactions,
                    totalIncome: metrics.summary?.totalIncome,
                    totalExpenses: metrics.summary?.totalExpenses
                });
                return resultId;
            } else {
                this.printError(`File processing failed with status ${response.status}`, response.data);
                return null;
            }
        } catch (error) {
            this.printError('File processing failed', error);
            return null;
        }
    }

    /**
     * Decrypt file
     * फाइल डिक्रिप्ट करें
     */
    async decryptFile(encryptedFileId, keyId) {
        try {
            this.printStep('File Decryption', 'Decrypting the encrypted file');

            const response = await this.client.post('/api/files/decrypt', {
                encryptedFileId,
                keyId
            }, {
                headers: {
                    'Authorization': `Bearer ${this.userToken}`
                }
            });

            if (response.status === 200) {
                const { fileName, fileSize } = response.data.data;
                this.printSuccess('File decrypted successfully', {
                    fileName,
                    fileSize: `${fileSize} bytes`
                });
                return true;
            } else {
                this.printError(`File decryption failed with status ${response.status}`, response.data);
                return false;
            }
        } catch (error) {
            this.printError('File decryption failed', error);
            return false;
        }
    }

    /**
     * Get processing result
     * प्रसंस्करण परिणाम प्राप्त करें
     */
    async getResult(resultId) {
        try {
            this.printStep('Result Retrieval', 'Fetching the processed financial metrics');

            const response = await this.client.get(`/api/files/result/${resultId}`, {
                headers: {
                    'Authorization': `Bearer ${this.userToken}`
                }
            });

            if (response.status === 200) {
                const result = response.data.data;
                this.printSuccess('Result retrieved successfully', {
                    fileName: result.fileName,
                    processedAt: result.createdAt,
                    metricsAvailable: !!result.metrics
                });

                // Display key metrics
                if (result.metrics && result.metrics.summary) {
                    console.log(chalk.blue('\n   📊 Financial Metrics Summary:'));
                    console.log(chalk.white(`      • Total Transactions: ${result.metrics.summary.totalTransactions}`));
                    console.log(chalk.white(`      • Total Income: $${result.metrics.summary.totalIncome}`));
                    console.log(chalk.white(`      • Total Expenses: $${result.metrics.summary.totalExpenses}`));
                    console.log(chalk.white(`      • Net Cash Flow: $${result.metrics.summary.netCashFlow}`));
                }

                return result;
            } else {
                this.printError(`Failed to retrieve result with status ${response.status}`, response.data);
                return null;
            }
        } catch (error) {
            this.printError('Result retrieval failed', error);
            return null;
        }
    }

    /**
     * Register admin user
     * एडमिन उपयोगकर्ता पंजीकरण करें
     */
    async registerAdmin() {
        try {
            this.printStep('Admin Registration', 'Creating admin user account');

            const response = await this.client.post('/api/auth/register', DEMO_CONFIG.adminUser);

            if (response.status === 201 || response.status === 409) {
                if (response.status === 409) {
                    this.printWarning('Admin user already exists, will proceed with login');
                } else {
                    this.printSuccess('Admin registered successfully');
                }
                return true;
            } else {
                this.printError(`Admin registration failed with status ${response.status}`, response.data);
                return false;
            }
        } catch (error) {
            this.printError('Admin registration failed', error);
            return false;
        }
    }

    /**
     * Login admin user
     * एडमिन उपयोगकर्ता लॉगिन करें
     */
    async loginAdmin() {
        try {
            this.printStep('Admin Login', 'Authenticating admin user');

            const response = await this.client.post('/api/auth/login', {
                email: DEMO_CONFIG.adminUser.email,
                password: DEMO_CONFIG.adminUser.password
            });

            if (response.status === 200) {
                this.adminToken = response.data.data.token;
                this.printSuccess('Admin login successful');
                return true;
            } else {
                this.printError(`Admin login failed with status ${response.status}`, response.data);
                return false;
            }
        } catch (error) {
            this.printError('Admin login failed', error);
            return false;
        }
    }

    /**
     * Get admin dashboard
     * एडमिन डैशबोर्ड प्राप्त करें
     */
    async getAdminDashboard() {
        try {
            this.printStep('Admin Dashboard', 'Accessing administrative dashboard');

            const response = await this.client.get('/api/admin/dashboard', {
                headers: {
                    'Authorization': `Bearer ${this.adminToken}`
                }
            });

            if (response.status === 200) {
                const dashboard = response.data.data;
                this.printSuccess('Admin dashboard accessed', {
                    totalUsers: dashboard.summary?.totalUsers,
                    totalResults: dashboard.summary?.totalResults,
                    systemHealth: dashboard.summary?.systemHealth
                });
                return dashboard;
            } else {
                this.printError(`Failed to access admin dashboard with status ${response.status}`, response.data);
                return null;
            }
        } catch (error) {
            this.printError('Admin dashboard access failed', error);
            return null;
        }
    }

    /**
     * Clean up demo files
     * डेमो फाइलें साफ करें
     */
    async cleanup() {
        try {
            this.printStep('Cleanup', 'Removing demo files');

            const filePath = path.join(__dirname, 'sample_financial_data.csv');
            await fs.unlink(filePath).catch(() => { }); // Ignore if file doesn't exist

            this.printSuccess('Cleanup completed');
        } catch (error) {
            this.printWarning('Cleanup had some issues', error);
        }
    }

    /**
     * Run complete demo
     * पूर्ण डेमो चलाएं
     */
    async runDemo() {
        console.log(chalk.blue.bold('\n🚀 Secure Financial Data Platform Demo'));
        console.log(chalk.blue.bold('   सुरक्षित वित्तीय डेटा प्लेटफॉर्म डेमो'));
        console.log(chalk.gray('\n   This demo showcases the key features of our secure platform:'));
        console.log(chalk.gray('   • File encryption with AES-256-GCM'));
        console.log(chalk.gray('   • Financial data processing and metrics extraction'));
        console.log(chalk.gray('   • Role-based access control'));
        console.log(chalk.gray('   • Administrative dashboard'));
        console.log(chalk.gray('   • Audit logging and security monitoring'));

        let currentStep = 1;

        try {
            // 1. Check server health
            if (!await this.checkServerHealth()) {
                return;
            }

            await this.waitForEnter();

            // 2. User registration and login
            if (!await this.registerUser()) return;
            if (!await this.loginUser()) return;

            await this.waitForEnter();

            // 3. File operations
            const sampleFilePath = await this.createSampleFile();
            if (!sampleFilePath) return;

            const encryptionResult = await this.encryptFile(sampleFilePath);
            if (!encryptionResult) return;

            await this.waitForEnter();

            // 4. File processing
            const resultId = await this.processFile(sampleFilePath);
            if (!resultId) return;

            await this.waitForEnter();

            // 5. Decrypt file
            if (!await this.decryptFile(encryptionResult.encryptedFileId, encryptionResult.keyId)) return;

            await this.waitForEnter();

            // 6. Get processing results
            if (!await this.getResult(resultId)) return;

            await this.waitForEnter();

            // 7. Admin operations
            if (!await this.registerAdmin()) return;
            if (!await this.loginAdmin()) return;
            if (!await this.getAdminDashboard()) return;

            // 8. Cleanup
            await this.cleanup();

            console.log(chalk.green.bold('\n🎉 Demo completed successfully!'));
            console.log(chalk.green.bold('   डेमो सफलतापूर्वक पूरा हुआ!'));
            console.log(chalk.yellow('\n💡 Next steps:'));
            console.log(chalk.white('   • Explore the React frontend (coming soon)'));
            console.log(chalk.white('   • Test additional API endpoints'));
            console.log(chalk.white('   • Review the security audit logs'));
            console.log(chalk.white('   • Integrate with production key management'));

        } catch (error) {
            this.printError('Demo failed unexpectedly', error);
        }
    }
}

// Run demo if called directly
if (require.main === module) {
    const demo = new DemoRunner();
    demo.runDemo().catch(error => {
        console.error(chalk.red('\n💥 Demo crashed:'), error);
        process.exit(1);
    });
}

module.exports = DemoRunner;