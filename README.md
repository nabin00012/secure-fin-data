# 🔐 Secure Financial Data Platform

A **production-ready, hackathon-quality** MERN stack application for secure financial data processing with enterprise-grade encryption, role-based access control, and comprehensive audit logging.

## 🎯 Project Overview

This platform demonstrates advanced security practices for financial data handling, featuring:

- **🔒 Military-Grade Encryption**: AES-256-GCM with RSA-OAEP envelope encryption
- **🛡️ Zero-Trust Architecture**: Role-based access control with comprehensive audit trails
- **📊 Intelligent Analytics**: Financial metrics extraction from Excel/PDF files
- **⚡ Production-Ready**: Scalable architecture with monitoring and health checks
- **🎨 Modern UI**: React with Material-UI design system
- **🔄 Real-time Processing**: File encryption, processing, and results in real-time

## 🏗️ Architecture

### System Components

```
secure-fin-data/
├── 🖥️  backend/           # Node.js + Express API Server
│   ├── src/
│   │   ├── controllers/   # Request handlers
│   │   ├── middleware/    # Auth, validation, audit
│   │   ├── models/        # MongoDB schemas  
│   │   ├── routes/        # API endpoints
│   │   ├── services/      # Business logic
│   │   └── utils/         # Crypto, logging, key management
│   ├── demo.js           # Interactive demo script
│   └── package.json
├── 🎨 frontend/          # React + Material-UI
│   ├── src/
│   │   ├── components/   # Reusable UI components
│   │   ├── pages/        # Application screens
│   │   ├── services/     # API integration
│   │   ├── hooks/        # Custom React hooks
│   │   └── contexts/     # Global state management
│   └── package.json
├── 📁 sample-data/      # Demo financial files
└── 📖 docs/            # Documentation
```

## 🚀 Quick Start

### Prerequisites
- Node.js >= 16.0.0
- MongoDB >= 5.0.0
- npm >= 8.0.0

### 1. Clone & Install
```bash
git clone <repository-url>
cd secure-fin-data

# Install backend dependencies
cd backend
npm install

# Install frontend dependencies (when ready)
cd ../frontend
npm install
```

### 2. Environment Setup
```bash
# Backend configuration
cd backend
cp .env.example .env
# Edit .env with your database and secrets
```

### 3. Start MongoDB
```bash
# Using Docker (recommended)
docker run -d -p 27017:27017 --name mongodb mongo:latest

# Or start local MongoDB
mongod --dbpath /your/db/path
```

### 4. Launch Application
```bash
# Start backend
cd backend
npm run dev

# Run interactive demo
npm run demo
```

## 🎮 Interactive Demo

Experience the platform's capabilities with our guided demo:

```bash
cd backend
npm run demo
```

The demo showcases:
1. **User Authentication** - Registration and JWT-based login
2. **File Encryption** - Upload and encrypt financial data
3. **Data Processing** - Extract metrics from Excel/CSV/PDF files
4. **Secure Decryption** - Retrieve and decrypt processed data
5. **Admin Dashboard** - System monitoring and user management
6. **Audit Trail** - Security event logging and compliance

## 🔐 Security Features

### Encryption Implementation

**File Protection Flow:**
1. **Content Encryption Key (CEK)** - Random 256-bit key generated
2. **File Encryption** - AES-256-GCM with authenticated encryption
3. **Key Wrapping** - CEK encrypted with RSA-OAEP-2048 public key
4. **Searchable Indexing** - HMAC-SHA256 for encrypted search capability
5. **Secure Storage** - Separated encrypted data and wrapped keys

### Access Control Matrix

| Role | File Operations | Analytics | User Management | System Admin |
|------|----------------|-----------|-----------------|--------------|
| **User** | ✅ Encrypt/Decrypt | ❌ | ❌ | ❌ |
| **Analyst** | ✅ Full Access | ✅ View Reports | ❌ | ❌ |
| **Admin** | ✅ Full Access | ✅ Full Access | ✅ Manage Users | ✅ View Logs |
| **Super Admin** | ✅ Full Access | ✅ Full Access | ✅ Full Control | ✅ Full Control |

## 📊 Financial Analytics

### Supported File Types
- **Excel Files** (.xlsx, .xls) - Full spreadsheet analysis
- **CSV Files** (.csv) - Structured financial data
- **PDF Files** (.pdf) - Text extraction and pattern recognition

### Extracted Metrics
```javascript
{
  summary: {
    totalTransactions: 150,
    totalIncome: 5000.00,
    totalExpenses: 3500.00,
    netCashFlow: 1500.00,
    savingsRate: 0.30
  },
  categories: {
    income: { salary: 4000, freelance: 1000 },
    expenses: { rent: 1200, food: 800 }
  },
  insights: [
    "High savings rate detected (30%)",
    "Transportation costs trending upward"
  ]
}
```

## 🔌 API Endpoints

### Authentication
```http
POST /api/auth/register         # User registration
POST /api/auth/login           # JWT authentication
GET  /api/auth/profile         # User profile
PUT  /api/auth/profile         # Update profile
POST /api/auth/change-password # Password change
```

### File Operations
```http
POST /api/files/encrypt        # Encrypt file
POST /api/files/decrypt        # Decrypt file  
POST /api/files/process        # Extract metrics
GET  /api/files/result/:id     # Get results
GET  /api/files/search         # Search encrypted data
```

### Administration
```http
GET  /api/admin/dashboard      # System overview
GET  /api/admin/users          # User management
GET  /api/admin/logs           # Security audit logs
GET  /api/admin/analytics      # System analytics
GET  /api/admin/keys/:action   # Key management
```

## 🧪 Testing & Validation

### Backend Testing
```bash
cd backend
npm test                # Run test suite
npm run health:check    # Health validation
```

### API Testing Examples
```bash
# Health check
curl http://localhost:5000/api/health

# Register user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","email":"demo@example.com","password":"SecurePass123!"}'
```

## 🔧 Configuration

### Key Environment Variables

**Backend (.env):**
```bash
# Security
JWT_SECRET=your-super-secret-jwt-key
ENCRYPTION_KEY=your-32-byte-encryption-key
BCRYPT_SALT_ROUNDS=12

# Database
MONGODB_URI=mongodb://localhost:27017/secure_fin_data

# File Processing
MAX_FILE_SIZE=10485760
ALLOWED_FILE_TYPES=.xlsx,.xls,.csv,.pdf
```

## 🏆 Competition Advantages

### Technical Excellence
- ✅ **Production Architecture** - Enterprise-grade scalability
- ✅ **Security First** - Military-grade encryption standards
- ✅ **Modern Stack** - Latest technologies and best practices
- ✅ **Comprehensive Testing** - Full test coverage and validation
- ✅ **Documentation** - Complete technical documentation

### Business Value
- 💼 **Financial Industry Ready** - Compliance-focused design
- 📊 **Data Insights** - Automated financial analysis
- 🔒 **Trust & Privacy** - Zero-knowledge data handling
- ⚡ **Performance** - Optimized for high-throughput scenarios
- 🌐 **Scalability** - Cloud-native architecture

## 📚 Documentation

- 📖 **[Backend API Documentation](./backend/README.md)** - Complete backend guide
- 🏗️ **[Architecture Overview](./docs/ARCHITECTURE.md)** - System design details
- 🔐 **[Security Implementation](./docs/SECURITY.md)** - Security features guide
- 🎬 **[Demo Script Guide](./docs/DEMO.md)** - Interactive demo walkthrough

## 🤝 Contributing

1. Fork repository and create feature branch
2. Follow ESLint configuration and code standards  
3. Write comprehensive tests for new features
4. Update documentation for API changes
5. Submit PR with detailed description

## 📄 License & Legal

This project is licensed under the **MIT License** - see [LICENSE](./LICENSE) file for details.

**Security Notice:** This implementation includes demo cryptographic features for educational/hackathon purposes. For production use, integrate with certified key management systems and conduct thorough security audits.

---

**Built with ❤️ for secure financial data processing**  
**Made for hackathons, ready for production** 🚀

## 📞 Support & Contact

- � **Email**: team@secureFinance.demo
- 💬 **Issues**: GitHub Issues for bug reports
- 📖 **Docs**: Complete documentation in project folders
- 🎥 **Demo**: Run `npm run demo` for interactive showcase# secure-fin-data
