# Secure Financial Data Platform - Backend API

A production-ready, secure backend API for processing and encrypting financial data with comprehensive audit logging, role-based access control, and enterprise-grade security features.

## 🚀 Quick Start

### Prerequisites

- Node.js >= 16.0.0
- MongoDB >= 5.0.0
- npm >= 8.0.0

### Installation

1. **Clone and navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Environment setup:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start MongoDB:**
   ```bash
   # Using Docker
   docker run -d -p 27017:27017 --name mongodb mongo:latest
   
   # Or use your local MongoDB installation
   mongod --dbpath /your/db/path
   ```

5. **Start the server:**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   
   # Run demo
   npm run demo
   ```

## 🏗️ Architecture

### Core Components

```
backend/
├── src/
│   ├── app.js                 # Main Express application
│   ├── controllers/           # Request handlers
│   │   ├── authController.js
│   │   ├── fileController.js
│   │   └── adminController.js
│   ├── middleware/            # Custom middleware
│   │   ├── authMiddleware.js
│   │   ├── errorMiddleware.js
│   │   └── auditMiddleware.js
│   ├── models/               # MongoDB schemas
│   │   ├── User.js
│   │   └── EncryptedResult.js
│   ├── routes/               # API route definitions
│   │   ├── authRoutes.js
│   │   ├── fileRoutes.js
│   │   ├── adminRoutes.js
│   │   └── healthRoutes.js
│   ├── services/             # Business logic
│   │   ├── encryptionService.js
│   │   └── metricService.js
│   └── utils/                # Utilities
│       ├── cryptoUtils.js
│       ├── logger.js
│       └── keyStore.js
├── demo.js                   # Interactive demo script
├── package.json
└── README.md
```

### Security Architecture

- **Encryption**: AES-256-GCM with envelope encryption using RSA-OAEP-2048
- **Authentication**: JWT with bcrypt password hashing (12 rounds)
- **Authorization**: Role-based access control (RBAC)
- **Data Integrity**: HMAC-SHA256 for deterministic indexing
- **Audit Trail**: Comprehensive security event logging

## 📡 API Endpoints

### Authentication
```http
POST /api/auth/register         # User registration
POST /api/auth/login           # User authentication
GET  /api/auth/profile         # Get user profile
PUT  /api/auth/profile         # Update user profile
POST /api/auth/change-password # Change password
```

### File Operations
```http
POST /api/files/encrypt        # Encrypt uploaded file
POST /api/files/decrypt        # Decrypt encrypted file
POST /api/files/process        # Process file for metrics
GET  /api/files/result/:id     # Get processing result
GET  /api/files/search         # Search encrypted results
```

### Admin Operations
```http
GET  /api/admin/dashboard      # System dashboard
GET  /api/admin/users          # List users (paginated)
GET  /api/admin/users/:id      # Get user details
PUT  /api/admin/users/:id      # Update user
DELETE /api/admin/users/:id    # Delete user
GET  /api/admin/logs           # System logs
GET  /api/admin/analytics      # System analytics
GET  /api/admin/keys/:action   # Key management
```

### Health & Monitoring
```http
GET  /api/health              # Basic health check
GET  /api/health/detailed     # Detailed system status
GET  /api/health/metrics      # Performance metrics
```

## 🔐 Security Features

### Encryption Implementation

**File Encryption Flow:**
1. Generate random Content Encryption Key (CEK)
2. Encrypt file with AES-256-GCM using CEK
3. Wrap CEK with RSA-OAEP-2048 public key
4. Store wrapped key and encrypted data separately
5. Generate HMAC-SHA256 index for searchability

**Key Management:**
- Envelope encryption for scalability
- Key rotation capabilities
- Secure key derivation (PBKDF2/Argon2id)
- Demo key store (replace with KMS in production)

### Access Control

**User Roles:**
- `user`: Basic file operations
- `analyst`: Advanced analytics access
- `admin`: User management
- `super_admin`: Full system control

**Permission Matrix:**
```javascript
const permissions = {
  user: ['file:encrypt', 'file:decrypt', 'file:process'],
  analyst: ['file:*', 'analytics:read'],
  admin: ['user:*', 'logs:read', 'system:read'],
  super_admin: ['*']
};
```

### Audit & Compliance

**Security Events Logged:**
- Authentication attempts
- File operations
- Admin actions
- Key management operations
- System errors

**Log Structure:**
```javascript
{
  timestamp: "2023-12-10T10:30:00Z",
  level: "info",
  event: "FILE_ENCRYPTED", 
  userId: "user123",
  details: { fileName: "data.xlsx", keyId: "key456" },
  ip: "192.168.1.100",
  userAgent: "Mozilla/5.0..."
}
```

## 📊 Financial Data Processing

### Supported File Types
- Excel files (.xlsx, .xls)
- CSV files (.csv)
- PDF files (.pdf)

### Extracted Metrics
```javascript
{
  summary: {
    totalTransactions: 150,
    totalIncome: 5000.00,
    totalExpenses: 3500.00,
    netCashFlow: 1500.00,
    averageTransaction: 23.33
  },
  categories: {
    income: { salary: 4000, freelance: 1000 },
    expenses: { rent: 1200, food: 800, transport: 300 }
  },
  trends: {
    monthlyFlow: [...],
    expenseGrowth: 0.05,
    savingsRate: 0.30
  },
  insights: [
    "High savings rate detected",
    "Transportation costs increasing"
  ]
}
```

## 🧪 Testing & Demo

### Run Interactive Demo
```bash
npm run demo
```

The demo showcases:
1. User registration and authentication
2. File encryption and decryption
3. Financial data processing
4. Admin dashboard access
5. Security audit logging

### API Testing
```bash
# Health check
curl http://localhost:5000/api/health

# Register user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"SecurePass123!"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'
```

## 🔧 Configuration

### Environment Variables

Key configuration options:

```bash
# Security
JWT_SECRET=your-secret-key
ENCRYPTION_KEY=your-encryption-key-32-bytes
BCRYPT_SALT_ROUNDS=12

# Database  
MONGODB_URI=mongodb://localhost:27017/secure_fin_data

# File Handling
MAX_FILE_SIZE=10485760  # 10MB
ALLOWED_FILE_TYPES=.xlsx,.xls,.csv,.pdf

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100
```

### Production Considerations

**Database:**
- Use MongoDB Atlas or dedicated instance
- Enable authentication and SSL
- Configure replica sets for high availability
- Set up automated backups

**Key Management:**
- Replace demo key store with AWS KMS/Azure Key Vault
- Implement key rotation policies
- Use Hardware Security Modules (HSMs) for critical keys

**Security:**
- Enable HTTPS with valid SSL certificates
- Configure Web Application Firewall (WAF)
- Set up intrusion detection
- Regular security audits

**Monitoring:**
- Integrate with monitoring solutions (DataDog, New Relic)
- Set up alerting for security events
- Monitor performance metrics
- Log aggregation (ELK stack)

## 📈 Performance & Scaling

### Current Limits
- File size: 10MB per upload
- Concurrent users: 100 (rate limited)
- Database connections: 10 (connection pool)

### Scaling Strategies
1. **Horizontal Scaling**: Load balancer + multiple instances
2. **Database Sharding**: Partition by user ID or date
3. **Caching**: Redis for session storage and frequently accessed data
4. **CDN**: Static assets and file downloads
5. **Microservices**: Split encryption and analytics services

### Performance Optimization
```javascript
// Database indexing
db.users.createIndex({ email: 1 }, { unique: true })
db.encryptedResults.createIndex({ userId: 1, createdAt: -1 })
db.encryptedResults.createIndex({ hmacIndex: 1 })

// Connection pooling
mongoose.connect(uri, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
})
```

## 🛠️ Development

### Code Quality
```bash
# Linting
npm run lint
npm run lint:fix

# Testing
npm test
npm run test:watch
npm run test:coverage

# Documentation
npm run docs:generate
```

### Project Structure Guidelines

**Controllers**: Handle HTTP requests/responses only
**Services**: Business logic and external integrations
**Middleware**: Cross-cutting concerns (auth, logging, validation)
**Utils**: Pure functions and utilities
**Models**: Database schemas and data access methods

## 🚨 Error Handling

### Error Types
- **ValidationError**: Input validation failures
- **AuthenticationError**: Invalid credentials
- **AuthorizationError**: Insufficient permissions
- **EncryptionError**: Cryptographic operation failures
- **DatabaseError**: Data persistence issues

### Error Response Format
```javascript
{
  success: false,
  message: "Human readable error message",
  error: "VALIDATION_ERROR",
  details: {
    field: "email",
    code: "INVALID_FORMAT"
  },
  timestamp: "2023-12-10T10:30:00Z"
}
```

## 📚 Documentation

- **API Documentation**: Generated with JSDoc
- **Postman Collection**: Available in `/docs` folder
- **Architecture Diagrams**: Security and data flow diagrams
- **Deployment Guide**: Production deployment instructions

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Guidelines
- Follow ESLint configuration
- Write unit tests for new features
- Update documentation
- Follow semantic versioning

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🎯 Roadmap

### Phase 1 (Current)
- ✅ Core encryption/decryption
- ✅ File processing and metrics
- ✅ User authentication and RBAC
- ✅ Admin dashboard
- ✅ Audit logging

### Phase 2 (Next)
- 🔄 React frontend application  
- 🔄 Real-time notifications
- 🔄 Advanced analytics dashboard
- 🔄 API rate limiting per user
- 🔄 Docker containerization

### Phase 3 (Future)
- ⏳ Microservices architecture
- ⏳ GraphQL API
- ⏳ Machine learning insights
- ⏳ Mobile applications
- ⏳ Blockchain integration

## 🆘 Support

For support and questions:

- 📧 Email: team@secureFinance.demo
- 💬 Issues: GitHub Issues
- 📖 Docs: `/docs` directory
- 🎥 Demo: `npm run demo`

---

**Built with ❤️ for secure financial data processing**