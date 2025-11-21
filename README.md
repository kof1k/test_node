# 🚀 Advanced User Management System

A production-ready Node.js application with comprehensive user management, event registration, and API capabilities.

![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Security](https://img.shields.io/badge/Security-Enhanced-red)

## ✨ Features

### 🔐 Authentication & Security
- **Secure Registration & Login** with bcrypt password hashing
- **Two-Factor Authentication (2FA)** with TOTP
- **JWT Token-based API Authentication**
- **Session Management** with Redis support
- **Password Reset** via secure email tokens
- **Email Verification** for new accounts
- **Account Lockout** after failed attempts
- **Rate Limiting** on all endpoints
- **CSRF Protection** for web forms
- **XSS & SQL Injection Protection**
- **Device Fingerprinting**
- **IP-based Security Monitoring**

### 👥 User Management
- User profiles with avatars
- Role-based access control (User, Admin, Moderator)
- User activity logging
- Account deactivation/reactivation
- Profile customization
- Password history tracking

### 📅 Event System
- Create and manage events
- Online/Offline/Hybrid event types
- Event registration with capacity limits
- Payment integration ready
- QR code check-in system
- Event reminders and notifications

### 🔌 RESTful API
- Complete REST API with JWT authentication
- API key management for external integrations
- Webhook support for real-time updates
- Rate limiting per API key
- Comprehensive API documentation
- Versioned endpoints (v1)

### 📊 Admin Dashboard
- User management interface
- Event management
- System logs viewer
- Session monitoring
- API key management
- Statistics and analytics
- Audit trail

### 🎨 Modern UI/UX
- Responsive design with Tailwind CSS
- Dark/Light theme support
- Real-time form validation
- Password strength indicator
- Loading states and animations
- Mobile-friendly interface

## 🛠️ Technology Stack

- **Backend:** Node.js, Express.js
- **Database:** MySQL 8.0 with Sequelize ORM
- **Cache:** Redis (optional)
- **Authentication:** JWT, Passport.js, Speakeasy (2FA)
- **Security:** Helmet, bcrypt, express-rate-limit
- **Frontend:** EJS templates, Tailwind CSS
- **Real-time:** Socket.io
- **Email:** Nodemailer
- **File Upload:** Multer with Sharp for image processing
- **Logging:** Winston
- **Testing:** Jest, Supertest

## 📋 Prerequisites

- Node.js 18.0 or higher
- MySQL 8.0 or higher
- Redis (optional, for enhanced session management)
- SMTP server for email functionality

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/user-management-system.git
cd user-management-system
```

### 2. Install dependencies
```bash
npm install
```

### 3. Set up the database
```bash
# Import the database schema
mysql -u root -p < database_schema.sql
```

### 4. Configure environment variables
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration
nano .env
```

Key environment variables:
```env
DB_HOST=localhost
DB_USER=webapp
DB_PASSWORD=YourSecurePassword
DB_NAME=user_management_system
SESSION_SECRET=your-secret-key-here
JWT_SECRET=your-jwt-secret-key
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-email-password
```

### 5. Run database migrations
```bash
npm run migrate
```

### 6. (Optional) Seed the database with sample data
```bash
npm run seed
```

### 7. Start the application
```bash
# Development mode with hot reload
npm run dev

# Production mode
npm start
```

The application will be available at `http://localhost:3000`

## 📁 Project Structure

```
user-management-system/
├── src/
│   ├── config/         # Configuration files
│   ├── controllers/    # Request handlers
│   ├── middleware/     # Express middleware
│   ├── models/         # Sequelize models
│   ├── routes/         # Route definitions
│   ├── services/       # Business logic
│   ├── utils/          # Utility functions
│   ├── views/          # EJS templates
│   └── server.js       # Main application file
├── public/             # Static files
│   ├── css/           
│   ├── js/            
│   └── images/        
├── tests/              # Test files
├── logs/               # Application logs
├── database_schema.sql # Database structure
├── package.json        
├── .env.example        
└── README.md          
```

## 🔧 Configuration

### Database Connection
Configure MySQL connection in `.env`:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=webapp
DB_PASSWORD=SecurePassword123!
DB_NAME=user_management_system
```

### Email Service
Configure SMTP settings for email functionality:
```env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

### Security Settings
```env
SESSION_SECRET=generate-a-long-random-string
JWT_SECRET=another-long-random-string
JWT_EXPIRES_IN=7d
RATE_LIMIT_MAX_REQUESTS=100
```

## 🔌 API Documentation

### Authentication Endpoints

#### Register
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "johndoe",
  "password": "SecurePass123!"
}

Response:
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "...",
  "user": { ... }
}
```

#### Authenticated Requests
```http
GET /api/v1/users/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Event Endpoints

#### List Events
```http
GET /api/v1/events?page=1&limit=10&type=online
```

#### Create Event
```http
POST /api/v1/events
Authorization: Bearer token
Content-Type: application/json

{
  "title": "Tech Conference 2024",
  "description": "Annual technology conference",
  "eventType": "hybrid",
  "eventDate": "2024-06-15T10:00:00Z",
  "location": "Convention Center",
  "maxParticipants": 500
}
```

Full API documentation available at `/api` when the server is running.

## 🧪 Testing

Run the test suite:
```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 🚢 Deployment

### Using Docker
```bash
# Build the Docker image
docker build -t user-management-system .

# Run with docker-compose
docker-compose up -d
```

### Manual Deployment
1. Set `NODE_ENV=production` in environment
2. Use a process manager like PM2:
```bash
npm install -g pm2
pm2 start src/server.js --name user-management
pm2 save
pm2 startup
```

3. Configure Nginx as reverse proxy:
```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## 🔒 Security Best Practices

1. **Environment Variables**: Never commit `.env` file
2. **HTTPS**: Always use HTTPS in production
3. **Updates**: Keep dependencies updated
4. **Passwords**: Enforce strong password policies
5. **Rate Limiting**: Configure appropriate rate limits
6. **Logging**: Monitor logs for suspicious activity
7. **Backups**: Regular database backups
8. **2FA**: Encourage users to enable 2FA

## 🛡️ Security Features

- Password hashing with bcrypt (12 rounds)
- JWT tokens with expiration
- CSRF token validation
- XSS protection via Helmet
- SQL injection prevention via Sequelize ORM
- Rate limiting on all endpoints
- Account lockout after 5 failed attempts
- Session invalidation on logout
- Secure password reset tokens
- Email verification for new accounts
- Input validation and sanitization
- HTTPS enforcement in production
- Security headers via Helmet

## 📊 Monitoring

The application includes built-in monitoring:
- Health check endpoint: `/health`
- Metrics endpoint: `/api/v1/metrics`
- Structured logging with Winston
- Error tracking and reporting
- Performance monitoring hooks

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support, email support@yourdomain.com or open an issue in the GitHub repository.

## 🙏 Acknowledgments

- Express.js community
- Sequelize ORM
- Tailwind CSS
- All contributors

## 📈 Roadmap

- [ ] OAuth integration (Google, Facebook, GitHub)
- [ ] Multi-language support
- [ ] Advanced reporting and analytics
- [ ] Mobile app API
- [ ] Microservices architecture
- [ ] GraphQL API
- [ ] Kubernetes deployment configuration
- [ ] Advanced caching strategies
- [ ] WebAuthn support
- [ ] GDPR compliance tools

---

**Built with ❤️ by [Your Name]**
