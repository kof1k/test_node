// src/routes/api.routes.js
const express = require('express');
const { body, query, param, validationResult } = require('express-validator');
const apiController = require('../controllers/api.controller');
const { authenticateAPI, authenticateJWT } = require('../middleware/api.middleware');
const rateLimiter = require('../middleware/rateLimiter');

const router = express.Router();

// API Documentation endpoint
router.get('/', (req, res) => {
    res.json({
        version: process.env.API_VERSION || 'v1',
        endpoints: {
            authentication: {
                login: 'POST /api/v1/auth/login',
                refresh: 'POST /api/v1/auth/refresh',
                logout: 'POST /api/v1/auth/logout',
                register: 'POST /api/v1/auth/register',
                verify: 'GET /api/v1/auth/verify/:token'
            },
            users: {
                profile: 'GET /api/v1/users/profile',
                update: 'PUT /api/v1/users/profile',
                delete: 'DELETE /api/v1/users/profile',
                list: 'GET /api/v1/users (admin)',
                getUser: 'GET /api/v1/users/:id (admin)',
                updateUser: 'PUT /api/v1/users/:id (admin)',
                deleteUser: 'DELETE /api/v1/users/:id (admin)'
            },
            events: {
                list: 'GET /api/v1/events',
                create: 'POST /api/v1/events',
                get: 'GET /api/v1/events/:id',
                update: 'PUT /api/v1/events/:id',
                delete: 'DELETE /api/v1/events/:id',
                register: 'POST /api/v1/events/:id/register',
                unregister: 'DELETE /api/v1/events/:id/register'
            },
            stats: {
                dashboard: 'GET /api/v1/stats/dashboard',
                users: 'GET /api/v1/stats/users',
                events: 'GET /api/v1/stats/events'
            },
            admin: {
                logs: 'GET /api/v1/admin/logs',
                sessions: 'GET /api/v1/admin/sessions',
                apiKeys: 'GET /api/v1/admin/api-keys'
            }
        },
        authentication: {
            jwt: 'Bearer token in Authorization header',
            apiKey: 'X-API-Key and X-API-Secret headers'
        },
        rateLimit: {
            default: '1000 requests per 15 minutes',
            authenticated: '5000 requests per 15 minutes'
        }
    });
});

// API Version 1 routes
const v1Router = express.Router();

// ==================== Authentication Endpoints ====================

// Login with credentials to get JWT token
v1Router.post('/auth/login', 
    rateLimiter.loginLimiter,
    [
        body('username').trim().notEmpty().withMessage('Username or email is required'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    apiController.login
);

// Register new user
v1Router.post('/auth/register',
    rateLimiter.strictLimiter,
    [
        body('username')
            .trim()
            .isLength({ min: 3, max: 50 })
            .matches(/^[a-zA-Z0-9_]+$/),
        body('email').isEmail().normalizeEmail(),
        body('password')
            .isLength({ min: 8 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/),
        body('firstName').optional().trim().isLength({ min: 1, max: 50 }),
        body('lastName').optional().trim().isLength({ min: 1, max: 50 })
    ],
    apiController.register
);

// Refresh JWT token
v1Router.post('/auth/refresh',
    [
        body('refreshToken').notEmpty().withMessage('Refresh token is required')
    ],
    apiController.refreshToken
);

// Logout (invalidate tokens)
v1Router.post('/auth/logout',
    authenticateJWT,
    apiController.logout
);

// Verify email
v1Router.get('/auth/verify/:token',
    param('token').notEmpty(),
    apiController.verifyEmail
);

// Forgot password
v1Router.post('/auth/forgot-password',
    rateLimiter.strictLimiter,
    [
        body('email').isEmail().normalizeEmail()
    ],
    apiController.forgotPassword
);

// Reset password
v1Router.post('/auth/reset-password',
    [
        body('token').notEmpty(),
        body('password')
            .isLength({ min: 8 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
    ],
    apiController.resetPassword
);

// ==================== User Endpoints ====================

// Get current user profile
v1Router.get('/users/profile',
    authenticateJWT,
    apiController.getCurrentUser
);

// Update current user profile
v1Router.put('/users/profile',
    authenticateJWT,
    [
        body('firstName').optional().trim().isLength({ min: 1, max: 50 }),
        body('lastName').optional().trim().isLength({ min: 1, max: 50 }),
        body('bio').optional().trim().isLength({ max: 500 }),
        body('phone').optional().matches(/^[\d\s\-\+\(\)]+$/),
        body('dateOfBirth').optional().isISO8601()
    ],
    apiController.updateProfile
);

// Delete current user account
v1Router.delete('/users/profile',
    authenticateJWT,
    [
        body('password').notEmpty().withMessage('Password confirmation required')
    ],
    apiController.deleteAccount
);

// Change password
v1Router.post('/users/change-password',
    authenticateJWT,
    [
        body('currentPassword').notEmpty(),
        body('newPassword')
            .isLength({ min: 8 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/),
        body('confirmPassword')
            .custom((value, { req }) => value === req.body.newPassword)
    ],
    apiController.changePassword
);

// Upload avatar
v1Router.post('/users/avatar',
    authenticateJWT,
    apiController.uploadAvatar
);

// Enable/disable 2FA
v1Router.post('/users/2fa/enable',
    authenticateJWT,
    apiController.enable2FA
);

v1Router.post('/users/2fa/disable',
    authenticateJWT,
    [
        body('token').notEmpty().matches(/^\d{6}$/)
    ],
    apiController.disable2FA
);

// ==================== Admin User Management ====================

// Get all users (admin only)
v1Router.get('/users',
    authenticateJWT,
    apiController.requireRole('admin'),
    [
        query('page').optional().isInt({ min: 1 }),
        query('limit').optional().isInt({ min: 1, max: 100 }),
        query('search').optional().trim(),
        query('role').optional().isIn(['user', 'admin', 'moderator']),
        query('status').optional().isIn(['active', 'inactive', 'verified', 'unverified'])
    ],
    apiController.getAllUsers
);

// Get specific user (admin only)
v1Router.get('/users/:id',
    authenticateJWT,
    apiController.requireRole('admin'),
    param('id').isInt(),
    apiController.getUser
);

// Update user (admin only)
v1Router.put('/users/:id',
    authenticateJWT,
    apiController.requireRole('admin'),
    param('id').isInt(),
    [
        body('role').optional().isIn(['user', 'admin', 'moderator']),
        body('isActive').optional().isBoolean(),
        body('isVerified').optional().isBoolean()
    ],
    apiController.updateUser
);

// Delete user (admin only)
v1Router.delete('/users/:id',
    authenticateJWT,
    apiController.requireRole('admin'),
    param('id').isInt(),
    apiController.deleteUser
);

// ==================== Event Endpoints ====================

// Get all events
v1Router.get('/events',
    [
        query('page').optional().isInt({ min: 1 }),
        query('limit').optional().isInt({ min: 1, max: 100 }),
        query('search').optional().trim(),
        query('type').optional().isIn(['online', 'offline', 'hybrid']),
        query('status').optional().isIn(['draft', 'published', 'cancelled', 'completed']),
        query('startDate').optional().isISO8601(),
        query('endDate').optional().isISO8601()
    ],
    apiController.getAllEvents
);

// Get single event
v1Router.get('/events/:id',
    param('id').isInt(),
    apiController.getEvent
);

// Create new event (authenticated)
v1Router.post('/events',
    authenticateJWT,
    [
        body('title').trim().isLength({ min: 3, max: 200 }),
        body('description').optional().trim(),
        body('shortDescription').optional().trim().isLength({ max: 500 }),
        body('eventType').isIn(['online', 'offline', 'hybrid']),
        body('eventDate').isISO8601(),
        body('endDate').optional().isISO8601(),
        body('location').optional().trim(),
        body('onlineUrl').optional().isURL(),
        body('maxParticipants').optional().isInt({ min: 1 }),
        body('price').optional().isFloat({ min: 0 }),
        body('currency').optional().isLength({ min: 3, max: 3 })
    ],
    apiController.createEvent
);

// Update event (owner or admin)
v1Router.put('/events/:id',
    authenticateJWT,
    param('id').isInt(),
    [
        body('title').optional().trim().isLength({ min: 3, max: 200 }),
        body('description').optional().trim(),
        body('eventDate').optional().isISO8601(),
        body('status').optional().isIn(['draft', 'published', 'cancelled', 'completed'])
    ],
    apiController.updateEvent
);

// Delete event (owner or admin)
v1Router.delete('/events/:id',
    authenticateJWT,
    param('id').isInt(),
    apiController.deleteEvent
);

// Register for event
v1Router.post('/events/:id/register',
    authenticateJWT,
    param('id').isInt(),
    apiController.registerForEvent
);

// Unregister from event
v1Router.delete('/events/:id/register',
    authenticateJWT,
    param('id').isInt(),
    apiController.unregisterFromEvent
);

// Get event participants (owner or admin)
v1Router.get('/events/:id/participants',
    authenticateJWT,
    param('id').isInt(),
    apiController.getEventParticipants
);

// ==================== Statistics Endpoints ====================

// Get dashboard statistics
v1Router.get('/stats/dashboard',
    authenticateJWT,
    apiController.getDashboardStats
);

// Get user statistics
v1Router.get('/stats/users',
    authenticateJWT,
    apiController.requireRole(['admin', 'moderator']),
    [
        query('startDate').optional().isISO8601(),
        query('endDate').optional().isISO8601(),
        query('groupBy').optional().isIn(['day', 'week', 'month', 'year'])
    ],
    apiController.getUserStats
);

// Get event statistics
v1Router.get('/stats/events',
    authenticateJWT,
    apiController.requireRole(['admin', 'moderator']),
    [
        query('startDate').optional().isISO8601(),
        query('endDate').optional().isISO8601(),
        query('groupBy').optional().isIn(['day', 'week', 'month', 'year'])
    ],
    apiController.getEventStats
);

// ==================== Admin Endpoints ====================

// Get system logs
v1Router.get('/admin/logs',
    authenticateJWT,
    apiController.requireRole('admin'),
    [
        query('page').optional().isInt({ min: 1 }),
        query('limit').optional().isInt({ min: 1, max: 100 }),
        query('userId').optional().isInt(),
        query('action').optional().trim(),
        query('status').optional().isIn(['success', 'failed', 'warning']),
        query('startDate').optional().isISO8601(),
        query('endDate').optional().isISO8601()
    ],
    apiController.getSystemLogs
);

// Get active sessions
v1Router.get('/admin/sessions',
    authenticateJWT,
    apiController.requireRole('admin'),
    apiController.getActiveSessions
);

// Terminate session
v1Router.delete('/admin/sessions/:sessionId',
    authenticateJWT,
    apiController.requireRole('admin'),
    param('sessionId').notEmpty(),
    apiController.terminateSession
);

// Get API keys
v1Router.get('/admin/api-keys',
    authenticateJWT,
    apiController.requireRole('admin'),
    apiController.getAPIKeys
);

// Create API key
v1Router.post('/admin/api-keys',
    authenticateJWT,
    apiController.requireRole('admin'),
    [
        body('name').trim().isLength({ min: 3, max: 100 }),
        body('permissions').optional().isArray(),
        body('rateLimit').optional().isInt({ min: 1 }),
        body('expiresAt').optional().isISO8601()
    ],
    apiController.createAPIKey
);

// Revoke API key
v1Router.delete('/admin/api-keys/:keyId',
    authenticateJWT,
    apiController.requireRole('admin'),
    param('keyId').isInt(),
    apiController.revokeAPIKey
);

// ==================== Health & Monitoring ====================

// Health check
v1Router.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.API_VERSION || 'v1'
    });
});

// Metrics endpoint
v1Router.get('/metrics',
    authenticateAPI,
    apiController.getMetrics
);

// ==================== Webhooks ====================

// Register webhook
v1Router.post('/webhooks',
    authenticateJWT,
    [
        body('url').isURL(),
        body('events').isArray(),
        body('secret').optional().isLength({ min: 16 })
    ],
    apiController.registerWebhook
);

// List webhooks
v1Router.get('/webhooks',
    authenticateJWT,
    apiController.getWebhooks
);

// Delete webhook
v1Router.delete('/webhooks/:id',
    authenticateJWT,
    param('id').isInt(),
    apiController.deleteWebhook
);

// Mount v1 router
router.use('/v1', v1Router);

// 404 for undefined API routes
router.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        message: `The endpoint ${req.method} ${req.originalUrl} does not exist`,
        documentation: '/api'
    });
});

module.exports = router;
