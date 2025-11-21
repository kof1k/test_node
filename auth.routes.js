// src/routes/auth.routes.js
const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/auth.controller');
const { isGuest, isAuthenticated } = require('../middleware/auth.middleware');
const { csrfProtection } = require('../middleware/csrf.middleware');

const router = express.Router();

// Validation rules
const registrationRules = () => {
    return [
        body('username')
            .trim()
            .isLength({ min: 3, max: 50 })
            .withMessage('Username must be between 3 and 50 characters')
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username can only contain letters, numbers, and underscores')
            .custom(async (value) => {
                const User = require('../models/User');
                const user = await User.findOne({ where: { username: value.toLowerCase() } });
                if (user) {
                    throw new Error('Username already in use');
                }
                return true;
            }),
        body('email')
            .trim()
            .isEmail()
            .normalizeEmail()
            .withMessage('Please provide a valid email')
            .custom(async (value) => {
                const User = require('../models/User');
                const user = await User.findOne({ where: { email: value.toLowerCase() } });
                if (user) {
                    throw new Error('Email already in use');
                }
                return true;
            }),
        body('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
            .withMessage('Password must contain uppercase, lowercase, number, and special character'),
        body('confirmPassword')
            .custom((value, { req }) => value === req.body.password)
            .withMessage('Passwords do not match'),
        body('firstName')
            .optional()
            .trim()
            .isLength({ min: 1, max: 50 })
            .withMessage('First name must be between 1 and 50 characters')
            .matches(/^[a-zA-Z\s]+$/)
            .withMessage('First name can only contain letters and spaces'),
        body('lastName')
            .optional()
            .trim()
            .isLength({ min: 1, max: 50 })
            .withMessage('Last name must be between 1 and 50 characters')
            .matches(/^[a-zA-Z\s]+$/)
            .withMessage('Last name can only contain letters and spaces'),
    ];
};

const loginRules = () => {
    return [
        body('username')
            .trim()
            .notEmpty()
            .withMessage('Username or email is required')
            .escape(),
        body('password')
            .notEmpty()
            .withMessage('Password is required'),
    ];
};

const forgotPasswordRules = () => {
    return [
        body('email')
            .trim()
            .isEmail()
            .normalizeEmail()
            .withMessage('Please provide a valid email'),
    ];
};

const resetPasswordRules = () => {
    return [
        body('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
            .withMessage('Password must contain uppercase, lowercase, number, and special character'),
        body('confirmPassword')
            .custom((value, { req }) => value === req.body.password)
            .withMessage('Passwords do not match'),
    ];
};

const verify2FARules = () => {
    return [
        body('token')
            .trim()
            .notEmpty()
            .withMessage('Verification code is required')
            .matches(/^\d{6}$/)
            .withMessage('Invalid verification code format'),
    ];
};

// Routes - Guest only
router.get('/login', isGuest, csrfProtection, authController.showLogin);
router.post('/login', isGuest, csrfProtection, loginRules(), authController.login);

router.get('/register', isGuest, csrfProtection, authController.showRegister);
router.post('/register', isGuest, csrfProtection, registrationRules(), authController.register);

router.get('/forgot-password', isGuest, csrfProtection, authController.showForgotPassword);
router.post('/forgot-password', isGuest, csrfProtection, forgotPasswordRules(), authController.forgotPassword);

router.get('/reset-password/:token', isGuest, csrfProtection, authController.showResetPassword);
router.post('/reset-password/:token', isGuest, csrfProtection, resetPasswordRules(), authController.resetPassword);

router.get('/verify-email/:token', authController.verifyEmail);

// 2FA routes
router.get('/verify-2fa', csrfProtection, authController.show2FA);
router.post('/verify-2fa', csrfProtection, verify2FARules(), authController.verify2FA);

// Protected routes
router.post('/setup-2fa', isAuthenticated, authController.setup2FA);

// Logout - authenticated users only
router.get('/logout', isAuthenticated, authController.logout);
router.post('/logout', isAuthenticated, csrfProtection, authController.logout);

module.exports = router;
