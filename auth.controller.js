// src/controllers/auth.controller.js
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const User = require('../models/User');
const UserLog = require('../models/UserLog');
const Session = require('../models/Session');
const emailService = require('../services/email.service');
const logger = require('../utils/logger');
const { generateTokens, verifyRefreshToken } = require('../utils/jwt');
const { sanitizeUser } = require('../utils/sanitizer');

class AuthController {
    // Register new user
    async register(req, res) {
        try {
            // Check validation errors
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).render('auth/register', {
                    title: 'Register',
                    errors: errors.array(),
                    formData: req.body,
                    success: null
                });
            }

            const { username, email, password, firstName, lastName } = req.body;

            // Check if user already exists
            const existingUser = await User.findOne({
                where: {
                    [require('sequelize').Op.or]: [
                        { username: username.toLowerCase() },
                        { email: email.toLowerCase() }
                    ]
                }
            });

            if (existingUser) {
                return res.status(400).render('auth/register', {
                    title: 'Register',
                    errors: [{ msg: 'Username or email already exists' }],
                    formData: req.body,
                    success: null
                });
            }

            // Create new user
            const user = await User.create({
                username: username.toLowerCase(),
                email: email.toLowerCase(),
                firstName,
                lastName,
            });

            // Set password (hashed)
            await user.setPassword(password);

            // Generate verification token
            const verificationToken = user.generateVerificationToken();
            await user.save();

            // Send verification email
            await emailService.sendVerificationEmail(user.email, verificationToken);

            // Log registration
            await UserLog.create({
                userId: user.id,
                action: 'register',
                status: 'success',
                ipAddress: req.ip,
                userAgent: req.get('user-agent'),
                details: { method: 'email' },
                metadata: { fingerprint: req.fingerprint?.hash }
            });

            // Render success
            res.render('auth/register', {
                title: 'Register',
                errors: [],
                formData: {},
                success: 'Registration successful! Please check your email to verify your account.'
            });

        } catch (error) {
            logger.error('Registration error:', error);
            res.status(500).render('auth/register', {
                title: 'Register',
                errors: [{ msg: 'An error occurred during registration' }],
                formData: req.body,
                success: null
            });
        }
    }

    // Login user
    async login(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).render('auth/login', {
                    title: 'Login',
                    errors: errors.array(),
                    formData: req.body,
                    success: null
                });
            }

            const { username, password, rememberMe } = req.body;

            // Find user by username or email
            const user = await User.findOne({
                where: {
                    [require('sequelize').Op.or]: [
                        { username: username.toLowerCase() },
                        { email: username.toLowerCase() }
                    ]
                }
            });

            if (!user) {
                await UserLog.create({
                    action: 'login',
                    status: 'failed',
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent'),
                    details: { reason: 'user_not_found', username },
                    metadata: { fingerprint: req.fingerprint?.hash }
                });

                return res.status(401).render('auth/login', {
                    title: 'Login',
                    errors: [{ msg: 'Invalid credentials' }],
                    formData: req.body,
                    success: null
                });
            }

            // Check if account is locked
            if (user.isLocked()) {
                await UserLog.create({
                    userId: user.id,
                    action: 'login',
                    status: 'failed',
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent'),
                    details: { reason: 'account_locked' },
                    metadata: { fingerprint: req.fingerprint?.hash }
                });

                return res.status(423).render('auth/login', {
                    title: 'Login',
                    errors: [{ msg: 'Account is temporarily locked due to multiple failed login attempts' }],
                    formData: req.body,
                    success: null
                });
            }

            // Check if account is active
            if (!user.isActive) {
                return res.status(403).render('auth/login', {
                    title: 'Login',
                    errors: [{ msg: 'Account is deactivated' }],
                    formData: req.body,
                    success: null
                });
            }

            // Validate password
            const isValidPassword = await user.validatePassword(password);
            if (!isValidPassword) {
                await user.incrementFailedAttempts();
                
                await UserLog.create({
                    userId: user.id,
                    action: 'login',
                    status: 'failed',
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent'),
                    details: { reason: 'invalid_password' },
                    metadata: { fingerprint: req.fingerprint?.hash }
                });

                return res.status(401).render('auth/login', {
                    title: 'Login',
                    errors: [{ msg: 'Invalid credentials' }],
                    formData: req.body,
                    success: null
                });
            }

            // Check if 2FA is enabled
            if (user.twoFactorEnabled) {
                // Store user ID temporarily for 2FA verification
                req.session.tempUserId = user.id;
                req.session.remember2FA = rememberMe;
                return res.redirect('/auth/verify-2fa');
            }

            // Reset failed attempts
            await user.resetFailedAttempts();

            // Update last login
            user.lastLogin = new Date();
            await user.save();

            // Create session
            req.session.userId = user.id;
            req.session.userRole = user.role;
            
            if (rememberMe) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
            }

            // Create session record
            await Session.create({
                sessionId: req.sessionID,
                userId: user.id,
                ipAddress: req.ip,
                userAgent: req.get('user-agent'),
                expiresAt: new Date(Date.now() + req.session.cookie.maxAge),
                refreshToken: crypto.randomBytes(64).toString('hex')
            });

            // Log successful login
            await UserLog.create({
                userId: user.id,
                action: 'login',
                status: 'success',
                ipAddress: req.ip,
                userAgent: req.get('user-agent'),
                details: { method: 'password' },
                metadata: { fingerprint: req.fingerprint?.hash }
            });

            // Redirect to dashboard
            const redirectUrl = req.session.returnTo || '/user/dashboard';
            delete req.session.returnTo;
            res.redirect(redirectUrl);

        } catch (error) {
            logger.error('Login error:', error);
            res.status(500).render('auth/login', {
                title: 'Login',
                errors: [{ msg: 'An error occurred during login' }],
                formData: req.body,
                success: null
            });
        }
    }

    // Setup 2FA
    async setup2FA(req, res) {
        try {
            const userId = req.session.userId;
            const user = await User.findByPk(userId);

            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Generate secret
            const secret = speakeasy.generateSecret({
                name: `${process.env.TWO_FACTOR_APP_NAME} (${user.email})`,
                length: 32
            });

            // Store secret temporarily
            user.twoFactorSecret = secret.base32;
            await user.save();

            // Generate QR code
            const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

            res.json({
                success: true,
                secret: secret.base32,
                qrCode: qrCodeUrl
            });

        } catch (error) {
            logger.error('2FA setup error:', error);
            res.status(500).json({ error: 'Failed to setup 2FA' });
        }
    }

    // Verify 2FA
    async verify2FA(req, res) {
        try {
            const { token } = req.body;
            const userId = req.session.tempUserId || req.session.userId;

            if (!userId) {
                return res.status(401).render('auth/verify-2fa', {
                    title: 'Verify 2FA',
                    error: 'Session expired. Please login again.'
                });
            }

            const user = await User.findByPk(userId);
            if (!user || !user.twoFactorSecret) {
                return res.status(400).render('auth/verify-2fa', {
                    title: 'Verify 2FA',
                    error: '2FA not configured'
                });
            }

            // Verify token
            const verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: token,
                window: 2
            });

            if (!verified) {
                await UserLog.create({
                    userId: user.id,
                    action: '2fa_verify',
                    status: 'failed',
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent'),
                    details: { reason: 'invalid_token' }
                });

                return res.status(401).render('auth/verify-2fa', {
                    title: 'Verify 2FA',
                    error: 'Invalid verification code'
                });
            }

            // If setting up 2FA for first time
            if (!user.twoFactorEnabled) {
                user.twoFactorEnabled = true;
                await user.save();
            }

            // Complete login process
            req.session.userId = user.id;
            req.session.userRole = user.role;
            delete req.session.tempUserId;

            if (req.session.remember2FA) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            }
            delete req.session.remember2FA;

            // Update last login
            user.lastLogin = new Date();
            await user.save();

            // Log successful 2FA
            await UserLog.create({
                userId: user.id,
                action: '2fa_verify',
                status: 'success',
                ipAddress: req.ip,
                userAgent: req.get('user-agent')
            });

            res.redirect('/user/dashboard');

        } catch (error) {
            logger.error('2FA verification error:', error);
            res.status(500).render('auth/verify-2fa', {
                title: 'Verify 2FA',
                error: 'An error occurred during verification'
            });
        }
    }

    // Forgot password
    async forgotPassword(req, res) {
        try {
            const { email } = req.body;
            const user = await User.findOne({ where: { email: email.toLowerCase() } });

            if (user) {
                const resetToken = user.generateResetToken();
                await user.save();

                // Send reset email
                await emailService.sendPasswordResetEmail(user.email, resetToken);

                // Log password reset request
                await UserLog.create({
                    userId: user.id,
                    action: 'password_reset_request',
                    status: 'success',
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent')
                });
            }

            // Always show success message (security)
            res.render('auth/forgot-password', {
                title: 'Password Reset',
                success: 'If an account exists with that email, a password reset link has been sent.'
            });

        } catch (error) {
            logger.error('Password reset error:', error);
            res.status(500).render('auth/forgot-password', {
                title: 'Password Reset',
                error: 'An error occurred. Please try again.'
            });
        }
    }

    // Reset password
    async resetPassword(req, res) {
        try {
            const { token } = req.params;
            const { password } = req.body;

            const user = await User.findOne({
                where: {
                    resetToken: token,
                    resetTokenExpires: {
                        [require('sequelize').Op.gt]: new Date()
                    }
                }
            });

            if (!user) {
                return res.status(400).render('auth/reset-password', {
                    title: 'Reset Password',
                    error: 'Invalid or expired reset token',
                    token
                });
            }

            // Set new password
            await user.setPassword(password);
            user.resetToken = null;
            user.resetTokenExpires = null;
            await user.save();

            // Log password reset
            await UserLog.create({
                userId: user.id,
                action: 'password_reset',
                status: 'success',
                ipAddress: req.ip,
                userAgent: req.get('user-agent')
            });

            res.render('auth/reset-password', {
                title: 'Reset Password',
                success: 'Password has been reset successfully. You can now login.',
                token: null
            });

        } catch (error) {
            logger.error('Password reset error:', error);
            res.status(500).render('auth/reset-password', {
                title: 'Reset Password',
                error: 'An error occurred. Please try again.',
                token: req.params.token
            });
        }
    }

    // Verify email
    async verifyEmail(req, res) {
        try {
            const { token } = req.params;

            const user = await User.findOne({
                where: { verificationToken: token }
            });

            if (!user) {
                return res.status(400).render('auth/verify-email', {
                    title: 'Email Verification',
                    error: 'Invalid verification token'
                });
            }

            user.isVerified = true;
            user.verificationToken = null;
            await user.save();

            // Log verification
            await UserLog.create({
                userId: user.id,
                action: 'email_verify',
                status: 'success',
                ipAddress: req.ip,
                userAgent: req.get('user-agent')
            });

            res.render('auth/verify-email', {
                title: 'Email Verification',
                success: 'Email verified successfully! You can now login.'
            });

        } catch (error) {
            logger.error('Email verification error:', error);
            res.status(500).render('auth/verify-email', {
                title: 'Email Verification',
                error: 'An error occurred during verification'
            });
        }
    }

    // Logout
    async logout(req, res) {
        try {
            const userId = req.session.userId;

            if (userId) {
                // Delete session from database
                await Session.destroy({
                    where: { sessionId: req.sessionID }
                });

                // Log logout
                await UserLog.create({
                    userId,
                    action: 'logout',
                    status: 'success',
                    ipAddress: req.ip,
                    userAgent: req.get('user-agent')
                });
            }

            // Destroy session
            req.session.destroy((err) => {
                if (err) {
                    logger.error('Session destruction error:', err);
                }
                res.redirect('/');
            });

        } catch (error) {
            logger.error('Logout error:', error);
            res.redirect('/');
        }
    }

    // Render login page
    showLogin(req, res) {
        res.render('auth/login', {
            title: 'Login',
            errors: [],
            formData: {},
            success: null
        });
    }

    // Render register page
    showRegister(req, res) {
        res.render('auth/register', {
            title: 'Register',
            errors: [],
            formData: {},
            success: null
        });
    }

    // Render 2FA page
    show2FA(req, res) {
        if (!req.session.tempUserId) {
            return res.redirect('/auth/login');
        }
        res.render('auth/verify-2fa', {
            title: 'Verify 2FA',
            error: null
        });
    }

    // Render forgot password page
    showForgotPassword(req, res) {
        res.render('auth/forgot-password', {
            title: 'Forgot Password',
            error: null,
            success: null
        });
    }

    // Render reset password page
    showResetPassword(req, res) {
        const { token } = req.params;
        res.render('auth/reset-password', {
            title: 'Reset Password',
            token,
            error: null,
            success: null
        });
    }
}

module.exports = new AuthController();
