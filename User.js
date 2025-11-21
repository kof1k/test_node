// src/models/User.js
const { DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { sequelize } = require('../config/database');

const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    username: {
        type: DataTypes.STRING(50),
        unique: true,
        allowNull: false,
        validate: {
            len: [3, 50],
            isAlphanumeric: {
                msg: 'Username can only contain letters and numbers',
            },
        },
    },
    email: {
        type: DataTypes.STRING(100),
        unique: true,
        allowNull: false,
        validate: {
            isEmail: {
                msg: 'Must be a valid email address',
            },
        },
    },
    passwordHash: {
        type: DataTypes.STRING(255),
        allowNull: false,
        field: 'password_hash',
    },
    firstName: {
        type: DataTypes.STRING(50),
        field: 'first_name',
        validate: {
            len: [1, 50],
        },
    },
    lastName: {
        type: DataTypes.STRING(50),
        field: 'last_name',
        validate: {
            len: [1, 50],
        },
    },
    avatarUrl: {
        type: DataTypes.STRING(255),
        field: 'avatar_url',
        defaultValue: '/images/default-avatar.png',
    },
    bio: {
        type: DataTypes.TEXT,
    },
    phone: {
        type: DataTypes.STRING(20),
        validate: {
            is: /^[\d\s\-\+\(\)]+$/,
        },
    },
    dateOfBirth: {
        type: DataTypes.DATEONLY,
        field: 'date_of_birth',
    },
    role: {
        type: DataTypes.ENUM('user', 'admin', 'moderator'),
        defaultValue: 'user',
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
        field: 'is_active',
    },
    isVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'is_verified',
    },
    verificationToken: {
        type: DataTypes.STRING(255),
        field: 'verification_token',
    },
    resetToken: {
        type: DataTypes.STRING(255),
        field: 'reset_token',
    },
    resetTokenExpires: {
        type: DataTypes.DATE,
        field: 'reset_token_expires',
    },
    twoFactorEnabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'two_factor_enabled',
    },
    twoFactorSecret: {
        type: DataTypes.STRING(255),
        field: 'two_factor_secret',
    },
    lastLogin: {
        type: DataTypes.DATE,
        field: 'last_login',
    },
    failedLoginAttempts: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        field: 'failed_login_attempts',
    },
    lockedUntil: {
        type: DataTypes.DATE,
        field: 'locked_until',
    },
}, {
    tableName: 'users',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    indexes: [
        { fields: ['username'] },
        { fields: ['email'] },
        { fields: ['role'] },
        { fields: ['is_active'] },
    ],
});

// Instance methods
User.prototype.setPassword = async function(password) {
    const saltRounds = 12;
    this.passwordHash = await bcrypt.hash(password, saltRounds);
};

User.prototype.validatePassword = async function(password) {
    return await bcrypt.compare(password, this.passwordHash);
};

User.prototype.generateVerificationToken = function() {
    this.verificationToken = crypto.randomBytes(32).toString('hex');
    return this.verificationToken;
};

User.prototype.generateResetToken = function() {
    this.resetToken = crypto.randomBytes(32).toString('hex');
    this.resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour
    return this.resetToken;
};

User.prototype.incrementFailedAttempts = async function() {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= 5) {
        this.lockedUntil = new Date(Date.now() + 900000); // 15 minutes
    }
    await this.save();
};

User.prototype.resetFailedAttempts = async function() {
    this.failedLoginAttempts = 0;
    this.lockedUntil = null;
    await this.save();
};

User.prototype.isLocked = function() {
    return this.lockedUntil && this.lockedUntil > new Date();
};

User.prototype.toJSON = function() {
    const values = Object.assign({}, this.get());
    delete values.passwordHash;
    delete values.verificationToken;
    delete values.resetToken;
    delete values.twoFactorSecret;
    return values;
};

// Hooks
User.beforeCreate(async (user) => {
    if (user.email) {
        user.email = user.email.toLowerCase();
    }
    if (user.username) {
        user.username = user.username.toLowerCase();
    }
});

User.beforeUpdate(async (user) => {
    if (user.changed('email')) {
        user.email = user.email.toLowerCase();
    }
    if (user.changed('username')) {
        user.username = user.username.toLowerCase();
    }
});

module.exports = User;
