// src/config/database.js
const { Sequelize } = require('sequelize');
const winston = require('winston');
require('dotenv').config();

// Create logger for database operations
const dbLogger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console({
            format: winston.format.simple(),
        }),
    ],
});

// Database configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    username: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'user_management_system',
    dialect: 'mysql',
    pool: {
        max: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
        min: 0,
        acquire: 30000,
        idle: 10000,
    },
    logging: process.env.NODE_ENV === 'development' ? 
        (msg) => dbLogger.debug(msg) : false,
    dialectOptions: {
        charset: 'utf8mb4',
        dateStrings: true,
        typeCast: true,
    },
    timezone: '+00:00',
    define: {
        timestamps: true,
        underscored: false,
        freezeTableName: true,
        charset: 'utf8mb4',
        collate: 'utf8mb4_unicode_ci',
    },
};

// Create Sequelize instance
const sequelize = new Sequelize(
    dbConfig.database,
    dbConfig.username,
    dbConfig.password,
    dbConfig
);

// Test database connection
const testConnection = async () => {
    try {
        await sequelize.authenticate();
        dbLogger.info('Database connection has been established successfully.');
        return true;
    } catch (error) {
        dbLogger.error('Unable to connect to the database:', error);
        return false;
    }
};

// Export
module.exports = {
    sequelize,
    Sequelize,
    testConnection,
};
