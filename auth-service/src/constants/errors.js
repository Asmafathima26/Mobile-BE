/**
 * Custom Error Classes and Error Types
 * Better error handling and categorization
 */

const STATUS_CODES = require('./statusCodes');

/**
 * Base Application Error
 */
class AppError extends Error {
    constructor(message, statusCode, errorType = 'APP_ERROR') {
        super(message);
        this.statusCode = statusCode;
        this.errorType = errorType;
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Validation Error
 */
class ValidationError extends AppError {
    constructor(message) {
        super(message, STATUS_CODES.BAD_REQUEST, 'VALIDATION_ERROR');
    }
}

/**
 * Authentication Error
 */
class AuthenticationError extends AppError {
    constructor(message) {
        super(message, STATUS_CODES.UNAUTHORIZED, 'AUTHENTICATION_ERROR');
    }
}

/**
 * Authorization Error
 */
class AuthorizationError extends AppError {
    constructor(message) {
        super(message, STATUS_CODES.FORBIDDEN, 'AUTHORIZATION_ERROR');
    }
}

/**
 * Not Found Error
 */
class NotFoundError extends AppError {
    constructor(message) {
        super(message, STATUS_CODES.NOT_FOUND, 'NOT_FOUND_ERROR');
    }
}

/**
 * Conflict Error (e.g., duplicate email)
 */
class ConflictError extends AppError {
    constructor(message) {
        super(message, STATUS_CODES.CONFLICT, 'CONFLICT_ERROR');
    }
}

/**
 * Database Error
 */
class DatabaseError extends AppError {
    constructor(message) {
        super(message, STATUS_CODES.INTERNAL_SERVER_ERROR, 'DATABASE_ERROR');
    }
}

/**
 * External Service Error (e.g., email service)
 */
class ExternalServiceError extends AppError {
    constructor(message) {
        super(message, STATUS_CODES.SERVICE_UNAVAILABLE, 'EXTERNAL_SERVICE_ERROR');
    }
}

// Error Type Constants
const ERROR_TYPES = {
    APP_ERROR: 'APP_ERROR',
    VALIDATION_ERROR: 'VALIDATION_ERROR',
    AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
    AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
    NOT_FOUND_ERROR: 'NOT_FOUND_ERROR',
    CONFLICT_ERROR: 'CONFLICT_ERROR',
    DATABASE_ERROR: 'DATABASE_ERROR',
    EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR'
};

module.exports = {
    AppError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ConflictError,
    DatabaseError,
    ExternalServiceError,
    ERROR_TYPES
};
