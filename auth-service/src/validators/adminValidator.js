/**
 * Admin Validators
 * Validation rules for admin endpoints
 */

const { body, query, param } = require('express-validator');
const USER_STATUS = require('../constants/userStatus');
const { AUTH_ACTIONS } = require('../constants/actions');

const adminLoginValidator = [
    body('email')
        .isEmail()
        .withMessage('Valid email required')
        .normalizeEmail(),
    body('password')
        .notEmpty()
        .withMessage('Password is required'),
];

const updateUserStatusValidator = [
    param('id')
        .isUUID()
        .withMessage('Invalid user ID'),
    body('is_active')
        .optional()
        .isBoolean()
        .withMessage('is_active must be a boolean'),
    body('is_blocked')
        .optional()
        .isBoolean()
        .withMessage('is_blocked must be a boolean'),
];

const getUsersQueryValidator = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100'),
    query('status')
        .optional()
        .isIn([USER_STATUS.ACTIVE, USER_STATUS.INACTIVE, USER_STATUS.BLOCKED])
        .withMessage(`Status must be ${USER_STATUS.ACTIVE}, ${USER_STATUS.INACTIVE}, or ${USER_STATUS.BLOCKED}`),
    query('search')
        .optional()
        .isString()
        .withMessage('Search must be a string'),
];

const getAuthLogsQueryValidator = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100'),
    query('userId')
        .optional()
        .isUUID()
        .withMessage('Invalid user ID'),
    query('action')
        .optional()
        .isIn(Object.values(AUTH_ACTIONS))
        .withMessage('Invalid action type'),
    query('startDate')
        .optional()
        .isISO8601()
        .withMessage('Start date must be a valid ISO 8601 date'),
    query('endDate')
        .optional()
        .isISO8601()
        .withMessage('End date must be a valid ISO 8601 date'),
];

const userIdParamValidator = [
    param('id')
        .isUUID()
        .withMessage('Invalid user ID'),
];

module.exports = {
    adminLoginValidator,
    updateUserStatusValidator,
    getUsersQueryValidator,
    getAuthLogsQueryValidator,
    userIdParamValidator
};
