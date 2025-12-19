/**
 * Admin Controllers
 * Handle admin-related HTTP requests
 */

const { validationResult } = require('express-validator');
const adminService = require('../services/adminService');
const logger = require('../utils/logger');
const STATUS_CODES = require('../constants/statusCodes');
const { ADMIN_MESSAGES, ERROR_MESSAGES, AUTH_MESSAGES } = require('../constants/messages');

// Helper function to extract IP and user agent
const getRequestMetadata = (req) => ({
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('user-agent') || 'Unknown'
});

const adminLogin = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(STATUS_CODES.BAD_REQUEST).json({
                success: false,
                message: ERROR_MESSAGES.VALIDATION_ERROR,
                errors: errors.array()
            });
        }

        const { email, password } = req.body;
        const { ipAddress, userAgent } = getRequestMetadata(req);

        const result = await adminService.adminLogin({
            email,
            password,
            ipAddress,
            userAgent
        });

        res.status(STATUS_CODES.OK).json({
            success: true,
            message: ADMIN_MESSAGES.ADMIN_LOGIN_SUCCESS,
            data: result
        });
    } catch (error) {
        logger.error('Admin login error:', error);

        if ([
            AUTH_MESSAGES.INVALID_CREDENTIALS,
            AUTH_MESSAGES.ACCOUNT_BLOCKED,
            AUTH_MESSAGES.ACCOUNT_INACTIVE,
            ADMIN_MESSAGES.ADMIN_ACCESS_DENIED
        ].includes(error.message)) {
            return res.status(STATUS_CODES.UNAUTHORIZED).json({
                success: false,
                message: error.message
            });
        }

        res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: ERROR_MESSAGES.INTERNAL_ERROR
        });
    }
};

const getAllUsers = async (req, res) => {
    try {
        const { page, limit, status, search } = req.query;

        const result = await adminService.getAllUsers({
            page,
            limit,
            status,
            search
        });

        res.status(STATUS_CODES.OK).json({
            success: true,
            message: ADMIN_MESSAGES.USERS_FETCHED,
            data: result
        });
    } catch (error) {
        logger.error('Get all users error:', error);
        res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: ERROR_MESSAGES.INTERNAL_ERROR
        });
    }
};

const getUserById = async (req, res) => {
    try {
        const { id } = req.params;

        const user = await adminService.getUserById(id);

        res.status(STATUS_CODES.OK).json({
            success: true,
            message: ADMIN_MESSAGES.USER_FETCHED,
            data: user
        });
    } catch (error) {
        logger.error('Get user by ID error:', error);

        if (error.message === ADMIN_MESSAGES.USER_NOT_FOUND) {
            return res.status(STATUS_CODES.NOT_FOUND).json({
                success: false,
                message: error.message
            });
        }

        res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: ERROR_MESSAGES.INTERNAL_ERROR
        });
    }
};

const updateUserStatus = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(STATUS_CODES.BAD_REQUEST).json({
                success: false,
                message: ERROR_MESSAGES.VALIDATION_ERROR,
                errors: errors.array()
            });
        }

        const { id } = req.params;
        const { is_active, is_blocked } = req.body;
        const { ipAddress, userAgent } = getRequestMetadata(req);

        const user = await adminService.updateUserStatus({
            userId: id,
            is_active,
            is_blocked,
            ipAddress,
            userAgent
        });

        res.status(STATUS_CODES.OK).json({
            success: true,
            message: ADMIN_MESSAGES.USER_STATUS_UPDATED,
            data: {
                id: user.id,
                email: user.email,
                is_active: user.is_active,
                is_blocked: user.is_blocked,
                updated_at: user.updated_at
            }
        });
    } catch (error) {
        logger.error('Update user status error:', error);

        if (error.message === ADMIN_MESSAGES.USER_NOT_FOUND) {
            return res.status(STATUS_CODES.NOT_FOUND).json({
                success: false,
                message: error.message
            });
        }

        res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: ERROR_MESSAGES.INTERNAL_ERROR
        });
    }
};

const resetUserPassword = async (req, res) => {
    try {
        const { id } = req.params;
        const { ipAddress, userAgent } = getRequestMetadata(req);

        const result = await adminService.resetUserPassword({
            userId: id,
            ipAddress,
            userAgent
        });

        res.status(STATUS_CODES.OK).json({
            success: true,
            message: ADMIN_MESSAGES.USER_PASSWORD_RESET,
            data: result
        });
    } catch (error) {
        logger.error('Reset user password error:', error);

        if (error.message === ADMIN_MESSAGES.USER_NOT_FOUND) {
            return res.status(STATUS_CODES.NOT_FOUND).json({
                success: false,
                message: error.message
            });
        }

        res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: ERROR_MESSAGES.INTERNAL_ERROR
        });
    }
};

const getAuthLogs = async (req, res) => {
    try {
        const { page, limit, userId, action, startDate, endDate } = req.query;

        const result = await adminService.getAuthLogs({
            page,
            limit,
            userId,
            action,
            startDate,
            endDate
        });

        res.status(STATUS_CODES.OK).json({
            success: true,
            message: ADMIN_MESSAGES.AUTH_LOGS_FETCHED,
            data: result
        });
    } catch (error) {
        logger.error('Get auth logs error:', error);
        res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: ERROR_MESSAGES.INTERNAL_ERROR
        });
    }
};

const getDashboardStats = async (req, res) => {
    try {
        const stats = await adminService.getDashboardStats();

        res.status(STATUS_CODES.OK).json({
            success: true,
            message: ADMIN_MESSAGES.STATS_FETCHED,
            data: stats
        });
    } catch (error) {
        logger.error('Get dashboard stats error:', error);
        res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: ERROR_MESSAGES.INTERNAL_ERROR
        });
    }
};

module.exports = {
    adminLogin,
    getAllUsers,
    getUserById,
    updateUserStatus,
    resetUserPassword,
    getAuthLogs,
    getDashboardStats
};
