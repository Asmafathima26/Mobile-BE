/**
 * Role-based Middleware
 * Restricts access to routes based on user roles
 */

const STATUS_CODES = require('../constants/statusCodes');
const { ADMIN_MESSAGES } = require('../constants/messages');
const ROLES = require('../constants/role');

/**
 * Middleware factory to check if user has required roles
 * @param {string[]} allowedRoles - Array of allowed role names
 * @returns {Function} Express middleware function
 */
const requireRole = (allowedRoles = []) => {
    return (req, res, next) => {
        try {
            // Check if user is authenticated (should be set by authMiddleware)
            if (!req.user) {
                return res.status(STATUS_CODES.UNAUTHORIZED).json({
                    success: false,
                    message: ADMIN_MESSAGES.ADMIN_ACCESS_DENIED
                });
            }

            // Check if user has any of the allowed roles
            const userRoles = req.user.roles || [];
            const hasPermission = allowedRoles.some(role => userRoles.includes(role));

            if (!hasPermission) {
                return res.status(STATUS_CODES.FORBIDDEN).json({
                    success: false,
                    message: ADMIN_MESSAGES.ADMIN_ACCESS_DENIED
                });
            }

            next();
        } catch (error) {
            console.error('Role middleware error:', error);
            return res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
                success: false,
                message: 'Authorization check failed'
            });
        }
    };
};

/**
 * Middleware to check if user is admin
 */
const requireAdmin = requireRole([ROLES.ADMIN]);

module.exports = {
    requireRole,
    requireAdmin
};
