/**
 * Admin Service
 * Business logic for admin operations
 */

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { User, Role, AuthLog, RefreshToken } = require('../models');
const { Op } = require('sequelize');
const { AUTH_MESSAGES, ADMIN_MESSAGES } = require('../constants/messages');
const { AUTH_ACTIONS } = require('../constants/actions');
const ROLES = require('../constants/role');
const USER_STATUS = require('../constants/userStatus');
const { generateAccessToken, generateRefreshToken } = require('../utils/jwt');
const logger = require('../utils/logger');
const { sendAdminPasswordReset } = require('../utils/emailService');

/**
 * Admin login (similar to regular login but for admin users)
 */
const adminLogin = async ({ email, password, ipAddress, userAgent }) => {
    // 1️⃣ Find user with roles and password hash
    const user = await User.scope('withPassword').findOne({
        where: { email },
        include: [{
            model: Role,
            through: { attributes: [] },
            attributes: ['name']
        }]
    });

    if (!user) {
        throw new Error(AUTH_MESSAGES.INVALID_CREDENTIALS);
    }

    // 2️⃣ Check if user has admin role
    const roles = user.Roles ? user.Roles.map(r => r.name) : [];
    const isAdmin = roles.includes(ROLES.ADMIN);

    if (!isAdmin) {
        await AuthLog.create({
            id: crypto.randomUUID(),
            user_id: user.id,
            action: AUTH_ACTIONS.ADMIN_LOGIN_DENIED,
            ip_address: ipAddress,
            user_agent: userAgent,
            created_at: new Date(),
            updated_at: new Date()
        });
        throw new Error(ADMIN_MESSAGES.ADMIN_ACCESS_DENIED);
    }

    // 3️⃣ Check if account is blocked
    if (user.is_blocked) {
        await AuthLog.create({
            id: crypto.randomUUID(),
            user_id: user.id,
            action: AUTH_ACTIONS.ADMIN_LOGIN_BLOCKED,
            ip_address: ipAddress,
            user_agent: userAgent,
            created_at: new Date(),
            updated_at: new Date()
        });
        throw new Error(AUTH_MESSAGES.ACCOUNT_BLOCKED);
    }

    // 4️⃣ Check if account is active
    if (!user.is_active) {
        throw new Error(AUTH_MESSAGES.ACCOUNT_INACTIVE);
    }

    // 5️⃣ Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
        await AuthLog.create({
            id: crypto.randomUUID(),
            user_id: user.id,
            action: AUTH_ACTIONS.ADMIN_LOGIN_FAILED,
            ip_address: ipAddress,
            user_agent: userAgent,
            created_at: new Date(),
            updated_at: new Date()
        });
        throw new Error(AUTH_MESSAGES.INVALID_CREDENTIALS);
    }

    // 6️⃣ Generate tokens
    const payload = {
        userId: user.id,
        email: user.email,
        roles
    };

    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    // 7️⃣ Store refresh token
    await RefreshToken.create({
        id: crypto.randomUUID(),
        user_id: user.id,
        token: refreshToken,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        is_revoked: false
    });

    // 8️⃣ Update last login
    await user.update({ last_login_at: new Date() });

    // 9️⃣ Log successful login
    await AuthLog.create({
        id: crypto.randomUUID(),
        user_id: user.id,
        action: AUTH_ACTIONS.ADMIN_LOGIN_SUCCESS,
        ip_address: ipAddress,
        user_agent: userAgent,
        created_at: new Date(),
        updated_at: new Date()
    });

    return {
        user: {
            id: user.id,
            email: user.email,
            roles
        },
        accessToken,
        refreshToken
    };
};

/**
 * Get all users with pagination and filtering
 */
const getAllUsers = async ({ page = 1, limit = 10, status, search }) => {
    const offset = (page - 1) * limit;
    const where = {};

    // Filter by status
    if (status === USER_STATUS.ACTIVE) {
        where.is_active = true;
        where.is_blocked = false;
    } else if (status === USER_STATUS.INACTIVE) {
        where.is_active = false;
    } else if (status === USER_STATUS.BLOCKED) {
        where.is_blocked = true;
    }

    // Search by email
    if (search) {
        where.email = { [Op.like]: `%${search}%` };
    }

    const { count, rows } = await User.findAndCountAll({
        where,
        include: [{
            model: Role,
            through: { attributes: [] },
            attributes: ['name']
        }],
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']]
    });

    return {
        users: rows.map(user => ({
            ...user.toJSON(),
            roles: user.Roles ? user.Roles.map(r => r.name) : []
        })),
        pagination: {
            total: count,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(count / limit)
        }
    };
};

/**
 * Get user by ID
 */
const getUserById = async (userId) => {
    const user = await User.findByPk(userId, {
        include: [{
            model: Role,
            through: { attributes: [] },
            attributes: ['name']
        }]
    });

    if (!user) {
        throw new Error(ADMIN_MESSAGES.USER_NOT_FOUND);
    }

    return {
        ...user.toJSON(),
        roles: user.Roles ? user.Roles.map(r => r.name) : []
    };
};

/**
 * Update user status (active/inactive/blocked)
 */
const updateUserStatus = async ({ userId, is_active, is_blocked, ipAddress, userAgent }) => {
    const user = await User.findByPk(userId);

    if (!user) {
        throw new Error(ADMIN_MESSAGES.USER_NOT_FOUND);
    }

    const updates = {};
    if (typeof is_active !== 'undefined') updates.is_active = is_active;
    if (typeof is_blocked !== 'undefined') updates.is_blocked = is_blocked;

    await user.update(updates);

    // Send email notification
    if (typeof is_blocked !== 'undefined' || (typeof is_active !== 'undefined' && is_active === true)) {
        try {
            const status = user.is_blocked ? USER_STATUS.BLOCKED : USER_STATUS.ACTIVE;
            const { sendAccountStatusNotification } = require('../utils/emailService');
            await sendAccountStatusNotification(user.email, status);
        } catch (emailError) {
            logger.error('Email notification error (Admin Status Update):', emailError);
        }
    }

    // Log the action
    let action = AUTH_ACTIONS.USER_STATUS_UPDATED;
    if (is_blocked === true) action = AUTH_ACTIONS.USER_BLOCKED;
    if (is_blocked === false && is_active === true) action = AUTH_ACTIONS.USER_ACTIVATED;

    await AuthLog.create({
        id: crypto.randomUUID(),
        user_id: userId,
        action,
        ip_address: ipAddress,
        user_agent: userAgent,
        created_at: new Date(),
        updated_at: new Date()
    });

    return user;
};

/**
 * Admin reset user password
 */
const resetUserPassword = async ({ userId, ipAddress, userAgent }) => {
    const user = await User.findByPk(userId);

    if (!user) {
        throw new Error(ADMIN_MESSAGES.USER_NOT_FOUND);
    }

    // Generate temporary password
    const tempPassword = crypto.randomBytes(8).toString('hex'); // 16 character password
    const passwordHash = await bcrypt.hash(tempPassword, 12);

    // Update password
    await user.update({ password_hash: passwordHash });

    // Revoke all refresh tokens
    await RefreshToken.update(
        { is_revoked: true },
        { where: { user_id: userId, is_revoked: false } }
    );

    // Send email with temp password
    try {
        await sendAdminPasswordReset(user.email, tempPassword);
    } catch (emailError) {
        logger.error('Email send error (Admin Reset Password):', emailError);
        // Continue even if email fails - admin can communicate password manually
    }

    // Log action
    await AuthLog.create({
        id: crypto.randomUUID(),
        user_id: userId,
        action: AUTH_ACTIONS.ADMIN_PASSWORD_RESET,
        ip_address: ipAddress,
        user_agent: userAgent,
        created_at: new Date(),
        updated_at: new Date()
    });

    return { tempPassword }; // Return so admin can see it if email fails
};

/**
 * Get authentication logs with filtering
 */
const getAuthLogs = async ({ page = 1, limit = 50, userId, action, startDate, endDate }) => {
    const offset = (page - 1) * limit;
    const where = {};

    if (userId) where.user_id = userId;
    if (action) where.action = action;

    if (startDate || endDate) {
        where.created_at = {};
        if (startDate) where.created_at[Op.gte] = new Date(startDate);
        if (endDate) where.created_at[Op.lte] = new Date(endDate);
    }

    const { count, rows } = await AuthLog.findAndCountAll({
        where,
        include: [{
            model: User,
            attributes: ['email'],
            required: false
        }],
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']]
    });

    return {
        logs: rows,
        pagination: {
            total: count,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(count / limit)
        }
    };
};

/**
 * Get dashboard statistics
 */
const getDashboardStats = async () => {
    const totalUsers = await User.count();
    const activeUsers = await User.count({ where: { is_active: true, is_blocked: false } });
    const blockedUsers = await User.count({ where: { is_blocked: true } });
    const inactiveUsers = await User.count({ where: { is_active: false } });

    // Users registered in last 30 days
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentUsers = await User.count({
        where: {
            created_at: { [Op.gte]: thirtyDaysAgo }
        }
    });

    // Recent login attempts (last 7 days)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentLogins = await AuthLog.count({
        where: {
            action: { [Op.in]: [AUTH_ACTIONS.LOGIN_SUCCESS, AUTH_ACTIONS.ADMIN_LOGIN_SUCCESS] },
            created_at: { [Op.gte]: sevenDaysAgo }
        }
    });

    const failedLogins = await AuthLog.count({
        where: {
            action: { [Op.in]: [AUTH_ACTIONS.LOGIN_FAILED, AUTH_ACTIONS.LOGIN_BLOCKED] },
            created_at: { [Op.gte]: sevenDaysAgo }
        }
    });

    return {
        totalUsers,
        activeUsers,
        blockedUsers,
        inactiveUsers,
        recentUsers,
        recentLogins,
        failedLogins
    };
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
