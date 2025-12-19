/**
 * Admin Routes
 * Protected routes for admin operations
 */

const express = require('express');
const adminController = require('../controllers/adminController');
const adminValidator = require('../validators/adminValidator');
const authMiddleware = require('../middlewares/authMiddleware');
const { requireAdmin } = require('../middlewares/roleMiddleware');

const router = express.Router();

// Admin Login (Public)
router.post('/login', adminValidator.adminLoginValidator, adminController.adminLogin);

// Protected Admin Routes (Requires Auth + Admin Role)
router.use(authMiddleware);
router.use(requireAdmin);

// User Management
router.get('/users', adminValidator.getUsersQueryValidator, adminController.getAllUsers);
router.get('/users/:id', adminValidator.userIdParamValidator, adminController.getUserById);
router.patch('/users/:id/status', adminValidator.updateUserStatusValidator, adminController.updateUserStatus);
router.post('/users/:id/reset-password', adminValidator.userIdParamValidator, adminController.resetUserPassword);

// Auth Logs
router.get('/auth-logs', adminValidator.getAuthLogsQueryValidator, adminController.getAuthLogs);

// Dashboard Statistics
router.get('/dashboard/stats', adminController.getDashboardStats);

module.exports = router;
