const express = require('express');
const authController = require('../controllers/authController');
const authValidator = require('../validators/authValidator');
const authMiddleware = require('../middlewares/authMiddleware');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Sensitive Auth Rate Limiter (5 attempts per 15 mins)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        message: 'Too many attempts from this IP, please try again after 15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Public routes
router.post('/register', authValidator.registerValidator, authController.register);
router.post('/login', authLimiter, authValidator.loginValidator, authController.login);
router.post('/forgot-password', authLimiter, authValidator.forgotPasswordValidator, authController.forgotPassword);
router.post('/reset-password', authValidator.resetPasswordValidator, authController.resetPassword);
router.post('/verify-otp', authValidator.verifyOtpValidator, authController.verifyOtp);
router.post('/resend-otp', authValidator.resendOtpValidator, authController.resendOtp);
router.post('/refresh-token', authValidator.refreshTokenValidator, authController.refreshToken);

// Protected routes
router.post('/logout', authMiddleware, authController.logout);

module.exports = router;
