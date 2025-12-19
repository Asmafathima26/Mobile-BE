const { body } = require('express-validator');
const { OTP_TYPES } = require('../constants/actions');

const registerValidator = [
  body('email')
    .isEmail()
    .withMessage('Valid email required')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),
];

const loginValidator = [
  body('email')
    .isEmail()
    .withMessage('Valid email required')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
];

const forgotPasswordValidator = [
  body('email')
    .isEmail()
    .withMessage('Valid email required')
    .normalizeEmail(),
];

const resetPasswordValidator = [
  body('email')
    .isEmail()
    .withMessage('Valid email required')
    .normalizeEmail(),
  body('otp')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('OTP must be 6 digits'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters'),
];

const verifyOtpValidator = [
  body('email')
    .isEmail()
    .withMessage('Valid email required')
    .normalizeEmail(),
  body('otp')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('OTP must be 6 digits'),
];

const resendOtpValidator = [
  body('email')
    .isEmail()
    .withMessage('Valid email required')
    .normalizeEmail(),
  body('type')
    .optional()
    .isIn([OTP_TYPES.EMAIL_VERIFY, OTP_TYPES.PASSWORD_RESET])
    .withMessage(`Type must be either ${OTP_TYPES.EMAIL_VERIFY} or ${OTP_TYPES.PASSWORD_RESET}`),
];

const refreshTokenValidator = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required'),
];

module.exports = {
  registerValidator,
  loginValidator,
  forgotPasswordValidator,
  resetPasswordValidator,
  verifyOtpValidator,
  resendOtpValidator,
  refreshTokenValidator
};
