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
  body('firstName')
    .trim()
    .notEmpty()
    .withMessage('First name is required'),
  body('lastName')
    .trim()
    .notEmpty()
    .withMessage('Last name is required'),
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
  body('token')
    .notEmpty()
    .withMessage('Token is required'),
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

const updateProfileValidator = [
  body('firstName')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('First name cannot be empty'),
  body('lastName')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Last name cannot be empty'),
];

const updatePasswordValidator = [
  body('oldPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters')
    .custom((value, { req }) => {
      if (value === req.body.oldPassword) {
        throw new Error('New password must be different from current password');
      }
      return true;
    }),
];

module.exports = {
  registerValidator,
  loginValidator,
  forgotPasswordValidator,
  resetPasswordValidator,
  verifyOtpValidator,
  resendOtpValidator,
  refreshTokenValidator,
  updateProfileValidator,
  updatePasswordValidator
};
