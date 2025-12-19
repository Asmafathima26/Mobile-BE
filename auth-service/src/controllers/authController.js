const { validationResult } = require('express-validator');
const authService = require('../services/authService');
const logger = require('../utils/logger');
const STATUS_CODES = require('../constants/statusCodes');
const { AUTH_MESSAGES, ERROR_MESSAGES } = require('../constants/messages');

// Helper function to extract IP and user agent
const getRequestMetadata = (req) => ({
  ipAddress: req.ip || req.connection.remoteAddress,
  userAgent: req.get('user-agent') || 'Unknown'
});

const register = async (req, res) => {
  try {
    // 1️⃣ Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
        success: false,
        message: ERROR_MESSAGES.VALIDATION_ERROR,
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Get IP and user agent from request
    const { ipAddress, userAgent } = getRequestMetadata(req);

    // 2️⃣ Call service
    const user = await authService.registerUser({
      email,
      password,
      ipAddress,
      userAgent
    });

    res.status(STATUS_CODES.CREATED).json({
      success: true,
      message: AUTH_MESSAGES.REGISTER_SUCCESS,
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (error) {
    logger.error('Register error:', error);

    // Check for duplicate email error
    if (error.message === AUTH_MESSAGES.EMAIL_ALREADY_EXISTS) {
      return res.status(STATUS_CODES.CONFLICT).json({
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

const login = async (req, res) => {
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

    const result = await authService.loginUser({
      email,
      password,
      ipAddress,
      userAgent
    });

    res.status(STATUS_CODES.OK).json({
      success: true,
      message: AUTH_MESSAGES.LOGIN_SUCCESS,
      data: result
    });
  } catch (error) {
    logger.error('Login error:', error);

    if ([
      AUTH_MESSAGES.INVALID_CREDENTIALS,
      AUTH_MESSAGES.ACCOUNT_BLOCKED,
      AUTH_MESSAGES.ACCOUNT_INACTIVE
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

const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const userId = req.user.id;

    await authService.logoutUser({ userId, refreshToken });

    res.status(STATUS_CODES.OK).json({
      success: true,
      message: AUTH_MESSAGES.LOGOUT_SUCCESS
    });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: ERROR_MESSAGES.INTERNAL_ERROR
    });
  }
};

const refreshToken = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
        success: false,
        message: ERROR_MESSAGES.VALIDATION_ERROR,
        errors: errors.array()
      });
    }

    const { refreshToken } = req.body;

    const result = await authService.refreshAccessToken({ refreshToken });

    res.status(STATUS_CODES.OK).json({
      success: true,
      message: AUTH_MESSAGES.TOKEN_REFRESHED,
      data: result
    });
  } catch (error) {
    logger.error('Refresh token error:', error);

    if ([
      AUTH_MESSAGES.INVALID_REFRESH_TOKEN,
      AUTH_MESSAGES.TOKEN_REVOKED
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

const forgotPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
        success: false,
        message: ERROR_MESSAGES.VALIDATION_ERROR,
        errors: errors.array()
      });
    }

    const { email } = req.body;
    const { ipAddress, userAgent } = getRequestMetadata(req);

    await authService.forgotPassword({ email, ipAddress, userAgent });

    res.status(STATUS_CODES.OK).json({
      success: true,
      message: AUTH_MESSAGES.RESET_OTP_SENT
    });
  } catch (error) {
    logger.error('Forgot password error:', error);
    res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: ERROR_MESSAGES.INTERNAL_ERROR
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
        success: false,
        message: ERROR_MESSAGES.VALIDATION_ERROR,
        errors: errors.array()
      });
    }

    const { email, otp, newPassword } = req.body;
    const { ipAddress, userAgent } = getRequestMetadata(req);

    await authService.resetPassword({
      email,
      otp,
      newPassword,
      ipAddress,
      userAgent
    });

    res.status(STATUS_CODES.OK).json({
      success: true,
      message: AUTH_MESSAGES.PASSWORD_RESET_SUCCESS
    });
  } catch (error) {
    logger.error('Reset password error:', error);

    if ([
      AUTH_MESSAGES.INVALID_OTP,
      AUTH_MESSAGES.OTP_EXPIRED
    ].includes(error.message)) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
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

const verifyOtp = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
        success: false,
        message: ERROR_MESSAGES.VALIDATION_ERROR,
        errors: errors.array()
      });
    }

    const { email, otp } = req.body;
    const { ipAddress, userAgent } = getRequestMetadata(req);

    await authService.verifyOtp({ email, otp, ipAddress, userAgent });

    res.status(STATUS_CODES.OK).json({
      success: true,
      message: AUTH_MESSAGES.OTP_VERIFIED
    });
  } catch (error) {
    logger.error('Verify OTP error:', error);

    if ([
      AUTH_MESSAGES.INVALID_OTP,
      AUTH_MESSAGES.OTP_EXPIRED
    ].includes(error.message)) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
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

const resendOtp = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({
        success: false,
        message: ERROR_MESSAGES.VALIDATION_ERROR,
        errors: errors.array()
      });
    }

    const { email, type } = req.body;

    await authService.resendOtp({ email, type });

    res.status(STATUS_CODES.OK).json({
      success: true,
      message: AUTH_MESSAGES.OTP_RESENT
    });
  } catch (error) {
    logger.error('Resend OTP error:', error);
    res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: ERROR_MESSAGES.INTERNAL_ERROR
    });
  }
};

module.exports = {
  register,
  login,
  logout,
  refreshToken,
  forgotPassword,
  resetPassword,
  verifyOtp,
  resendOtp
};
