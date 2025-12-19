

const AUTH_MESSAGES = {
    // Registration
    REGISTER_SUCCESS: 'User registered successfully. Please verify your email.',
    EMAIL_ALREADY_EXISTS: 'Email already registered',

    // Login
    LOGIN_SUCCESS: 'Login successful',
    INVALID_CREDENTIALS: 'Invalid email or password',
    ACCOUNT_BLOCKED: 'Your account has been blocked. Please contact support.',
    ACCOUNT_INACTIVE: 'Your account is inactive. Please contact support.',
    EMAIL_NOT_VERIFIED: 'Please verify your email before logging in',

    // Logout
    LOGOUT_SUCCESS: 'Logged out successfully',

    // Token
    TOKEN_REFRESHED: 'Access token refreshed successfully',
    INVALID_REFRESH_TOKEN: 'Invalid or expired refresh token',
    TOKEN_REVOKED: 'Refresh token has been revoked',
    TOKEN_MISSING: 'Authorization token missing',
    TOKEN_INVALID: 'Invalid or expired token',

    // OTP
    OTP_SENT: 'OTP has been sent to your email',
    OTP_VERIFIED: 'Email verified successfully',
    OTP_INVALID: 'Invalid OTP',
    OTP_EXPIRED: 'OTP has expired. Please request a new one.',
    OTP_RESENT: 'OTP has been resent to your email',

    // Password Reset
    RESET_OTP_SENT: 'Password reset OTP has been sent to your email',
    PASSWORD_RESET_SUCCESS: 'Password reset successfully. Please login with your new password.',

    // General
    OPERATION_SUCCESS: 'Operation completed successfully',
    VALIDATION_ERROR: 'Validation error'
};

const ADMIN_MESSAGES = {
    // Admin Login
    ADMIN_LOGIN_SUCCESS: 'Admin login successful',
    ADMIN_ACCESS_DENIED: 'Admin access required',

    // User Management
    USER_FETCHED: 'User details fetched successfully',
    USERS_FETCHED: 'Users list fetched successfully',
    USER_STATUS_UPDATED: 'User status updated successfully',
    USER_NOT_FOUND: 'User not found',

    // Password Reset
    USER_PASSWORD_RESET: 'User password has been reset successfully',

    // Auth Logs
    AUTH_LOGS_FETCHED: 'Authentication logs fetched successfully',

    // Dashboard
    STATS_FETCHED: 'Dashboard statistics fetched successfully'
};

const ERROR_MESSAGES = {
    // Server Errors
    INTERNAL_ERROR: 'Internal server error. Please try again later.',
    DATABASE_ERROR: 'Database operation failed',

    // Email Service
    EMAIL_SEND_FAILED: 'Failed to send email. Please try again later.',

    // Validation
    REQUIRED_FIELDS_MISSING: 'Required fields are missing',
    INVALID_EMAIL_FORMAT: 'Invalid email format',
    INVALID_PASSWORD_LENGTH: 'Password must be at least 8 characters',
    INVALID_OTP_FORMAT: 'OTP must be 6 digits',

    // Authorization
    UNAUTHORIZED_ACCESS: 'Unauthorized access',
    INSUFFICIENT_PERMISSIONS: 'Insufficient permissions to perform this action'
};

module.exports = {
    AUTH_MESSAGES,
    ADMIN_MESSAGES,
    ERROR_MESSAGES
};
