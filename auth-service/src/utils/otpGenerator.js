/**
 * OTP Generator Utility
 * Generates and validates OTP codes
 */

const crypto = require('crypto');

/**
 * Generate a 6-digit OTP
 * @returns {string} 6-digit OTP
 */
const generateOTP = () => {
    return crypto.randomInt(100000, 999999).toString();
};

/**
 * Calculate OTP expiration time
 * @param {number} minutes - Expiration time in minutes (default: 10)
 * @returns {Date} Expiration timestamp
 */
const getOTPExpiration = (minutes = 10) => {
    return new Date(Date.now() + minutes * 60 * 1000);
};

/**
 * Validate OTP format
 * @param {string} otp - OTP to validate
 * @returns {boolean} True if valid format
 */
const isValidOTPFormat = (otp) => {
    return /^\d{6}$/.test(otp);
};

module.exports = {
    generateOTP,
    getOTPExpiration,
    isValidOTPFormat
};
