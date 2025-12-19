/**
 * Email Service
 * Handles all email sending functionality using Brevo SMTP
 */

const nodemailer = require('nodemailer');

// Configure SMTP transport
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // Use TLS
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

/**
 * Send email verification OTP
 * @param {string} email - Recipient email
 * @param {string} otp - OTP code
 */
const sendVerificationOTP = async (email, otp) => {
  const mailOptions = {
    from: `"Auth Service" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Email Verification - OTP',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Email Verification</h2>
        <p>Thank you for registering with us!</p>
        <p>Your verification OTP is:</p>
        <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
          ${otp}
        </div>
        <p>This OTP will expire in <strong>10 minutes</strong>.</p>
        <p>If you didn't request this verification, please ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">This is an automated email, please do not reply.</p>
      </div>
    `
  };

  return await transporter.sendMail(mailOptions);
};

/**
 * Send password reset OTP
 * @param {string} email - Recipient email
 * @param {string} otp - OTP code
 */
const sendPasswordResetOTP = async (email, otp) => {
  const mailOptions = {
    from: `"Auth Service" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Password Reset - OTP',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>We received a request to reset your password.</p>
        <p>Your password reset OTP is:</p>
        <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
          ${otp}
        </div>
        <p>This OTP will expire in <strong>10 minutes</strong>.</p>
        <p>If you didn't request a password reset, please ignore this email and your password will remain unchanged.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">This is an automated email, please do not reply.</p>
      </div>
    `
  };

  return await transporter.sendMail(mailOptions);
};

const USER_STATUS = require('../constants/userStatus');

/**
 * Send account status notification
 * @param {string} email - Recipient email
 * @param {string} status - Account status (blocked/activated)
 */
const sendAccountStatusNotification = async (email, status) => {
  const isBlocked = status === USER_STATUS.BLOCKED;

  const mailOptions = {
    from: `"Auth Service" <${process.env.SMTP_USER}>`,
    to: email,
    subject: `Account ${isBlocked ? 'Blocked' : 'Activated'}`,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
        <h2 style="color: ${isBlocked ? '#d9534f' : '#5cb85c'};">Account ${isBlocked ? 'Blocked' : 'Activated'}</h2>
        <p>Your account has been ${isBlocked ? 'blocked' : 'activated'} by an administrator.</p>
        ${isBlocked
        ? '<p>If you believe this is a mistake, please contact our support team.</p>'
        : '<p>You can now log in to your account.</p>'
      }
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">This is an automated email, please do not reply.</p>
      </div>
    `
  };

  return await transporter.sendMail(mailOptions);
};

/**
 * Send password reset confirmation (admin reset)
 * @param {string} email - Recipient email
 * @param {string} tempPassword - Temporary password
 */
const sendAdminPasswordReset = async (email, tempPassword) => {
  const mailOptions = {
    from: `"Auth Service" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Password Reset by Administrator',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset</h2>
        <p>Your password has been reset by an administrator.</p>
        <p>Your temporary password is:</p>
        <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 20px; font-weight: bold; margin: 20px 0;">
          ${tempPassword}
        </div>
        <p><strong>Important:</strong> Please change your password after logging in.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">This is an automated email, please do not reply.</p>
      </div>
    `
  };

  return await transporter.sendMail(mailOptions);
};

module.exports = {
  sendVerificationOTP,
  sendPasswordResetOTP,
  sendAccountStatusNotification,
  sendAdminPasswordReset
};
