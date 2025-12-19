const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { User, Role, UserRole, AuthLog, UserOtp } = require('../models');
const { AUTH_MESSAGES } = require('../constants/messages');
const { AUTH_ACTIONS, OTP_TYPES } = require('../constants/actions');
const ROLES = require('../constants/role');
const logger = require('../utils/logger');
const { generateOTP, getOTPExpiration } = require('../utils/otpGenerator');
const { sendVerificationOTP } = require('../utils/emailService');

const registerUser = async ({ email, password, ipAddress, userAgent }) => {
  const existing = await User.findOne({ where: { email } });
  if (existing) {
    throw new Error(AUTH_MESSAGES.EMAIL_ALREADY_EXISTS);
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await User.create({
    id: crypto.randomUUID(),
    email,
    password_hash: passwordHash,
    email_verified: false,
    is_active: true,
    is_blocked: false
  });
  // Assign default ROLE USER
  const role = await Role.findOne({ where: { name: ROLES.USER } });
  if (role) {
    await UserRole.create({
      id: crypto.randomUUID(),
      user_id: user.id,
      role_id: role.id
    });
  }
  // Generate OTP 
  const otp = generateOTP();
  await UserOtp.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    otp,
    type: OTP_TYPES.EMAIL_VERIFY,
    expires_at: getOTPExpiration(),
    is_verified: false
  });

  // verification email
  try {
    await sendVerificationOTP(email, otp);
  } catch (emailError) {
    logger.error('Email send error (Registration):', emailError);
    // Don't fail registration if email fails, user can resend OTP
  }

  // Log registration action
  await AuthLog.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    action: AUTH_ACTIONS.REGISTER,
    ip_address: ipAddress,
    user_agent: userAgent,
    created_at: new Date(),
    updated_at: new Date()
  });

  return user;
};

const loginUser = async ({ email, password, ipAddress, userAgent }) => {
  const { RefreshToken } = require('../models');
  const { generateAccessToken, generateRefreshToken } = require('../utils/jwt');

  // 1️⃣ Find user with password hash for verification
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

  if (user.is_blocked) {
    await AuthLog.create({
      id: crypto.randomUUID(),
      user_id: user.id,
      action: AUTH_ACTIONS.LOGIN_BLOCKED,
      ip_address: ipAddress,
      user_agent: userAgent,
      created_at: new Date(),
      updated_at: new Date()
    });
    throw new Error(AUTH_MESSAGES.ACCOUNT_BLOCKED);
  }

  if (!user.is_active) {
    throw new Error(AUTH_MESSAGES.ACCOUNT_INACTIVE);
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);
  if (!isPasswordValid) {
    await AuthLog.create({
      id: crypto.randomUUID(),
      user_id: user.id,
      action: AUTH_ACTIONS.LOGIN_FAILED,
      ip_address: ipAddress,
      user_agent: userAgent,
      created_at: new Date(),
      updated_at: new Date()
    });
    throw new Error(AUTH_MESSAGES.INVALID_CREDENTIALS);
  }

  const roles = user.Roles ? user.Roles.map(r => r.name) : [];

  const payload = {
    userId: user.id,
    email: user.email,
    roles
  };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  await RefreshToken.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    token: refreshToken,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    is_revoked: false
  });

  await user.update({ last_login_at: new Date() });

  await AuthLog.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    action: AUTH_ACTIONS.LOGIN_SUCCESS,
    ip_address: ipAddress,
    user_agent: userAgent,
    created_at: new Date(),
    updated_at: new Date()
  });

  return {
    user: {
      id: user.id,
      email: user.email,
      roles,
      email_verified: user.email_verified
    },
    accessToken,
    refreshToken
  };
};

const logoutUser = async ({ userId, refreshToken }) => {
  const { RefreshToken } = require('../models');
  const token = await RefreshToken.findOne({
    where: { token: refreshToken, user_id: userId, is_revoked: false }
  });

  if (token) {
    await token.update({ is_revoked: true });
  }

  return true;
};

const refreshAccessToken = async ({ refreshToken }) => {
  const { RefreshToken } = require('../models');
  const { verifyRefreshToken, generateAccessToken } = require('../utils/jwt');

  let decoded;
  try {
    decoded = verifyRefreshToken(refreshToken);
  } catch (error) {
    throw new Error(AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
  }

  const tokenRecord = await RefreshToken.findOne({
    where: { token: refreshToken, is_revoked: false }
  });

  if (!tokenRecord) {
    throw new Error(AUTH_MESSAGES.TOKEN_REVOKED);
  }

  if (new Date() > new Date(tokenRecord.expires_at)) {
    throw new Error(AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
  }

  const payload = {
    userId: decoded.userId,
    email: decoded.email,
    roles: decoded.roles
  };

  const accessToken = generateAccessToken(payload);

  return { accessToken };
};

const forgotPassword = async ({ email, ipAddress, userAgent }) => {
  const { sendPasswordResetOTP } = require('../utils/emailService');

  const user = await User.findOne({ where: { email } });

  // Don't reveal if user exists or not for security
  if (!user) {
    return { sent: true };
  }

  const otp = generateOTP();

  await UserOtp.update(
    { is_verified: true },
    { where: { user_id: user.id, type: OTP_TYPES.PASSWORD_RESET, is_verified: false } }
  );
  await UserOtp.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    otp,
    type: OTP_TYPES.PASSWORD_RESET,
    expires_at: getOTPExpiration(),
    is_verified: false
  });

  try {
    await sendPasswordResetOTP(email, otp);
  } catch (emailError) {
    logger.error('Email send error (Forgot Password):', emailError);
    throw new Error(AUTH_MESSAGES.EMAIL_ALREADY_EXISTS); // Reuse for email send failure
  }

  // 6️⃣ Log action
  await AuthLog.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    action: AUTH_ACTIONS.FORGOT_PASSWORD,
    ip_address: ipAddress,
    user_agent: userAgent,
    created_at: new Date(),
    updated_at: new Date()
  });

  return { sent: true };
};

const resetPassword = async ({ email, otp, newPassword, ipAddress, userAgent }) => {
  // 1️⃣ Find user
  const user = await User.findOne({ where: { email } });
  if (!user) {
    throw new Error(AUTH_MESSAGES.INVALID_OTP);
  }

  // 2️⃣ Find and validate OTP
  const otpRecord = await UserOtp.findOne({
    where: {
      user_id: user.id,
      otp,
      type: OTP_TYPES.PASSWORD_RESET,
      is_verified: false
    },
    order: [['created_at', 'DESC']]
  });

  if (!otpRecord) {
    throw new Error(AUTH_MESSAGES.INVALID_OTP);
  }

  // 3️⃣ Check if OTP is expired
  if (new Date() > new Date(otpRecord.expires_at)) {
    throw new Error(AUTH_MESSAGES.OTP_EXPIRED);
  }

  // 4️⃣ Hash new password
  const passwordHash = await bcrypt.hash(newPassword, 12);

  // 5️⃣ Update password
  await user.update({ password_hash: passwordHash });

  // 6️⃣ Mark OTP as verified
  await otpRecord.update({ is_verified: true });

  // 7️⃣ Revoke all refresh tokens for this user
  const { RefreshToken } = require('../models');
  await RefreshToken.update(
    { is_revoked: true },
    { where: { user_id: user.id, is_revoked: false } }
  );

  // 8️⃣ Log action
  await AuthLog.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    action: AUTH_ACTIONS.PASSWORD_RESET,
    ip_address: ipAddress,
    user_agent: userAgent,
    created_at: new Date(),
    updated_at: new Date()
  });

  return true;
};

const verifyOtp = async ({ email, otp, ipAddress, userAgent }) => {
  // 1️⃣ Find user
  const user = await User.findOne({ where: { email } });
  if (!user) {
    throw new Error(AUTH_MESSAGES.INVALID_OTP);
  }

  // 2️⃣ Find and validate OTP
  const otpRecord = await UserOtp.findOne({
    where: {
      user_id: user.id,
      otp,
      type: OTP_TYPES.EMAIL_VERIFY,
      is_verified: false
    },
    order: [['created_at', 'DESC']]
  });

  if (!otpRecord) {
    throw new Error(AUTH_MESSAGES.INVALID_OTP);
  }

  // 3️⃣ Check if OTP is expired
  if (new Date() > new Date(otpRecord.expires_at)) {
    throw new Error(AUTH_MESSAGES.OTP_EXPIRED);
  }

  // 4️⃣ Mark email as verified
  await user.update({ email_verified: true });

  // 5️⃣ Mark OTP as verified
  await otpRecord.update({ is_verified: true });

  // 6️⃣ Log action
  await AuthLog.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    action: AUTH_ACTIONS.EMAIL_VERIFIED,
    ip_address: ipAddress,
    user_agent: userAgent,
    created_at: new Date(),
    updated_at: new Date()
  });

  return true;
};

const resendOtp = async ({ email, type = OTP_TYPES.EMAIL_VERIFY }) => {
  const { sendPasswordResetOTP } = require('../utils/emailService');

  // 1️⃣ Find user
  const user = await User.findOne({ where: { email } });
  if (!user) {
    // Don't reveal if user exists
    return { sent: true };
  }

  // 2️⃣ Generate new OTP
  const otp = generateOTP();

  // 3️⃣ Invalidate previous OTPs of same type
  await UserOtp.update(
    { is_verified: true },
    { where: { user_id: user.id, type, is_verified: false } }
  );

  // 4️⃣ Save new OTP
  await UserOtp.create({
    id: crypto.randomUUID(),
    user_id: user.id,
    otp,
    type,
    expires_at: getOTPExpiration(),
    is_verified: false
  });

  // 5️⃣ Send email based on type
  try {
    if (type === OTP_TYPES.EMAIL_VERIFY) {
      await sendVerificationOTP(email, otp);
    } else if (type === OTP_TYPES.PASSWORD_RESET) {
      await sendPasswordResetOTP(email, otp);
    }
  } catch (emailError) {
    logger.error('Email send error (Resend OTP):', emailError);
    throw new Error('Failed to send OTP email');
  }

  return { sent: true };
};

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  forgotPassword,
  resetPassword,
  verifyOtp,
  resendOtp
};
