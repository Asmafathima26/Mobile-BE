const jwt = require('jsonwebtoken');

const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m'
  });
};

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d'
  });
};

const verifyAccessToken = (token) => {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
};

const verifyRefreshToken = (token) => {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
};

const generateResetToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_RESET_SECRET || process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_RESET_EXPIRES || '10m'
  });
};

const verifyResetToken = (token) => {
  return jwt.verify(token, process.env.JWT_RESET_SECRET || process.env.JWT_ACCESS_SECRET);
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  generateResetToken,
  verifyResetToken
};
