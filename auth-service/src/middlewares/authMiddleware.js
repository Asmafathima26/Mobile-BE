const { verifyAccessToken } = require('../utils/jwt');
const { AUTH_MESSAGES } = require('../constants/messages');
const STATUS_CODES = require('../constants/statusCodes');

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(STATUS_CODES.UNAUTHORIZED).json({
        success: false,
        message: AUTH_MESSAGES.TOKEN_MISSING
      });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyAccessToken(token);

    req.user = {
      id: decoded.userId,
      email: decoded.email,
      roles: decoded.roles
    };

    next();
  } catch (error) {
    return res.status(STATUS_CODES.UNAUTHORIZED).json({
      success: false,
      message: AUTH_MESSAGES.TOKEN_INVALID
    });
  }
};

module.exports = authMiddleware;
