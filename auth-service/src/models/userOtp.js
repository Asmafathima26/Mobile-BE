module.exports = (sequelize, DataTypes) => {
  const UserOtp = sequelize.define('UserOtp', {
    id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
    user_id: DataTypes.UUID,
    otp: DataTypes.STRING,
    type: DataTypes.ENUM('email_verify', 'password_reset', 'login'),
    expires_at: DataTypes.DATE,
    is_verified: { type: DataTypes.BOOLEAN, defaultValue: false }
  }, {
    tableName: 'user_otps',
    underscored: true,
    timestamps: true,
    updatedAt: false
  });

  UserOtp.associate = models => {
    UserOtp.belongsTo(models.User, { foreignKey: 'user_id' });
  };

  return UserOtp;
};
