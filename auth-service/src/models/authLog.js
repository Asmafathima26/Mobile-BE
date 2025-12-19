module.exports = (sequelize, DataTypes) => {
  const AuthLog = sequelize.define('AuthLog', {
    id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
    user_id: DataTypes.UUID,
    action: DataTypes.STRING,
    ip_address: DataTypes.STRING,
    user_agent: DataTypes.TEXT
  }, {
    tableName: 'auth_logs',
    underscored: true,
    timestamps: true,
    updatedAt: false
  });

  AuthLog.associate = models => {
    AuthLog.belongsTo(models.User, { foreignKey: 'user_id' });
  };

  return AuthLog;
};
