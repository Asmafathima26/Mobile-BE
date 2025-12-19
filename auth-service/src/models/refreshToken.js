module.exports = (sequelize, DataTypes) => {
  const RefreshToken = sequelize.define('RefreshToken', {
    id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
    user_id: DataTypes.UUID,
    token: { type: DataTypes.STRING(512), allowNull: false, unique: true },
    expires_at: DataTypes.DATE,
    is_revoked: { type: DataTypes.BOOLEAN, defaultValue: false }
  }, {
    tableName: 'refresh_tokens',
    underscored: true,
    timestamps: true,
    updatedAt: false
  });

  RefreshToken.associate = models => {
    RefreshToken.belongsTo(models.User, { foreignKey: 'user_id' });
  };

  return RefreshToken;
};
