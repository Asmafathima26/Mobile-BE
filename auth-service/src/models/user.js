module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
    email: DataTypes.STRING,
    first_name: DataTypes.STRING,
    last_name: DataTypes.STRING,
    password_hash: DataTypes.STRING,
    email_verified: DataTypes.BOOLEAN,
    is_active: DataTypes.BOOLEAN,
    is_blocked: DataTypes.BOOLEAN,
    last_login_at: DataTypes.DATE
  }, {
    tableName: 'users',
    underscored: true,
    defaultScope: {
      attributes: { exclude: ['password_hash'] }
    },
    scopes: {
      withPassword: { attributes: {} }
    }
  });

  User.associate = models => {
    User.belongsToMany(models.Role, { through: models.UserRole, foreignKey: 'user_id', onDelete: 'CASCADE' });
    User.hasMany(models.RefreshToken, { foreignKey: 'user_id', onDelete: 'CASCADE' });
    User.hasMany(models.UserOtp, { foreignKey: 'user_id', onDelete: 'CASCADE' });
    User.hasMany(models.AuthLog, { foreignKey: 'user_id', onDelete: 'CASCADE' });
  };

  return User;
};
