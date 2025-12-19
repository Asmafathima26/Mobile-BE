module.exports = (sequelize, DataTypes) => {
  return sequelize.define('UserRole', {}, {
    tableName: 'user_roles',
    timestamps: false
  });
};
