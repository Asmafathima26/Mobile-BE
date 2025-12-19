module.exports = (sequelize, DataTypes) => {
  const Role = sequelize.define('Role', {
    id: {
  type: DataTypes.UUID,
  primaryKey: true,
  defaultValue: DataTypes.UUIDV4
},
 name: DataTypes.STRING
  }, {
    tableName: 'roles',
    timestamps: false
  });

  Role.associate = models => {
    Role.belongsToMany(models.User, { through: models.UserRole, foreignKey: 'role_id' });
  };

  return Role;
};
