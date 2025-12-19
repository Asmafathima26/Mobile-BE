module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('user_roles', {
      id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
      user_id: {
        type: Sequelize.UUID,
        references: { model: 'users', key: 'id' }
      },
 role_id: {
  type: Sequelize.UUID,
  allowNull: false,
  references: {
    model: 'roles',
    key: 'id'
  },
  onDelete: 'CASCADE'
}

    });
  },
  async down(queryInterface) {
    await queryInterface.dropTable('user_roles');
  }
};
