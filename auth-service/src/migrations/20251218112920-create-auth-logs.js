module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('auth_logs', {
      id: { type: Sequelize.UUID, primaryKey: true, defaultValue: Sequelize.UUIDV4 },
      user_id: {
        type: Sequelize.UUID,
        allowNull: true,
        references: { model: 'users', key: 'id' }
      },
      action: Sequelize.STRING,
      ip_address: Sequelize.STRING,
      user_agent: Sequelize.TEXT,
      created_at: Sequelize.DATE
    });
  },
  async down(queryInterface) {
    await queryInterface.dropTable('auth_logs');
  }
};
