module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('refresh_tokens', {
      id: { type: Sequelize.UUID, primaryKey: true, defaultValue: Sequelize.UUIDV4 },
      user_id: {
        type: Sequelize.UUID,
        references: { model: 'users', key: 'id' }
      },
      token: {
        type: Sequelize.STRING(255),
        allowNull: false,
        unique: true
      }
      ,
      expires_at: Sequelize.DATE,
      is_revoked: { type: Sequelize.BOOLEAN, defaultValue: false },
      created_at: Sequelize.DATE
    });
  },
  async down(queryInterface) {
    await queryInterface.dropTable('refresh_tokens');
  }
};
