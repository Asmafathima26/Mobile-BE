module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('user_otps', {
      id: { type: Sequelize.UUID, primaryKey: true, defaultValue: Sequelize.UUIDV4 },
      user_id: {
        type: Sequelize.UUID,
        references: { model: 'users', key: 'id' }
      },
      otp: Sequelize.STRING,
      type: Sequelize.ENUM('email_verify', 'password_reset', 'login'),
      expires_at: Sequelize.DATE,
      is_verified: { type: Sequelize.BOOLEAN, defaultValue: false },
      created_at: Sequelize.DATE
    });
  },
  async down(queryInterface) {
    await queryInterface.dropTable('user_otps');
  }
};
