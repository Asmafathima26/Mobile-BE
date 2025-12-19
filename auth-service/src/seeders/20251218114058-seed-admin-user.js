const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

module.exports = {
  async up(queryInterface) {
    const passwordHash = await bcrypt.hash('Admin@123', 12);

    await queryInterface.bulkInsert('users', [
      {
        id: uuidv4(),
        email: 'admin@yourapp.com',
        password_hash: passwordHash,
        email_verified: true,
        is_active: true,
        is_blocked: false,
        created_at: new Date(),
        updated_at: new Date()
      }
    ]);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('users', {
      email: 'admin@yourapp.com'
    });
  }
};
