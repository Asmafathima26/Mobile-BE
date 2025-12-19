const crypto = require('crypto');

module.exports = {
  async up(queryInterface) {
    await queryInterface.bulkInsert('roles', [
      {
        id: crypto.randomUUID(),
        name: 'USER',
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        id: crypto.randomUUID(),
        name: 'ADMIN',
        created_at: new Date(),
        updated_at: new Date()
      }
    ]);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('roles', null, {});
  }
};
