module.exports = {
  async up(queryInterface) {
    
    const [[adminRole]] = await queryInterface.sequelize.query(
      `SELECT id FROM roles WHERE name = 'ADMIN' LIMIT 1`
    );

    if (!adminRole) {
      throw new Error('ADMIN role not found');
    }

  
    const [[adminUser]] = await queryInterface.sequelize.query(
      `SELECT id FROM users WHERE email = 'admin@yourapp.com' LIMIT 1`
    );

    if (!adminUser) {
      throw new Error('Admin user not found');
    }


    await queryInterface.bulkInsert('user_roles', [
      {
        id: 1,
        user_id: adminUser.id,
        role_id: adminRole.id,
      }
    ]);
  },

  async down(queryInterface) {
    await queryInterface.bulkDelete('user_roles', null, {});
  }
};
