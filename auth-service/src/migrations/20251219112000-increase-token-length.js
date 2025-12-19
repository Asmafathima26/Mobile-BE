module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.changeColumn('refresh_tokens', 'token', {
            type: Sequelize.STRING(512),
            allowNull: false,
            unique: true
        });
    },
    async down(queryInterface, Sequelize) {
        await queryInterface.changeColumn('refresh_tokens', 'token', {
            type: Sequelize.STRING(255),
            allowNull: false,
            unique: true
        });
    }
};
