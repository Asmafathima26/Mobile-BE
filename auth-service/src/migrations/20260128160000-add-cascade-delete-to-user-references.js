'use strict';

module.exports = {
    async up(queryInterface, Sequelize) {
        const tables = [
            { name: 'auth_logs', foreignKey: 'user_id' },
            { name: 'refresh_tokens', foreignKey: 'user_id' },
            { name: 'user_otps', foreignKey: 'user_id' },
            { name: 'user_roles', foreignKey: 'user_id' }
        ];

        for (const table of tables) {
            try {
                // 1. Get current constraints
                const constraints = await queryInterface.getForeignKeyReferencesForTable(table.name);
                const userConstraint = constraints.find(c => c.columnName === table.foreignKey && c.referencedTableName === 'users');

                if (userConstraint) {
                    // 2. Remove existing constraint
                    await queryInterface.removeConstraint(table.name, userConstraint.constraintName);
                }

                // 3. Add new constraint with CASCADE
                await queryInterface.addConstraint(table.name, {
                    fields: [table.foreignKey],
                    type: 'foreign key',
                    name: `${table.name}_${table.foreignKey}_fkey_cascade`, // Explicit name to avoid conflicts
                    references: {
                        table: 'users',
                        field: 'id'
                    },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE'
                });
            } catch (error) {
                console.error(`Error updating constraints for ${table.name}:`, error.message);
                // Continue with other tables if one fails
            }
        }
    },

    async down(queryInterface, Sequelize) {
        const tables = [
            { name: 'auth_logs', foreignKey: 'user_id' },
            { name: 'refresh_tokens', foreignKey: 'user_id' },
            { name: 'user_otps', foreignKey: 'user_id' },
            { name: 'user_roles', foreignKey: 'user_id' }
        ];

        for (const table of tables) {
            try {
                await queryInterface.removeConstraint(table.name, `${table.name}_${table.foreignKey}_fkey_cascade`);

                // Re-add without CASCADE (reverting to default)
                await queryInterface.addConstraint(table.name, {
                    fields: [table.foreignKey],
                    type: 'foreign key',
                    references: {
                        table: 'users',
                        field: 'id'
                    }
                });
            } catch (error) {
                console.error(`Error reverting constraints for ${table.name}:`, error.message);
            }
        }
    }
};
