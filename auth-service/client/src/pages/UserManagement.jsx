import React, { useState, useEffect } from 'react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import api from '../api/axios';
import { UserX, UserCheck, KeyRound } from 'lucide-react';
import { cn } from '../utils/cn';

const UserManagement = () => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchUsers = async () => {
        try {
            const response = await api.get('/admin/users');
            setUsers(response.data.data.users);
        } catch (error) {
            console.error('Failed to fetch users');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchUsers();
    }, []);

    const handleToggleStatus = async (userId, isBlocked) => {
        try {
            await api.patch(`/admin/users/${userId}/status`, {
                status: isBlocked ? 'active' : 'blocked'
            });
            fetchUsers();
        } catch (error) {
            alert('Failed to update status');
        }
    };

    const handleResetPassword = async (userId) => {
        if (!confirm('Are you sure you want to reset this user\'s password?')) return;
        try {
            await api.post(`/admin/users/${userId}/reset-password`);
            alert('Password reset successfully.');
        } catch (error) {
            alert('Failed to reset password');
        }
    };

    if (loading) return <div className="p-8 text-center text-slate-500">Loading user list...</div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold text-slate-900">User Management</h1>
            </div>

            <Card className="overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50 border-b border-slate-200">
                                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase">User</th>
                                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase">Email</th>
                                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase">Status</th>
                                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {users.map((user) => (
                                <tr key={user.id} className="hover:bg-slate-50 transition-colors">
                                    <td className="px-6 py-4">
                                        <div className="flex items-center gap-3">
                                            <div className="h-9 w-9 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-700 font-bold uppercase text-xs">
                                                {user.first_name?.[0]}{user.last_name?.[0]}
                                            </div>
                                            <span className="font-medium text-slate-900">{user.first_name} {user.last_name}</span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 text-slate-600 font-normal">{user.email}</td>
                                    <td className="px-6 py-4">
                                        <span className={cn(
                                            "px-2 py-1 text-xs font-bold rounded-full",
                                            user.is_blocked ? "bg-red-100 text-red-700" : "bg-green-100 text-green-700"
                                        )}>
                                            {user.is_blocked ? 'Blocked' : 'Active'}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                        <div className="flex justify-end gap-2">
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() => handleResetPassword(user.id)}
                                                title="Reset Password"
                                            >
                                                <KeyRound className="h-4 w-4" />
                                            </Button>
                                            <Button
                                                variant={user.is_blocked ? "outline" : "danger"}
                                                size="sm"
                                                onClick={() => handleToggleStatus(user.id, user.is_blocked)}
                                            >
                                                {user.is_blocked ? <UserCheck className="h-4 w-4" /> : <UserX className="h-4 w-4" />}
                                            </Button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};

export default UserManagement;
