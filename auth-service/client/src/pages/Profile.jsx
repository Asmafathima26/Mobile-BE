import React, { useState } from 'react';
import { Card, CardHeader, CardContent } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';

const Profile = () => {
    const { user, setUser } = useAuth();
    const [profileData, setProfileData] = useState({
        firstName: user.first_name || '',
        lastName: user.last_name || '',
    });
    const [passwordData, setPasswordData] = useState({
        oldPassword: '',
        newPassword: '',
        confirmPassword: '',
    });
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState('');
    const [error, setError] = useState('');

    const handleProfileSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess('');
        try {
            const response = await api.put('/auth/profile', profileData);
            setUser(response.data.data);
            setSuccess('Profile updated successfully');
        } catch (err) {
            setError('Failed to update profile');
        } finally {
            setLoading(false);
        }
    };

    const handlePasswordSubmit = async (e) => {
        e.preventDefault();
        if (passwordData.newPassword !== passwordData.confirmPassword) {
            setError('New passwords do not match');
            return;
        }
        setLoading(true);
        setError('');
        setSuccess('');
        try {
            await api.put('/auth/update-password', {
                oldPassword: passwordData.oldPassword,
                newPassword: passwordData.newPassword,
            });
            setSuccess('Password changed successfully');
            setPasswordData({ oldPassword: '', newPassword: '', confirmPassword: '' });
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to change password');
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteAccount = async () => {
        if (!confirm('CRITICAL: Are you sure you want to delete your account? This action cannot be undone.')) return;
        try {
            await api.delete('/auth/delete-account');
            localStorage.clear();
            window.location.href = '/login';
        } catch (err) {
            alert('Failed to delete account');
        }
    };

    return (
        <div className="max-w-2xl mx-auto space-y-8">
            <h1 className="text-2xl font-bold text-slate-900 text">Profile Settings</h1>

            {success && <div className="p-4 bg-green-50 text-green-700 rounded-lg text-sm font-medium">{success}</div>}
            {error && <div className="p-4 bg-red-50 text-red-700 rounded-lg text-sm font-medium">{error}</div>}

            <Card>
                <CardHeader>
                    <h3 className="font-semibold text-slate-900">Personal Information</h3>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleProfileSubmit} className="space-y-4 text">
                        <div className="grid grid-cols-2 gap-4">
                            <Input
                                label="First Name"
                                value={profileData.firstName}
                                onChange={(e) => setProfileData({ ...profileData, firstName: e.target.value })}
                                required
                            />
                            <Input
                                label="Last Name"
                                value={profileData.lastName}
                                onChange={(e) => setProfileData({ ...profileData, lastName: e.target.value })}
                                required
                            />
                        </div>
                        <Input label="Email Address" value={user.email} disabled className="bg-slate-50 cursor-not-allowed" />
                        <Button type="submit" isLoading={loading}>Save Changes</Button>
                    </form>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <h3 className="font-semibold text-slate-900 text">Change Password</h3>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handlePasswordSubmit} className="space-y-4">
                        <Input
                            label="Current Password"
                            type="password"
                            value={passwordData.oldPassword}
                            onChange={(e) => setPasswordData({ ...passwordData, oldPassword: e.target.value })}
                            required
                        />
                        <Input
                            label="New Password"
                            type="password"
                            value={passwordData.newPassword}
                            onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                            required
                        />
                        <Input
                            label="Confirm New Password"
                            type="password"
                            value={passwordData.confirmPassword}
                            onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                            required
                        />
                        <Button type="submit" isLoading={loading}>Update Password</Button>
                    </form>
                </CardContent>
            </Card>

            <Card className="border-red-100">
                <CardHeader className="bg-red-50/50">
                    <h3 className="font-semibold text-red-900">Danger Zone</h3>
                </CardHeader>
                <CardContent className="pt-6">
                    <p className="text-sm text-slate-600 mb-4">
                        Deleting your account will permanently remove all your data from our servers.
                    </p>
                    <Button variant="danger" onClick={handleDeleteAccount}>Delete My Account</Button>
                </CardContent>
            </Card>
        </div>
    );
};

export default Profile;
