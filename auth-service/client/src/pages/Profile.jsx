import React, { useState } from 'react';
import { Card, CardHeader, CardContent } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';
import { cn } from '../utils/cn';
import { Eye, EyeOff, Lock, CheckCircle2, Circle } from 'lucide-react';

const PasswordRequirement = ({ met, text }) => (
    <div className={cn("flex items-center gap-2 text-sm transition-colors duration-200", met ? "text-emerald-500" : "text-slate-400")}>
        {met ? <CheckCircle2 size={16} className="shrink-0" /> : <Circle size={16} className="shrink-0" />}
        <span>{text}</span>
    </div>
);

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
    const [showPasswords, setShowPasswords] = useState({
        old: false,
        new: false,
        confirm: false
    });
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState('');
    const [error, setError] = useState('');

    const togglePassword = (field) => {
        setShowPasswords(prev => ({ ...prev, [field]: !prev[field] }));
    };

    const requirements = [
        { met: passwordData.newPassword.length >= 8, text: 'At least 8 characters' },
        { met: /[A-Z]/.test(passwordData.newPassword), text: 'Uppercase letter (A-Z)' },
        { met: /[a-z]/.test(passwordData.newPassword), text: 'Lowercase letter (a-z)' },
        { met: /[0-9]/.test(passwordData.newPassword), text: 'Number (0-9)' },
        { met: /[!@#$%^&*]/.test(passwordData.newPassword), text: 'Special character (!@#$%^&*)' },
    ];

    const isAllMet = requirements.every(req => req.met);

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
        if (!isAllMet) {
            setError('Please meet all password requirements');
            return;
        }
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
        <div className="max-w-2xl mx-auto space-y-8 pb-12">
            <h1 className="text-2xl font-bold text-slate-900">Profile Settings</h1>

            {success && (
                <div className="p-4 bg-emerald-50 text-emerald-700 rounded-xl text-sm font-semibold border border-emerald-100 animate-in fade-in slide-in-from-top-2 duration-300">
                    {success}
                </div>
            )}
            {error && (
                <div className="p-4 bg-red-50 text-red-700 rounded-xl text-sm font-semibold border border-red-100 animate-in fade-in slide-in-from-top-2 duration-300">
                    {error}
                </div>
            )}

            <Card className="border-none shadow-sm ring-1 ring-slate-200/50">
                <CardHeader className="border-b border-slate-50">
                    <h3 className="font-bold text-slate-800 text-lg">Personal Information</h3>
                </CardHeader>
                <CardContent className="pt-6">
                    <form onSubmit={handleProfileSubmit} className="space-y-6">
                        <div className="grid grid-cols-2 gap-4">
                            <Input
                                label="First Name"
                                value={profileData.firstName}
                                onChange={(e) => setProfileData({ ...profileData, firstName: e.target.value })}
                                required
                                className="rounded-xl"
                            />
                            <Input
                                label="Last Name"
                                value={profileData.lastName}
                                onChange={(e) => setProfileData({ ...profileData, lastName: e.target.value })}
                                required
                                className="rounded-xl"
                            />
                        </div>
                        <Input label="Email Address" value={user.email} disabled className="bg-slate-50 cursor-not-allowed rounded-xl" />
                        <Button
                            type="submit"
                            isLoading={loading}
                            className="bg-indigo-600 hover:bg-indigo-700 rounded-xl shadow-md transition-all font-bold px-8"
                        >
                            Save Changes
                        </Button>
                    </form>
                </CardContent>
            </Card>

            <Card className="border-none shadow-sm ring-1 ring-slate-200/50">
                <CardHeader className="border-b border-slate-50">
                    <h3 className="font-bold text-slate-800 text-lg">Change Password</h3>
                </CardHeader>
                <CardContent className="pt-6">
                    <form onSubmit={handlePasswordSubmit} className="space-y-6">
                        <div className="space-y-4">
                            <div className="relative">
                                <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 mb-2 ml-1">
                                    <Lock size={16} className="text-slate-400" />
                                    Current Password
                                </label>
                                <div className="relative">
                                    <input
                                        type={showPasswords.old ? "text" : "password"}
                                        placeholder="Enter current password"
                                        className="w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3 pr-12 text-base outline-none focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all duration-300"
                                        value={passwordData.oldPassword}
                                        onChange={(e) => setPasswordData({ ...passwordData, oldPassword: e.target.value })}
                                        required
                                    />
                                    <button
                                        type="button"
                                        onClick={() => togglePassword('old')}
                                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                                    >
                                        {showPasswords.old ? <EyeOff size={20} /> : <Eye size={20} />}
                                    </button>
                                </div>
                            </div>

                            <div className="relative">
                                <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 mb-2 ml-1">
                                    <Lock size={16} className="text-slate-400" />
                                    New Password
                                </label>
                                <div className="relative">
                                    <input
                                        type={showPasswords.new ? "text" : "password"}
                                        placeholder="Enter new password"
                                        className={cn(
                                            "w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3 pr-12 text-base outline-none transition-all duration-300",
                                            "focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500",
                                            passwordData.newPassword && (isAllMet ? "border-emerald-500/50" : "border-amber-500/50")
                                        )}
                                        value={passwordData.newPassword}
                                        onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                                        required
                                    />
                                    <button
                                        type="button"
                                        onClick={() => togglePassword('new')}
                                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                                    >
                                        {showPasswords.new ? <EyeOff size={20} /> : <Eye size={20} />}
                                    </button>
                                </div>
                            </div>

                            <div className="bg-slate-50/50 rounded-xl p-4 space-y-2.5 border border-slate-100">
                                {requirements.map((req, i) => (
                                    <PasswordRequirement key={i} met={req.met} text={req.text} />
                                ))}
                            </div>

                            <div className="relative">
                                <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 mb-2 ml-1">
                                    <Lock size={16} className="text-slate-400" />
                                    Confirm New Password
                                </label>
                                <div className="relative">
                                    <input
                                        type={showPasswords.confirm ? "text" : "password"}
                                        placeholder="Confirm your new password"
                                        className={cn(
                                            "w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3 pr-12 text-base outline-none transition-all duration-300",
                                            "focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500",
                                            passwordData.confirmPassword && (passwordData.confirmPassword === passwordData.newPassword ? "border-emerald-500/50" : "border-red-500/50")
                                        )}
                                        value={passwordData.confirmPassword}
                                        onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                                        required
                                    />
                                    <button
                                        type="button"
                                        onClick={() => togglePassword('confirm')}
                                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                                    >
                                        {showPasswords.confirm ? <EyeOff size={20} /> : <Eye size={20} />}
                                    </button>
                                </div>
                            </div>
                        </div>

                        <Button
                            type="submit"
                            isLoading={loading}
                            className={cn(
                                "w-full py-6 text-lg font-bold rounded-xl shadow-lg transition-all duration-300",
                                isAllMet && passwordData.confirmPassword === passwordData.newPassword
                                    ? "bg-indigo-600 hover:bg-indigo-700"
                                    : "bg-slate-300 cursor-not-allowed opacity-70"
                            )}
                            disabled={!isAllMet || passwordData.confirmPassword !== passwordData.newPassword}
                        >
                            Update Password
                        </Button>
                    </form>
                </CardContent>
            </Card>

            <Card className="border-red-100/50 shadow-sm">
                <CardHeader className="bg-red-50/30 border-b border-red-50">
                    <h3 className="font-bold text-red-900">Danger Zone</h3>
                </CardHeader>
                <CardContent className="pt-6">
                    <p className="text-sm text-slate-600 mb-6 font-medium leading-relaxed">
                        Deleting your account will permanently remove all your data from our servers.
                        This action is irreversible and requires confirmation.
                    </p>
                    <Button
                        variant="danger"
                        onClick={handleDeleteAccount}
                        className="bg-red-50 text-red-600 hover:bg-red-600 hover:text-white rounded-xl font-bold px-8 transition-all border-none"
                    >
                        Delete My Account
                    </Button>
                </CardContent>
            </Card>
        </div>
    );
};

export default Profile;
