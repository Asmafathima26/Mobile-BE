import React, { useState } from 'react';
import { useNavigate, useSearchParams, Navigate } from 'react-router-dom';
import AuthLayout from '../layouts/AuthLayout';
import { Card, CardContent } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Eye, EyeOff, Lock, CheckCircle2, Circle } from 'lucide-react';
import api from '../api/axios';
import { cn } from '../utils/cn';

const PasswordRequirement = ({ met, text }) => (
    <div className={cn("flex items-center gap-2 text-sm transition-colors duration-200", met ? "text-emerald-500" : "text-slate-400")}>
        {met ? <CheckCircle2 size={16} className="shrink-0" /> : <Circle size={16} className="shrink-0" />}
        <span>{text}</span>
    </div>
);

const ResetPassword = () => {
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const requirements = [
        { met: newPassword.length >= 8, text: 'At least 8 characters' },
        { met: /[A-Z]/.test(newPassword), text: 'Uppercase letter (A-Z)' },
        { met: /[a-z]/.test(newPassword), text: 'Lowercase letter (a-z)' },
        { met: /[0-9]/.test(newPassword), text: 'Number (0-9)' },
        { met: /[!@#$%^&*]/.test(newPassword), text: 'Special character (!@#$%^&*)' },
    ];

    const isAllMet = requirements.every(req => req.met);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!isAllMet) {
            setError('Please meet all password requirements');
            return;
        }
        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        setLoading(true);
        setError('');
        try {
            await api.post('/auth/reset-password', { token, newPassword });
            navigate('/login', { state: { message: 'Password reset successfully. Please login.' } });
        } catch (err) {
            setError(err.response?.data?.message || 'Invalid token or expired');
        } finally {
            setLoading(false);
        }
    };

    if (!token) {
        return <Navigate to="/login" />;
    }

    return (
        <AuthLayout
            title="Set new password"
            subtitle="Enter a strong new password to reset your account"
        >
            <Card className="border-none shadow-xl ring-1 ring-slate-200/50">
                <CardContent className="pt-8 px-6 pb-8">
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-4">
                            <div className="relative">
                                <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 mb-2 ml-1">
                                    <Lock size={16} className="text-slate-400" />
                                    New Password
                                </label>
                                <div className="relative group">
                                    <input
                                        type={showPassword ? "text" : "password"}
                                        placeholder="Enter new password"
                                        className={cn(
                                            "w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3.5 pr-12 text-base outline-none transition-all duration-300",
                                            "focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500",
                                            newPassword && (isAllMet ? "border-emerald-500/50" : "border-amber-500/50")
                                        )}
                                        value={newPassword}
                                        onChange={(e) => setNewPassword(e.target.value)}
                                        required
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowPassword(!showPassword)}
                                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors p-1"
                                    >
                                        {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
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
                                    Confirm Password
                                </label>
                                <div className="relative group">
                                    <input
                                        type={showConfirmPassword ? "text" : "password"}
                                        placeholder="Confirm your password"
                                        className={cn(
                                            "w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3.5 pr-12 text-base outline-none transition-all duration-300",
                                            "focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500",
                                            confirmPassword && (confirmPassword === newPassword ? "border-emerald-500/50" : "border-red-500/50")
                                        )}
                                        value={confirmPassword}
                                        onChange={(e) => setConfirmPassword(e.target.value)}
                                        required
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors p-1"
                                    >
                                        {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                                    </button>
                                </div>
                                {error && error.includes('match') && <p className="text-xs text-red-500 mt-2 ml-1">{error}</p>}
                            </div>
                        </div>

                        {error && !error.includes('match') && (
                            <div className="bg-red-50 text-red-600 p-3 rounded-lg text-sm text-center font-medium border border-red-100">
                                {error}
                            </div>
                        )}

                        <Button
                            type="submit"
                            className={cn(
                                "w-full py-6 text-lg font-bold rounded-xl shadow-lg transition-all duration-300",
                                isAllMet && newPassword === confirmPassword
                                    ? "bg-indigo-600 hover:bg-indigo-700 hover:scale-[1.02] shadow-indigo-200"
                                    : "bg-slate-300 cursor-not-allowed opacity-70"
                            )}
                            disabled={!isAllMet || newPassword !== confirmPassword}
                            isLoading={loading}
                        >
                            Reset Password
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </AuthLayout>
    );
};

export default ResetPassword;
