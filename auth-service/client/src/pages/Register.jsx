import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import AuthLayout from '../layouts/AuthLayout';
import { Card, CardContent } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Eye, EyeOff, Lock, CheckCircle2, Circle, Mail, User } from 'lucide-react';
import api from '../api/axios';
import { cn } from '../utils/cn';

const PasswordRequirement = ({ met, text }) => (
    <div className={cn("flex items-center gap-2 text-sm transition-colors duration-200", met ? "text-emerald-500" : "text-slate-400")}>
        {met ? <CheckCircle2 size={16} className="shrink-0" /> : <Circle size={16} className="shrink-0" />}
        <span>{text}</span>
    </div>
);

const Register = () => {
    const [formData, setFormData] = useState({
        firstName: '',
        lastName: '',
        email: '',
        password: '',
    });
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const requirements = [
        { met: formData.password.length >= 8, text: 'At least 8 characters' },
        { met: /[A-Z]/.test(formData.password), text: 'Uppercase letter (A-Z)' },
        { met: /[a-z]/.test(formData.password), text: 'Lowercase letter (a-z)' },
        { met: /[0-9]/.test(formData.password), text: 'Number (0-9)' },
        { met: /[!@#$%^&*]/.test(formData.password), text: 'Special character (!@#$%^&*)' },
    ];

    const isAllMet = requirements.every(req => req.met);

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!isAllMet) {
            setError('Please meet all password requirements');
            return;
        }
        setError('');
        setLoading(true);
        try {
            await api.post('/auth/register', formData);
            navigate('/verify-otp', { state: { email: formData.email } });
        } catch (err) {
            setError(err.response?.data?.message || 'Something went wrong. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthLayout
            title="Create account"
            subtitle="Join us and start managing your account"
        >
            <Card className="border-none shadow-xl ring-1 ring-slate-200/50">
                <CardContent className="pt-8 px-6 pb-8">
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 ml-1">
                                    <User size={16} className="text-slate-400" />
                                    First Name
                                </label>
                                <input
                                    name="firstName"
                                    placeholder="John"
                                    className="w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3 text-base outline-none focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all duration-300"
                                    value={formData.firstName}
                                    onChange={handleChange}
                                    required
                                />
                            </div>
                            <div className="space-y-2">
                                <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 ml-1">
                                    <User size={16} className="text-slate-400" />
                                    Last Name
                                </label>
                                <input
                                    name="lastName"
                                    placeholder="Doe"
                                    className="w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3 text-base outline-none focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all duration-300"
                                    value={formData.lastName}
                                    onChange={handleChange}
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 ml-1">
                                <Mail size={16} className="text-slate-400" />
                                Email Address
                            </label>
                            <input
                                type="email"
                                name="email"
                                placeholder="name@example.com"
                                className="w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3 text-base outline-none focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all duration-300"
                                value={formData.email}
                                onChange={handleChange}
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 ml-1">
                                <Lock size={16} className="text-slate-400" />
                                Password
                            </label>
                            <div className="relative group">
                                <input
                                    type={showPassword ? "text" : "password"}
                                    name="password"
                                    placeholder="••••••••"
                                    className={cn(
                                        "w-full bg-slate-50 border border-slate-200 text-slate-900 rounded-xl px-4 py-3 pr-12 text-base outline-none transition-all duration-300",
                                        "focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500",
                                        formData.password && (isAllMet ? "border-emerald-500/50" : "border-amber-500/50")
                                    )}
                                    value={formData.password}
                                    onChange={handleChange}
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

                        {error && (
                            <div className="bg-red-50 text-red-600 p-3 rounded-lg text-sm text-center font-medium border border-red-100">
                                {error}
                            </div>
                        )}

                        <Button
                            type="submit"
                            className={cn(
                                "w-full py-6 text-lg font-bold rounded-xl shadow-lg transition-all duration-300",
                                isAllMet ? "bg-indigo-600 hover:bg-indigo-700 hover:scale-[1.02] shadow-indigo-200" : "bg-slate-300 cursor-not-allowed opacity-70"
                            )}
                            disabled={!isAllMet}
                            isLoading={loading}
                        >
                            Create Account
                        </Button>
                    </form>

                    <div className="mt-8 text-center text-sm">
                        <span className="text-slate-500">Already have an account? </span>
                        <Link to="/login" className="font-bold text-indigo-600 hover:text-indigo-700 underline underline-offset-4 decoration-indigo-200 hover:decoration-indigo-600 transition-all">
                            Sign in
                        </Link>
                    </div>
                </CardContent>
            </Card>
        </AuthLayout>
    );
};

export default Register;
