import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import AuthLayout from '../layouts/AuthLayout';
import { Card, CardContent } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import api from '../api/axios';

const ResetPassword = () => {
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const [email, setEmail] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        setLoading(true);
        setError('');
        try {
            await api.post('/auth/reset-password', { email, token, newPassword });
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
            subtitle="Enter your email and a strong new password"
        >
            <Card>
                <CardContent className="pt-8">
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <Input
                            label="Confirm Email"
                            type="email"
                            placeholder="name@example.com"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                        <Input
                            label="New Password"
                            type="password"
                            placeholder="••••••••"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            required
                        />
                        <Input
                            label="Confirm Password"
                            type="password"
                            placeholder="••••••••"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            error={error}
                        />

                        <Button
                            type="submit"
                            className="w-full mt-2"
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
