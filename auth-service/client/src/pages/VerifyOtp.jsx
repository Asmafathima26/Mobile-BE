import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import AuthLayout from '../layouts/AuthLayout';
import { Card, CardContent } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import api from '../api/axios';

const VerifyOtp = () => {
    const [otp, setOtp] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const location = useLocation();
    const navigate = useNavigate();
    const email = location.state?.email;

    if (!email) {
        navigate('/login');
        return null;
    }

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            await api.post('/auth/verify-otp', { email, otp });
            navigate('/login', { state: { message: 'Email verified successfully. Please login.' } });
        } catch (err) {
            setError(err.response?.data?.message || 'Invalid OTP');
        } finally {
            setLoading(false);
        }
    };

    const handleResend = async () => {
        try {
            await api.post('/auth/resend-otp', { email, type: 'email_verify' });
            alert('OTP resent to your email');
        } catch (err) {
            alert('Failed to resend OTP');
        }
    };

    return (
        <AuthLayout
            title="Verify your email"
            subtitle={`We've sent a 6-digit code to ${email}`}
        >
            <Card>
                <CardContent className="pt-8 text-center">
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="flex justify-center">
                            <Input
                                type="text"
                                placeholder="000000"
                                className="text-center text-2xl tracking-[1em] font-mono h-14"
                                maxLength={6}
                                value={otp}
                                onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, ''))}
                                required
                                error={error}
                            />
                        </div>

                        <Button
                            type="submit"
                            className="w-full"
                            isLoading={loading}
                        >
                            Verify Code
                        </Button>
                    </form>

                    <div className="mt-6">
                        <button
                            onClick={handleResend}
                            className="text-sm font-medium text-indigo-600 hover:text-indigo-500"
                        >
                            Didn't receive the code? Resend
                        </button>
                    </div>
                </CardContent>
            </Card>
        </AuthLayout>
    );
};

export default VerifyOtp;
