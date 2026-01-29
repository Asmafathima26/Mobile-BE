import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import AuthLayout from '../layouts/AuthLayout';
import { Card, CardContent } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import api from '../api/axios';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [submitted, setSubmitted] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            await api.post('/auth/forgot-password', { email });
            setSubmitted(true);
        } catch (err) {
            setError(err.response?.data?.message || 'Something went wrong');
        } finally {
            setLoading(false);
        }
    };

    if (submitted) {
        return (
            <AuthLayout title="Check your email" subtitle={`A reset link has been sent to ${email}`}>
                <Card>
                    <CardContent className="pt-8 text-center space-y-4">
                        <p className="text-slate-600">
                            Please click the link in the email to reset your password.
                        </p>
                        <Link to="/login" className="block">
                            <Button variant="secondary" className="w-full">
                                Back to sign in
                            </Button>
                        </Link>
                    </CardContent>
                </Card>
            </AuthLayout>
        );
    }

    return (
        <AuthLayout
            title="Forgot password?"
            subtitle="No worries, we'll send you reset instructions"
        >
            <Card>
                <CardContent className="pt-8">
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <Input
                            label="Email Address"
                            type="email"
                            placeholder="name@example.com"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                            error={error}
                        />

                        <Button
                            type="submit"
                            className="w-full"
                            isLoading={loading}
                        >
                            Reset Password
                        </Button>
                    </form>

                    <div className="mt-6 text-center">
                        <Link to="/login" className="text-sm font-medium text-indigo-600 hover:text-indigo-500">
                            Return to sign in
                        </Link>
                    </div>
                </CardContent>
            </Card>
        </AuthLayout>
    );
};

export default ForgotPassword;
