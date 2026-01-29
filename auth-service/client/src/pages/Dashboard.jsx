import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Card, CardHeader, CardContent } from '../components/ui/Card';
import { User, Mail, ShieldCheck, Calendar } from 'lucide-react';

const Dashboard = () => {
    const { user } = useAuth();

    const stats = [
        { label: 'Account Status', value: 'Active', icon: ShieldCheck, color: 'text-green-600', bg: 'bg-green-100' },
        { label: 'Role', value: user.roles[0], icon: User, color: 'text-indigo-600', bg: 'bg-indigo-100' },
    ];

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-bold text-slate-900">Welcome, {user.first_name || 'User'}!</h1>
                <p className="text-slate-500 mt-1">Here is an overview of your account information.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {stats.map((stat) => (
                    <Card key={stat.label}>
                        <CardContent className="p-6 flex items-center gap-4">
                            <div className={`${stat.bg} p-3 rounded-xl`}>
                                <stat.icon className={`h-6 w-6 ${stat.color}`} />
                            </div>
                            <div>
                                <p className="text-sm font-medium text-slate-500">{stat.label}</p>
                                <p className="text-xl font-bold text-slate-900 capitalize">{stat.value.toLowerCase()}</p>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            <Card>
                <CardHeader>
                    <h3 className="text-lg font-semibold text-slate-900 text">Profile Details</h3>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div className="space-y-6">
                            <div className="flex items-center gap-4">
                                <div className="h-10 w-10 flex items-center justify-center bg-slate-100 rounded-full text-slate-500">
                                    <User size={20} />
                                </div>
                                <div>
                                    <p className="text-sm text-slate-500">Full Name</p>
                                    <p className="font-medium text-slate-900">{user.first_name} {user.last_name}</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-4">
                                <div className="h-10 w-10 flex items-center justify-center bg-slate-100 rounded-full text-slate-500">
                                    <Mail size={20} />
                                </div>
                                <div>
                                    <p className="text-sm text-slate-500">Email Address</p>
                                    <p className="font-medium text-slate-900">{user.email}</p>
                                </div>
                            </div>
                        </div>
                        <div className="space-y-6">
                            <div className="flex items-center gap-4">
                                <div className="h-10 w-10 flex items-center justify-center bg-slate-100 rounded-full text-slate-500">
                                    <ShieldCheck size={20} />
                                </div>
                                <div>
                                    <p className="text-sm text-slate-500">Email Verified</p>
                                    <p className="font-medium text-slate-900">
                                        {user.email_verified ? 'Verified' : 'Not Verified'}
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

export default Dashboard;
