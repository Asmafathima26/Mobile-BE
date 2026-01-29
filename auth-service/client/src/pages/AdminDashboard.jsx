import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardContent } from '../components/ui/Card';
import api from '../api/axios';
import { Users, ShieldAlert, LogIn, TrendingUp } from 'lucide-react';

const AdminDashboard = () => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const response = await api.get('/admin/dashboard/stats');
                setStats(response.data.data);
            } catch (error) {
                console.error('Failed to fetch stats');
            } finally {
                setLoading(false);
            }
        };
        fetchStats();
    }, []);

    const statCards = [
        { label: 'Total Users', value: stats?.totalUsers || 0, icon: Users, color: 'text-blue-600', bg: 'bg-blue-100' },
        { label: 'Active Users', value: stats?.activeUsers || 0, icon: TrendingUp, color: 'text-green-600', bg: 'bg-green-100' },
        { label: 'Blocked Users', value: stats?.blockedUsers || 0, icon: ShieldAlert, color: 'text-red-600', bg: 'bg-red-100' },
        { label: 'Total Logs', value: stats?.totalAuthLogs || 0, icon: LogIn, color: 'text-purple-600', bg: 'bg-purple-100' },
    ];

    if (loading) return <div>Loading statistics...</div>;

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-bold text-slate-900">Admin Overview</h1>
                <p className="text-slate-500 mt-1">Real-time statistics of your authentication service.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {statCards.map((stat) => (
                    <Card key={stat.label}>
                        <CardContent className="p-6 flex items-center gap-4">
                            <div className={`${stat.bg} p-3 rounded-xl`}>
                                <stat.icon className={`h-6 w-6 ${stat.color}`} />
                            </div>
                            <div>
                                <p className="text-sm font-medium text-slate-500">{stat.label}</p>
                                <p className="text-2xl font-bold text-slate-900">{stat.value}</p>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <Card>
                    <CardHeader>
                        <h3 className="text-lg font-semibold text-slate-900 text">Security Overview</h3>
                    </CardHeader>
                    <CardContent>
                        <div className="h-64 flex items-center justify-center bg-slate-50 rounded-lg border-2 border-dashed border-slate-200">
                            <p className="text-slate-400">Activity Graph Coming Soon</p>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <h3 className="text-lg font-semibold text-slate-900 text">System Status</h3>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="flex justify-between items-center py-2 border-b border-slate-100 text">
                            <span className="text-slate-600">Auth Server</span>
                            <span className="px-2 py-1 text-xs font-bold bg-green-100 text-green-700 rounded-full">OPERATIONAL</span>
                        </div>
                        <div className="flex justify-between items-center py-2 border-b border-slate-100">
                            <span className="text-slate-600">Database</span>
                            <span className="px-2 py-1 text-xs font-bold bg-green-100 text-green-700 rounded-full">OPERATIONAL</span>
                        </div>
                        <div className="flex justify-between items-center py-2">
                            <span className="text-slate-600">SMTP Service</span>
                            <span className="px-2 py-1 text-xs font-bold bg-green-100 text-green-700 rounded-full">OPERATIONAL</span>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
};

export default AdminDashboard;
