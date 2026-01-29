import React, { useState, useEffect } from 'react';
import { Card } from '../components/ui/Card';
import api from '../api/axios';

const AuditLogs = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchLogs = async () => {
            try {
                const response = await api.get('/admin/auth-logs');
                setLogs(response.data.data.logs);
            } catch (error) {
                console.error('Failed to fetch logs');
            } finally {
                setLoading(false);
            }
        };
        fetchLogs();
    }, []);

    if (loading) return <div className="p-8 text-center text-slate-500">Loading logs...</div>;

    return (
        <div className="space-y-6">
            <h1 className="text-2xl font-bold text-slate-900">Audit Logs</h1>

            <Card className="overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50 border-b border-slate-200">
                                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase">Action</th>
                                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase">IP Address</th>
                                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase">Timestamp</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {logs.map((log) => (
                                <tr key={log.id} className="hover:bg-slate-50 transition-colors">
                                    <td className="px-6 py-4">
                                        <span className="font-medium text-slate-900 capitalize">
                                            {log.action.toLowerCase().replace(/_/g, ' ')}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-slate-600 font-mono text-sm">{log.ip_address}</td>
                                    <td className="px-6 py-4 text-slate-500 text-sm">
                                        {new Date(log.created_at).toLocaleString()}
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

export default AuditLogs;
