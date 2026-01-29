import React, { useState } from 'react';
import { NavLink, useNavigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { LayoutDashboard, User, Shield, LogOut, Menu, X, Settings, LucideActivity } from 'lucide-react';
import { cn } from '../utils/cn';

const DashboardLayout = () => {
    const { user, logout } = useAuth();
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);
    const navigate = useNavigate();

    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };

    const menuItems = [
        { name: 'Dashboard', path: user.roles.includes('ADMIN') ? '/admin' : '/dashboard', icon: LayoutDashboard },
        { name: 'Profile', path: '/profile', icon: User },
    ];

    if (user.roles.includes('ADMIN')) {
        menuItems.push(
            { name: 'User Management', path: '/admin/users', icon: Shield },
            { name: 'Audit Logs', path: '/admin/logs', icon: LucideActivity }
        );
    }

    return (
        <div className="min-h-screen bg-slate-50 flex">
            {/* Mobile Sidebar Backdrop */}
            {isSidebarOpen && (
                <div
                    className="fixed inset-0 bg-slate-900/50 z-40 lg:hidden backdrop-blur-sm"
                    onClick={() => setIsSidebarOpen(false)}
                />
            )}

            {/* Sidebar */}
            <aside className={cn(
                "fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-slate-200 transform transition-transform duration-300 lg:relative lg:translate-x-0 shadow-sm",
                isSidebarOpen ? "translate-x-0" : "-translate-x-full"
            )}>
                <div className="h-full flex flex-col">
                    <div className="p-6 h-16 border-b border-slate-100 flex items-center gap-3">
                        <div className="h-8 w-8 bg-indigo-600 rounded-lg flex items-center justify-center">
                            <Shield className="h-5 w-5 text-white" />
                        </div>
                        <span className="text-xl font-bold text-slate-900">AuthService</span>
                    </div>

                    <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
                        {menuItems.map((item) => (
                            <NavLink
                                key={item.path}
                                to={item.path}
                                onClick={() => setIsSidebarOpen(false)}
                                className={({ isActive }) => cn(
                                    "flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors",
                                    isActive
                                        ? "bg-indigo-50 text-indigo-700"
                                        : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                                )}
                            >
                                <item.icon className="h-5 w-5" />
                                {item.name}
                            </NavLink>
                        ))}
                    </nav>

                    <div className="p-4 border-t border-slate-100 space-y-2">
                        <div className="px-4 py-3 bg-slate-50 rounded-lg">
                            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Logged in as</p>
                            <p className="text-sm font-medium text-slate-900 truncate mt-0.5">{user.email}</p>
                            <p className="text-[10px] text-indigo-600 font-bold mt-1 uppercase leading-none">
                                {user.roles.join(', ')}
                            </p>
                        </div>
                        <button
                            onClick={handleLogout}
                            className="flex items-center gap-3 w-full px-4 py-2.5 text-sm font-medium text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        >
                            <LogOut className="h-5 w-5" />
                            Sign Out
                        </button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <div className="flex-1 flex flex-col min-w-0">
                <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6 lg:px-8 shadow-sm z-30 sticky top-0">
                    <button
                        className="lg:hidden p-2 text-slate-600"
                        onClick={() => setIsSidebarOpen(true)}
                    >
                        <Menu className="h-6 w-6" />
                    </button>

                    <div className="flex items-center gap-4">
                        {/* Header Actions */}
                        <button className="p-2 text-slate-400 hover:text-slate-600 transition-colors">
                            <Settings className="h-5 w-5" />
                        </button>
                    </div>
                </header>

                <main className="flex-1 p-6 lg:p-8">
                    <div className="max-w-7xl mx-auto">
                        <Outlet />
                    </div>
                </main>
            </div>
        </div>
    );
};

export default DashboardLayout;
