import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, ArrowRight, CheckCircle2, Zap, Smartphone } from 'lucide-react';
import { Button } from '../components/ui/Button';

const Landing = () => {
    return (
        <div className="bg-white">
            {/* Header */}
            <nav className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <div className="h-10 w-10 bg-indigo-600 rounded-lg flex items-center justify-center">
                        <Shield className="h-6 w-6 text-white" />
                    </div>
                    <span className="text-xl font-bold text-slate-900">AuthService</span>
                </div>
                <div className="hidden md:flex items-center gap-8">
                    <a href="#features" className="text-sm font-medium text-slate-600 hover:text-slate-900">Features</a>
                    <a href="#about" className="text-sm font-medium text-slate-600 hover:text-slate-900">About</a>
                    <Link to="/login">
                        <Button variant="ghost">Sign In</Button>
                    </Link>
                    <Link to="/register">
                        <Button>Get Started</Button>
                    </Link>
                </div>
            </nav>

            {/* Hero Section */}
            <section className="relative pt-20 pb-32 overflow-hidden">
                <div className="max-w-7xl mx-auto px-6 relative z-10 text">
                    <div className="max-w-3xl">
                        <h1 className="text-5xl md:text-6xl font-extrabold text-slate-900 leading-tight">
                            Secure Authentication <br />
                            <span className="text-indigo-600">Simplified.</span>
                        </h1>
                        <p className="mt-6 text-xl text-slate-600 leading-relaxed">
                            A robust, mobile-first authentication service with role-based access control,
                            OTP verification, and a mature administrative dashboard. Built for security and scale.
                        </p>
                        <div className="mt-10 flex flex-col sm:flex-row gap-4">
                            <Link to="/register">
                                <Button size="lg" className="h-14 px-8 w-full sm:w-auto">
                                    Get Started for Free <ArrowRight className="ml-2 h-5 w-5" />
                                </Button>
                            </Link>
                            <Link to="/login">
                                <Button variant="secondary" size="lg" className="h-14 px-8 w-full sm:w-auto">
                                    Admin Demo
                                </Button>
                            </Link>
                        </div>
                    </div>
                </div>

                {/* Background Decoration */}
                <div className="absolute top-0 right-0 -translate-y-1/2 translate-x-1/2 w-[800px] h-[800px] bg-indigo-50 rounded-full blur-3xl opacity-50 z-0" />
            </section>

            {/* Features Table */}
            <section id="features" className="py-24 bg-slate-50">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center max-w-2xl mx-auto mb-16 text">
                        <h2 className="text-3xl font-bold text-slate-900">Everything you need</h2>
                        <p className="mt-4 text-slate-600">A complete auth solution out of the box with features designed for modern applications.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text">
                        {[
                            { title: 'OTP Verification', desc: 'Secure email-based verification to ensure authentic user accounts.', icon: CheckCircle2 },
                            { title: 'RBAC Support', desc: 'Manage permissions easily with built-in Role Based Access Control.', icon: Shield },
                            { title: 'Mobile First', desc: 'Fully responsive design that looks stunning on every device.', icon: Smartphone }
                        ].map((f) => (
                            <div key={f.title} className="bg-white p-8 rounded-2xl shadow-sm border border-slate-100">
                                <div className="h-12 w-12 bg-indigo-50 rounded-lg flex items-center justify-center mb-6">
                                    <f.icon className="h-6 w-6 text-indigo-600" />
                                </div>
                                <h3 className="text-xl font-bold text-slate-900 mb-3">{f.title}</h3>
                                <p className="text-slate-600">{f.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="py-12 border-t border-slate-200">
                <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-6">
                    <div className="flex items-center gap-2">
                        <Shield className="h-5 w-5 text-indigo-600" />
                        <span className="font-bold text-slate-900">AuthService</span>
                    </div>
                    <p className="text-sm text-slate-500">© 2026 AuthService. Built for performance and security.</p>
                </div>
            </footer>
        </div>
    );
};

export default Landing;
