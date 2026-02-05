import React from 'react';
import bgShield from '../assets/bg_shield.png';
import logos from '../assets/logo_text.png';

const AuthLayout = ({ children, title, subtitle }) => {
    return (
        <div className="relative min-h-screen bg-slate-50 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 overflow-hidden">
            {/* Background Shield */}
            <div
                className="fixed inset-0 z-0 flex items-center justify-center opacity-[0.1] pointer-events-none animate-pulse-slow scale-110"
                style={{
                    backgroundImage: `url(${bgShield})`,
                    backgroundSize: 'contain',
                    backgroundPosition: 'center',
                    backgroundRepeat: 'no-repeat',
                }}
            />

            <div className="relative z-10 sm:mx-auto sm:w-full sm:max-w-md">
                <h2 className="mt-6 text-center text-3xl font-extrabold text-slate-900">
                    {title}
                </h2>
                {subtitle && (
                    <p className="mt-2 text-center text-sm text-slate-600">
                        {subtitle}
                    </p>
                )}
            </div>

            <div className="relative z-10 mt-8 sm:mx-auto sm:w-full sm:max-w-md">
                {children}
            </div>

            <style>{`
                @keyframes pulse-slow {
                    0%, 100% { opacity: 0.1; transform: scale(1.1); }
                    50% { opacity: 0.15; transform: scale(1.15); }
                }
                .animate-pulse-slow {
                    animation: pulse-slow 8s infinite ease-in-out;
                }
            `}</style>
        </div>
    );
};

export default AuthLayout;
