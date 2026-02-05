import React from 'react';
import bgShield from '../assets/bg_shield.png';

const Landing = () => {
    return (
        <div className="fixed inset-0 bg-white flex items-center justify-center selection:bg-[#A78BFA]/30">
            {/* Centered Shield Logo */}
            <div className="relative z-10 max-w-2xl w-full p-8 animate-in fade-in zoom-in duration-1000 ease-out">
                <img
                    src={bgShield}
                    alt="Shield Logo"
                    className="w-full h-auto max-h-[70vh] object-contain"
                />
            </div>
        </div>
    );
};

export default Landing;
