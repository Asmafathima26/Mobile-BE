import React from 'react';
import { cn } from '../../utils/cn';

const Card = ({ className, children, ...props }) => {
    return (
        <div
            className={cn(
                'bg-white/70 backdrop-blur-md border border-slate-200 rounded-2xl shadow-sm overflow-hidden',
                className
            )}
            {...props}
        >
            {children}
        </div>
    );
};

const CardHeader = ({ className, children, ...props }) => (
    <div className={cn('px-6 py-4 border-b border-slate-100', className)} {...props}>
        {children}
    </div>
);

const CardContent = ({ className, children, ...props }) => (
    <div className={cn('p-6', className)} {...props}>
        {children}
    </div>
);

const CardFooter = ({ className, children, ...props }) => (
    <div className={cn('px-6 py-4 bg-slate-50 border-t border-slate-100', className)} {...props}>
        {children}
    </div>
);

export { Card, CardHeader, CardContent, CardFooter };
