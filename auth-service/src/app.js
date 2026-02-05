const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const logger = require('./utils/logger');

const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();

app.set('trust proxy', 1);
app.use(helmet());
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};
app.use(cors(corsOptions));

app.use(express.json());

// Use winston for morgan logging
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Routes
app.get('/api', (req, res) => {
    res.status(200).json({
        success: true,
        service: 'Auth Service',
        message: 'Backend Auth Service is running',
        version: 'v1',
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/admin', adminRoutes);

// Serve static files from the React app build folder if it exists
const buildPath = path.join(__dirname, '../client/dist');
if (fs.existsSync(buildPath)) {
    app.use(express.static(buildPath));
    app.get(/.*/, (req, res) => {
        res.sendFile(path.join(buildPath, 'index.html'));
    });
}

// Global Error Handler
app.use((err, req, res, next) => {
    logger.error(err);

    const statusCode = err.statusCode || 500;
    const message = err.message || 'Internal Server Error';

    res.status(statusCode).json({
        success: false,
        message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

module.exports = app;
