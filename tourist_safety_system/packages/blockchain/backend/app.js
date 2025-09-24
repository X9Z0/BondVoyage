// backend/app.js
// Main Express application with blockchain routes

('use strict');
// cors morgan helmet compression
import express, { json, urlencoded } from 'express';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import compression from 'compression';
require('dotenv').config();

// Import routes
import blockchainRoutes from './routes/blockchainRoutes';
import {
  blockchainRateLimit,
  logBlockchainRequest,
} from './middleware/blockchainMiddleware';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(morgan('combined'));
app.use(json({ limit: '10mb' }));
app.use(urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'tourist-safety-blockchain',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
  });
});

// Apply rate limiting and logging to blockchain routes
app.use('/api/blockchain', blockchainRateLimit, logBlockchainRequest);

// Mount blockchain routes
app.use('/api/blockchain', blockchainRoutes);

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('API Error:', error);

  res.status(error.status || 500).json({
    success: false,
    error: error.message || 'Internal server error',
    timestamp: new Date().toISOString(),
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.originalUrl,
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Blockchain API server running on port ${PORT}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
  console.log(`⛓️  Blockchain API: http://localhost:${PORT}/api/blockchain`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

export default app;
