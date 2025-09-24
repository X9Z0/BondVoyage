// backend/middleware/blockchainMiddleware.js
// Middleware for blockchain operations

'use strict';

// import crypto from 'crypto';
import { verify as _verify } from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';

// Rate limiting for blockchain operations
const blockchainRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 blockchain requests per windowMs
  message: {
    success: false,
    error: 'Too many blockchain requests, please try again later',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Signature verification middleware for device messages
const verifyDeviceSignature = (req, res, next) => {
  const { signature, deviceId, timestamp } = req.body;

  if (!signature || !deviceId || !timestamp) {
    return res.status(400).json({
      success: false,
      error: 'Missing signature, deviceId, or timestamp',
    });
  }

  // Check timestamp to prevent replay attacks (5 minute window)
  const now = Date.now();
  const messageTime = new Date(timestamp).getTime();
  const timeDiff = Math.abs(now - messageTime);

  if (timeDiff > 5 * 60 * 1000) {
    return res.status(400).json({
      success: false,
      error: 'Message timestamp too old',
    });
  }

  // TODO: Verify device signature with stored public key
  // For MVP, we'll skip this verification
  req.verified = true;
  next();
};

// Enhanced authentication with JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Access token required',
    });
  }

  _verify(
    token,
    process.env.JWT_SECRET || 'tourist-safety-secret',
    (err, user) => {
      if (err) {
        return res.status(403).json({
          success: false,
          error: 'Invalid or expired token',
        });
      }
      req.user = user;
      next();
    }
  );
};

// Role-based authorization
const authorize = (requiredRoles) => {
  return (req, res, next) => {
    const userRole = req.user?.role;
    const userRoles = Array.isArray(userRole) ? userRole : [userRole];

    const hasRequiredRole = requiredRoles.some((role) =>
      userRoles.includes(role)
    );

    if (!hasRequiredRole) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Required roles: ${requiredRoles.join(', ')}`,
      });
    }
    next();
  };
};

// Tourist data access validation
const validateTouristAccess = async (req, res, next) => {
  const { touristId } = req.params;
  const user = req.user;

  // Admin and police can access any tourist data
  if (user.role === 'admin' || user.role === 'police') {
    return next();
  }

  // Tourist can only access their own data
  if (user.role === 'tourist' && user.id === touristId) {
    return next();
  }

  // Family members can access if they have grants
  if (user.role === 'family') {
    // TODO: Check if family member has active access grant
    // For MVP, allow family access
    return next();
  }

  return res.status(403).json({
    success: false,
    error: 'Insufficient permissions to access this tourist data',
  });
};

// Input validation for blockchain operations
const validateEventData = (req, res, next) => {
  const { location, touristId } = req.body;

  if (
    !location ||
    typeof location.lat !== 'number' ||
    typeof location.lon !== 'number'
  ) {
    return res.status(400).json({
      success: false,
      error: 'Valid location with lat/lon coordinates required',
    });
  }

  if (!touristId || typeof touristId !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Valid touristId string required',
    });
  }

  // Validate location bounds (for demo, using Rajasthan bounds)
  const lat = location.lat;
  const lon = location.lon;

  if (lat < 23.0 || lat > 30.0 || lon < 69.0 || lon > 78.0) {
    return res.status(400).json({
      success: false,
      error: 'Location outside supported region',
    });
  }

  next();
};

// Request logging for audit trail
const logBlockchainRequest = (req, res, next) => {
  const requestLog = {
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    userId: req.user?.id,
    userRole: req.user?.role,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
  };

  console.log('Blockchain Request:', JSON.stringify(requestLog));

  // TODO: Store in audit log database
  req.auditLog = requestLog;
  next();
};

export default {
  blockchainRateLimit,
  verifyDeviceSignature,
  authenticateToken,
  authorize,
  validateTouristAccess,
  validateEventData,
  logBlockchainRequest,
};
