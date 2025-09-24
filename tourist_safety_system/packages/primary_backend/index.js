const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const axios = require('axios');
const WebSocket = require('ws');
const http = require('http');
const Joi = require('joi');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Import MongoDB Models
const Tourist = require('./models/Tourist');
const Device = require('./models/Device');
const Event = require('./models/Event');
const Itinerary = require('./models/Itinerary');
const EFIR = require('./models/EFIR');
const AccessGrant = require('./models/AccessGrant');
const AuditLog = require('./models/AuditLog');
const User = require('./models/User');

// Configuration
const JWT_SECRET =
  process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const BLOCKCHAIN_API_URL =
  process.env.BLOCKCHAIN_API_URL || 'http://localhost:3000/api/blockchain';
const SMS_GATEWAY_URL =
  process.env.SMS_GATEWAY_URL || 'https://api.sms-gateway.com';
const MONGODB_URI =
  process.env.MONGODB_URI || 'mongodb://localhost:27017/tourist_safety';

// MongoDB Connection
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('✅ MongoDB connected successfully'))
  .catch((err) => console.error('❌ MongoDB connection error:', err));

// Security Middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'", 'wss:', 'ws:'],
      },
    },
  })
);

// Rate Limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs for sensitive endpoints
  message: {
    error: 'Too many sensitive requests from this IP, please try again later.',
  },
});

app.use('/api/', limiter);
app.use('/api/v1/event/panic', strictLimiter);
app.use('/api/v1/auth/login', strictLimiter);

// General Middleware
app.use(compression());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Device-Signature',
      'X-Client-Version',
    ],
  })
);

app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(mongoSanitize()); // Prevent NoSQL injection attacks

// WebSocket connection tracking
const wsConnections = new Map();

// Utility Functions
const generateId = (prefix) =>
  `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

const hashPayload = (payload) => {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');
};

const verifySignature = (payload, signature, publicKey) => {
  try {
    const verify = crypto.createVerify('SHA256');
    verify.update(JSON.stringify(payload));
    return verify.verify(publicKey, signature, 'base64');
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
};

const auditLog = async (action, userId, data, ipAddress = null) => {
  try {
    await AuditLog.create({
      action,
      userId,
      data,
      ipAddress,
      userAgent: data.userAgent || null,
      timestamp: new Date(),
    });
  } catch (error) {
    console.error('Audit log error:', error);
  }
};

// Validation Schemas
const schemas = {
  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    role: Joi.string()
      .valid('tourist', 'family_member', 'police_officer', 'admin')
      .default('tourist'),
  }),

  registerTourist: Joi.object({
    touristId: Joi.string().required(),
    name: Joi.string().min(2).max(100).required(),
    nationality: Joi.string().min(2).max(50).required(),
    passportNumber: Joi.string().min(5).max(20).required(),
    kycStorage: Joi.object({
      storageKey: Joi.string().required(),
      documentHash: Joi.string().required(),
    }).required(),
    consents: Joi.array().items(Joi.string()).default([]),
  }),

  registerDevice: Joi.object({
    deviceId: Joi.string().required(),
    touristId: Joi.string().required(),
    pubKey: Joi.string().required(),
  }),

  panicEvent: Joi.object({
    clientEventId: Joi.string().uuid().required(),
    payload: Joi.object({
      type: Joi.string().valid('panic', 'warning', 'alert').required(),
      touristId: Joi.string().required(),
      deviceId: Joi.string().required(),
      ts: Joi.string().isoDate().required(),
      lat: Joi.number().min(-90).max(90).required(),
      lon: Joi.number().min(-180).max(180).required(),
      meta: Joi.object().default({}),
    }).required(),
    payloadHash: Joi.string().required(),
    signature: Joi.string().required(),
  }),

  anchorItinerary: Joi.object({
    touristId: Joi.string().required(),
    itinerary: Joi.object({
      startDate: Joi.string().isoDate().required(),
      endDate: Joi.string().isoDate().required(),
      locations: Joi.array().items(Joi.string()).min(1).required(),
      activities: Joi.array().items(Joi.string()).default([]),
      accommodations: Joi.array().items(Joi.string()).default([]),
    }).required(),
  }),

  fileEFIR: Joi.object({
    eventId: Joi.string().required(),
    touristId: Joi.string().required(),
    policeStation: Joi.string().required(),
    officerId: Joi.string().required(),
    reportDetails: Joi.object({
      incidentType: Joi.string().required(),
      description: Joi.string().required(),
      actionTaken: Joi.string().required(),
      status: Joi.string()
        .valid('Open', 'In Progress', 'Resolved', 'Closed')
        .required(),
      witnesses: Joi.array().items(Joi.string()).default([]),
      evidenceCollected: Joi.array().items(Joi.string()).default([]),
    }).required(),
    attachments: Joi.array().items(Joi.string()).default([]),
  }),

  grantAccess: Joi.object({
    touristId: Joi.string().required(),
    targetOrg: Joi.string().required(),
    scope: Joi.array()
      .items(
        Joi.string().valid('location', 'safety_status', 'events', 'itinerary')
      )
      .min(1)
      .required(),
    expiryHours: Joi.number().min(1).max(8760).required(), // max 1 year
  }),

  updateConsent: Joi.object({
    consentType: Joi.string()
      .valid('location_sharing', 'family_access', 'kyc_share', 'data_analytics')
      .required(),
    granted: Joi.boolean().required(),
  }),
};

// Validation Middleware
const validate = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation error',
        details: error.details.map((detail) => ({
          field: detail.path.join('.'),
          message: detail.message,
        })),
      });
    }
    next();
  };
};

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    // Check if user still exists and is active
    const user = await User.findById(decoded.id).select('-password');
    if (!user || user.status !== 'active') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Role-based Authorization Middleware
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: roles,
        current: req.user.role,
      });
    }

    next();
  };
};

// Device signature verification middleware
const verifyDeviceSignature = async (req, res, next) => {
  try {
    const signature = req.headers['x-device-signature'];
    const deviceId = req.body.payload?.deviceId;

    if (signature && deviceId) {
      const device = await Device.findOne({ deviceId, status: 'active' });
      if (!device) {
        return res.status(401).json({ error: 'Device not found or inactive' });
      }

      if (!verifySignature(req.body, signature, device.pubKey)) {
        await auditLog('INVALID_SIGNATURE', null, { deviceId, ip: req.ip });
        return res.status(401).json({ error: 'Invalid device signature' });
      }

      // Update device last seen
      await Device.findByIdAndUpdate(device._id, { lastSeen: new Date() });
    }
    next();
  } catch (error) {
    console.error('Device signature verification error:', error);
    return res.status(500).json({ error: 'Signature verification failed' });
  }
};

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathParts = url.pathname.split('/');
  const touristId = pathParts[pathParts.length - 1];

  // Validate touristId format
  if (touristId && touristId.match(/^T-/)) {
    wsConnections.set(touristId, ws);
    console.log(`WebSocket connected for tourist: ${touristId}`);

    ws.send(
      JSON.stringify({
        type: 'connection_established',
        touristId,
        timestamp: new Date().toISOString(),
      })
    );
  }

  ws.on('close', () => {
    wsConnections.delete(touristId);
    console.log(`WebSocket disconnected for tourist: ${touristId}`);
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    wsConnections.delete(touristId);
  });
});

const broadcastToTourist = (touristId, data) => {
  const ws = wsConnections.get(touristId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(
      JSON.stringify({
        ...data,
        timestamp: new Date().toISOString(),
      })
    );
    return true;
  }
  return false;
};

// Blockchain API Integration
const callBlockchainAPI = async (endpoint, method = 'GET', data = null) => {
  try {
    const config = {
      method,
      url: `${BLOCKCHAIN_API_URL}${endpoint}`,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${
          process.env.BLOCKCHAIN_SERVICE_TOKEN || 'blockchain-service-token'
        }`,
      },
      timeout: 10000, // 10 second timeout
    };

    if (data) {
      config.data = data;
    }

    const response = await axios(config);
    return response.data;
  } catch (error) {
    console.error('Blockchain API error:', error.message);
    throw new Error(
      `Blockchain service unavailable: ${
        error.response?.data?.message || error.message
      }`
    );
  }
};

// Routes

// Health Check
app.get('/api/v1/health', async (req, res) => {
  try {
    const dbStatus =
      mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const blockchainStatus = await callBlockchainAPI('/health')
      .then(() => 'connected')
      .catch(() => 'disconnected');

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        database: dbStatus,
        blockchain: blockchainStatus,
        websocket: 'running',
      },
      metrics: {
        activeConnections: wsConnections.size,
        uptime: process.uptime(),
      },
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
    });
  }
});

// Authentication Routes
app.post('/api/v1/auth/login', validate(schemas.login), async (req, res) => {
  try {
    const { email, password, role } = req.body;

    // Find user by email
    let user = await User.findOne({ email, status: 'active' });

    // For demo purposes, create user if not exists
    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 12);
      user = await User.create({
        email,
        password: hashedPassword,
        role,
        status: 'active',
      });
    } else {
      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        await auditLog('LOGIN_FAILED', user._id, {
          email,
          reason: 'invalid_password',
          ip: req.ip,
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    // Update last login
    await User.findByIdAndUpdate(user._id, {
      lastLogin: new Date(),
      lastLoginIP: req.ip,
    });

    await auditLog('LOGIN_SUCCESS', user._id, { email, ip: req.ip });

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
      },
      expiresIn: 86400,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Tourist Registration
app.post(
  '/api/v1/tourist/register',
  authenticateToken,
  authorize('tourist', 'admin'),
  validate(schemas.registerTourist),
  async (req, res) => {
    try {
      const {
        touristId,
        name,
        nationality,
        passportNumber,
        kycStorage,
        consents,
      } = req.body;

      // Check if tourist already exists
      const existingTourist = await Tourist.findOne({ touristId });
      if (existingTourist) {
        return res.status(409).json({ error: 'Tourist already registered' });
      }

      // Call blockchain service
      const blockchainData = await callBlockchainAPI(
        '/tourist/register',
        'POST',
        {
          touristId,
          name,
          nationality,
          passportNumber,
          kycDocuments: {
            storageKey: kycStorage.storageKey,
            documentHash: kycStorage.documentHash,
          },
        }
      );

      // Store in database
      const tourist = await Tourist.create({
        touristId,
        name,
        nationality,
        passportNumber,
        kycStorage,
        consents,
        blockchainRecord: blockchainData.blockchainRecord,
        status: 'active',
        registeredBy: req.user._id,
      });

      await auditLog('TOURIST_REGISTER', req.user._id, {
        touristId,
        name,
        nationality,
        ip: req.ip,
      });

      res.status(201).json({
        touristId,
        blockchainTxId: blockchainData.blockchainRecord?.id,
        timestamp: tourist.createdAt,
      });
    } catch (error) {
      console.error('Tourist registration error:', error);
      if (error.code === 11000) {
        return res
          .status(409)
          .json({ error: 'Tourist ID or passport number already exists' });
      }
      res.status(500).json({ error: error.message });
    }
  }
);

// Device Registration
app.post(
  '/api/v1/device/register',
  authenticateToken,
  validate(schemas.registerDevice),
  async (req, res) => {
    try {
      const { deviceId, touristId, pubKey } = req.body;

      // Verify tourist exists
      const tourist = await Tourist.findOne({ touristId, status: 'active' });
      if (!tourist) {
        return res.status(404).json({ error: 'Tourist not found' });
      }

      // Check if device already exists
      const existingDevice = await Device.findOne({ deviceId });
      if (existingDevice) {
        return res.status(409).json({ error: 'Device already registered' });
      }

      const device = await Device.create({
        deviceId,
        touristId,
        pubKey,
        type: 'phone',
        status: 'active',
        registeredBy: req.user._id,
      });

      await auditLog('DEVICE_REGISTER', req.user._id, {
        deviceId,
        touristId,
        ip: req.ip,
      });

      res.status(201).json({
        success: true,
        deviceId: device.deviceId,
        registeredAt: device.createdAt,
      });
    } catch (error) {
      console.error('Device registration error:', error);
      if (error.code === 11000) {
        return res.status(409).json({ error: 'Device ID already exists' });
      }
      res.status(500).json({ error: error.message });
    }
  }
);

// Device Pairing
app.post('/api/v1/device/pair', authenticateToken, async (req, res) => {
  try {
    const { touristId, deviceId, wearableId, wearablePubKey } = req.body;

    // Verify tourist and primary device exist
    const tourist = await Tourist.findOne({ touristId, status: 'active' });
    const primaryDevice = await Device.findOne({
      deviceId,
      touristId,
      status: 'active',
    });

    if (!tourist || !primaryDevice) {
      return res
        .status(404)
        .json({ error: 'Tourist or primary device not found' });
    }

    // Check if wearable already exists
    const existingWearable = await Device.findOne({ deviceId: wearableId });
    if (existingWearable) {
      return res.status(409).json({ error: 'Wearable already registered' });
    }

    const wearableDevice = await Device.create({
      deviceId: wearableId,
      touristId,
      pubKey: wearablePubKey,
      type: 'wearable',
      pairedWith: deviceId,
      status: 'active',
      registeredBy: req.user._id,
    });

    await auditLog('DEVICE_PAIR', req.user._id, {
      touristId,
      deviceId,
      wearableId,
      ip: req.ip,
    });

    res.status(201).json({
      success: true,
      wearableId: wearableDevice.deviceId,
      pairedAt: wearableDevice.createdAt,
    });
  } catch (error) {
    console.error('Device pairing error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Device Status
app.get(
  '/api/v1/device/:deviceId/status',
  authenticateToken,
  async (req, res) => {
    try {
      const { deviceId } = req.params;
      const device = await Device.findOne({ deviceId }).populate(
        'touristId',
        'name'
      );

      if (!device) {
        return res.status(404).json({ error: 'Device not found' });
      }

      // Check authorization - user should own the device or be admin
      if (
        req.user.role !== 'admin' &&
        device.touristId?.toString() !== req.user.touristId
      ) {
        const tourist = await Tourist.findOne({ touristId: device.touristId });
        if (
          !tourist ||
          tourist.registeredBy?.toString() !== req.user._id.toString()
        ) {
          return res.status(403).json({ error: 'Access denied' });
        }
      }

      const timeSinceLastSeen = device.lastSeen
        ? Math.floor((Date.now() - device.lastSeen.getTime()) / 1000)
        : null;

      res.json({
        deviceId: device.deviceId,
        type: device.type,
        status: device.status,
        lastSeen: device.lastSeen,
        timeSinceLastSeenSeconds: timeSinceLastSeen,
        batteryLevel: Math.floor(Math.random() * 100), // Mock - integrate with actual device data
        signalStrength: ['excellent', 'good', 'fair', 'poor'][
          Math.floor(Math.random() * 4)
        ],
        pairedWith: device.pairedWith || null,
      });
    } catch (error) {
      console.error('Device status error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Panic Event Creation
app.post(
  '/api/v1/event/panic',
  verifyDeviceSignature,
  validate(schemas.panicEvent),
  async (req, res) => {
    try {
      const { clientEventId, payload, payloadHash, signature } = req.body;

      // Check for duplicate events using clientEventId
      const existingEvent = await Event.findOne({ clientEventId });
      if (existingEvent) {
        return res.json({
          eventId: existingEvent.eventId,
          blockchainRecord: existingEvent.blockchainRecord,
          eventStorage: existingEvent.eventStorage,
        });
      }

      // Verify payload hash
      const computedHash = hashPayload(payload);
      if (computedHash !== payloadHash) {
        return res.status(400).json({ error: 'Payload hash mismatch' });
      }

      // Verify tourist and device exist
      const tourist = await Tourist.findOne({
        touristId: payload.touristId,
        status: 'active',
      });
      const device = await Device.findOne({
        deviceId: payload.deviceId,
        status: 'active',
      });

      if (!tourist || !device) {
        return res.status(404).json({ error: 'Tourist or device not found' });
      }

      const eventId = generateId('EVT');

      // Call blockchain service
      const blockchainData = await callBlockchainAPI('/event/panic', 'POST', {
        touristId: payload.touristId,
        location: { lat: payload.lat, lon: payload.lon },
        deviceId: payload.deviceId,
        source: device.type,
        panicType: 'manual',
        additionalData: payload.meta || {},
      });

      // Store event in database
      const event = await Event.create({
        eventId,
        clientEventId,
        type: payload.type,
        touristId: payload.touristId,
        deviceId: payload.deviceId,
        location: {
          type: 'Point',
          coordinates: [payload.lon, payload.lat],
        },
        payload,
        payloadHash,
        signature,
        status: 'open',
        priority: payload.type === 'panic' ? 'high' : 'medium',
        blockchainRecord: blockchainData.blockchainRecord,
        eventStorage: blockchainData.eventStorage,
      });

      // Broadcast to connected WebSocket clients
      const broadcastSuccess = broadcastToTourist(payload.touristId, {
        type: 'panic_event_created',
        eventId,
        status: 'anchored',
        location: { lat: payload.lat, lon: payload.lon },
      });

      // Log for emergency response system
      console.log(
        `🚨 PANIC EVENT: ${payload.touristId} at ${payload.lat},${payload.lon} - Event ID: ${eventId}`
      );

      await auditLog('PANIC_EVENT', payload.touristId, {
        eventId,
        location: { lat: payload.lat, lon: payload.lon },
        deviceId: payload.deviceId,
        broadcastSuccess,
      });

      res.status(201).json({
        eventId,
        blockchainRecord: blockchainData.blockchainRecord,
        eventStorage: blockchainData.eventStorage,
        timestamp: event.createdAt,
      });
    } catch (error) {
      console.error('Panic event error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// SMS Fallback Report
app.post('/api/v1/fallback/sms/report', async (req, res) => {
  try {
    const { touristId, message, timestamp } = req.body;

    await auditLog('SMS_FALLBACK', touristId, {
      message: message.substring(0, 100), // Log only first 100 chars for privacy
      reportedAt: timestamp || new Date().toISOString(),
      ip: req.ip,
    });

    res.json({
      success: true,
      reported: true,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('SMS fallback report error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Event Details
app.get('/api/v1/event/:eventId', authenticateToken, async (req, res) => {
  try {
    const { eventId } = req.params;
    const event = await Event.findOne({ eventId })
      .populate('touristId', 'name nationality')
      .populate('deviceId', 'type');

    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    // Authorization check
    if (req.user.role !== 'admin' && req.user.role !== 'police_officer') {
      const tourist = await Tourist.findOne({ touristId: event.touristId });
      if (
        !tourist ||
        tourist.registeredBy?.toString() !== req.user._id.toString()
      ) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    // Verify event integrity with blockchain if requested
    let verification = null;
    if (req.query.verify === 'true') {
      try {
        verification = await callBlockchainAPI('/verify/event', 'POST', {
          eventId,
          originalPayload: event.payload,
        });
      } catch (error) {
        console.warn('Blockchain verification failed:', error.message);
      }
    }

    res.json({
      eventId: event.eventId,
      type: event.type,
      touristId: event.touristId,
      deviceId: event.deviceId,
      location: {
        lat: event.location.coordinates[1],
        lon: event.location.coordinates[0],
      },
      status: event.status,
      priority: event.priority,
      createdAt: event.createdAt,
      updatedAt: event.updatedAt,
      blockchainRecord: event.blockchainRecord,
      verification,
      responseTime: event.responseTime,
      resolvedAt: event.resolvedAt,
    });
  } catch (error) {
    console.error('Event details error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Tourist Events History
app.get(
  '/api/v1/tourist/:touristId/events',
  authenticateToken,
  async (req, res) => {
    try {
      const { touristId } = req.params;
      const { limit = 50, status, type, page = 1 } = req.query;

      // Authorization check
      if (req.user.role !== 'admin' && req.user.role !== 'police_officer') {
        const tourist = await Tourist.findOne({ touristId });
        if (
          !tourist ||
          tourist.registeredBy?.toString() !== req.user._id.toString()
        ) {
          return res.status(403).json({ error: 'Access denied' });
        }
      }

      const query = { touristId };

      if (status) query.status = status;
      if (type) query.type = type;

      const skip = (parseInt(page) - 1) * parseInt(limit);
      const events = await Event.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .select(
          'eventId type status priority location createdAt updatedAt blockchainRecord responseTime'
        );

      const total = await Event.countDocuments(query);

      const eventsWithLocation = events.map((event) => ({
        eventId: event.eventId,
        type: event.type,
        status: event.status,
        priority: event.priority,
        location: {
          lat: event.location.coordinates[1],
          lon: event.location.coordinates[0],
        },
        createdAt: event.createdAt,
        updatedAt: event.updatedAt,
        blockchainTxId: event.blockchainRecord?.id,
        responseTime: event.responseTime,
      }));

      res.json({
        events: eventsWithLocation,
        pagination: {
          current: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit)),
        },
      });
    } catch (error) {
      console.error('Tourist events history error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Itinerary Anchoring
app.post(
  '/api/v1/itinerary/anchor',
  authenticateToken,
  validate(schemas.anchorItinerary),
  async (req, res) => {
    try {
      const { touristId, itinerary } = req.body;

      // Verify tourist exists
      const tourist = await Tourist.findOne({ touristId, status: 'active' });
      if (!tourist) {
        return res.status(404).json({ error: 'Tourist not found' });
      }

      // Authorization check
      if (req.user.role !== 'admin') {
        if (tourist.registeredBy?.toString() !== req.user._id.toString()) {
          return res.status(403).json({ error: 'Access denied' });
        }
      }

      const itineraryId = generateId('ITIN');

      // Call blockchain service
      const blockchainData = await callBlockchainAPI(
        '/itinerary/anchor',
        'POST',
        {
          touristId,
          ...itinerary,
        }
      );

      // Store itinerary in database
      const savedItinerary = await Itinerary.create({
        itineraryId,
        touristId,
        startDate: new Date(itinerary.startDate),
        endDate: new Date(itinerary.endDate),
        locations: itinerary.locations,
        activities: itinerary.activities || [],
        accommodations: itinerary.accommodations || [],
        status: 'active',
        blockchainRecord: blockchainData.blockchainRecord,
        itineraryStorage: blockchainData.itineraryStorage,
        createdBy: req.user._id,
      });

      await auditLog('ITINERARY_ANCHOR', req.user._id, {
        itineraryId,
        touristId,
        locationsCount: itinerary.locations.length,
        ip: req.ip,
      });

      res.status(201).json({
        itineraryId,
        blockchainRecord: blockchainData.blockchainRecord,
        itineraryStorage: blockchainData.itineraryStorage,
        createdAt: savedItinerary.createdAt,
      });
    } catch (error) {
      console.error('Itinerary anchor error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Get Tourist Itineraries
app.get('/api/v1/itinerary/:touristId', authenticateToken, async (req, res) => {
  try {
    const { touristId } = req.params;

    // Authorization check
    if (req.user.role !== 'admin' && req.user.role !== 'police_officer') {
      const tourist = await Tourist.findOne({ touristId });
      if (
        !tourist ||
        tourist.registeredBy?.toString() !== req.user._id.toString()
      ) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    const itineraries = await Itinerary.find({ touristId, status: 'active' })
      .sort({ createdAt: -1 })
      .select('-__v');

    res.json({
      touristId,
      itineraries: itineraries.map((itin) => ({
        itineraryId: itin.itineraryId,
        startDate: itin.startDate,
        endDate: itin.endDate,
        locations: itin.locations,
        activities: itin.activities,
        accommodations: itin.accommodations,
        status: itin.status,
        createdAt: itin.createdAt,
        blockchainTxId: itin.blockchainRecord?.id,
      })),
    });
  } catch (error) {
    console.error('Get itineraries error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Safety Scores - Tourist
app.get(
  '/api/v1/safety/tourist/:touristId',
  authenticateToken,
  async (req, res) => {
    try {
      const { touristId } = req.params;

      // Authorization check
      if (req.user.role !== 'admin' && req.user.role !== 'police_officer') {
        const tourist = await Tourist.findOne({ touristId });
        if (
          !tourist ||
          tourist.registeredBy?.toString() !== req.user._id.toString()
        ) {
          return res.status(403).json({ error: 'Access denied' });
        }
      }

      // Get recent events for scoring
      const recentEvents = await Event.find({
        touristId,
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }, // Last 24 hours
      }).sort({ createdAt: -1 });

      const currentItinerary = await Itinerary.findOne({
        touristId,
        startDate: { $lte: new Date() },
        endDate: { $gte: new Date() },
        status: 'active',
      });

      // Mock safety score calculation (replace with actual AI/ML model)
      let baseScore = 85;

      // Reduce score for recent panic events
      const panicEvents = recentEvents.filter((e) => e.type === 'panic');
      baseScore -= panicEvents.length * 15;

      // Reduce score if deviating from itinerary
      let routeDeviationFactor = 0.8;
      if (!currentItinerary) {
        routeDeviationFactor = 0.6; // No itinerary is riskier
      }

      // Time of day factor (higher risk at night)
      const hour = new Date().getHours();
      const timeOfDayFactor = hour >= 22 || hour <= 6 ? 0.7 : 0.9;

      const finalScore = Math.max(
        0,
        Math.min(
          100,
          Math.floor(baseScore * routeDeviationFactor * timeOfDayFactor)
        )
      );

      const factors = [
        { name: 'routeDeviation', weight: 30, value: routeDeviationFactor },
        { name: 'locationSafety', weight: 25, value: 0.9 },
        { name: 'timeOfDay', weight: 20, value: timeOfDayFactor },
        {
          name: 'recentIncidents',
          weight: 15,
          value: panicEvents.length === 0 ? 1.0 : 0.5,
        },
        { name: 'weatherConditions', weight: 10, value: 0.85 },
      ];

      res.json({
        touristId,
        score: finalScore,
        riskLevel:
          finalScore > 80 ? 'low' : finalScore > 60 ? 'medium' : 'high',
        factors,
        recentEvents: recentEvents.length,
        hasActiveItinerary: !!currentItinerary,
        lastUpdated: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Tourist safety score error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Safety Scores - Place
app.get('/api/v1/safety/place', authenticateToken, async (req, res) => {
  try {
    const { lat, lon, radius = 1000 } = req.query;

    if (!lat || !lon) {
      return res
        .status(400)
        .json({ error: 'Latitude and longitude are required' });
    }

    const latitude = parseFloat(lat);
    const longitude = parseFloat(lon);
    const searchRadius = parseInt(radius);

    // Validate coordinates
    if (
      latitude < -90 ||
      latitude > 90 ||
      longitude < -180 ||
      longitude > 180
    ) {
      return res.status(400).json({ error: 'Invalid coordinates' });
    }

    // Get recent incidents in the area (last 30 days)
    const recentIncidents = await Event.find({
      location: {
        $near: {
          $geometry: { type: 'Point', coordinates: [longitude, latitude] },
          $maxDistance: searchRadius,
        },
      },
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
      type: { $in: ['panic', 'warning'] },
    });

    // Get recent alerts (last 24 hours)
    const recentAlerts = recentIncidents.filter(
      (incident) =>
        incident.createdAt >= new Date(Date.now() - 24 * 60 * 60 * 1000)
    );

    // Calculate place safety score
    let baseScore = 90;
    baseScore -= Math.min(recentIncidents.length * 5, 30); // Max -30 for incidents
    baseScore -= Math.min(recentAlerts.length * 10, 20); // Max -20 for recent alerts

    // Time of day adjustment
    const hour = new Date().getHours();
    if (hour >= 22 || hour <= 6) {
      baseScore -= 10; // Night penalty
    }

    const finalScore = Math.max(0, Math.min(100, baseScore));
    const riskLevel =
      finalScore > 85 ? 'low' : finalScore > 70 ? 'medium' : 'high';

    res.json({
      location: { lat: latitude, lon: longitude },
      radius: searchRadius,
      score: finalScore,
      riskLevel,
      factors: {
        historicalIncidents: recentIncidents.length,
        recentAlerts: recentAlerts.length,
        weatherRisk: 'low', // Mock - integrate with weather API
        crowdDensity: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)], // Mock
        timeOfDay: hour >= 22 || hour <= 6 ? 'high_risk' : 'normal',
      },
      incidents: recentIncidents.map((incident) => ({
        eventId: incident.eventId,
        type: incident.type,
        distance: Math.floor(Math.random() * searchRadius), // Mock distance calculation
        timestamp: incident.createdAt,
      })),
      lastUpdated: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Place safety score error:', error);
    res.status(500).json({ error: error.message });
  }
});

// E-FIR Management
app.post(
  '/api/v1/efir/file',
  authenticateToken,
  authorize('police_officer', 'admin'),
  validate(schemas.fileEFIR),
  async (req, res) => {
    try {
      const {
        eventId,
        touristId,
        policeStation,
        officerId,
        reportDetails,
        attachments,
      } = req.body;

      // Verify event exists
      const event = await Event.findOne({ eventId });
      if (!event) {
        return res.status(404).json({ error: 'Event not found' });
      }

      // Check if E-FIR already exists for this event
      const existingEFIR = await EFIR.findOne({ eventId });
      if (existingEFIR) {
        return res
          .status(409)
          .json({ error: 'E-FIR already filed for this event' });
      }

      const efirId = generateId('EFIR');

      // Call blockchain service
      const blockchainData = await callBlockchainAPI('/efir/file', 'POST', {
        eventId,
        touristId,
        policeStation,
        officerId,
        reportDetails,
        attachments,
      });

      // Store E-FIR in database
      const efir = await EFIR.create({
        efirId,
        eventId,
        touristId,
        policeStation,
        officerId,
        reportDetails,
        attachments,
        status: 'filed',
        blockchainRecord: blockchainData.blockchainRecord,
        efirStorage: blockchainData.efirStorage,
        filedBy: req.user._id,
      });

      // Update event status
      await Event.findOneAndUpdate(
        { eventId },
        {
          status: reportDetails.status.toLowerCase().replace(' ', '_'),
          resolvedAt: reportDetails.status === 'Resolved' ? new Date() : null,
          responseTime: new Date() - event.createdAt,
        }
      );

      await auditLog('EFIR_FILE', req.user._id, {
        efirId,
        eventId,
        touristId,
        policeStation,
        status: reportDetails.status,
        ip: req.ip,
      });

      res.status(201).json({
        efirId,
        blockchainRecord: blockchainData.blockchainRecord,
        efirStorage: blockchainData.efirStorage,
        filedAt: efir.createdAt,
      });
    } catch (error) {
      console.error('E-FIR filing error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Access Management
app.post(
  '/api/v1/access/grant',
  authenticateToken,
  validate(schemas.grantAccess),
  async (req, res) => {
    try {
      const { touristId, targetOrg, scope, expiryHours } = req.body;

      // Verify tourist exists and user has permission
      const tourist = await Tourist.findOne({ touristId, status: 'active' });
      if (!tourist) {
        return res.status(404).json({ error: 'Tourist not found' });
      }

      if (
        req.user.role !== 'admin' &&
        tourist.registeredBy?.toString() !== req.user._id.toString()
      ) {
        return res.status(403).json({ error: 'Access denied' });
      }

      const grantId = generateId('GRT');
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + expiryHours);

      // Call blockchain service (optional for access grants)
      try {
        await callBlockchainAPI('/access/grant', 'POST', {
          touristId,
          targetOrg,
          scope,
          expiryHours,
        });
      } catch (error) {
        console.warn(
          'Blockchain access grant failed (non-critical):',
          error.message
        );
      }

      // Store access grant
      const grant = await AccessGrant.create({
        grantId,
        touristId,
        targetOrg,
        scope,
        expiresAt,
        status: 'active',
        grantedBy: req.user._id,
      });

      await auditLog('ACCESS_GRANT', req.user._id, {
        grantId,
        touristId,
        targetOrg,
        scope,
        expiryHours,
        ip: req.ip,
      });

      res.status(201).json({
        grantId,
        accessGrant: {
          status: 'active',
          expiresAt: expiresAt.toISOString(),
          scope,
        },
      });
    } catch (error) {
      console.error('Access grant error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Consent Management
app.post(
  '/api/v1/tourist/:touristId/consent',
  authenticateToken,
  validate(schemas.updateConsent),
  async (req, res) => {
    try {
      const { touristId } = req.params;
      const { consentType, granted } = req.body;

      const tourist = await Tourist.findOne({ touristId });
      if (!tourist) {
        return res.status(404).json({ error: 'Tourist not found' });
      }

      // Authorization check
      if (
        req.user.role !== 'admin' &&
        tourist.registeredBy?.toString() !== req.user._id.toString()
      ) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // Update consent
      if (granted) {
        if (!tourist.consents.includes(consentType)) {
          tourist.consents.push(consentType);
        }
      } else {
        tourist.consents = tourist.consents.filter((c) => c !== consentType);
      }

      await tourist.save();

      // Call blockchain service for consent record
      try {
        await callBlockchainAPI(`/tourist/${touristId}/consent`, 'POST', {
          consentType,
          granted,
        });
      } catch (error) {
        console.warn('Blockchain consent update failed:', error.message);
      }

      await auditLog('CONSENT_UPDATE', req.user._id, {
        touristId,
        consentType,
        granted,
        ip: req.ip,
      });

      res.json({
        success: true,
        message: 'Consent updated successfully',
        consents: tourist.consents,
      });
    } catch (error) {
      console.error('Consent update error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// WebSocket Stream Endpoint Info
app.get(
  '/api/v1/stream/tourist/:touristId',
  authenticateToken,
  async (req, res) => {
    const { touristId } = req.params;

    // Authorization check
    if (req.user.role !== 'admin') {
      const tourist = await Tourist.findOne({ touristId });
      if (
        !tourist ||
        tourist.registeredBy?.toString() !== req.user._id.toString()
      ) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    res.json({
      message: 'WebSocket endpoint for real-time updates',
      endpoint: `ws://localhost:${
        process.env.PORT || 4000
      }/api/v1/stream/tourist/${touristId}`,
      protocol: 'WebSocket',
      authentication:
        'Include JWT token in connection query: ?token=YOUR_JWT_TOKEN',
      messageTypes: [
        'panic_event_created',
        'event_status_update',
        'safety_score_update',
        'geofence_alert',
        'itinerary_updated',
      ],
    });
  }
);

// Admin Statistics
app.get(
  '/api/v1/admin/stats',
  authenticateToken,
  authorize('admin'),
  async (req, res) => {
    try {
      const [
        totalTourists,
        activeTourists,
        totalDevices,
        activeDevices,
        totalEvents,
        openEvents,
        totalItineraries,
        totalEfirs,
        auditLogCount,
        todayEvents,
      ] = await Promise.all([
        Tourist.countDocuments(),
        Tourist.countDocuments({ status: 'active' }),
        Device.countDocuments(),
        Device.countDocuments({ status: 'active' }),
        Event.countDocuments(),
        Event.countDocuments({ status: 'open' }),
        Itinerary.countDocuments({ status: 'active' }),
        EFIR.countDocuments(),
        AuditLog.countDocuments(),
        Event.countDocuments({
          createdAt: {
            $gte: new Date(new Date().setHours(0, 0, 0, 0)),
          },
        }),
      ]);

      // Get event statistics by type
      const eventsByType = await Event.aggregate([
        { $group: { _id: '$type', count: { $sum: 1 } } },
      ]);

      // Get recent activity
      const recentEvents = await Event.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .select('eventId type touristId status createdAt')
        .populate('touristId', 'name');

      res.json({
        summary: {
          totalTourists,
          activeTourists,
          totalDevices,
          activeDevices,
          totalEvents,
          openEvents,
          todayEvents,
          totalItineraries,
          totalEfirs,
          auditLogEntries: auditLogCount,
        },
        eventsByType: eventsByType.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        activeConnections: wsConnections.size,
        systemHealth: {
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          dbConnection:
            mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        },
        recentActivity: recentEvents.map((event) => ({
          eventId: event.eventId,
          type: event.type,
          touristName: event.touristId?.name || 'Unknown',
          status: event.status,
          createdAt: event.createdAt,
        })),
      });
    } catch (error) {
      console.error('Admin stats error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Audit Logs (Admin only)
app.get(
  '/api/v1/admin/audit-logs',
  authenticateToken,
  authorize('admin'),
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        action,
        userId,
        startDate,
        endDate,
      } = req.query;

      const query = {};
      if (action) query.action = new RegExp(action, 'i');
      if (userId) query.userId = userId;
      if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) query.timestamp.$gte = new Date(startDate);
        if (endDate) query.timestamp.$lte = new Date(endDate);
      }

      const skip = (parseInt(page) - 1) * parseInt(limit);
      const logs = await AuditLog.find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .populate('userId', 'email role');

      const total = await AuditLog.countDocuments(query);

      res.json({
        logs: logs.map((log) => ({
          id: log._id,
          action: log.action,
          user: log.userId
            ? {
                email: log.userId.email,
                role: log.userId.role,
              }
            : null,
          data: log.data,
          ipAddress: log.ipAddress,
          timestamp: log.timestamp,
        })),
        pagination: {
          current: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit)),
        },
      });
    } catch (error) {
      console.error('Audit logs error:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Geo-fence Engine (Mock Implementation)
const geoFenceEngine = {
  checkBoundary: async (lat, lon, touristId) => {
    try {
      // Get tourist's active itinerary
      const itinerary = await Itinerary.findOne({
        touristId,
        startDate: { $lte: new Date() },
        endDate: { $gte: new Date() },
        status: 'active',
      });

      // Define safe zones (in a real implementation, this would come from a database)
      const safeZones = [
        {
          name: 'Jaipur City Center',
          lat: 26.9124,
          lon: 75.7873,
          radius: 10000,
        },
        { name: 'Tourist Area', lat: 26.8851, lon: 75.8144, radius: 5000 },
        { name: 'Airport Zone', lat: 26.8242, lon: 75.812, radius: 3000 },
      ];

      // Add itinerary locations as safe zones if available
      if (itinerary) {
        // This is a simplified implementation - in reality you'd geocode the location names
        safeZones.push({
          name: 'Planned Route',
          lat: lat, // Current location is safe if following itinerary
          lon: lon,
          radius: 2000,
        });
      }

      const isWithinSafeZone = safeZones.some((zone) => {
        const distance = calculateDistance(lat, lon, zone.lat, zone.lon);
        return distance <= zone.radius;
      });

      return {
        isWithinSafeZone,
        nearestZone: safeZones.reduce((nearest, zone) => {
          const distance = calculateDistance(lat, lon, zone.lat, zone.lon);
          return !nearest || distance < nearest.distance
            ? { ...zone, distance }
            : nearest;
        }, null),
        hasActiveItinerary: !!itinerary,
      };
    } catch (error) {
      console.error('Geofence check error:', error);
      return { isWithinSafeZone: true, nearestZone: null }; // Fail safe
    }
  },
};

const calculateDistance = (lat1, lon1, lat2, lon2) => {
  const R = 6371e3; // Earth's radius in meters
  const φ1 = (lat1 * Math.PI) / 180;
  const φ2 = (lat2 * Math.PI) / 180;
  const Δφ = ((lat2 - lat1) * Math.PI) / 180;
  const Δλ = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
};

// Geofence Check Endpoint
app.post('/api/v1/geofence/check', authenticateToken, async (req, res) => {
  try {
    const { lat, lon, touristId } = req.body;

    if (!lat || !lon || !touristId) {
      return res
        .status(400)
        .json({ error: 'lat, lon, and touristId are required' });
    }

    const result = await geoFenceEngine.checkBoundary(lat, lon, touristId);

    if (!result.isWithinSafeZone) {
      // Log geofence violation
      await auditLog('GEOFENCE_VIOLATION', touristId, {
        location: { lat, lon },
        nearestZone: result.nearestZone?.name,
        distance: result.nearestZone?.distance,
      });

      // Broadcast alert to WebSocket connections
      broadcastToTourist(touristId, {
        type: 'geofence_alert',
        alert: 'Outside safe zone',
        location: { lat, lon },
        nearestZone: result.nearestZone,
      });
    }

    res.json(result);
  } catch (error) {
    console.error('Geofence check error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Global Error Handling Middleware
app.use((error, req, res, next) => {
  console.error('API Error:', error);

  // Log error to audit system
  auditLog('API_ERROR', req.user?._id || null, {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
  });

  // Mongoose validation error
  if (error.name === 'ValidationError') {
    const errors = Object.values(error.errors).map((err) => ({
      field: err.path,
      message: err.message,
    }));
    return res.status(400).json({
      error: 'Validation error',
      details: errors,
    });
  }

  // Mongoose duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(409).json({
      error: 'Duplicate entry',
      field,
      message: `${field} already exists`,
    });
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Default error
  res.status(error.statusCode || 500).json({
    error: error.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack }),
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    method: req.method,
    url: req.originalUrl,
  });
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    mongoose.connection.close(() => {
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    mongoose.connection.close(() => {
      process.exit(0);
    });
  });
});

// Start server
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`🚀 Tourist Safety Backend API running on port ${PORT}`);
  console.log(`📊 WebSocket server running for real-time updates`);
  console.log(`🔗 Blockchain API URL: ${BLOCKCHAIN_API_URL}`);
  console.log(`🗄️  MongoDB URL: ${MONGODB_URI}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
