// backend/routes/blockchainRoutes.js
// Express routes for blockchain operations

'use strict';

import { Router } from 'express';
const router = Router();
import FabricService from '../services/fabricService';
import LocalStorageService from '../services/localStorageService';
import { v4 as uuidv4 } from 'uuid';

// Initialize services
const fabricService = new FabricService();
const storageService = new LocalStorageService({
  // MinIO configuration (S3 alternative)
  minio: {
    endPoint: process.env.MINIO_ENDPOINT || 'localhost',
    port: parseInt(process.env.MINIO_PORT) || 9000,
    useSSL: process.env.MINIO_USE_SSL === 'true',
    accessKey: process.env.MINIO_ACCESS_KEY || 'minioadmin',
    secretKey: process.env.MINIO_SECRET_KEY || 'minioadmin123',
  },
  bucketName: process.env.MINIO_BUCKET_NAME || 'tourist-safety-encrypted',

  // Vault configuration (KMS alternative)
  vault: {
    endpoint: process.env.VAULT_ENDPOINT || 'http://localhost:8200',
    token: process.env.VAULT_TOKEN || 'myroot',
    mountPath: process.env.VAULT_MOUNT_PATH || 'transit',
  },

  // Fallback to file system if needed
  useFileSystem: process.env.USE_LOCAL_STORAGE === 'true',
  localStoragePath: process.env.LOCAL_STORAGE_PATH || './encrypted_storage',
});

// Middleware for authentication
const authenticate = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  // TODO: Implement proper JWT token verification
  // For MVP, we'll allow all requests
  req.user = { id: 'test-user', role: 'tourist' };
  next();
};

// Middleware for role-based access control
const authorize = (roles) => {
  return (req, res, next) => {
    const userRole = req.user?.role || 'tourist';
    if (!roles.includes(userRole)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Initialize Fabric connection
router.post('/initialize', async (req, res) => {
  try {
    await fabricService.initialize();

    // Also check storage service health
    const storageHealth = await storageService.healthCheck();

    res.json({
      success: true,
      message: 'Blockchain service initialized',
      storage: storageHealth,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Register tourist with KYC
router.post('/tourist/register', authenticate, async (req, res) => {
  try {
    const { touristId, name, nationality, passportNumber, kycDocuments } =
      req.body;

    // Validate required fields
    if (!touristId || !name || !nationality || !passportNumber) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
      });
    }

    // Store KYC documents off-chain using local storage service
    const kycStorage = await storageService.storeKYCDocument(
      touristId,
      {
        name,
        passportNumber,
        kycDocuments,
        uploadedAt: new Date().toISOString(),
      },
      { nationality }
    );

    // Register tourist on blockchain
    const blockchainResult = await fabricService.registerTourist({
      touristId,
      kycDocument: kycStorage.documentHash,
      nationality,
      passportNumber,
    });

    res.json({
      success: true,
      touristId,
      blockchainRecord: blockchainResult,
      kycStorage: {
        storageKey: kycStorage.storageKey,
        documentHash: kycStorage.documentHash,
        timestamp: kycStorage.timestamp,
        encryptionMethod: kycStorage.encryptionMethod,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Anchor panic event
router.post('/event/panic', authenticate, async (req, res) => {
  try {
    const { touristId, location, deviceId, source, panicType, additionalData } =
      req.body;

    // Validate required fields
    if (!touristId || !location || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: touristId, location, deviceId',
      });
    }

    const eventId = `EVT_${uuidv4()}`;
    const eventPayload = {
      type: 'panic',
      touristId,
      deviceId,
      source: source || 'phone',
      panicType: panicType || 'manual',
      location,
      additionalData,
      timestamp: new Date().toISOString(),
    };

    // Store full event payload off-chain using local storage
    const eventStorage = await storageService.storeEventPayload(
      eventId,
      eventPayload
    );

    // Anchor event on blockchain
    const blockchainResult = await fabricService.anchorPanicEvent({
      eventId,
      touristId,
      eventPayload,
      source: source || 'phone',
      deviceId,
      location,
    });

    res.json({
      success: true,
      eventId,
      blockchainRecord: blockchainResult,
      eventStorage: {
        storageKey: eventStorage.storageKey,
        payloadHash: eventStorage.payloadHash,
        timestamp: eventStorage.timestamp,
        encryptionMethod: eventStorage.encryptionMethod,
      },
    });
  } catch (error) {
    console.error('Panic event error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Anchor anomaly event
router.post('/event/anomaly', authenticate, async (req, res) => {
  try {
    const {
      touristId,
      anomalyType,
      anomalyScore,
      location,
      deviceId,
      source,
      details,
    } = req.body;

    if (!touristId || !anomalyType || !location) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: touristId, anomalyType, location',
      });
    }

    const eventId = `ANO_${uuidv4()}`;
    const anomalyDetails = {
      type: 'anomaly',
      anomalyType,
      anomalyScore: anomalyScore || 0.5,
      touristId,
      location,
      deviceId,
      source: source || 'system',
      details,
      timestamp: new Date().toISOString(),
    };

    // Store anomaly details off-chain
    const eventStorage = await storageService.storeEventPayload(
      eventId,
      anomalyDetails
    );

    // Anchor on blockchain
    const blockchainResult = await fabricService.anchorAnomalyEvent({
      eventId,
      touristId,
      anomalyDetails,
      source: source || 'system',
      deviceId,
      location,
    });

    res.json({
      success: true,
      eventId,
      blockchainRecord: blockchainResult,
      eventStorage: {
        storageKey: eventStorage.storageKey,
        payloadHash: eventStorage.payloadHash,
        encryptionMethod: eventStorage.encryptionMethod,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// File E-FIR
router.post(
  '/efir/file',
  authenticate,
  authorize(['police', 'admin']),
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

      if (!eventId || !touristId || !policeStation || !officerId) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields for E-FIR',
        });
      }

      const efirId = `EFIR_${uuidv4()}`;
      const reportDocument = {
        efirId,
        eventId,
        touristId,
        policeStation,
        officerId,
        reportDetails,
        attachments: attachments || [],
        filedAt: new Date().toISOString(),
      };

      // Store E-FIR document off-chain
      const efirStorage = await storageService.storeEventPayload(
        efirId,
        reportDocument
      );

      // Anchor E-FIR on blockchain
      const blockchainResult = await fabricService.fileEFIR({
        efirId,
        eventId,
        touristId,
        policeStation,
        officerId,
        reportDocument: JSON.stringify(reportDocument),
      });

      res.json({
        success: true,
        efirId,
        blockchainRecord: blockchainResult,
        efirStorage: {
          storageKey: efirStorage.storageKey,
          reportHash: efirStorage.payloadHash,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

// Update consent
router.post('/tourist/:touristId/consent', authenticate, async (req, res) => {
  try {
    const { touristId } = req.params;
    const { consentType, granted } = req.body;

    if (!consentType || typeof granted !== 'boolean') {
      return res.status(400).json({
        success: false,
        error: 'Missing consentType or granted boolean value',
      });
    }

    const result = await fabricService.updateTouristConsent(
      touristId,
      consentType,
      granted
    );

    res.json({
      success: true,
      touristId,
      consentUpdate: result,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Grant access to organization
router.post(
  '/access/grant',
  authenticate,
  authorize(['admin', 'police']),
  async (req, res) => {
    try {
      const { touristId, targetOrg, scope, expiryHours } = req.body;

      if (!touristId || !targetOrg || !scope) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: touristId, targetOrg, scope',
        });
      }

      const grantId = `GRT_${uuidv4()}`;

      const result = await fabricService.grantAccess({
        grantId,
        touristId,
        targetOrg,
        scope: Array.isArray(scope) ? scope : [scope],
        expiryHours: expiryHours || 24,
      });

      res.json({
        success: true,
        grantId,
        accessGrant: result,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

// Anchor itinerary
router.post('/itinerary/anchor', authenticate, async (req, res) => {
  try {
    const {
      touristId,
      startDate,
      endDate,
      locations,
      activities,
      accommodations,
    } = req.body;

    if (!touristId || !startDate || !endDate || !locations) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields for itinerary',
      });
    }

    const itineraryId = `ITIN_${uuidv4()}`;
    const itineraryData = {
      itineraryId,
      touristId,
      startDate,
      endDate,
      locations,
      activities: activities || [],
      accommodations: accommodations || [],
      createdAt: new Date().toISOString(),
    };

    // Store full itinerary off-chain
    const itineraryStorage = await storageService.storeItinerary(
      itineraryId,
      touristId,
      itineraryData
    );

    // Anchor itinerary on blockchain
    const blockchainResult = await fabricService.anchorItinerary({
      itineraryId,
      touristId,
      itineraryDocument: JSON.stringify(itineraryData),
      startDate,
      endDate,
      locations,
    });

    res.json({
      success: true,
      itineraryId,
      blockchainRecord: blockchainResult,
      itineraryStorage: {
        storageKey: itineraryStorage.storageKey,
        itineraryHash: itineraryStorage.itineraryHash,
        encryptionMethod: itineraryStorage.encryptionMethod,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Anchor merkle root for batch verification
router.post(
  '/merkle/anchor',
  authenticate,
  authorize(['admin']),
  async (req, res) => {
    try {
      const { events } = req.body;

      if (!events || !Array.isArray(events) || events.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'Events array is required',
        });
      }

      const result = await fabricService.anchorMerkleRoot(events);

      res.json({
        success: true,
        merkleRoot: result,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

// Query Routes

// Get tourist information
router.get('/tourist/:touristId', authenticate, async (req, res) => {
  try {
    const { touristId } = req.params;

    const tourist = await fabricService.getTourist(touristId);

    res.json({
      success: true,
      tourist,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Get event details
router.get('/event/:eventId', authenticate, async (req, res) => {
  try {
    const { eventId } = req.params;

    const event = await fabricService.getEvent(eventId);

    res.json({
      success: true,
      event,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Get E-FIR details
router.get(
  '/efir/:efirId',
  authenticate,
  authorize(['police', 'admin']),
  async (req, res) => {
    try {
      const { efirId } = req.params;

      const efir = await fabricService.getEFIR(efirId);

      res.json({
        success: true,
        efir,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

// Get all events for a tourist
router.get('/tourist/:touristId/events', authenticate, async (req, res) => {
  try {
    const { touristId } = req.params;

    const events = await fabricService.getTouristEvents(touristId);

    res.json({
      success: true,
      touristId,
      events,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Get active access grants for a tourist
router.get('/tourist/:touristId/grants', authenticate, async (req, res) => {
  try {
    const { touristId } = req.params;

    const grants = await fabricService.getActiveGrants(touristId);

    res.json({
      success: true,
      touristId,
      grants,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Get audit history for a tourist
router.get(
  '/tourist/:touristId/audit',
  authenticate,
  authorize(['admin', 'police']),
  async (req, res) => {
    try {
      const { touristId } = req.params;

      const auditHistory = await fabricService.getAuditHistory(touristId);

      res.json({
        success: true,
        touristId,
        auditHistory,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

// Verify event integrity
router.post('/verify/event', authenticate, async (req, res) => {
  try {
    const { eventId, originalPayload } = req.body;

    if (!eventId || !originalPayload) {
      return res.status(400).json({
        success: false,
        error: 'eventId and originalPayload are required',
      });
    }

    const verification = await fabricService.verifyEventIntegrity(
      eventId,
      originalPayload
    );

    res.json({
      success: true,
      eventId,
      verification,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Delete tourist data (GDPR compliance)
router.delete(
  '/tourist/:touristId',
  authenticate,
  authorize(['admin']),
  async (req, res) => {
    try {
      const { touristId } = req.params;

      // Delete off-chain data using local storage service
      const deletionResult = await storageService.deleteTouristData(touristId);

      // Note: We don't delete blockchain data as it provides immutable audit trail
      // Only off-chain PII is deleted for GDPR compliance

      res.json({
        success: true,
        touristId,
        deletionResult,
        note: 'Off-chain data deleted. Blockchain hashes preserved for audit trail.',
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

// Health check
router.get('/health', async (req, res) => {
  try {
    const isHealthy = fabricService.contract !== null;

    // Check storage health
    let storageHealth = 'unknown';
    try {
      const health = await storageService.healthCheck();
      storageHealth = health.storage;
    } catch (error) {
      storageHealth = 'unhealthy';
    }

    res.json({
      success: true,
      blockchain: isHealthy ? 'healthy' : 'initializing',
      storage: storageHealth,
      services: {
        fabric: isHealthy,
        storageType: storageService.useFileSystem ? 'filesystem' : 'minio',
        encryption: storageService.vaultClient ? 'vault' : 'local',
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Add storage stats endpoint
router.get(
  '/storage/stats',
  authenticate,
  authorize(['admin']),
  async (req, res) => {
    try {
      const stats = await storageService.getStorageStats();
      res.json({
        success: true,
        stats,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

export default router;
