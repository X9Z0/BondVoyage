// backend/services/fabricService.js
// Node.js Backend Service for Hyperledger Fabric Integration

'use strict';
// fabric-network fabric-ca-client crypto
import { Gateway, Wallets } from 'fabric-network';
import FabricCAServices from 'fabric-ca-client';
import { resolve, join } from 'path';
import { readFileSync } from 'fs';
import { createHash } from 'crypto';

import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class FabricService {
  constructor() {
    this.gateway = null;
    this.network = null;
    this.contract = null;
    this.wallet = null;
    this.connectionProfile = null;
  }

  // Initialize the Fabric connection
  async initialize() {
    try {
      // Load connection profile (network configuration)
      const ccpPath = resolve(
        __dirname,
        '..',
        'config',
        'connection-org1.json'
      );
      const ccp = JSON.parse(readFileSync(ccpPath, 'utf8'));
      this.connectionProfile = ccp;

      // Create wallet for managing identities
      const walletPath = join(process.cwd(), 'wallet');
      this.wallet = await Wallets.newFileSystemWallet(walletPath);

      // Check if admin identity exists, if not enroll
      const adminIdentity = await this.wallet.get('admin');
      if (!adminIdentity) {
        await this.enrollAdmin();
      }

      // Connect to the gateway
      this.gateway = new Gateway();
      await this.gateway.connect(ccp, {
        wallet: this.wallet,
        identity: 'admin',
        discovery: { enabled: true, asLocalhost: true },
        eventHandlerOptions: { commitTimeout: 100 },
        // Add this for local TLS override
        // clientTlsIdentity: 'admin',
        grpcOptions: {
          'grpc.ssl-target-name-override': 'peer0.org1.example.com',
          'grpc.default_authority': 'peer0.org1.example.com',
          'grpc.keepalive_time_ms': 60000,
        },
      });

      // Get the network channel
      this.network = await this.gateway.getNetwork('mychannel');

      // Get the smart contract
      this.contract = this.network.getContract('tourist-chaincode');

      console.log('✅ Fabric service initialized successfully');
    } catch (error) {
      console.error(`❌ Failed to initialize Fabric service: ${error}`);
      throw error;
    }
  }

  // Enroll admin user
  async enrollAdmin() {
    try {
      const caInfo =
        this.connectionProfile.certificateAuthorities['ca.org1.example.com'];
      const caTLSCACerts = caInfo.tlsCACerts.pem;
      const ca = new FabricCAServices(
        caInfo.url,
        {
          trustedRoots: caTLSCACerts,
          verify: false,
        },
        caInfo.caName
      );

      // Enroll the admin user
      const enrollment = await ca.enroll({
        enrollmentID: 'admin',
        enrollmentSecret: 'adminpw',
      });

      // Create identity
      const x509Identity = {
        credentials: {
          certificate: enrollment.certificate,
          privateKey: enrollment.key.toBytes(),
        },
        mspId: 'Org1MSP',
        type: 'X.509',
      };

      // Import identity to wallet
      await this.wallet.put('admin', x509Identity);
      console.log('✅ Successfully enrolled admin user and imported to wallet');
    } catch (error) {
      console.error(`❌ Failed to enroll admin: ${error}`);
      throw error;
    }
  }

  // Register a new user
  async registerUser(userId, affiliation = 'org1.department1') {
    try {
      const userIdentity = await this.wallet.get(userId);
      if (userIdentity) {
        console.log(`User ${userId} already exists`);
        return;
      }

      // Get admin identity
      const adminIdentity = await this.wallet.get('admin');
      if (!adminIdentity) {
        throw new Error('Admin identity not found. Run enrollAdmin first');
      }

      // Build user object for CA
      const provider = this.wallet
        .getProviderRegistry()
        .getProvider(adminIdentity.type);
      const adminUser = await provider.getUserContext(adminIdentity, 'admin');

      // Get CA client
      const caInfo =
        this.connectionProfile.certificateAuthorities['ca.org1.example.com'];
      const caTLSCACerts = caInfo.tlsCACerts.pem;
      const ca = new FabricCAServices(
        caInfo.url,
        {
          trustedRoots: caTLSCACerts,
          verify: false,
        },
        caInfo.caName
      );

      // Register user
      const secret = await ca.register(
        {
          affiliation: affiliation,
          enrollmentID: userId,
          role: 'client',
        },
        adminUser
      );

      // Enroll user
      const enrollment = await ca.enroll({
        enrollmentID: userId,
        enrollmentSecret: secret,
      });

      // Create identity
      const x509Identity = {
        credentials: {
          certificate: enrollment.certificate,
          privateKey: enrollment.key.toBytes(),
        },
        mspId: 'Org1MSP',
        type: 'X.509',
      };

      // Import identity to wallet
      await this.wallet.put(userId, x509Identity);
      console.log(`✅ Successfully registered user ${userId}`);

      return { userId, certificate: enrollment.certificate };
    } catch (error) {
      console.error(`❌ Failed to register user ${userId}: ${error}`);
      throw error;
    }
  }

  // Tourist Registration
  async registerTourist(touristData) {
    try {
      const { touristId, kycDocument, nationality, passportNumber } =
        touristData;

      // Hash the KYC document
      const kycHash = this.hashDocument(kycDocument);
      const passportHash = this.hashData(passportNumber);

      // Submit transaction to blockchain
      const result = await this.contract.submitTransaction(
        'registerTourist',
        touristId,
        kycHash,
        nationality,
        passportHash
      );

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to register tourist: ${error}`);
      throw error;
    }
  }

  // Anchor panic event
  async anchorPanicEvent(eventData) {
    try {
      const { eventId, touristId, eventPayload, source, deviceId, location } =
        eventData;

      // Hash the event payload
      const payloadHash = this.hashDocument(JSON.stringify(eventPayload));

      // Submit transaction
      const result = await this.contract.submitTransaction(
        'anchorEvent',
        eventId,
        touristId,
        'panic',
        payloadHash,
        source,
        deviceId,
        location.lat.toString(),
        location.lon.toString()
      );

      // Listen for event
      this.listenForEvents();

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to anchor panic event: ${error}`);
      throw error;
    }
  }

  // Anchor anomaly event
  async anchorAnomalyEvent(anomalyData) {
    try {
      const { eventId, touristId, anomalyDetails, source, deviceId, location } =
        anomalyData;

      const payloadHash = this.hashDocument(JSON.stringify(anomalyDetails));

      const result = await this.contract.submitTransaction(
        'anchorEvent',
        eventId,
        touristId,
        'anomaly',
        payloadHash,
        source,
        deviceId,
        location.lat.toString(),
        location.lon.toString()
      );

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to anchor anomaly event: ${error}`);
      throw error;
    }
  }

  // File E-FIR
  async fileEFIR(efirData) {
    try {
      const {
        efirId,
        eventId,
        touristId,
        policeStation,
        officerId,
        reportDocument,
      } = efirData;

      const reportHash = this.hashDocument(reportDocument);

      const result = await this.contract.submitTransaction(
        'anchorEFIR',
        efirId,
        eventId,
        touristId,
        policeStation,
        officerId,
        reportHash
      );

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to file E-FIR: ${error}`);
      throw error;
    }
  }

  // Update tourist consent
  async updateTouristConsent(touristId, consentType, granted) {
    try {
      const result = await this.contract.submitTransaction(
        'updateConsent',
        touristId,
        consentType,
        granted.toString()
      );

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to update consent: ${error}`);
      throw error;
    }
  }

  // Grant access to organization
  async grantAccess(accessData) {
    try {
      const { grantId, touristId, targetOrg, scope, expiryHours } = accessData;

      const result = await this.contract.submitTransaction(
        'grantAccess',
        grantId,
        touristId,
        targetOrg,
        scope.join(','),
        expiryHours.toString()
      );

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to grant access: ${error}`);
      throw error;
    }
  }

  // Anchor itinerary
  async anchorItinerary(itineraryData) {
    try {
      const {
        itineraryId,
        touristId,
        itineraryDocument,
        startDate,
        endDate,
        locations,
      } = itineraryData;

      const itineraryHash = this.hashDocument(itineraryDocument);

      const result = await this.contract.submitTransaction(
        'anchorItinerary',
        itineraryId,
        touristId,
        itineraryHash,
        startDate,
        endDate,
        JSON.stringify(locations)
      );

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to anchor itinerary: ${error}`);
      throw error;
    }
  }

  // Anchor merkle root for batch verification
  async anchorMerkleRoot(events) {
    try {
      const rootId = `ROOT_${Date.now()}`;
      const merkleRoot = this.calculateMerkleRoot(events);
      const startTime = events[0].timestamp;
      const endTime = events[events.length - 1].timestamp;

      const result = await this.contract.submitTransaction(
        'anchorMerkleRoot',
        rootId,
        merkleRoot,
        events.length.toString(),
        startTime,
        endTime
      );

      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to anchor merkle root: ${error}`);
      throw error;
    }
  }

  // Query functions
  async getTourist(touristId) {
    try {
      const result = await this.contract.evaluateTransaction(
        'readTourist',
        touristId
      );
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to query tourist: ${error}`);
      throw error;
    }
  }

  async getEvent(eventId) {
    try {
      const result = await this.contract.evaluateTransaction(
        'queryEvent',
        eventId
      );
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to query event: ${error}`);
      throw error;
    }
  }

  async getEFIR(efirId) {
    try {
      const result = await this.contract.evaluateTransaction(
        'queryEFIR',
        efirId
      );
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to query E-FIR: ${error}`);
      throw error;
    }
  }

  async getTouristEvents(touristId) {
    try {
      const result = await this.contract.evaluateTransaction(
        'getTouristEvents',
        touristId
      );
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to get tourist events: ${error}`);
      throw error;
    }
  }

  async getActiveGrants(touristId) {
    try {
      const result = await this.contract.evaluateTransaction(
        'getActiveGrants',
        touristId
      );
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to get active grants: ${error}`);
      throw error;
    }
  }

  async getAuditHistory(touristId) {
    try {
      const result = await this.contract.evaluateTransaction(
        'getAuditHistory',
        touristId
      );
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`❌ Failed to get audit history: ${error}`);
      throw error;
    }
  }

  // Event listeners
  async listenForEvents() {
    try {
      // Listen for critical events
      await this.contract.addContractListener(
        'critical-event-listener',
        'CriticalEvent',
        (err, event, blockNumber, transactionId, status) => {
          if (err) {
            console.error(err);
            return;
          }

          const eventData = JSON.parse(event.payload.toString());
          console.log(
            `🚨 Critical Event: ${eventData.eventType} for tourist ${eventData.touristId}`
          );

          // Trigger alert mechanisms
          this.handleCriticalEvent(eventData);
        }
      );

      // Listen for E-FIR events
      await this.contract.addContractListener(
        'efir-listener',
        'EFIRFiled',
        (err, event, blockNumber, transactionId, status) => {
          if (err) {
            console.error(err);
            return;
          }

          const eventData = JSON.parse(event.payload.toString());
          console.log(
            `📋 E-FIR Filed: ${eventData.efirId} for tourist ${eventData.touristId}`
          );
        }
      );

      console.log('✅ Event listeners registered');
    } catch (error) {
      console.error(`❌ Failed to register event listeners: ${error}`);
      throw error;
    }
  }

  // Handle critical events
  async handleCriticalEvent(eventData) {
    // This would integrate with your notification system
    // Send alerts to police dashboard, family members, etc.
    console.log('Handling critical event:', eventData);

    // Example: Send to message queue for processing
    // await messageQueue.publish('critical-events', eventData);
  }

  // Utility functions
  hashDocument(document) {
    return createHash('sha256').update(document).digest('hex');
  }

  hashData(data) {
    return createHash('sha256').update(data).digest('hex');
  }

  calculateMerkleRoot(events) {
    // Simple merkle root calculation
    let hashes = events.map((e) => this.hashDocument(JSON.stringify(e)));

    while (hashes.length > 1) {
      const newHashes = [];
      for (let i = 0; i < hashes.length; i += 2) {
        const left = hashes[i];
        const right = hashes[i + 1] || hashes[i];
        const combined = createHash('sha256')
          .update(left + right)
          .digest('hex');
        newHashes.push(combined);
      }
      hashes = newHashes;
    }

    return hashes[0];
  }

  // Verify event integrity
  async verifyEventIntegrity(eventId, originalPayload) {
    try {
      const event = await this.getEvent(eventId);
      const computedHash = this.hashDocument(JSON.stringify(originalPayload));

      return {
        valid: event.payloadHash === computedHash,
        storedHash: event.payloadHash,
        computedHash: computedHash,
        timestamp: event.timestamp,
      };
    } catch (error) {
      console.error(`❌ Failed to verify event integrity: ${error}`);
      throw error;
    }
  }

  // Disconnect from the network
  async disconnect() {
    if (this.gateway) {
      await this.gateway.disconnect();
      console.log('✅ Disconnected from Fabric network');
    }
  }
}

export default FabricService;
