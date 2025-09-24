// backend/tests/blockchain.test.js
// Unit tests for blockchain functionality

'use strict';

import { expect } from 'chai';
import { createSandbox } from 'sinon';
import FabricService from '../services/fabricService.js';
import LocalStorageService from '../services/localStorageService.js'; // FIXED: Changed import

describe('Blockchain Integration Tests', function () {
  this.timeout(10000);

  let fabricService;
  let storageService;
  let sandbox;

  beforeEach(() => {
    sandbox = createSandbox();

    fabricService = new FabricService();

    // FIXED: Use LocalStorageService with proper config
    storageService = new LocalStorageService({
      useFileSystem: true,
      localStoragePath: './test_storage',
      // Disable external services for testing
      minio: null,
      vault: null,
    });

    // Mock fabric network calls for testing
    sandbox.stub(fabricService, 'initialize').resolves();
    // FIXED: Mock contract property properly
    fabricService.contract = {
      submitTransaction: sandbox.stub().resolves('{}'),
    };
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('Tourist Registration', () => {
    it('should register a tourist with KYC', async () => {
      const touristData = {
        touristId: 'T-TEST-001',
        kycDocument: 'test-kyc-data',
        nationality: 'Indian',
        passportNumber: 'A1234567',
      };

      // Mock the hash calculation
      sandbox.stub(fabricService, 'hashDocument').returns('test-hash');

      const result = await fabricService.registerTourist(touristData);

      expect(result).to.be.an('object');
      expect(fabricService.contract.submitTransaction).to.have.been.calledOnce;
    });

    it('should handle registration errors', async () => {
      fabricService.contract.submitTransaction.rejects(
        new Error('Network error')
      );

      const touristData = {
        touristId: 'T-TEST-002',
        kycDocument: 'test-kyc-data',
        nationality: 'Indian',
        passportNumber: 'A1234567',
      };

      try {
        await fabricService.registerTourist(touristData);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).to.include('Network error');
      }
    });
  });

  describe('Event Anchoring', () => {
    it('should anchor a panic event', async () => {
      const eventData = {
        eventId: 'EVT-TEST-001',
        touristId: 'T-TEST-001',
        eventPayload: { type: 'panic', timestamp: new Date().toISOString() },
        source: 'phone',
        deviceId: 'D-001',
        location: { lat: 26.9124, lon: 75.7873 },
      };

      const result = await fabricService.anchorPanicEvent(eventData);
      expect(result).to.be.an('object');
    });

    it('should verify event integrity', async () => {
      const eventId = 'EVT-TEST-001';
      const originalPayload = { type: 'panic', data: 'test' };

      // Mock the event retrieval
      sandbox.stub(fabricService, 'getEvent').resolves({
        payloadHash: fabricService.hashDocument(
          JSON.stringify(originalPayload)
        ),
        timestamp: new Date().toISOString(),
      });

      const verification = await fabricService.verifyEventIntegrity(
        eventId,
        originalPayload
      );

      expect(verification.valid).to.be.true;
    });
  });

  describe('Local Storage Service', () => {
    it('should store and retrieve KYC documents', async () => {
      const touristId = 'T-TEST-001';
      const kycDocument = {
        name: 'Test Tourist',
        passport: 'A1234567',
        documents: ['passport.pdf', 'visa.pdf'],
      };

      // Store document
      const storageResult = await storageService.storeKYCDocument(
        touristId,
        kycDocument
      );

      expect(storageResult).to.have.property('documentHash');
      expect(storageResult).to.have.property('storageKey');
      expect(storageResult).to.have.property('encryptionMethod'); // LocalStorageService returns this

      // Retrieve document - FIXED: LocalStorageService doesn't use encryptedKeyId the same way
      const retrieved = await storageService.retrieveKYCDocument(
        storageResult.storageKey
      );

      expect(retrieved.document).to.deep.equal(kycDocument);
    });

    it('should store and retrieve event payloads', async () => {
      const eventId = 'EVT-TEST-001';
      const eventData = {
        type: 'panic',
        touristId: 'T-TEST-001',
        timestamp: new Date().toISOString(),
        location: { lat: 26.9124, lon: 75.7873 },
      };

      // Store event
      const storageResult = await storageService.storeEventPayload(
        eventId,
        eventData
      );

      expect(storageResult).to.have.property('payloadHash');
      expect(storageResult).to.have.property('storageKey');

      // Retrieve event
      const retrieved = await storageService.retrieveEventPayload(
        storageResult.storageKey
      );

      expect(retrieved.eventData).to.deep.equal(eventData);
    });

    it('should delete tourist data for GDPR compliance', async () => {
      const touristId = 'T-TEST-DELETE';

      // First store some data
      await storageService.storeKYCDocument(touristId, { test: 'data' });

      // Then delete it
      const deleteResult = await storageService.deleteTouristData(touristId);
      expect(deleteResult.success).to.be.true;
    });

    it('should perform health check', async () => {
      const health = await storageService.healthCheck();

      expect(health).to.have.property('storage');
      expect(health).to.have.property('encryption');
      expect(health).to.have.property('timestamp');
    });
  });

  describe('Storage Service Fallbacks', () => {
    it('should fallback to local encryption when Vault unavailable', async () => {
      // Create service without Vault
      const localOnlyService = new LocalStorageService({
        useFileSystem: true,
        localStoragePath: './test_storage_local',
        vault: null,
      });

      const testData = { test: 'encryption fallback' };
      const encrypted = await localOnlyService.encryptData(
        JSON.stringify(testData)
      );

      expect(encrypted.method).to.equal('local');
      expect(encrypted).to.have.property('encrypted');
      expect(encrypted).to.have.property('key');
    });
  });
});

// Updated package.json scripts
const packageJsonScripts = {
  'blockchain:deploy': 'node scripts/deployChaincode.js',
  'blockchain:init': 'node scripts/initializeNetwork.js',
  'blockchain:test': 'mocha tests/blockchain.test.js --timeout 30000',
  'fabric:start':
    'cd ../fabric-samples/test-network && ./network.sh up createChannel -c mychannel -ca',
  'fabric:stop': 'cd ../fabric-samples/test-network && ./network.sh down',
  'storage:test':
    'node -e "import("./services/localStorageService.js").then(m => new m.default({useFileSystem:true}).healthCheck().then(console.log))"',
};

console.log('\n📋 Add these scripts to your package.json:');
console.log(JSON.stringify(packageJsonScripts, null, 2));

console.log('\n🔧 Test your LocalStorageService with:');
console.log('npm run storage:test');
