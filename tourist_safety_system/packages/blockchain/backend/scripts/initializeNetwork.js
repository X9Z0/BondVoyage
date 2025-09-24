// backend/scripts/initializeNetwork.js
// Script to initialize the blockchain network for development

'use strict';

import FabricService from '../services/fabricService.js';
import LocalStorageService from '../services/localStorageService.js'; // FIXED: Added import
import { v4 as uuidv4 } from 'uuid';

class NetworkInitializer {
  constructor() {
    this.fabricService = new FabricService();

    // FIXED: Initialize storage service for test data
    this.storageService = new LocalStorageService({
      useFileSystem: process.env.USE_LOCAL_STORAGE === 'true',
      localStoragePath: './demo_storage',
      minio: {
        endPoint: process.env.MINIO_ENDPOINT || 'localhost',
        port: parseInt(process.env.MINIO_PORT) || 9000,
        useSSL: process.env.MINIO_USE_SSL === 'true',
        accessKey: process.env.MINIO_ACCESS_KEY || 'minioadmin',
        secretKey: process.env.MINIO_SECRET_KEY || 'minioadmin123',
      },
      vault: {
        endpoint: process.env.VAULT_ENDPOINT || 'http://localhost:8200',
        token: process.env.VAULT_TOKEN || 'myroot',
      },
    });
  }

  async initialize() {
    console.log('🌐 Initializing blockchain network...');

    try {
      // Initialize Fabric service
      await this.fabricService.initialize();
      console.log('✅ Fabric service initialized');

      // Check storage service
      const storageHealth = await this.storageService.healthCheck();
      console.log('✅ Storage service health:', storageHealth.storage);

      // Create test data
      await this.createTestData();
      console.log('✅ Test data created');

      // Register event listeners
      await this.fabricService.listenForEvents();
      console.log('✅ Event listeners registered');

      console.log('🎉 Network initialization completed!');
    } catch (error) {
      console.error('❌ Initialization failed:', error.message);
      process.exit(1);
    }
  }

  async createTestData() {
    console.log('📝 Creating test data...');

    try {
      // Store test KYC data first
      const kycData = {
        name: 'Demo Tourist',
        passportNumber: 'DEMO123456',
        nationality: 'Indian',
        documents: ['passport_scan.pdf', 'visa.pdf'],
        uploadedAt: new Date().toISOString(),
      };

      const kycStorage = await this.storageService.storeKYCDocument(
        'T-DEMO-001',
        kycData,
        { nationality: 'Indian' }
      );

      console.log('✅ Test KYC data stored:', kycStorage.documentHash);

      // Register test tourist
      const testTourist = {
        touristId: 'T-DEMO-001',
        kycDocument: kycStorage.documentHash,
        nationality: 'Indian',
        passportNumber: 'DEMO123456',
      };

      await this.fabricService.registerTourist(testTourist);
      console.log('✅ Test tourist registered:', testTourist.touristId);

      // Create test panic event
      const eventPayload = {
        type: 'panic',
        touristId: testTourist.touristId,
        panicType: 'manual',
        timestamp: new Date().toISOString(),
        additionalData: 'Test panic event for demo',
        location: { lat: 26.9124, lon: 75.7873 },
      };

      // Store event payload
      const eventStorage = await this.storageService.storeEventPayload(
        `EVT-${uuidv4()}`,
        eventPayload
      );

      const testEvent = {
        eventId: eventStorage.storageKey.split('/').pop().split('.')[0], // Extract ID from storage key
        touristId: testTourist.touristId,
        eventPayload,
        source: 'phone',
        deviceId: 'D-DEMO-001',
        location: { lat: 26.9124, lon: 75.7873 },
      };

      await this.fabricService.anchorPanicEvent(testEvent);
      console.log('✅ Test panic event created:', testEvent.eventId);

      // Update test consent
      await this.fabricService.updateTouristConsent(
        testTourist.touristId,
        'family_tracking',
        true
      );
      console.log('✅ Test consent updated');

      return { testTourist, testEvent, kycStorage, eventStorage };
    } catch (error) {
      console.error('❌ Test data creation failed:', error);
      throw error;
    }
  }

  async cleanup() {
    if (this.fabricService) {
      await this.fabricService.disconnect();
      console.log('🧹 Network connection closed');
    }
  }
}

// Usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const initializer = new NetworkInitializer();

  // Handle graceful shutdown
  process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down...');
    await initializer.cleanup();
    process.exit(0);
  });

  initializer.initialize().catch(console.error);
}

export default NetworkInitializer;
