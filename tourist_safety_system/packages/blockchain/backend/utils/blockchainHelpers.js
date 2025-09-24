// backend/utils/blockchainHelpers.js
// Utility functions for blockchain operations

('use strict');

import { createHash } from 'crypto';
import { performance } from 'perf_hooks';

class BlockchainHelpers {
  // Generate unique IDs with prefixes
  static generateId(prefix = 'ID') {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 5);
    return `${prefix}-${timestamp}-${random}`.toUpperCase();
  }

  // Calculate hash of any data
  static calculateHash(data, algorithm = 'sha256') {
    const hash = createHash(algorithm);
    const dataString = typeof data === 'string' ? data : JSON.stringify(data);
    return hash.update(dataString).digest('hex');
  }

  // Verify data integrity
  static verifyIntegrity(data, expectedHash, algorithm = 'sha256') {
    const computedHash = this.calculateHash(data, algorithm);
    return {
      valid: computedHash === expectedHash,
      computedHash,
      expectedHash,
      algorithm,
    };
  }

  // Create merkle tree from array of data
  static createMerkleTree(dataArray) {
    if (!Array.isArray(dataArray) || dataArray.length === 0) {
      throw new Error('Input must be a non-empty array');
    }

    // Start with leaf hashes
    let currentLevel = dataArray.map((item) => this.calculateHash(item));
    const tree = [currentLevel];

    // Build tree bottom-up
    while (currentLevel.length > 1) {
      const nextLevel = [];

      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = currentLevel[i + 1] || left; // Duplicate if odd number
        const parentHash = this.calculateHash(left + right);
        nextLevel.push(parentHash);
      }

      currentLevel = nextLevel;
      tree.push(currentLevel);
    }

    return {
      root: currentLevel[0],
      tree: tree,
      leaves: tree[0],
    };
  }

  // Validate location coordinates
  static validateLocation(lat, lon) {
    const isValidLat = typeof lat === 'number' && lat >= -90 && lat <= 90;
    const isValidLon = typeof lon === 'number' && lon >= -180 && lon <= 180;

    return {
      valid: isValidLat && isValidLon,
      latitude: isValidLat,
      longitude: isValidLon,
      message: !isValidLat
        ? 'Invalid latitude'
        : !isValidLon
        ? 'Invalid longitude'
        : 'Valid coordinates',
    };
  }

  // Check if location is within Rajasthan bounds (for demo)
  static isInRajasthan(lat, lon) {
    const rajasthanBounds = {
      north: 30.2,
      south: 23.0,
      east: 78.0,
      west: 69.0,
    };

    return (
      lat >= rajasthanBounds.south &&
      lat <= rajasthanBounds.north &&
      lon >= rajasthanBounds.west &&
      lon <= rajasthanBounds.east
    );
  }

  // Performance monitoring wrapper
  static async measurePerformance(operation, operationName = 'operation') {
    const startTime = performance.now();

    try {
      const result = await operation();
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);

      console.log(`⏱️  ${operationName} completed in ${duration}ms`);
      return { result, duration, success: true };
    } catch (error) {
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);

      console.error(
        `❌ ${operationName} failed after ${duration}ms:`,
        error.message
      );
      return { error, duration, success: false };
    }
  }

  // Create event payload structure
  static createEventPayload(type, touristId, data = {}) {
    return {
      eventId: this.generateId('EVT'),
      type,
      touristId,
      timestamp: new Date().toISOString(),
      version: '1.0',
      ...data,
    };
  }

  // Validate event data
  static validateEventData(eventData) {
    const requiredFields = ['eventId', 'type', 'touristId', 'timestamp'];
    const errors = [];

    requiredFields.forEach((field) => {
      if (!eventData[field]) {
        errors.push(`Missing required field: ${field}`);
      }
    });

    if (eventData.location) {
      const locationValidation = this.validateLocation(
        eventData.location.lat,
        eventData.location.lon
      );
      if (!locationValidation.valid) {
        errors.push(`Invalid location: ${locationValidation.message}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // Format response for API
  static formatApiResponse(success, data = null, error = null) {
    const response = {
      success,
      timestamp: new Date().toISOString(),
    };

    if (success && data) {
      response.data = data;
    }

    if (!success && error) {
      response.error = typeof error === 'string' ? error : error.message;
    }

    return response;
  }

  // Generate demo data
  static generateDemoTourist(index = 1) {
    const names = ['Alice Johnson', 'Bob Smith', 'Carol Davis', 'David Wilson'];
    const nationalities = ['American', 'British', 'Canadian', 'Australian'];

    return {
      touristId: this.generateId('T'),
      name: names[index % names.length],
      nationality: nationalities[index % nationalities.length],
      passportNumber: `DEMO${String(index).padStart(6, '0')}`,
      kycDocuments: {
        passport: `demo_passport_${index}`,
        visa: `demo_visa_${index}`,
        photo: `demo_photo_${index}`,
      },
    };
  }

  // Generate demo locations in Rajasthan
  static generateDemoLocation() {
    const locations = [
      { name: 'Jaipur', lat: 26.9124, lon: 75.7873 },
      { name: 'Udaipur', lat: 24.5854, lon: 73.7125 },
      { name: 'Jodhpur', lat: 26.2389, lon: 73.0243 },
      { name: 'Jaisalmer', lat: 26.9157, lon: 70.9083 },
      { name: 'Pushkar', lat: 26.4899, lon: 74.5511 },
    ];

    return locations[Math.floor(Math.random() * locations.length)];
  }
}

export default BlockchainHelpers;
