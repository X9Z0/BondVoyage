// backend/services/localStorageService.js
// Local storage service using MinIO and Vault instead of AWS

'use strict';

import { Client } from 'minio';
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
} from 'crypto';
import { promises as fs } from 'fs';
import { join, dirname } from 'path';
import axios from 'axios';

class LocalStorageService {
  constructor(config = {}) {
    // MinIO client (S3 alternative)
    this.minioClient = new Client({
      endPoint: config.minio?.endPoint || 'localhost',
      port: config.minio?.port || 9000,
      useSSL: config.minio?.useSSL || false,
      accessKey: config.minio?.accessKey || 'minioadmin',
      secretKey: config.minio?.secretKey || 'minioadmin123',
    });

    this.bucketName = config.bucketName || 'tourist-safety-encrypted';

    // Vault client (KMS alternative)
    this.vaultConfig = {
      endpoint: config.vault?.endpoint || 'http://localhost:8200',
      token: config.vault?.token || 'myroot',
      mountPath: config.vault?.mountPath || 'transit',
    };

    // Local file system fallback
    this.useFileSystem = config.useFileSystem || false;
    this.localStoragePath = config.localStoragePath || './encrypted_storage';

    this.initializeStorage();
  }

  async initializeStorage() {
    try {
      // Initialize MinIO bucket
      const bucketExists = await this.minioClient.bucketExists(this.bucketName);
      if (!bucketExists) {
        await this.minioClient.makeBucket(this.bucketName, 'us-east-1');
        console.log(`✅ MinIO bucket '${this.bucketName}' created`);
      }

      // Initialize Vault encryption engine
      await this.initializeVault();

      // Create local directories as fallback
      if (this.useFileSystem) {
        await this.initLocalStorage();
      }

      console.log('✅ Local storage service initialized');
    } catch (error) {
      console.warn(
        '⚠️ Storage initialization failed, using file system fallback'
      );
      this.useFileSystem = true;
      await this.initLocalStorage();
    }
  }

  async initializeVault() {
    try {
      const vaultClient = axios.create({
        baseURL: this.vaultConfig.endpoint,
        headers: {
          'X-Vault-Token': this.vaultConfig.token,
          'Content-Type': 'application/json',
        },
      });

      // Enable transit secrets engine
      await vaultClient
        .post('/v1/sys/mounts/transit', {
          type: 'transit',
          description: 'Tourist Safety Encryption',
        })
        .catch(() => {}); // Ignore if already exists

      // Create encryption key
      await vaultClient
        .post('/v1/transit/keys/tourist-safety-key', {
          type: 'aes256-gcm96',
        })
        .catch(() => {}); // Ignore if already exists

      this.vaultClient = vaultClient;
      console.log('✅ Vault encryption engine initialized');
    } catch (error) {
      console.warn('⚠️ Vault unavailable, using local encryption');
      this.vaultClient = null;
    }
  }

  async initLocalStorage() {
    try {
      await fs.mkdir(this.localStoragePath, { recursive: true });
      await fs.mkdir(join(this.localStoragePath, 'kyc'), {
        recursive: true,
      });
      await fs.mkdir(join(this.localStoragePath, 'events'), {
        recursive: true,
      });
      await fs.mkdir(join(this.localStoragePath, 'itineraries'), {
        recursive: true,
      });
      console.log('✅ Local file storage initialized');
    } catch (error) {
      console.error('❌ Failed to initialize local storage:', error);
    }
  }

  // Encrypt data using Vault or local AES
  async encryptData(data, keyName = 'tourist-safety-key') {
    if (this.vaultClient) {
      try {
        const response = await this.vaultClient.post(
          `/v1/transit/encrypt/${keyName}`,
          {
            plaintext: Buffer.from(data).toString('base64'),
          }
        );

        return {
          encrypted: response.data.data.ciphertext,
          method: 'vault',
          keyName: keyName,
        };
      } catch (error) {
        console.warn('⚠️ Vault encryption failed, using local AES');
      }
    }

    // Fallback to local AES encryption
    const key = randomBytes(32);
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();

    return {
      encrypted: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      key: key.toString('base64'),
      method: 'local',
    };
  }

  // Decrypt data using Vault or local AES
  async decryptData(encryptedData, decryptionInfo) {
    if (decryptionInfo.method === 'vault' && this.vaultClient) {
      try {
        const response = await this.vaultClient.post(
          `/v1/transit/decrypt/${decryptionInfo.keyName}`,
          {
            ciphertext: encryptedData,
          }
        );

        return Buffer.from(response.data.data.plaintext, 'base64').toString(
          'utf8'
        );
      } catch (error) {
        throw new Error('Vault decryption failed: ' + error.message);
      }
    }

    // Local AES decryption
    if (decryptionInfo.method === 'local') {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        Buffer.from(decryptionInfo.key, 'base64'),
        Buffer.from(decryptionInfo.iv, 'base64')
      );

      decipher.setAuthTag(Buffer.from(decryptionInfo.authTag, 'base64'));

      let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }

    throw new Error('Unknown encryption method');
  }

  // Store KYC document
  async storeKYCDocument(touristId, kycDocument, metadata = {}) {
    try {
      // Encrypt the document
      const encryptionResult = await this.encryptData(
        JSON.stringify(kycDocument)
      );

      // Create storage object
      const storageObject = {
        touristId: touristId,
        encryptedData: encryptionResult.encrypted,
        encryptionInfo: {
          method: encryptionResult.method,
          iv: encryptionResult.iv,
          authTag: encryptionResult.authTag,
          key: encryptionResult.key,
          keyName: encryptionResult.keyName,
        },
        metadata: metadata,
        timestamp: new Date().toISOString(),
        contentType: 'application/json',
      };

      // Calculate hash for blockchain
      const documentHash = createHash('sha256')
        .update(JSON.stringify(kycDocument))
        .digest('hex');

      // Store the encrypted document
      const objectKey = `kyc/${touristId}/${Date.now()}.json`;

      if (this.useFileSystem) {
        const filePath = join(this.localStoragePath, objectKey);
        await fs.mkdir(dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, JSON.stringify(storageObject));
      } else {
        const buffer = Buffer.from(JSON.stringify(storageObject));
        await this.minioClient.putObject(
          this.bucketName,
          objectKey,
          buffer,
          buffer.length,
          {
            'Content-Type': 'application/json',
            'Tourist-Id': touristId,
            ...metadata,
          }
        );
      }

      console.log(`✅ KYC document stored for tourist ${touristId}`);

      return {
        storageKey: objectKey,
        documentHash: documentHash,
        encryptionMethod: encryptionResult.method,
        timestamp: storageObject.timestamp,
        size: Buffer.byteLength(JSON.stringify(storageObject)),
      };
    } catch (error) {
      console.error(`❌ Failed to store KYC document: ${error}`);
      throw error;
    }
  }

  // Store event payload
  async storeEventPayload(eventId, eventData) {
    try {
      const encryptionResult = await this.encryptData(
        JSON.stringify(eventData)
      );

      const storageObject = {
        eventId: eventId,
        touristId: eventData.touristId,
        encryptedData: encryptionResult.encrypted,
        encryptionInfo: {
          method: encryptionResult.method,
          iv: encryptionResult.iv,
          authTag: encryptionResult.authTag,
          key: encryptionResult.key,
          keyName: encryptionResult.keyName,
        },
        eventType: eventData.type,
        timestamp: new Date().toISOString(),
        contentType: 'application/json',
      };

      const payloadHash = createHash('sha256')
        .update(JSON.stringify(eventData))
        .digest('hex');

      const objectKey = `events/${eventData.touristId}/${eventId}.json`;

      if (this.useFileSystem) {
        const filePath = join(this.localStoragePath, objectKey);
        await fs.mkdir(dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, JSON.stringify(storageObject));
      } else {
        const buffer = Buffer.from(JSON.stringify(storageObject));
        await this.minioClient.putObject(
          this.bucketName,
          objectKey,
          buffer,
          buffer.length,
          {
            'Content-Type': 'application/json',
            'Event-Type': eventData.type,
            'Tourist-Id': eventData.touristId,
          }
        );
      }

      console.log(`✅ Event payload stored: ${eventId}`);

      return {
        storageKey: objectKey,
        payloadHash: payloadHash,
        encryptionMethod: encryptionResult.method,
        timestamp: storageObject.timestamp,
        size: Buffer.byteLength(JSON.stringify(storageObject)),
      };
    } catch (error) {
      console.error(`❌ Failed to store event payload: ${error}`);
      throw error;
    }
  }

  // Store itinerary
  async storeItinerary(itineraryId, touristId, itineraryData) {
    try {
      const encryptionResult = await this.encryptData(
        JSON.stringify(itineraryData)
      );

      const storageObject = {
        itineraryId: itineraryId,
        touristId: touristId,
        encryptedData: encryptionResult.encrypted,
        encryptionInfo: {
          method: encryptionResult.method,
          iv: encryptionResult.iv,
          authTag: encryptionResult.authTag,
          key: encryptionResult.key,
          keyName: encryptionResult.keyName,
        },
        timestamp: new Date().toISOString(),
        contentType: 'application/json',
      };

      const itineraryHash = createHash('sha256')
        .update(JSON.stringify(itineraryData))
        .digest('hex');

      const objectKey = `itineraries/${touristId}/${itineraryId}.json`;

      if (this.useFileSystem) {
        const filePath = join(this.localStoragePath, objectKey);
        await fs.mkdir(dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, JSON.stringify(storageObject));
      } else {
        const buffer = Buffer.from(JSON.stringify(storageObject));
        await this.minioClient.putObject(
          this.bucketName,
          objectKey,
          buffer,
          buffer.length,
          {
            'Content-Type': 'application/json',
            'Tourist-Id': touristId,
          }
        );
      }

      console.log(`✅ Itinerary stored: ${itineraryId}`);

      return {
        storageKey: objectKey,
        itineraryHash: itineraryHash,
        encryptionMethod: encryptionResult.method,
        timestamp: storageObject.timestamp,
        size: Buffer.byteLength(JSON.stringify(storageObject)),
      };
    } catch (error) {
      console.error(`❌ Failed to store itinerary: ${error}`);
      throw error;
    }
  }

  // Retrieve and decrypt KYC document
  async retrieveKYCDocument(storageKey) {
    try {
      let storageObject;

      if (this.useFileSystem) {
        const filePath = join(this.localStoragePath, storageKey);
        const data = await fs.readFile(filePath, 'utf8');
        storageObject = JSON.parse(data);
      } else {
        const dataStream = await this.minioClient.getObject(
          this.bucketName,
          storageKey
        );

        let data = '';
        return new Promise((resolve, reject) => {
          dataStream.on('data', (chunk) => (data += chunk));
          dataStream.on('end', async () => {
            try {
              storageObject = JSON.parse(data);

              const decryptedData = await this.decryptData(
                storageObject.encryptedData,
                storageObject.encryptionInfo
              );

              resolve({
                document: JSON.parse(decryptedData),
                metadata: storageObject.metadata,
                timestamp: storageObject.timestamp,
              });
            } catch (error) {
              reject(error);
            }
          });
          dataStream.on('error', reject);
        });
      }

      const decryptedData = await this.decryptData(
        storageObject.encryptedData,
        storageObject.encryptionInfo
      );

      return {
        document: JSON.parse(decryptedData),
        metadata: storageObject.metadata,
        timestamp: storageObject.timestamp,
      };
    } catch (error) {
      console.error(`❌ Failed to retrieve KYC document: ${error}`);
      throw error;
    }
  }

  // Retrieve and decrypt event payload
  async retrieveEventPayload(storageKey) {
    try {
      let storageObject;

      if (this.useFileSystem) {
        const filePath = join(this.localStoragePath, storageKey);
        const data = await fs.readFile(filePath, 'utf8');
        storageObject = JSON.parse(data);
      } else {
        const dataStream = await this.minioClient.getObject(
          this.bucketName,
          storageKey
        );

        return new Promise((resolve, reject) => {
          let data = '';
          dataStream.on('data', (chunk) => (data += chunk));
          dataStream.on('end', async () => {
            try {
              storageObject = JSON.parse(data);

              const decryptedData = await this.decryptData(
                storageObject.encryptedData,
                storageObject.encryptionInfo
              );

              resolve({
                eventData: JSON.parse(decryptedData),
                eventId: storageObject.eventId,
                eventType: storageObject.eventType,
                timestamp: storageObject.timestamp,
              });
            } catch (error) {
              reject(error);
            }
          });
          dataStream.on('error', reject);
        });
      }

      const decryptedData = await this.decryptData(
        storageObject.encryptedData,
        storageObject.encryptionInfo
      );

      return {
        eventData: JSON.parse(decryptedData),
        eventId: storageObject.eventId,
        eventType: storageObject.eventType,
        timestamp: storageObject.timestamp,
      };
    } catch (error) {
      console.error(`❌ Failed to retrieve event payload: ${error}`);
      throw error;
    }
  }

  // Delete tourist data (GDPR compliance)
  async deleteTouristData(touristId) {
    try {
      const prefixes = [
        `kyc/${touristId}/`,
        `events/${touristId}/`,
        `itineraries/${touristId}/`,
      ];

      for (const prefix of prefixes) {
        if (this.useFileSystem) {
          const dirPath = join(this.localStoragePath, prefix);
          try {
            await fs.rm(dirPath, { recursive: true, force: true });
          } catch (error) {
            console.log(`Directory ${dirPath} might not exist`);
          }
        } else {
          // List and delete all objects with the prefix
          const objectsStream = this.minioClient.listObjects(
            this.bucketName,
            prefix,
            true
          );

          const objectsToDelete = [];
          objectsStream.on('data', (obj) => objectsToDelete.push(obj.name));

          await new Promise((resolve, reject) => {
            objectsStream.on('end', async () => {
              try {
                if (objectsToDelete.length > 0) {
                  await this.minioClient.removeObjects(
                    this.bucketName,
                    objectsToDelete
                  );
                }
                resolve();
              } catch (error) {
                reject(error);
              }
            });
            objectsStream.on('error', reject);
          });
        }
      }

      console.log(`✅ All data deleted for tourist ${touristId}`);
      return { success: true, touristId: touristId };
    } catch (error) {
      console.error(`❌ Failed to delete tourist data: ${error}`);
      throw error;
    }
  }

  // Get storage statistics
  async getStorageStats() {
    try {
      if (this.useFileSystem) {
        const stats = await fs.stat(this.localStoragePath);
        return {
          type: 'filesystem',
          path: this.localStoragePath,
          created: stats.birthtime,
        };
      } else {
        // Get MinIO bucket statistics
        const bucketStats = await this.minioClient.statObject(
          this.bucketName,
          ''
        );
        return {
          type: 'minio',
          bucket: this.bucketName,
          stats: bucketStats,
        };
      }
    } catch (error) {
      return {
        type: this.useFileSystem ? 'filesystem' : 'minio',
        error: error.message,
      };
    }
  }

  // Health check
  async healthCheck() {
    const health = {
      storage: 'unknown',
      encryption: 'unknown',
      timestamp: new Date().toISOString(),
    };

    try {
      if (this.useFileSystem) {
        await fs.access(this.localStoragePath);
        health.storage = 'healthy';
      } else {
        await this.minioClient.bucketExists(this.bucketName);
        health.storage = 'healthy';
      }
    } catch (error) {
      health.storage = 'unhealthy';
      health.storageError = error.message;
    }

    try {
      if (this.vaultClient) {
        await this.vaultClient.get('/v1/sys/health');
        health.encryption = 'vault';
      } else {
        health.encryption = 'local';
      }
    } catch (error) {
      health.encryption = 'local';
      health.encryptionNote = 'Vault unavailable, using local encryption';
    }

    return health;
  }
}

export default LocalStorageService;
