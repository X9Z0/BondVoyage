// backend/config/blockchain.js
// Blockchain configuration

('use strict');

import { resolve, join } from 'path';

const blockchainConfig = {
  // Hyperledger Fabric Configuration
  fabric: {
    networkConfigPath: resolve(__dirname, 'connection-org1.json'),
    channelName: process.env.FABRIC_CHANNEL || 'mychannel',
    chaincodeName: process.env.FABRIC_CHAINCODE || 'tourist-chaincode',
    walletPath: join(process.cwd(), 'wallet'),

    // For production, these should be environment variables
    org: {
      mspId: 'Org1MSP',
      name: 'tourism-authority',
    },

    // CA Configuration
    ca: {
      name: 'ca.org1.example.com',
      adminUserId: 'admin',
      adminSecret: 'adminpw',
    },
  },

  // Storage Configuration
  storage: {
    type: process.env.STORAGE_TYPE || 'local', // 'local' or 's3'
    local: {
      path: './encrypted_storage',
    },
    s3: {
      bucketName: process.env.S3_BUCKET_NAME || 'tourist-safety-encrypted',
      region: process.env.AWS_REGION || 'us-east-1',
    },
  },

  // Security Configuration
  security: {
    encryptionAlgorithm: 'aes-256-gcm',
    hashAlgorithm: 'sha256',
    keySize: 32, // 256 bits
    jwtSecret: process.env.JWT_SECRET || 'tourist-safety-secret',
    jwtExpiresIn: '24h',
  },

  // Event Configuration
  events: {
    // Critical events that trigger immediate alerts
    criticalEventTypes: ['panic', 'efir'],
    // Events that require signature verification
    signedEventTypes: ['panic', 'anomaly'],
    // Maximum age for accepting events (in milliseconds)
    maxEventAge: 5 * 60 * 1000, // 5 minutes
  },

  // Access Control
  roles: {
    tourist: ['read:own', 'write:own'],
    family: ['read:granted'],
    police: ['read:all', 'write:efir'],
    admin: ['read:all', 'write:all', 'delete:all'],
  },
};

export default blockchainConfig;

// backend/config/connection-org1.json
// Fabric network connection profile (example)
const connectionProfile = {
  name: 'tourist-safety-network',
  version: '1.0.0',
  client: {
    organization: 'Org1',
    connection: {
      timeout: {
        peer: {
          endorser: '300',
        },
      },
    },
  },
  organizations: {
    Org1: {
      mspid: 'Org1MSP',
      peers: ['peer0.org1.example.com'],
      certificateAuthorities: ['ca.org1.example.com'],
    },
  },
  peers: {
    'peer0.org1.example.com': {
      url: 'grpcs://localhost:7051',
      tlsCACerts: {
        pem: '-----BEGIN CERTIFICATE-----\n...peer cert...\n-----END CERTIFICATE-----\n',
      },
      grpcOptions: {
        'ssl-target-name-override': 'peer0.org1.example.com',
        hostnameOverride: 'peer0.org1.example.com',
      },
    },
  },
  certificateAuthorities: {
    'ca.org1.example.com': {
      url: 'https://localhost:7054',
      caName: 'ca-org1',
      tlsCACerts: {
        pem: '-----BEGIN CERTIFICATE-----\n...ca cert...\n-----END CERTIFICATE-----\n',
      },
      httpOptions: {
        verify: false,
      },
    },
  },
};

// For development, save this as a JSON file
// fs.writeFileSync('./backend/config/connection-org1.json', JSON.stringify(connectionProfile, null, 2));
