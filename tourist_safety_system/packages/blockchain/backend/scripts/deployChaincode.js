// backend/scripts/deployChaincode.js
'use strict';

import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fabricBinPath = path.resolve(__dirname, '../../../../fabric-samples/bin');
const org1MspPath = path.resolve(
  __dirname,
  '../../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp'
);

const org1TlsCert = path.resolve(
  __dirname,
  '../../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt'
);

const org2MspPath = path.resolve(
  __dirname,
  '../../../../fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp'
);
const org2TlsCert = path.resolve(
  __dirname,
  '../../../../fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt'
);
// --- update peerEnv (replace the current peerEnv block) ---
const peerEnv = {
  ...process.env,
  PATH: `${fabricBinPath}:${process.env.PATH}`,
  FABRIC_CFG_PATH: path.resolve(__dirname, '../../../../fabric-samples/config'),

  // Peer identity & TLS
  CORE_PEER_LOCALMSPID: 'Org1MSP',
  CORE_PEER_MSPCONFIGPATH: org1MspPath,

  // Use host-mapped port so host -> container works
  CORE_PEER_ADDRESS: 'localhost:7051',

  // TLS settings (required when test-network runs with TLS)
  CORE_PEER_TLS_ENABLED: 'true',
  CORE_PEER_TLS_ROOTCERT_FILE: org1TlsCert,

  // Important: tell the client to expect the peer TLS CN (certificate name)
  CORE_PEER_TLS_SERVERHOSTOVERRIDE: 'peer0.org1.example.com',
};

// Helper to run Fabric CLI commands with the right env
function runCmd(cmd, cwd) {
  execSync(cmd, {
    cwd,
    stdio: 'inherit',
    env: peerEnv,
    shell: '/bin/bash',
  });
}

class ChaincodeDeployer {
  constructor(config = {}) {
    this.networkPath =
      config.networkPath ||
      path.resolve(__dirname, '../../../../fabric-samples/test-network');
    this.chaincodeName = config.chaincodeName || 'tourist-chaincode';
    this.chaincodeVersion = config.version || '1.0';
    this.channelName = config.channelName || 'mychannel';
    this.chaincodePath =
      config.chaincodePath || path.resolve(__dirname, '../../chaincode'); // your chaincode dir
  }

  async deploy() {
    console.log('🚀 Starting chaincode deployment...');
    try {
      console.log('📦 Packaging chaincode...');
      this.packageChaincode();

      console.log('📥 Installing chaincode on peers...');
      this.installChaincode();

      console.log('✅ Approving chaincode definition...');
      this.approveChaincode();

      console.log('🔐 Committing chaincode definition...');
      this.commitChaincode();

      console.log('🎉 Chaincode deployment completed successfully!');
    } catch (error) {
      console.error('❌ Deployment failed:', error.message);
      process.exit(1);
    }
  }

  packageChaincode() {
    const packagePath = `${this.chaincodeName}_${this.chaincodeVersion}.tar.gz`;
    const cmd = `peer lifecycle chaincode package ${packagePath} \
      --path ${this.chaincodePath} \
      --lang node \
      --label ${this.chaincodeName}_${this.chaincodeVersion}`;

    runCmd(cmd, this.networkPath);
    console.log(`✅ Chaincode packaged: ${packagePath}`);
  }

  installChaincode() {
    const packagePath = `${this.chaincodeName}_${this.chaincodeVersion}.tar.gz`;

    // --- Org1 install (existing) ---
    runCmd(`peer lifecycle chaincode install ${packagePath}`, this.networkPath);

    // --- Org2 install ---
    const org2Env = {
      ...peerEnv,
      CORE_PEER_LOCALMSPID: 'Org2MSP',
      CORE_PEER_MSPCONFIGPATH: org2MspPath,
      CORE_PEER_TLS_ROOTCERT_FILE: org2TlsCert,
      CORE_PEER_ADDRESS: 'localhost:9051',
      CORE_PEER_TLS_SERVERHOSTOVERRIDE: 'peer0.org2.example.com',
    };
    execSync(`peer lifecycle chaincode install ${packagePath}`, {
      cwd: this.networkPath,
      stdio: 'inherit',
      env: org2Env,
      shell: '/bin/bash',
    });

    console.log('✅ Chaincode installed on Org1 and Org2');
  }

  approveChaincode() {
    const queryResult = execSync('peer lifecycle chaincode queryinstalled', {
      cwd: this.networkPath,
      encoding: 'utf8',
      env: peerEnv,
      shell: '/bin/bash',
    });

    const packageIdMatch = queryResult.match(
      new RegExp(
        `Package ID: (${this.chaincodeName}_${this.chaincodeVersion}:[a-f0-9]+)`
      )
    );
    if (!packageIdMatch) {
      throw new Error('Package ID not found');
    }
    const packageId = packageIdMatch[1];
    console.log(`📋 Package ID: ${packageId}`);

    // --- Approve for Org1 ---
    const approveCmdOrg1 = `peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --channelID ${this.channelName} \
    --name ${this.chaincodeName} \
    --version ${this.chaincodeVersion} \
    --package-id ${packageId} \
    --sequence 1 \
    --tls \
    --cafile $PWD/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem`;
    runCmd(approveCmdOrg1, this.networkPath);
    console.log('✅ Chaincode approved by Org1');

    // --- Approve for Org2 ---
    const org2Env = {
      ...peerEnv,
      CORE_PEER_LOCALMSPID: 'Org2MSP',
      CORE_PEER_MSPCONFIGPATH: org2MspPath,
      CORE_PEER_TLS_ROOTCERT_FILE: org2TlsCert,
      CORE_PEER_ADDRESS: 'localhost:9051',
      CORE_PEER_TLS_SERVERHOSTOVERRIDE: 'peer0.org2.example.com',
    };
    const approveCmdOrg2 = approveCmdOrg1; // same command works, just env differs
    execSync(approveCmdOrg2, {
      cwd: this.networkPath,
      stdio: 'inherit',
      env: org2Env,
      shell: '/bin/bash',
    });
    console.log('✅ Chaincode approved by Org2');
  }

  // --- replace commitChaincode() with this version ---
  commitChaincode() {
    const commitCmd = `peer lifecycle chaincode commit \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID ${this.channelName} \
  --name ${this.chaincodeName} \
  --version ${this.chaincodeVersion} \
  --sequence 1 \
  --tls \
  --cafile $PWD/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles ${org1TlsCert} \
  --peerAddresses localhost:9051 \
  --tlsRootCertFiles ${org2TlsCert}`;

    // Important: remove CORE_PEER_TLS_SERVERHOSTOVERRIDE here
    const commitEnv = {
      ...peerEnv,
    };
    delete commitEnv.CORE_PEER_TLS_SERVERHOSTOVERRIDE;

    execSync(commitCmd, {
      cwd: this.networkPath,
      stdio: 'inherit',
      env: commitEnv,
      shell: '/bin/bash',
    });

    console.log('✅ Chaincode committed to channel');
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const deployer = new ChaincodeDeployer();
  deployer.deploy().catch(console.error);
}

export default ChaincodeDeployer;
