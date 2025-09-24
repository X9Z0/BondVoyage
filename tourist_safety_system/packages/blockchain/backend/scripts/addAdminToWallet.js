// addAdminToWallet.js
import { Wallets } from 'fabric-network';
import { readdirSync, readFileSync } from 'fs';
import { join, resolve } from 'path';

import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const wallet = await Wallets.newFileSystemWallet(join(__dirname, 'wallet'));
  const certPath = resolve(
    '/home/x9z0/hackaton/tourist_safety_system/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/cert.pem'
  );
  const keyDir = resolve(
    '/home/x9z0/hackaton/tourist_safety_system/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore'
  );
  const keyFile = readdirSync(keyDir)[0];

  const cert = readFileSync(certPath).toString();
  const key = readFileSync(join(keyDir, keyFile)).toString();

  const identity = {
    credentials: { certificate: cert, privateKey: key },
    mspId: 'Org1MSP',
    type: 'X.509',
  };

  await wallet.put('admin', identity);
  console.log('Admin identity imported to wallet as "admin"');
}

main();
