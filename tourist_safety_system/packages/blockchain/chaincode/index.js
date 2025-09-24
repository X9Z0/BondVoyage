// chaincode/index.js (ESM) — safe import + fallback
import shim from 'fabric-shim';
import pkg from 'fabric-contract-api'; // import the CommonJS module as a default
import TouristContract from './touristContract.js';

const Chaincode =
  pkg?.Chaincode || pkg?.default?.Chaincode || pkg?.chaincode || pkg?.default;
// The above tries several common shapes. After this line `Chaincode` should be the constructor.

async function startChaincode() {
  try {
    // Diagnostic: uncomment if you want to inspect what we actually imported
    // console.log('fabric-contract-api keys:', Object.keys(pkg));
    // console.log('Chaincode typeof:', typeof Chaincode);

    if (!Chaincode || typeof Chaincode !== 'function') {
      console.error(
        'ERROR: fabric-contract-api did not expose a Chaincode constructor. Imported object keys:',
        Object.keys(pkg || {})
      );
      throw new Error(
        'Chaincode is not available from fabric-contract-api import'
      );
    }

    const chaincode = new Chaincode(new TouristContract());
    await shim.start(chaincode);
    console.log('Chaincode started successfully');
  } catch (err) {
    console.error('Failed to start chaincode:', err);
    process.exit(1);
  }
}

startChaincode();
