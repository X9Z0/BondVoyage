// chaincode/touristContract.js
// Hyperledger Fabric Smart Contract for Tourist Safety System

'use strict';

import { Contract } from 'fabric-contract-api';
// import crypto from 'crypto';

class TouristContract extends Contract {
  async initLedger(ctx) {
    console.info('============= START : Initialize Ledger ===========');
    // Initialize with sample data if needed
    console.info('============= END : Initialize Ledger ===========');
  }

  // Register a new tourist with KYC hash
  async registerTourist(ctx, touristId, kycHash, nationality, passportHash) {
    console.info('============= START : Register Tourist ===========');

    // Check if tourist already exists
    const exists = await this.touristExists(ctx, touristId);
    if (exists) {
      throw new Error(`Tourist ${touristId} already exists`);
    }

    // Get caller identity for audit
    const clientIdentity = ctx.clientIdentity;
    const verifierOrg = clientIdentity.getMSPID();

    const tourist = {
      docType: 'tourist',
      touristId: touristId,
      kycHash: kycHash,
      nationality: nationality,
      passportHash: passportHash,
      kycVerifiedBy: verifierOrg,
      kycVerifiedAt: new Date().toISOString(),
      consentFlags: [],
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await ctx.stub.putState(touristId, Buffer.from(JSON.stringify(tourist)));

    // Emit event for listeners
    ctx.stub.setEvent(
      'TouristRegistered',
      Buffer.from(
        JSON.stringify({
          touristId: touristId,
          verifiedBy: verifierOrg,
          timestamp: tourist.createdAt,
        })
      )
    );

    console.info('============= END : Register Tourist ===========');
    return JSON.stringify(tourist);
  }

  // Verify KYC for a tourist
  async verifyKYC(ctx, touristId, verifierId, kycHash) {
    console.info('============= START : Verify KYC ===========');

    const touristString = await this.readTourist(ctx, touristId);
    const tourist = JSON.parse(touristString);

    // Verify KYC hash matches
    if (tourist.kycHash !== kycHash) {
      throw new Error('KYC hash mismatch');
    }

    tourist.kycVerifiedBy = verifierId;
    tourist.kycVerifiedAt = new Date().toISOString();
    tourist.kycStatus = 'verified';
    tourist.updatedAt = new Date().toISOString();

    await ctx.stub.putState(touristId, Buffer.from(JSON.stringify(tourist)));

    console.info('============= END : Verify KYC ===========');
    return JSON.stringify(tourist);
  }

  // Anchor a panic/emergency event
  async anchorEvent(
    ctx,
    eventId,
    touristId,
    eventType,
    payloadHash,
    source,
    deviceId,
    lat,
    lon
  ) {
    console.info('============= START : Anchor Event ===========');

    // Check if event already exists
    const eventKey = `EVENT_${eventId}`;
    const exists = await this.assetExists(ctx, eventKey);
    if (exists) {
      throw new Error(`Event ${eventId} already exists`);
    }

    // Verify tourist exists
    const touristExists = await this.touristExists(ctx, touristId);
    if (!touristExists) {
      throw new Error(`Tourist ${touristId} not found`);
    }

    const event = {
      docType: 'event',
      eventId: eventId,
      touristId: touristId,
      eventType: eventType, // panic, efir, location-check, anomaly
      payloadHash: payloadHash,
      source: source, // phone, wearable, lora
      deviceId: deviceId,
      location: {
        lat: parseFloat(lat),
        lon: parseFloat(lon),
      },
      timestamp: new Date().toISOString(),
      status: 'recorded',
      responderId: null,
      responseTime: null,
    };

    await ctx.stub.putState(eventKey, Buffer.from(JSON.stringify(event)));

    // Update tourist's last known location
    await this.updateLastLocation(ctx, touristId, lat, lon);

    // Emit critical event
    if (eventType === 'panic' || eventType === 'efir') {
      ctx.stub.setEvent(
        'CriticalEvent',
        Buffer.from(
          JSON.stringify({
            eventId: eventId,
            touristId: touristId,
            eventType: eventType,
            location: { lat, lon },
            timestamp: event.timestamp,
          })
        )
      );
    }

    console.info('============= END : Anchor Event ===========');
    return JSON.stringify(event);
  }

  // Update tourist consent
  async updateConsent(ctx, touristId, consentType, granted) {
    console.info('============= START : Update Consent ===========');

    const touristString = await this.readTourist(ctx, touristId);
    const tourist = JSON.parse(touristString);

    if (!tourist.consentFlags) {
      tourist.consentFlags = [];
    }

    if (granted === 'true') {
      if (!tourist.consentFlags.includes(consentType)) {
        tourist.consentFlags.push(consentType);
      }
    } else {
      tourist.consentFlags = tourist.consentFlags.filter(
        (c) => c !== consentType
      );
    }

    tourist.updatedAt = new Date().toISOString();

    // Store consent change audit
    const consentAudit = {
      docType: 'consentAudit',
      touristId: touristId,
      consentType: consentType,
      action: granted === 'true' ? 'granted' : 'revoked',
      timestamp: new Date().toISOString(),
      requestedBy: ctx.clientIdentity.getID(),
    };

    const auditKey = `CONSENT_${touristId}_${Date.now()}`;
    await ctx.stub.putState(
      auditKey,
      Buffer.from(JSON.stringify(consentAudit))
    );
    await ctx.stub.putState(touristId, Buffer.from(JSON.stringify(tourist)));

    console.info('============= END : Update Consent ===========');
    return JSON.stringify(tourist);
  }

  // Grant access to specific organization
  async grantAccess(ctx, grantId, touristId, targetOrg, scope, expiryHours) {
    console.info('============= START : Grant Access ===========');

    // Verify tourist exists
    const touristExists = await this.touristExists(ctx, touristId);
    if (!touristExists) {
      throw new Error(`Tourist ${touristId} not found`);
    }

    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + parseInt(expiryHours));

    const accessGrant = {
      docType: 'accessGrant',
      grantId: grantId,
      touristId: touristId,
      grantedTo: targetOrg,
      grantedBy: ctx.clientIdentity.getMSPID(),
      scope: scope.split(','), // e.g., "kyc,events,location"
      createdAt: new Date().toISOString(),
      expiresAt: expiryDate.toISOString(),
      status: 'active',
    };

    const grantKey = `GRANT_${grantId}`;
    await ctx.stub.putState(grantKey, Buffer.from(JSON.stringify(accessGrant)));

    console.info('============= END : Grant Access ===========');
    return JSON.stringify(accessGrant);
  }

  // Anchor E-FIR (Electronic First Information Report)
  async anchorEFIR(
    ctx,
    efirId,
    eventId,
    touristId,
    policeStation,
    officerId,
    reportHash
  ) {
    console.info('============= START : Anchor E-FIR ===========');

    const efir = {
      docType: 'efir',
      efirId: efirId,
      eventId: eventId,
      touristId: touristId,
      policeStation: policeStation,
      officerId: officerId,
      reportHash: reportHash,
      status: 'filed',
      filedAt: new Date().toISOString(),
      investigationStatus: 'pending',
    };

    const efirKey = `EFIR_${efirId}`;
    await ctx.stub.putState(efirKey, Buffer.from(JSON.stringify(efir)));

    // Update the original event
    const eventKey = `EVENT_${eventId}`;
    const eventString = await this.readAsset(ctx, eventKey);
    const event = JSON.parse(eventString);
    event.efirId = efirId;
    event.responderId = officerId;
    event.responseTime = new Date().toISOString();
    event.status = 'efir-filed';

    await ctx.stub.putState(eventKey, Buffer.from(JSON.stringify(event)));

    ctx.stub.setEvent(
      'EFIRFiled',
      Buffer.from(
        JSON.stringify({
          efirId: efirId,
          eventId: eventId,
          touristId: touristId,
          timestamp: efir.filedAt,
        })
      )
    );

    console.info('============= END : Anchor E-FIR ===========');
    return JSON.stringify(efir);
  }

  // Store itinerary hash
  async anchorItinerary(
    ctx,
    itineraryId,
    touristId,
    itineraryHash,
    startDate,
    endDate,
    locations
  ) {
    console.info('============= START : Anchor Itinerary ===========');

    const itinerary = {
      docType: 'itinerary',
      itineraryId: itineraryId,
      touristId: touristId,
      itineraryHash: itineraryHash,
      startDate: startDate,
      endDate: endDate,
      locations: JSON.parse(locations), // Array of location names
      status: 'active',
      createdAt: new Date().toISOString(),
    };

    const itineraryKey = `ITIN_${itineraryId}`;
    await ctx.stub.putState(
      itineraryKey,
      Buffer.from(JSON.stringify(itinerary))
    );

    console.info('============= END : Anchor Itinerary ===========');
    return JSON.stringify(itinerary);
  }

  // Anchor Merkle root for batch verification
  async anchorMerkleRoot(
    ctx,
    rootId,
    rootHash,
    eventCount,
    startTime,
    endTime
  ) {
    console.info('============= START : Anchor Merkle Root ===========');

    const merkleRoot = {
      docType: 'merkleRoot',
      rootId: rootId,
      rootHash: rootHash,
      eventCount: parseInt(eventCount),
      startTime: startTime,
      endTime: endTime,
      anchoredAt: new Date().toISOString(),
      anchoredBy: ctx.clientIdentity.getMSPID(),
    };

    const rootKey = `MERKLE_${rootId}`;
    await ctx.stub.putState(rootKey, Buffer.from(JSON.stringify(merkleRoot)));

    console.info('============= END : Anchor Merkle Root ===========');
    return JSON.stringify(merkleRoot);
  }

  // Query functions
  async readTourist(ctx, touristId) {
    const touristAsBytes = await ctx.stub.getState(touristId);
    if (!touristAsBytes || touristAsBytes.length === 0) {
      throw new Error(`Tourist ${touristId} does not exist`);
    }
    return touristAsBytes.toString();
  }

  async readAsset(ctx, key) {
    const assetBytes = await ctx.stub.getState(key);
    if (!assetBytes || assetBytes.length === 0) {
      throw new Error(`Asset ${key} does not exist`);
    }
    return assetBytes.toString();
  }

  async queryEvent(ctx, eventId) {
    return await this.readAsset(ctx, `EVENT_${eventId}`);
  }

  async queryEFIR(ctx, efirId) {
    return await this.readAsset(ctx, `EFIR_${efirId}`);
  }

  // Get all events for a tourist
  async getTouristEvents(ctx, touristId) {
    const startKey = 'EVENT_';
    const endKey = 'EVENT_\uffff';
    const allResults = [];

    for await (const { key, value } of ctx.stub.getStateByRange(
      startKey,
      endKey
    )) {
      const strValue = Buffer.from(value).toString('utf8');
      let record;
      try {
        record = JSON.parse(strValue);
        if (record.touristId === touristId) {
          allResults.push({ Key: key, Record: record });
        }
      } catch (err) {
        console.log(err);
      }
    }
    return JSON.stringify(allResults);
  }

  // Get active access grants for a tourist
  async getActiveGrants(ctx, touristId) {
    const startKey = 'GRANT_';
    const endKey = 'GRANT_\uffff';
    const allResults = [];
    const now = new Date();

    for await (const { key, value } of ctx.stub.getStateByRange(
      startKey,
      endKey
    )) {
      const strValue = Buffer.from(value).toString('utf8');
      let record;
      try {
        record = JSON.parse(strValue);
        if (
          record.touristId === touristId &&
          record.status === 'active' &&
          new Date(record.expiresAt) > now
        ) {
          allResults.push({ Key: key, Record: record });
        }
      } catch (err) {
        console.log(err);
      }
    }
    return JSON.stringify(allResults);
  }

  // Helper functions
  async touristExists(ctx, touristId) {
    const touristAsBytes = await ctx.stub.getState(touristId);
    return touristAsBytes && touristAsBytes.length > 0;
  }

  async assetExists(ctx, key) {
    const assetBytes = await ctx.stub.getState(key);
    return assetBytes && assetBytes.length > 0;
  }

  async updateLastLocation(ctx, touristId, lat, lon) {
    const touristString = await this.readTourist(ctx, touristId);
    const tourist = JSON.parse(touristString);

    tourist.lastKnownLocation = {
      lat: parseFloat(lat),
      lon: parseFloat(lon),
      timestamp: new Date().toISOString(),
    };
    tourist.updatedAt = new Date().toISOString();

    await ctx.stub.putState(touristId, Buffer.from(JSON.stringify(tourist)));
  }

  // Get audit history for a tourist
  async getAuditHistory(ctx, touristId) {
    const history = await ctx.stub.getHistoryForKey(touristId);
    const allResults = [];

    while (true) {
      const result = await history.next();
      if (result.value && result.value.value.toString()) {
        const jsonRes = {};
        jsonRes.txId = result.value.txId;
        jsonRes.timestamp = result.value.timestamp;
        jsonRes.isDelete = result.value.isDelete;
        try {
          jsonRes.value = JSON.parse(result.value.value.toString('utf8'));
        } catch (err) {
          console.log(err);
          jsonRes.value = result.value.value.toString('utf8');
        }
        allResults.push(jsonRes);
      }

      if (result.done) {
        await history.close();
        return JSON.stringify(allResults);
      }
    }
  }
}

// at bottom of chaincode/touristContract.js (CommonJS style)
export default TouristContract;
