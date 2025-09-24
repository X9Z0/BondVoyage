// MongoDB initialization for Tourist Safety
db = db.getSiblingDB('tourist_safety');

// Create collections
db.createCollection('tourists');
db.createCollection('events');
db.createCollection('storage_metadata');

// Create indexes for performance
db.tourists.createIndex({ "touristId": 1 }, { unique: true });
db.events.createIndex({ "eventId": 1 }, { unique: true });
db.events.createIndex({ "touristId": 1 });
db.events.createIndex({ "timestamp": 1 });
db.storage_metadata.createIndex({ "storageKey": 1 }, { unique: true });

console.log("Tourist Safety database initialized");
