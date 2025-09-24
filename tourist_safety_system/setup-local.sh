# setup-local.sh
#!/bin/bash

# Tourist Safety Blockchain - Local Setup Script
echo "🚀 Setting up Tourist Safety System locally..."

# Check prerequisites
check_prerequisite() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is required but not installed"
        exit 1
    else
        echo "✅ $1 found"
    fi
}

echo "📋 Checking prerequisites..."
check_prerequisite docker
check_prerequisite docker-compose
check_prerequisite node
check_prerequisite npm

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p encrypted_storage/{kyc,events,itineraries}
mkdir -p monitoring/{prometheus,grafana/dashboards,grafana/datasources}
mkdir -p init-scripts
mkdir -p wallet

# Create Prometheus configuration
cat > monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'tourist-api'
    static_configs:
      - targets: ['host.docker.internal:3000']
    scrape_interval: 5s
    metrics_path: '/metrics'
EOF

# Create Grafana datasource
cat > monitoring/grafana/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

# Create MongoDB initialization script
cat > init-scripts/init-mongo.js << 'EOF'
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
EOF

# Create environment file

# Start Docker services
echo "🐳 Starting Docker services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check service health
echo "🔍 Checking service health..."

check_service() {
    local service_name=$1
    local url=$2
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s $url > /dev/null; then
            echo "✅ $service_name is ready"
            return 0
        fi
        echo "⏳ $service_name not ready, attempt $attempt/$max_attempts"
        sleep 5
        ((attempt++))
    done
    
    echo "❌ $service_name failed to start"
    return 1
}

check_service "MinIO" "http://localhost:9000/minio/health/live"
check_service "Vault" "http://localhost:8200/v1/sys/health"
check_service "MongoDB" "http://localhost:27017"

# Initialize MinIO buckets
echo "🪣 Initializing MinIO bucket..."
docker exec tourist-minio mc alias set local http://localhost:9000 minioadmin minioadmin123
docker exec tourist-minio mc mb local/tourist-safety-encrypted --ignore-existing

# Setup Vault encryption
echo "🔐 Setting up Vault encryption..."
sleep 5

# Enable transit secrets engine
curl -s -H "X-Vault-Token: myroot" \
     -X POST \
     -d '{"type": "transit", "description": "Tourist Safety Encryption"}' \
     http://localhost:8200/v1/sys/mounts/transit 2>/dev/null || echo "Transit engine may already exist"

# Create encryption key
curl -s -H "X-Vault-Token: myroot" \
     -X POST \
     -d '{"type": "aes256-gcm96"}' \
     http://localhost:8200/v1/transit/keys/tourist-safety-key 2>/dev/null || echo "Key may already exist"

# Verify Vault setup
echo "🔍 Verifying Vault setup..."
VAULT_STATUS=$(curl -s -H "X-Vault-Token: myroot" http://localhost:8200/v1/transit/keys/tourist-safety-key | grep -o '"name":"tourist-safety-key"' || echo "")

if [ -n "$VAULT_STATUS" ]; then
    echo "✅ Vault encryption key created successfully"
else
    echo "⚠️  Vault key creation may have failed, but system will fallback to local encryption"
fi
