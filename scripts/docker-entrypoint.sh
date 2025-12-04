#!/bin/bash
set -e

# Get configuration from environment variables
HOSTNAME=${HOSTNAME:-0.0.0.0}
PORT=${PORT:-8000}
HTTPS_ENABLED=${HTTPS_ENABLED:-false}
SSL_CERT_PATH=${SSL_CERT_PATH:-/app/certs/cert.pem}
SSL_KEY_PATH=${SSL_KEY_PATH:-/app/certs/key.pem}

# Ensure data and logs directories exist and are writable
# This must happen BEFORE uvicorn starts, as init_db() is called at module import time
echo "📁 Ensuring data and logs directories exist..."
mkdir -p /app/data /app/logs

# Function to check and report directory permissions
check_dir_permissions() {
    local dir=$1
    local host_dir_name=$2  # e.g., "data" or "logs"
    
    if [ ! -w "$dir" ]; then
        echo "❌ ERROR: $dir directory is not writable!"
        echo "   This happens when the host directory has wrong ownership."
        echo "   Container user: $(id -u):$(id -g) (fabricstudio:fabricstudio)"
        echo "   Current $dir permissions: $(ls -ld $dir)"
        echo ""
        echo "   🔧 Fix on the HOST machine (in the project directory):"
        echo "   sudo chown -R $(id -u):$(id -g) ./$host_dir_name"
        echo ""
        echo "   OR (for testing only, less secure):"
        echo "   sudo chmod -R 777 ./$host_dir_name"
        echo ""
        echo "   Then restart: docker-compose restart"
        return 1
    fi
    return 0
}

# Check permissions for data and logs directories
if ! check_dir_permissions /app/data "data"; then
    exit 1
fi

if ! check_dir_permissions /app/logs "logs"; then
    exit 1
fi

# Build uvicorn command
UVICORN_CMD="uvicorn src.app:app --host ${HOSTNAME} --port ${PORT}"

# Add HTTPS configuration if enabled
if [ "${HTTPS_ENABLED}" = "true" ] || [ "${HTTPS_ENABLED}" = "1" ]; then
    # Check if certificate files exist
    if [ ! -f "${SSL_CERT_PATH}" ] || [ ! -f "${SSL_KEY_PATH}" ]; then
        echo "⚠️  WARNING: HTTPS enabled but certificate files not found!"
        echo "   Certificate: ${SSL_CERT_PATH}"
        echo "   Key: ${SSL_KEY_PATH}"
        echo "   Falling back to HTTP mode."
    else
        echo "🔒 Starting with HTTPS enabled"
        UVICORN_CMD="${UVICORN_CMD} --ssl-certfile ${SSL_CERT_PATH} --ssl-keyfile ${SSL_KEY_PATH}"
    fi
else
    echo "🌐 Starting with HTTP (HTTPS disabled)"
fi

# Ensure initial users are created (runs automatically on startup)
echo "👤 Ensuring initial users exist..."
python /app/scripts/create_users.py || {
    echo "⚠️  WARNING: Failed to create initial users. Continuing anyway..."
}

echo "🚀 Starting FabricStudio API on ${HOSTNAME}:${PORT}"
echo "   Command: ${UVICORN_CMD}"

# Execute uvicorn
exec $UVICORN_CMD

