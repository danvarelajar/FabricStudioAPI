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

# Check if directories are writable
if [ ! -w /app/data ]; then
    echo "❌ ERROR: /app/data directory is not writable!"
    echo "   This usually happens when the ./data directory on the host has wrong permissions."
    echo "   Container user: $(id -u):$(id -g)"
    echo "   Current /app/data permissions: $(ls -ld /app/data)"
    echo "   Fix with: sudo chown -R $(id -u):$(id -g) ./data"
    echo "   Alternatively, for testing, make it world-writable: chmod -R 777 ./data"
    exit 1
fi

if [ ! -w /app/logs ]; then
    echo "❌ ERROR: /app/logs directory is not writable!"
    echo "   Container user: $(id -u):$(id -g)"
    echo "   Current /app/logs permissions: $(ls -ld /app/logs)"
    echo "   Fix with: sudo chown -R $(id -u):$(id -g) ./logs"
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

