#!/bin/bash
set -e

# Ensure data and logs directories exist and are writable
CONTAINER_UID=$(id -u)
CONTAINER_GID=$(id -g)

# Try to create directories (will fail silently if parent isn't writable)
mkdir -p /app/data /app/logs 2>/dev/null || true

if [ ! -w /app/data ]; then
    echo "❌ ERROR: /app/data directory is not writable!"
    echo "   This usually happens when the ./data directory on the host has wrong permissions."
    echo ""
    echo "   Container is running as UID:${CONTAINER_UID} GID:${CONTAINER_GID}"
    echo "   Current /app/data permissions: $(ls -ld /app/data 2>/dev/null || echo 'directory does not exist')"
    echo ""
    echo "   Fix on the HOST (outside container):"
    echo "   1. Stop the container: docker-compose down"
    echo "   2. Fix ownership (recommended):"
    echo "      sudo chown -R ${CONTAINER_UID}:${CONTAINER_GID} ./data ./logs"
    echo "   3. Or make world-writable (less secure, for testing only):"
    echo "      chmod -R 777 ./data ./logs"
    echo "   4. Restart: docker-compose up -d"
    echo ""
    echo "   Or create directories before starting container:"
    echo "      mkdir -p data logs certs"
    echo "      chmod 755 data logs certs"
    exit 1
fi

# Get configuration from environment variables
HOSTNAME=${HOSTNAME:-0.0.0.0}
PORT=${PORT:-8000}
HTTPS_ENABLED=${HTTPS_ENABLED:-false}
SSL_CERT_PATH=${SSL_CERT_PATH:-/app/certs/cert.pem}
SSL_KEY_PATH=${SSL_KEY_PATH:-/app/certs/key.pem}

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

echo "🚀 Starting FabricStudio API on ${HOSTNAME}:${PORT}"
echo "   Command: ${UVICORN_CMD}"

# Execute uvicorn
exec $UVICORN_CMD

