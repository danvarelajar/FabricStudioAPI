#!/bin/bash
# Quick start script for Docker deployment (works with Docker, Colima, or Podman)

set -e

# Detect if using podman-compose
if command -v podman-compose &> /dev/null && ! docker ps &> /dev/null 2>&1; then
    DOCKER_CMD="podman-compose"
    DOCKER_ENGINE="Podman"
elif command -v docker-compose &> /dev/null; then
    DOCKER_CMD="docker-compose"
    DOCKER_ENGINE="Docker/Colima"
else
    echo "❌ Error: Neither docker-compose nor podman-compose found!"
    echo "   Install Docker/Colima: ./setup-colima.sh"
    echo "   Or install Podman: brew install podman podman-compose"
    exit 1
fi

echo "🔒 FabricStudio API - Docker Setup"
echo "=================================="
echo "Using: $DOCKER_ENGINE"
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from env.example..."
    cp env.example .env
    echo ""
    echo "❌ CRITICAL: Please edit .env and set FS_SERVER_SECRET"
    echo "   Generate a secret with: openssl rand -base64 32"
    echo ""
    read -p "Press Enter after you've set FS_SERVER_SECRET in .env..."
fi

# Create required directories
echo "📁 Creating required directories..."
mkdir -p data logs

# Check if FS_SERVER_SECRET is set
source .env 2>/dev/null || true
if [ "$FS_SERVER_SECRET" = "CHANGE_ME_IN_PRODUCTION_USE_STRONG_RANDOM_SECRET" ] || [ -z "$FS_SERVER_SECRET" ]; then
    echo ""
    echo "❌ ERROR: FS_SERVER_SECRET is not set or is using default value!"
    echo "   Please edit .env and set a strong random secret."
    echo "   Generate with: openssl rand -base64 32"
    exit 1
fi

echo "✅ Environment variables configured"
echo ""

# Check if Docker/Colima/Podman is running
if [ "$DOCKER_CMD" = "podman-compose" ]; then
    if ! podman machine list | grep -q "running"; then
        echo "⚠️  Podman machine is not running. Starting..."
        podman machine start
    fi
else
    if ! docker ps &> /dev/null 2>&1; then
        echo "⚠️  Docker is not running."
        if command -v colima &> /dev/null; then
            echo "   Starting Colima..."
            colima start
        else
            echo "   Please start Docker Desktop or Colima first"
            exit 1
        fi
    fi
    
    # Check for credential helper issue (common with Colima)
    if [ -f "$HOME/.docker/config.json" ] && grep -q "credsStore.*osxkeychain" "$HOME/.docker/config.json" 2>/dev/null; then
        echo ""
        echo "⚠️  Docker credential helper issue detected. Fixing..."
        DOCKER_CONFIG_DIR="$HOME/.docker"
        if command -v jq &> /dev/null; then
            jq 'del(.credsStore)' "$DOCKER_CONFIG_DIR/config.json" > "$DOCKER_CONFIG_DIR/config.json.tmp" && \
            mv "$DOCKER_CONFIG_DIR/config.json.tmp" "$DOCKER_CONFIG_DIR/config.json"
            echo "✅ Removed credential helper from Docker config"
        else
            # Create config without credential helper
            cat > "$DOCKER_CONFIG_DIR/config.json" <<EOF
{
  "auths": {}
}
EOF
            echo "✅ Created Docker config without credential helper"
        fi
    fi
fi

# Build and start containers
echo "🐳 Building Docker image..."
$DOCKER_CMD build

echo ""
echo "🚀 Starting containers..."
$DOCKER_CMD up -d

echo ""
echo "✅ FabricStudio API is starting!"
echo ""
echo "📊 View logs: $DOCKER_CMD logs -f"
echo "🌐 Access at: http://localhost:8000"
echo "🛑 Stop with: $DOCKER_CMD down"
echo ""

