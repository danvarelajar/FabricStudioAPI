#!/bin/bash
# Setup script for Colima (Lightweight Docker alternative for Mac)

set -e

echo "🐳 Setting up Colima for FabricStudio API"
echo "=========================================="
echo ""

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew is not installed. Please install it first:"
    echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    exit 1
fi

# Check if Colima is installed
if ! command -v colima &> /dev/null; then
    echo "📦 Installing Colima..."
    brew install colima docker docker-compose
else
    echo "✅ Colima is already installed"
fi

# Check if Colima is running
if colima status &> /dev/null; then
    echo "✅ Colima is already running"
else
    echo "🚀 Starting Colima..."
    colima start
fi

# Fix Docker credential helper issue (common with Colima)
echo ""
echo "🔧 Configuring Docker credential helper..."
DOCKER_CONFIG_DIR="$HOME/.docker"
mkdir -p "$DOCKER_CONFIG_DIR"
if [ ! -f "$DOCKER_CONFIG_DIR/config.json" ] || ! grep -q "credsStore" "$DOCKER_CONFIG_DIR/config.json" 2>/dev/null; then
    # Create config.json without credential helper if it doesn't exist or doesn't have credsStore
    cat > "$DOCKER_CONFIG_DIR/config.json" <<EOF
{
  "auths": {},
  "credsStore": ""
}
EOF
    echo "✅ Configured Docker to not use credential helper"
elif grep -q "credsStore.*osxkeychain" "$DOCKER_CONFIG_DIR/config.json" 2>/dev/null; then
    # Remove osxkeychain credential helper if present
    if command -v jq &> /dev/null; then
        jq 'del(.credsStore)' "$DOCKER_CONFIG_DIR/config.json" > "$DOCKER_CONFIG_DIR/config.json.tmp" && \
        mv "$DOCKER_CONFIG_DIR/config.json.tmp" "$DOCKER_CONFIG_DIR/config.json"
        echo "✅ Removed osxkeychain credential helper"
    else
        # Fallback: install docker-credential-helper if jq not available
        if ! command -v docker-credential-osxkeychain &> /dev/null; then
            echo "📦 Installing docker-credential-helper..."
            brew install docker-credential-helper
        fi
    fi
fi

# Verify Docker is working
echo ""
echo "🔍 Verifying Docker installation..."
if docker ps &> /dev/null; then
    echo "✅ Docker is working correctly!"
else
    echo "❌ Docker is not working. Please check Colima status:"
    echo "   colima status"
    exit 1
fi

echo ""
echo "✅ Colima setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Copy env.example to .env:"
echo "      cp env.example .env"
echo ""
echo "   2. Edit .env and set FS_SERVER_SECRET:"
echo "      nano .env"
echo "      # Generate secret: openssl rand -base64 32"
echo ""
echo "   3. Start the application:"
echo "      ./docker-start.sh"
echo "      # or"
echo "      docker-compose up -d"
echo ""
echo "🛑 To stop Colima later:"
echo "   colima stop"
echo ""

