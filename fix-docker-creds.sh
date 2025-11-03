#!/bin/bash
# Quick fix for Docker credential helper issue with Colima

set -e

echo "🔧 Fixing Docker credential helper configuration..."
echo ""

DOCKER_CONFIG_DIR="$HOME/.docker"
mkdir -p "$DOCKER_CONFIG_DIR"

# Check if config.json exists
if [ -f "$DOCKER_CONFIG_DIR/config.json" ]; then
    # Try to use jq if available
    if command -v jq &> /dev/null; then
        echo "Using jq to update config..."
        jq 'del(.credsStore)' "$DOCKER_CONFIG_DIR/config.json" > "$DOCKER_CONFIG_DIR/config.json.tmp" && \
        mv "$DOCKER_CONFIG_DIR/config.json.tmp" "$DOCKER_CONFIG_DIR/config.json"
        echo "✅ Removed credential helper from Docker config"
    else
        # Manual fix: create a new config without credential helper
        echo "Creating new Docker config without credential helper..."
        cat > "$DOCKER_CONFIG_DIR/config.json" <<EOF
{
  "auths": {}
}
EOF
        echo "✅ Created Docker config without credential helper"
    fi
else
    # Create new config file
    echo "Creating Docker config file..."
    cat > "$DOCKER_CONFIG_DIR/config.json" <<EOF
{
  "auths": {}
}
EOF
    echo "✅ Created Docker config file"
fi

echo ""
echo "✅ Docker credential helper fixed!"
echo ""
echo "Try running docker-start.sh again:"
echo "  ./docker-start.sh"
echo ""

