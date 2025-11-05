#!/bin/bash
# Run uvicorn locally (outside Docker)

set -e  # Exit on error

# Activate virtual environment if it exists, or create one
if [ -d "venv" ]; then
    source venv/bin/activate
    VENV_PATH="venv"
elif [ -d ".venv" ]; then
    source .venv/bin/activate
    VENV_PATH=".venv"
else
    echo "⚠️  No virtual environment found. Creating one..."
    python3 -m venv venv
    source venv/bin/activate
    VENV_PATH="venv"
    echo "✅ Virtual environment created"
fi

# Check if requirements are installed
if ! python -c "import uvicorn" 2>/dev/null; then
    echo "📦 Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    echo "✅ Dependencies installed"
fi

# Set environment variables
export FS_SERVER_SECRET=${FS_SERVER_SECRET:-$(openssl rand -base64 32)}
export DB_PATH=${DB_PATH:-fabricstudio_ui.db}

echo ""
echo "Starting FabricStudio API..."
echo "Virtual environment: $VENV_PATH"
echo "Server secret: Set via FS_SERVER_SECRET environment variable"
echo "Database: $DB_PATH"
echo ""

# Run uvicorn with reload for development
uvicorn app:app --reload --host 0.0.0.0 --port 8000

