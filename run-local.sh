#!/bin/bash
# Run uvicorn locally (outside Docker)

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Set environment variables
export FS_SERVER_SECRET=${FS_SERVER_SECRET:-$(openssl rand -base64 32)}
export DB_PATH=${DB_PATH:-fabricstudio_ui.db}

echo "Starting FabricStudio API..."
echo "Server secret: Set via FS_SERVER_SECRET environment variable"
echo "Database: $DB_PATH"
echo ""

# Run uvicorn with reload for development
uvicorn app:app --reload --host 0.0.0.0 --port 8000

