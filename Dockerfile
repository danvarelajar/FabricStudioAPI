# Multi-stage build for security and smaller image size
FROM python:3.9-slim AS builder

# Set working directory
WORKDIR /app

# Install system dependencies needed for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies to a temporary location
# Use BuildKit cache mount for pip cache (faster rebuilds)
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# Production stage
FROM python:3.9-slim

# Create non-root user for security (before copying files)
RUN groupadd -r fabricstudio && useradd -r -g fabricstudio fabricstudio

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder stage to system location
COPY --from=builder /install /usr/local

# Verify uvicorn is accessible
RUN python -c "import uvicorn" && which uvicorn

# Copy application code - copy frontend separately to ensure cache invalidation on frontend changes
COPY --chown=fabricstudio:fabricstudio frontend/ ./frontend/
COPY --chown=fabricstudio:fabricstudio src/ ./src/
COPY --chown=fabricstudio:fabricstudio requirements.txt ./

# Create directories for database, logs, and certificates with proper permissions
RUN mkdir -p /app/data /app/logs /app/certs && \
    chown -R fabricstudio:fabricstudio /app/data /app/logs /app/certs /app

# Set environment variables
# Note: DB_PATH is set in docker-compose.yml to ensure correct path in container
# docker-compose.yml environment section takes precedence over Dockerfile ENV
ENV PATH=/usr/local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

# Switch to non-root user
USER fabricstudio

# Expose port (default 8000, can be overridden via PORT env var)
EXPOSE 8000

# Health check (use dedicated health endpoint)
# Port will be read from PORT environment variable at runtime
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import os, urllib.request; port=os.getenv('PORT', '8000'); protocol='https' if os.getenv('HTTPS_ENABLED', 'false').lower() == 'true' else 'http'; urllib.request.urlopen(f'{protocol}://localhost:{port}/health')" || exit 1

# Copy startup script
COPY --chown=fabricstudio:fabricstudio scripts/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Run the application via entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"]

