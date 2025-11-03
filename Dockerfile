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
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

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

# Copy application code
COPY --chown=fabricstudio:fabricstudio . .

# Create directories for database and logs with proper permissions
RUN mkdir -p /app/data /app/logs && \
    chown -R fabricstudio:fabricstudio /app/data /app/logs /app

# Set environment variables
ENV PATH=/usr/local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/app/data/fabricstudio_ui.db

# Switch to non-root user
USER fabricstudio

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Run the application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

