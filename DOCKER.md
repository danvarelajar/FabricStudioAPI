# Docker Deployment Guide

This guide covers secure Docker deployment for FabricStudio API.

## 🚀 Lightweight Docker Alternatives for Mac

If you can't use Docker Desktop, here are lightweight alternatives:

### Option 1: Colima (Recommended - Lightweight)

Colima (Container Linux on Mac) is a lightweight alternative to Docker Desktop.

#### Installation:
```bash
# Install via Homebrew
brew install colima docker docker-compose

# Start Colima
colima start

# Verify it's working
docker ps
```

#### Usage:
Use docker-compose normally - it works exactly the same:
```bash
docker-compose up -d
```

#### Stop Colima:
```bash
colima stop
```

### Option 2: Podman (Alternative)

Podman is a daemonless, rootless container engine.

#### Installation:
```bash
brew install podman

# Initialize Podman machine
podman machine init

# Start Podman machine
podman machine start
```

#### Using Podman with docker-compose:
```bash
# Install podman-compose
pip install podman-compose

# Use podman-compose instead of docker-compose
podman-compose up -d
```

### Option 3: Lima (Advanced)

Lima provides a lightweight VM for running containers.

#### Installation:
```bash
brew install lima

# Start Lima with Docker
limactl start template://docker
```

## 🔒 Security Best Practices

### 1. Environment Variables

**CRITICAL**: Always set `FS_SERVER_SECRET` before running in production. This secret is used to encrypt sensitive data in the database.

#### Generate a Strong Secret:
```bash
openssl rand -base64 32
```

#### Using .env file:
```bash
# Copy the example file
cp env.example .env

# Edit .env and set FS_SERVER_SECRET
nano .env
```

#### Using Docker Compose directly:
```bash
export FS_SERVER_SECRET=$(openssl rand -base64 32)
docker-compose up -d
```

#### Using Docker run:
```bash
docker run -d \
  -e FS_SERVER_SECRET=$(openssl rand -base64 32) \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -p 8000:8000 \
  fabricstudio-api
```

### 2. Database Persistence

The database is stored in the `./data` directory, which is mounted as a volume. This ensures:
- Data persists across container restarts
- Data survives container deletion
- Easy backup and restore

**Important**: Backup the `./data` directory regularly!

### 3. Logs

Logs are persisted in the `./logs` directory. Ensure proper log rotation in production.

### 4. Non-Root User

The container runs as a non-root user (`fabricstudio`) for enhanced security.

### 5. Secret Management

**Never commit secrets to version control!**

Options for managing secrets in production:
- Use Docker secrets (Docker Swarm)
- Use Kubernetes secrets
- Use external secret managers (AWS Secrets Manager, HashiCorp Vault, etc.)
- Use environment variables from CI/CD pipelines

## 🚀 Quick Start

### Prerequisites
- Docker or Colima/Podman installed
- Docker Compose (or podman-compose)

### Build and Run

1. **Set up environment variables:**
   ```bash
   cp env.example .env
   # Edit .env and set FS_SERVER_SECRET
   ```

2. **Create required directories:**
   ```bash
   mkdir -p data logs
   ```

3. **Build and start the container:**
   ```bash
   # With Docker/Colima
   docker-compose up -d
   
   # Or with Podman
   podman-compose up -d
   ```

4. **View logs:**
   ```bash
   docker-compose logs -f
   # or
   podman-compose logs -f
   ```

5. **Stop the container:**
   ```bash
   docker-compose down
   # or
   podman-compose down
   ```

## 📦 Building the Image

### Build locally:
```bash
docker build -t fabricstudio-api:latest .
# or
podman build -t fabricstudio-api:latest .
```

### Build with specific tag:
```bash
docker build -t fabricstudio-api:v1.0.0 .
```

## 🔍 Troubleshooting

### Container won't start
1. Check logs: `docker-compose logs`
2. Verify `FS_SERVER_SECRET` is set
3. Check directory permissions for `data/` and `logs/`

### Database issues
- Ensure `./data` directory exists and is writable
- Check file permissions: `ls -la data/`
- If needed, initialize database: `docker-compose exec fabricstudio-api python init_empty_db.py`

### Port already in use
- Change port mapping in `docker-compose.yml`:
  ```yaml
  ports:
    - "8001:8000"  # Use port 8001 on host
  ```

### Colima Issues
```bash
# Restart Colima
colima restart

# Check status
colima status

# View logs
colima logs
```

### Podman Issues
```bash
# Restart Podman machine
podman machine stop
podman machine start

# Check status
podman machine list
```

## 🔄 Updates and Maintenance

### Update the application:
```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose up -d --build
```

### Backup database:
```bash
# Stop container
docker-compose stop

# Backup data directory
tar -czf backup-$(date +%Y%m%d).tar.gz data/

# Restart container
docker-compose start
```

### Restore database:
```bash
# Stop container
docker-compose stop

# Restore backup
tar -xzf backup-YYYYMMDD.tar.gz

# Restart container
docker-compose start
```

## 🛡️ Production Deployment Checklist

- [ ] Generate strong `FS_SERVER_SECRET` using `openssl rand -base64 32`
- [ ] Set `FS_SERVER_SECRET` as environment variable (not in code)
- [ ] Use `.env` file or secure secret management
- [ ] Set up regular database backups
- [ ] Configure log rotation
- [ ] Use HTTPS reverse proxy (nginx, Traefik, etc.)
- [ ] Set up firewall rules
- [ ] Enable container resource limits
- [ ] Set up monitoring and alerting
- [ ] Review and update security policies
- [ ] Test backup and restore procedures
- [ ] Document runbook for your team

## 🌐 Reverse Proxy Setup (Recommended)

For production, use a reverse proxy like nginx or Traefik:

### Example nginx configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📊 Monitoring

### Health check:
The container includes a health check. Check status:
```bash
docker ps  # Look for "healthy" status
```

### Container stats:
```bash
docker stats fabricstudio-api
```

## 🔐 Additional Security Recommendations

1. **Use Docker secrets** for sensitive data in production
2. **Scan images** for vulnerabilities: `docker scan fabricstudio-api`
3. **Keep base images updated** regularly
4. **Use read-only filesystem** where possible (add `read_only: true` to docker-compose)
5. **Limit container capabilities** (already using non-root user)
6. **Use network policies** to restrict container communication
7. **Enable audit logging** for container actions
8. **Regularly update dependencies** in requirements.txt

## 📝 Notes

- The database file (`fabricstudio_ui.db`) is stored in `./data/`
- Logs are stored in `./logs/`
- The application runs on port 8000 inside the container
- All sensitive data in the database is encrypted using `FS_SERVER_SECRET`
