# Quick Docker Setup for Mac (Lightweight)

## 🚀 Fastest Setup: Colima

Colima is a lightweight Docker alternative that works perfectly with our setup.

### One-Command Setup:
```bash
./setup-colima.sh
```

This will:
- Install Colima (if not installed)
- Start Colima
- Verify everything works

### Then Start Your App:
```bash
# 1. Set up environment
cp env.example .env
# Edit .env and set FS_SERVER_SECRET (use: openssl rand -base64 32)

# 2. Start the application
./docker-start.sh
```

### That's it! 🎉

Your app will be running at: http://localhost:8000

---

## 📦 What is Colima?

Colima (Container Linux on Mac) is a lightweight, open-source alternative to Docker Desktop. It:
- ✅ Uses minimal resources
- ✅ Works with standard Docker commands
- ✅ Compatible with docker-compose
- ✅ Free and open-source
- ✅ No GUI required

## 🛠️ Manual Installation

If you prefer to install manually:

```bash
# Install Colima
brew install colima docker docker-compose

# Start Colima
colima start

# Verify
docker ps
```

## 🔄 Common Commands

```bash
# Start Colima
colima start

# Stop Colima
colima stop

# Restart Colima
colima restart

# Check status
colima status

# View logs
colima logs
```

## 🆚 Colima vs Docker Desktop

| Feature | Colima | Docker Desktop |
|---------|--------|----------------|
| Resource Usage | Minimal (~200MB) | Heavy (~1GB+) |
| GUI | No (CLI only) | Yes |
| Cost | Free | Free (with usage limits) |
| Docker CLI | ✅ Compatible | ✅ Compatible |
| docker-compose | ✅ Compatible | ✅ Compatible |
| Performance | Fast | Fast |

## 🐛 Troubleshooting

### Docker credential helper error
If you see: `docker-credential-osxkeychain: executable file not found`

**This is automatically fixed by `docker-start.sh`**, but if you need to fix it manually:

```bash
# Option 1: Use jq (if installed)
jq 'del(.credsStore)' ~/.docker/config.json > ~/.docker/config.json.tmp && \
mv ~/.docker/config.json.tmp ~/.docker/config.json

# Option 2: Create new config
cat > ~/.docker/config.json <<EOF
{
  "auths": {}
}
EOF
```

This configures Docker to not use the credential helper (which isn't needed for Colima).

### Colima won't start
```bash
# Check system requirements
colima status

# Restart Colima
colima stop
colima start
```

### Docker commands not found
After installing Colima, make sure Docker is in your PATH:
```bash
# Add to ~/.zshrc or ~/.bash_profile
export PATH="/usr/local/bin:$PATH"
```

### Port conflicts
If port 8000 is already in use, change it in `docker-compose.yml`:
```yaml
ports:
  - "8001:8000"  # Use 8001 instead
```

### Build warnings
The warnings about `version` in docker-compose.yml and Dockerfile casing are harmless and have been fixed in the latest versions. If you see them, update to the latest files.

## 📚 More Information

- Full documentation: See [DOCKER.md](DOCKER.md)
- Colima GitHub: https://github.com/abiosoft/colima

