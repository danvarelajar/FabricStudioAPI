# FabricStudio API

A FastAPI-based web application for managing FabricStudio configurations, NHI credentials, SSH keys, and event scheduling with Model Context Protocol (MCP) support.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [MCP (Model Context Protocol)](#mcp-model-context-protocol)
- [Database](#database)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)

## Features

### FabricStudio Runs
- **Configurations**: Create, edit, save, and run FabricStudio configurations without needing to contact hosts
  - Automatic cache management for fresh template and repository data
  - Template caching for faster access
  - Progress logging with timestamps for tracking installation progress
- **SSH Command Profiles**: Create reusable SSH command profiles with optional SSH key association
  - Execute SSH commands on fabric hosts before workspace installation
  - Configurable wait times between commands
- **Reports**: View detailed execution reports
  - Host Summary with execution results
  - SSH Profile Execution details
  - Microsoft Teams notifications (optional) - Send Adaptive Card notifications to Teams channels when reports are created

### Event Schedule
- **Automated Scheduling**: Schedule FabricStudio runs with date and time support
- **Execution History**: Track detailed execution history for scheduled events
  - SSH command execution results
  - Execution status and timestamps
- **Validation**: Prevents scheduling events in the past

### NHI Management
- **NHI Credentials**: Store and manage NHI credentials with encrypted client secrets
  - Session-based token management with secure server-side storage
  - Automatic token refresh (proactive and on-demand)
  - Tokens refresh automatically before expiration
- **SSH Keys**: Securely store and manage SSH key pairs
  - Public keys and encrypted private keys
  - Never exposed to the frontend

### User Management
- **User Authentication**: Secure user authentication with encrypted password storage
- **Password Security**: Passwords hashed using bcrypt before storage

### Model Context Protocol (MCP)
- **MCP Server**: Expose FabricStudio API functionality via MCP protocol
  - List templates, repositories, and configurations
  - Create and update configurations
  - Execute configurations
  - Manage NHI credentials, SSH keys, and SSH profiles
  - Schedule events
- **Remote Access**: Use `mcp-remote` to connect local MCP clients to the API

### Logs
- **Audit Logs**: Track user actions for security auditing
- **Server Logs**: View application logs with timestamps

### Additional Features
- **Modern UI**: Clean, responsive interface with Inter font family and styled navigation menu
- **Security**: HTTP-only cookies, encrypted data storage, and comprehensive security measures

## Requirements

### System Requirements

#### Minimum Requirements
- **Operating System**: Linux, macOS, or Windows (with WSL2)
- **CPU**: 1 core (2+ recommended)
- **Memory**: 512 MB RAM (2 GB recommended)
- **Disk Space**: 500 MB for application + data storage

#### Software Requirements

1. **Docker** (version 20.10 or later)
   - For Linux: Install via your distribution's package manager
   - For macOS: Use Colima (recommended, see below) or Docker Desktop
   - For Windows: Docker Desktop with WSL2 backend

2. **Docker Compose** (version 2.0 or later)
   - Usually included with Docker Desktop
   - For Linux: May need separate installation

3. **Python 3.9+** (for running scripts locally)
   - Required for user management scripts
   - Not required for Docker deployment

4. **OpenSSL** (for generating secrets)
   - Usually pre-installed on Linux/macOS
   - Available via package managers

#### macOS-Specific: Colima (Recommended)

Colima is a lightweight Docker alternative for macOS (~200MB vs Docker Desktop's 1GB+).

**Installation:**
```bash
# Using Homebrew
brew install colima docker docker-compose

# Or use the provided setup script
./scripts/setup-colima.sh
```

**Start Colima:**
```bash
colima start
```

Colima works seamlessly with Docker commands - no changes needed to your workflow.

### Python Dependencies

The following Python packages are required (automatically installed in Docker):

- `fastapi>=0.104.0` - Web framework
- `uvicorn[standard]>=0.24.0` - ASGI server
- `pydantic>=2.0.0` - Data validation
- `requests>=2.31.0` - HTTP client
- `cryptography>=41.0.0` - Encryption utilities
- `urllib3>=2.0.0` - HTTP library
- `paramiko>=3.0.0` - SSH client
- `pytest>=7.0.0` - Testing framework
- `httpx>=0.24.0` - Async HTTP client

All dependencies are listed in `requirements.txt` and installed automatically during Docker build.

## Installation

### Quick Start (Docker - Recommended)

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd FabricStudioAPI
   ```

2. **Create required directories:**
   ```bash
   # Create data and logs directories with proper permissions
   mkdir -p data logs certs
   chmod 755 data logs certs
   ```

3. **Set up environment variables:**
   ```bash
   # Create .env file from template
   cat > .env << EOF
   # CRITICAL: Generate a strong secret for encryption
   FS_SERVER_SECRET=$(openssl rand -base64 32)
   
   # Server Configuration
   HOSTNAME=0.0.0.0
   PORT=8000
   HTTPS_ENABLED=false
   
   # FabricStudio API Configuration (optional, can be set per NHI credential)
   LEAD_FABRIC_HOST=
   LEAD_CLIENT_ID=
   LEAD_CLIENT_SECRET=
   
   # MCP Configuration (required if MCP_ENABLED=true)
   MCP_ENABLED=true
   MCP_API_KEY=$(openssl rand -base64 32)  # REQUIRED: Generate a strong API key
   
   # Microsoft Teams (optional)
   TEAMS_WEBHOOK_URL=
   
   # Logging
   LOG_LEVEL=INFO
   EOF
   ```

4. **Start the application:**
   ```bash
   # Using helper script (recommended)
   ./scripts/docker-start.sh
   
   # Or manually
   docker-compose build
   docker-compose up -d
   ```

5. **Verify installation:**
   ```bash
   # Check container status
   docker-compose ps
   
   # Check logs
   docker-compose logs -f fabricstudio-api
   
   # Access the application
   # Open http://localhost:8000 in your browser
   ```

6. **Create initial users:**
   ```bash
   # Edit scripts/create_users.py to customize users
   # Default: admin / FortinetAssistant1!
   python scripts/create_users.py
   ```

### Manual Installation (Without Docker)

**Note:** Docker is the recommended deployment method. Manual installation is for development only.

1. **Install Python 3.9+ and dependencies:**
   ```bash
   # Install Python dependencies
   pip install -r requirements.txt
   ```

2. **Set up environment variables:**
   ```bash
   export FS_SERVER_SECRET=$(openssl rand -base64 32)
   export DB_PATH=./data/fabricstudio_ui.db
   export HOSTNAME=0.0.0.0
   export PORT=8000
   # MCP Configuration (required if MCP_ENABLED=true)
   export MCP_ENABLED=true
   export MCP_API_KEY=$(openssl rand -base64 32)  # REQUIRED: Generate a strong API key
   ```

3. **Initialize the database:**
   ```bash
   python src/init_empty_db.py
   ```

4. **Start the application:**
   ```bash
   cd src
   uvicorn app:app --host 0.0.0.0 --port 8000
   ```

### Post-Installation

1. **Access the application:**
   - Open `http://localhost:8000` (or your configured port)
   - Log in with the credentials created in step 5 above

2. **Configure NHI Credentials:**
   - Navigate to **NHI Management > NHI Credentials**
   - Add your FabricStudio OAuth Client ID and Secret
   - See [Registering a FabricStudio OAuth Application](#registering-a-fabricstudio-oauth-application) below

3. **Configure MCP (Optional):**
   - If MCP is enabled, configure your MCP client to connect
   - See [MCP Configuration](#mcp-model-context-protocol) section

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

#### Required Configuration

- **`FS_SERVER_SECRET`** (REQUIRED)
  - Strong random secret for encrypting sensitive data
  - Generate with: `openssl rand -base64 32`
  - **CRITICAL**: Never use the default value in production
  - Example: `FS_SERVER_SECRET=Kx9mP2vQ7wR5tY8uI3oP6aS1dF4gH7jK0lM9nB2cV5xZ8=`

#### Server Configuration

- **`HOSTNAME`** (default: `0.0.0.0`)
  - Hostname/IP to bind to
  - Use `0.0.0.0` to listen on all interfaces

- **`PORT`** (default: `8000`)
  - Port to listen on
  - Example: `PORT=9000`

- **`HTTPS_ENABLED`** (default: `false`)
  - Enable HTTPS
  - Requires SSL certificates (see below)

- **`SSL_CERT_PATH`** (default: `/app/certs/cert.pem`)
  - Path to SSL certificate file (inside container)

- **`SSL_KEY_PATH`** (default: `/app/certs/key.pem`)
  - Path to SSL private key file (inside container)

#### FabricStudio API Configuration

- **`LEAD_FABRIC_HOST`** (optional)
  - Primary FabricStudio host for template operations
  - Can be overridden per NHI credential

- **`LEAD_CLIENT_ID`** (optional)
  - Default OAuth Client ID for LEAD_FABRIC_HOST

- **`LEAD_CLIENT_SECRET`** (optional)
  - Default OAuth Client Secret for LEAD_FABRIC_HOST

#### MCP Configuration

- **`MCP_ENABLED`** (default: `true`)
  - Enable MCP protocol endpoint at `/mcp`

- **`MCP_API_KEY`** (REQUIRED if MCP_ENABLED is true)
  - API key for MCP authentication
  - Generate with: `openssl rand -base64 32`
  - **CRITICAL**: Must be set via environment variable - no default for security
  - If not set, MCP requests will be rejected with 401
  - Example: `MCP_API_KEY=Kx9mP2vQ7wR5tY8uI3oP6aS1dF4gH7jK0lM9nB2cV5xZ8=`

#### Microsoft Teams Notifications (Optional)

- **`TEAMS_WEBHOOK_URL`** (optional)
  - Microsoft Teams webhook URL for Adaptive Card notifications
  - Setup:
    1. In Microsoft Teams, go to your channel
    2. Click `...` menu → **Connectors**
    3. Search for **"Incoming Webhook"**
    4. Configure and copy the webhook URL
  - Example: `TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...`

#### Logging Configuration

- **`LOG_LEVEL`** (default: `INFO`)
  - Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

#### CORS Configuration (Optional)

- **`CORS_ALLOW_ORIGINS`** (optional)
  - Comma-separated list of allowed origins
  - Auto-generated if not set based on HOSTNAME/PORT/HTTPS_ENABLED
  - Example: `CORS_ALLOW_ORIGINS=http://example.com:8000,https://example.com`

### HTTPS Setup

To enable HTTPS:

1. **Create certificates directory:**
   ```bash
   mkdir -p certs
   ```

2. **Place your SSL certificates:**
   ```bash
   cp your-cert.pem certs/cert.pem
   cp your-key.pem certs/key.pem
   ```

3. **Update `.env`:**
   ```bash
   HTTPS_ENABLED=true
   ```

4. **Restart the container:**
   ```bash
   docker-compose restart
   ```

Certificates are mounted read-only from `./certs` to `/app/certs` in the container.

### Registering a FabricStudio OAuth Application

To use FabricStudio APIs, you need OAuth Client ID and Client Secret:

1. **Register an application:**
   - Navigate to: `https://[YOUR_FabricStudio]/oauth2/applications/register/`

2. **Fill the registration form:**
   - **Name**: Any descriptive name (e.g., "FabricStudio Assistant")
   - **Client type**: Confidential
   - **Authorization grant type**: Client credentials
   - **Algorithm**: HMAC with SHA-2 256
   - Save and copy the generated Client ID and Client Secret

3. **Use in the application:**
   - Go to **NHI Management > NHI Credentials**
   - Add a new credential with your Client ID and Client Secret
   - The secret is encrypted and stored securely
   - Tokens are retrieved and refreshed automatically

## Usage

### Starting the Application

**Using helper script (recommended):**
```bash
./scripts/docker-start.sh
```

**Rebuild without cache:**
```bash
./scripts/docker-start.sh --rebuild
```

**Manual commands:**
```bash
docker-compose build
docker-compose up -d
```

### Managing the Container

**Start:**
```bash
docker-compose up -d
```

**Stop:**
```bash
docker-compose down
```

**Restart:**
```bash
docker-compose restart
# Or:
docker-compose down && docker-compose up -d
```

**View logs:**
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f fabricstudio-api
```

**Execute commands in container:**
```bash
docker-compose exec fabricstudio-api <command>
```

### User Management

**Create users:**
```bash
# Edit scripts/create_users.py to customize
python scripts/create_users.py
```

**Reset user password:**
```bash
python scripts/reset_user_password.py <username>
```

**Default user:**
- Username: `admin`
- Password: `FortinetAssistant1!` (change after first login)

### Database Management

**Backup database:**
```bash
cp data/fabricstudio_ui.db data/fabricstudio_ui.db.backup.$(date +%Y%m%d_%H%M%S)
```

**Verify database:**
```bash
sqlite3 data/fabricstudio_ui.db "SELECT COUNT(*) FROM nhi_credentials;"
sqlite3 data/fabricstudio_ui.db "SELECT COUNT(*) FROM configurations;"
```

**⚠️ Important: Preserving Data During Rebuilds**

The database is stored in `./data/fabricstudio_ui.db` and persists via Docker volume mount.

**✅ SAFE - Preserves data:**
```bash
docker-compose down        # Stop containers (keeps volumes)
docker-compose build       # Rebuild image
docker-compose up -d       # Start with existing data
```

**❌ DANGEROUS - Deletes all data:**
```bash
# ⚠️ DO NOT USE unless you want to delete all data
docker-compose down -v     # Removes volumes and deletes database
docker-compose rm -v       # Also removes volumes
```

## MCP (Model Context Protocol)

The FabricStudio API exposes an MCP endpoint for integration with MCP clients.

### MCP Endpoint

- **URL**: `http://your-api-url/mcp`
- **Method**: POST
- **Authentication**: API key via `X-API-Key` header
- **Protocol**: JSON-RPC 2.0

### Available MCP Tools

- `list_templates` - List all available templates
- `list_repositories` - List all repositories
- `list_templates_for_repo` - List templates in a repository
- `create_configuration` - Create a new configuration
- `update_configuration` - Update an existing configuration
- `delete_configuration` - Delete a configuration
- `list_configurations` - List all configurations
- `execute_configuration` - Execute/run a configuration
- `list_nhi_credentials` - List NHI credentials
- `get_nhi_credential` - Get NHI credential details
- `create_nhi_credential` - Create a new NHI credential
- `update_nhi_credential` - Update an NHI credential
- `delete_nhi_credential` - Delete an NHI credential
- `list_ssh_keys` - List SSH keys
- `list_ssh_command_profiles` - List SSH command profiles
- `list_events` - List scheduled events
- `create_event` - Schedule a new event
- `update_event` - Update a scheduled event
- `delete_event` - Delete a scheduled event

### Using mcp-remote

To connect a local MCP client to the remote FabricStudio API:

1. **Configure your MCP client** (e.g., Cursor, Warp):
   ```json
   {
     "mcpServers": {
       "fabricstudio": {
         "command": "npx",
         "args": [
           "mcp-remote",
           "http://localhost:8000/mcp",
           "--header",
           "X-API-Key: ${FABRICSTUDIO_API_KEY}"
         ],
         "env": {
           "FABRICSTUDIO_API_KEY": "your-api-key-here"
         }
       }
     }
   }
   ```

2. **Set the API key** in your environment or config file

3. **Restart your MCP client**

The `mcp-remote` package acts as a bridge between local stdio-based MCP clients and the remote HTTP MCP server.

## Database

The application uses SQLite for data storage. The database file `fabricstudio_ui.db` is created automatically when the application starts.

### Database Schema

- `users` - User accounts for authentication (with encrypted passwords)
- `sessions` - Server-side session storage for user authentication and token management
- `configurations` - Saved FabricStudio configurations
- `event_schedules` - Scheduled events
- `event_executions` - Execution history for scheduled events (including SSH execution details)
- `nhi_credentials` - NHI credential storage (with encrypted secrets)
- `nhi_tokens` - Encrypted tokens per host per credential
- `cached_templates` - Cached template information
- `cached_repositories` - Cached repository information per host
- `ssh_keys` - SSH key pairs (public keys and encrypted private keys)
- `ssh_command_profiles` - SSH command profiles with optional SSH key association
- `audit_logs` - Audit trail of user actions

### Database Location

- **Docker**: `/app/data/fabricstudio_ui.db` (mounted from `./data/fabricstudio_ui.db`)
- **Manual**: Path specified by `DB_PATH` environment variable

### Database Persistence

The database and logs are stored in the `./data` and `./logs` directories, which are mounted as volumes. This ensures:
- Data persists across container restarts
- Easy backup and restore
- Data survives container deletion

**Important:** Backup the `./data` directory regularly!

## Security

### Authentication & Authorization

- **User Authentication**: Secure password-based authentication with bcrypt password hashing
- **Session-Based Token Management**: Tokens are stored server-side in encrypted sessions, never exposed to the frontend
- **HTTP-Only Cookies**: Session cookies are HTTP-only, preventing JavaScript access

### Data Encryption

- **NHI Credential Security**: Client secrets are encrypted using Fernet (symmetric encryption) and never returned to the frontend
- **SSH Key Security**: Private SSH keys are encrypted using Fernet before storage and are never returned to the frontend
- **Token Encryption**: All tokens are encrypted before storage in the database
- **Password-Based Key Derivation**: Passwords are used to derive encryption keys using PBKDF2 (100,000 iterations)
- **Password Hashing**: User passwords are hashed using bcrypt before storage

### Token Management

- **Lazy Refresh**: Tokens are automatically refreshed when API requests detect expiration or imminent expiration (< 1 minute)
- **Proactive Refresh**: A background task runs every 2 minutes to refresh tokens expiring within 5 minutes
- **Session-Based Storage**: Tokens are stored server-side in encrypted sessions, identified by HTTP-only cookies
- **Transparent Operation**: Token refresh happens automatically without user intervention

### Additional Security Measures

- **Container Security**: Application runs as non-root user (`fabricstudio`)
- **Resource Limits**: CPU and memory limits configured in docker-compose.yml
- **SSL Certificate Security**: Certificates mounted read-only (`:ro` flag)
- **CSRF Protection**: Session-based CSRF protection middleware
- **Audit Logging**: User actions are logged for security auditing
- **SSH Command Execution**: SSH commands are executed securely using Paramiko, with error validation and output checking

### Security Best Practices

1. **Never commit `.env` file** - Use `.env.example` as a template
2. **Generate strong `FS_SERVER_SECRET`** - Use `openssl rand -base64 32`
3. **Change default passwords** - Update admin password after first login
4. **Use HTTPS in production** - Enable `HTTPS_ENABLED=true` with valid certificates
5. **Regular backups** - Backup `./data` directory regularly
6. **Keep dependencies updated** - Regularly update Python packages and Docker images

## Troubleshooting

### Application Won't Start

1. **Check Docker is running:**
   ```bash
   docker ps
   # If not running, start Docker/Colima
   ```

2. **Check container status:**
   ```bash
   docker-compose ps
   docker-compose logs -f fabricstudio-api
   ```

3. **Verify environment variables:**
   ```bash
   docker-compose exec fabricstudio-api env | grep FS_SERVER_SECRET
   # Should show a value, not "CHANGE_ME_IN_PRODUCTION"
   ```

4. **Check port availability:**
   ```bash
   # Check if port is in use
   lsof -i :8000
   # Or change PORT in .env
   ```

5. **Database permission errors ("unable to open database file"):**
   ```bash
   # Ensure data directory exists and has proper permissions
   mkdir -p data logs certs
   chmod 755 data logs certs
   
   # If directory was created by Docker as root, fix ownership:
   sudo chown -R $USER:$USER data logs
   
   # Restart container
   docker-compose restart
   ```

### Changes Not Reflected

1. **Rebuild without cache:**
   ```bash
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

2. **Clear browser cache:**
   - Hard refresh: `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)
   - Or use incognito/private browsing mode

3. **Verify container status:**
   ```bash
   docker-compose ps
   docker-compose logs -f fabricstudio-api
   ```

### Database Issues

1. **Check database exists:**
   ```bash
   ls -lh data/fabricstudio_ui.db
   ```

2. **Verify database integrity:**
   ```bash
   sqlite3 data/fabricstudio_ui.db "PRAGMA integrity_check;"
   ```

3. **Restore from backup:**
   ```bash
   cp data/fabricstudio_ui.db.backup.YYYYMMDD_HHMMSS data/fabricstudio_ui.db
   docker-compose restart
   ```

### Authentication Issues

1. **Reset user password:**
   ```bash
   python scripts/reset_user_password.py <username>
   ```

2. **Create new user:**
   ```bash
   # Edit scripts/create_users.py
   python scripts/create_users.py
   ```

### MCP Connection Issues

1. **Verify MCP is enabled:**
   ```bash
   docker-compose exec fabricstudio-api env | grep MCP_ENABLED
   # Should be "true"
   ```

2. **Check API key:**
   ```bash
   docker-compose exec fabricstudio-api env | grep MCP_API_KEY
   ```

3. **Test MCP endpoint:**
   ```bash
   curl -X POST http://localhost:8000/mcp \
     -H "Content-Type: application/json" \
     -H "X-API-Key: your-api-key" \
     -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}},"id":1}'
   ```

### Token Refresh Issues

1. **Check NHI credentials:**
   - Verify Client ID and Secret are correct
   - Check token expiration in NHI Management

2. **Check logs:**
   ```bash
   docker-compose logs -f fabricstudio-api | grep -i token
   ```

3. **Manually refresh tokens:**
   - Go to NHI Management > NHI Credentials
   - Click "Refresh Tokens" for the credential

## Project Structure

```
FabricStudioAPI/
├── src/
│   ├── app.py                 # FastAPI application and API endpoints
│   ├── mcp_router.py          # MCP protocol router
│   ├── config.py              # Configuration constants
│   ├── db_utils.py            # Database utilities
│   ├── init_empty_db.py       # Database initialization script
│   └── fabricstudio/
│       ├── auth.py            # Authentication utilities
│       └── fabricstudio_api.py # FabricStudio API client
├── scripts/
│   ├── create_users.py        # User creation/management script
│   ├── reset_user_password.py # Password reset utility
│   ├── docker-start.sh        # Container startup helper script
│   ├── docker-entrypoint.sh   # Container entrypoint script
│   └── setup-colima.sh        # Colima setup script (Mac)
├── frontend/
│   ├── index.html             # Main HTML file
│   ├── app.js                 # Frontend JavaScript
│   ├── styles.css             # Stylesheet
│   ├── configurations.html    # Configurations section
│   ├── event-schedule.html    # Event Schedule section
│   ├── nhi-management.html    # NHI Management section
│   ├── ssh-command-profiles.html # SSH Command Profiles section
│   ├── ssh-keys.html          # SSH Keys section
│   └── fonts/                 # Custom font files (Inter)
├── data/                      # Database and persistent data (created at runtime)
├── logs/                      # Application logs (created at runtime)
├── certs/                     # SSL certificates (optional, for HTTPS)
├── Dockerfile                 # Docker image definition
├── docker-compose.yml         # Docker Compose configuration
├── requirements.txt           # Python dependencies
├── .env                       # Environment variables (not in git)
└── README.md                  # This file
```

## License

[Add your license here]
