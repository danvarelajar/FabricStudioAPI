# FabricStudio API

A FastAPI-based web application for managing FabricStudio configurations, NHI credentials, and event scheduling.

## Features

- **User Authentication**: Secure user authentication with encrypted password storage
- **FabricStudio Runs**: Configure and manage FabricStudio hosts, authenticate, and create/run workspaces
- **SSH Profile Execution**: Execute SSH commands on fabric hosts before workspace installation, with configurable wait times between commands
- **NHI Management**: Store and manage NHI credentials with encrypted client secrets
- **SSH Key Management**: Securely store and manage SSH key pairs (public and encrypted private keys)
- **SSH Command Profiles**: Create reusable SSH command profiles with optional SSH key association
- **Session-Based Token Management**: Secure server-side token storage with automatic refresh
- **Automatic Token Refresh**: Tokens refresh automatically before expiration (proactive and on-demand)
- **Configuration Management**: Save, load, and edit FabricStudio configurations
- **Event Scheduling**: Schedule automated tasks with date and time support, including validation to prevent past scheduling
- **Execution History**: Track detailed execution history for scheduled events, including SSH command execution results
- **Template Caching**: Cache templates for faster access
- **Expert Mode Logging**: Detailed logging with timestamps for debugging
- **Modern UI**: Clean, responsive interface with Inter font family and styled navigation menu

## Setup

### Prerequisites

- Docker and Docker Compose installed
- For Mac: **Colima** (lightweight Docker alternative) - see setup instructions below

### Quick Start

1. **Clone the repository:**
```bash
git clone <repository-url>
cd FabricStudioAPI
```

2. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env and set your configuration values (see Configuration section below)
```

3. **Start the application:**
```bash
./scripts/docker-start.sh
```

The application will be available at `http://localhost:8000` (or the port configured in `.env`)

**Note:** If you've configured a different port or enabled HTTPS, adjust the URL accordingly:
- HTTP: `http://localhost:PORT`
- HTTPS: `https://localhost:PORT`

### Initial Users

**Users are NOT created automatically.** You must create users manually after the first deployment.

**To create initial users:**

1. **Edit `scripts/create_users.py`** to customize which users to create:
   - Modify the `INITIAL_USERS` list with your desired usernames and passwords
   - Default user: `admin` with password `FortinetAssistant1!`

2. **Run the user creation script:**
   ```bash
   python scripts/create_users.py
   ```

   The script will create users defined in `INITIAL_USERS` if they don't already exist. It will not modify existing users.

**To reset a user password:**
```bash
python scripts/reset_user_password.py <username>
```

**Note:** The user creation script can be run multiple times safely - it only creates users that don't exist and won't overwrite existing users.

## Container Deployment

This project uses Docker for deployment. On Mac, **Colima** (a lightweight Docker alternative) is recommended instead of Docker Desktop (~200MB vs 1GB+).

### Prerequisites

- Docker and Docker Compose installed
- For Mac: Install Colima (see below)

### Mac Setup (Colima)

**Install Colima (one command):**
```bash
./scripts/setup-colima.sh
```

This installs Colima and sets it up automatically. Colima works seamlessly with Docker commands.

### Configuration

1. **Create environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` and configure:**
   
   **Required:**
   - `FS_SERVER_SECRET`: Generate with `openssl rand -base64 32` (CRITICAL for encryption)
   
   **Server Configuration:**
   - `HOSTNAME`: Hostname to bind to (default: `0.0.0.0`)
   - `PORT`: Port to listen on (default: `8000`)
   - `HTTPS_ENABLED`: Set to `true` to enable HTTPS (default: `false`)
   - `SSL_CERT_PATH`: Path to SSL certificate (default: `/app/certs/cert.pem`)
   - `SSL_KEY_PATH`: Path to SSL private key (default: `/app/certs/key.pem`)
   
   **FabricStudio API:**
   - `LEAD_FABRIC_HOST`: Primary FabricStudio host
   - `CLIENT_ID`: OAuth Client ID
   - `CLIENT_SECRET`: OAuth Client Secret
   
   **CORS (Optional):**
   - `CORS_ALLOW_ORIGINS`: Comma-separated list of allowed origins (auto-generated if not set)
   
   See `.env.example` for all available options with descriptions.

### Starting the Application

**Using the helper script (recommended):**
```bash
./scripts/docker-start.sh
```

**To rebuild without cache:**
```bash
./scripts/docker-start.sh --rebuild
```

**Manual commands:**
```bash
docker-compose build
docker-compose up -d
```

### Building the Container Image

**Standard build:**
```bash
docker-compose build
```

**Rebuild from scratch (no cache):**
```bash
docker-compose build --no-cache
docker-compose down
docker-compose up -d
```

**Using the helper script:**
```bash
./scripts/docker-start.sh --rebuild
```

This rebuilds without cache and restarts containers automatically.

### Managing the Container

**Start:**
```bash
docker-compose up -d
```

**Stop:**
```bash
docker-compose down
```

**Restart (to pick up configuration changes):**
```bash
docker-compose restart
# Or:
docker-compose down
docker-compose up -d
```

**View logs:**
```bash
docker-compose logs -f
```

**View logs for specific service:**
```bash
docker-compose logs -f fabricstudio-api
```

**Execute commands in container:**
```bash
docker-compose exec fabricstudio-api <command>
```

### Troubleshooting

**If changes aren't reflected after rebuilding:**

1. **Ensure containers are stopped and restarted:**
   ```bash
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

2. **Clear browser cache:**
   - Hard refresh: `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)
   - Or use incognito/private browsing mode
   - The application sets no-cache headers for all frontend files to prevent caching

3. **Verify container status:**
   ```bash
   docker-compose ps  # Check container status
   docker-compose logs -f fabricstudio-api  # Check logs for errors
   ```

4. **Check environment variables:**
   ```bash
   docker-compose exec fabricstudio-api env | grep -E "HOSTNAME|PORT|HTTPS"
   ```

5. **Verify configuration:**
   - Ensure `.env` file exists and has correct values
   - Check that `FS_SERVER_SECRET` is set (required for encryption)
   - Verify `HOSTNAME` and `PORT` match your access URL

### Database Persistence

The database and logs are stored in the `./data` and `./logs` directories, which are mounted as volumes. This ensures:
- Data persists across container restarts
- Easy backup and restore
- Data survives container deletion

**Important:** Backup the `./data` directory regularly!

**⚠️ CRITICAL: Preserving Data During Docker Rebuilds**

The database (including NHI credentials and SSH credentials) is stored in `./data/fabricstudio_ui.db` and is persisted via a Docker volume mount (`./data:/app/data`).

**To preserve data when rebuilding:**
```bash
# ✅ SAFE - Preserves data
docker-compose down        # Stop containers (keeps volumes)
docker-compose build       # Rebuild image
docker-compose up -d       # Start with existing data
```

**⚠️ DANGEROUS - Deletes all data:**
```bash
# ❌ This removes volumes and deletes the database!
docker-compose down -v     # ⚠️ DO NOT USE unless you want to delete all data
docker-compose rm -v       # ⚠️ Also removes volumes
```

**Always backup before rebuild:**
```bash
# Backup database before any rebuild
cp data/fabricstudio_ui.db data/fabricstudio_ui.db.backup.$(date +%Y%m%d_%H%M%S)
```

**Verify data persistence:**
```bash
# Check database exists and has data
ls -lh data/fabricstudio_ui.db
sqlite3 data/fabricstudio_ui.db "SELECT COUNT(*) FROM nhi_credentials;"
sqlite3 data/fabricstudio_ui.db "SELECT COUNT(*) FROM ssh_keys;"
```

### Server Configuration

The application can be configured via environment variables in `.env`:

**Basic Configuration:**
- `HOSTNAME`: Hostname to bind to (default: `0.0.0.0`)
- `PORT`: Port to listen on (default: `8000`)

**HTTPS Configuration:**
- `HTTPS_ENABLED`: Set to `true` to enable HTTPS (default: `false`)
- `SSL_CERT_PATH`: Path to SSL certificate file (default: `/app/certs/cert.pem`)
- `SSL_KEY_PATH`: Path to SSL private key file (default: `/app/certs/key.pem`)

**To enable HTTPS:**

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
   docker-compose down
   docker-compose up -d
   ```

The certificates are automatically mounted from `./certs` to `/app/certs` in the container (read-only for security).

**To change the port:**
```bash
# In .env file
PORT=9000
```

After changing port or HTTPS settings, restart the container:
```bash
docker-compose restart
# Or:
docker-compose down
docker-compose up -d
```

### CORS Configuration

CORS (Cross-Origin Resource Sharing) is automatically configured based on your server settings:

**Auto-generated (default):**
- If `CORS_ALLOW_ORIGINS` is not set, origins are auto-generated from `HOSTNAME`, `PORT`, and `HTTPS_ENABLED`
- Includes localhost variants for development
- Includes the configured hostname if not `0.0.0.0`

**Explicit configuration:**
- Set `CORS_ALLOW_ORIGINS` in `.env` with comma-separated origins:
  ```bash
  CORS_ALLOW_ORIGINS=http://example.com:8000,https://example.com,http://localhost:3000
  ```

**Note:** CSRF protection is session-based and works with any hostname, so it doesn't need CORS configuration.

### Security Notes

- The `FS_SERVER_SECRET` environment variable is **required** for encrypting sensitive data in the database
- Never commit `.env` file to version control (use `.env.example` as a template)
- The container runs as a non-root user for enhanced security
- All sensitive data (passwords, tokens) are encrypted before storage
- SSL certificates are mounted read-only (`:ro` flag) for additional security

For more detailed Docker documentation, see [DOCKER.md](DOCKER.md).

## Registering a FabricStudio OAuth Application (Client ID/Secret)

To use FabricStudio APIs from this app, you need a Client ID and Client Secret.

1) Using the FabricStudio web interface, register an application
- Open your browser and go to the application creation page:
  - `https://[YOUR_FabricStudio]/oauth2/applications/register/`

2) Fill the registration form
- Name: any descriptive name (e.g., "FabricStudio Assistant")
- Client type: Confidential
- Authorization grant type: Client credentials
- Algorithm: HMAC with SHA-2 256
- Save the application. Copy the generated Client ID and Client Secret.

3) Where the Client ID and Client Secret are used in this app
- NHI Management > NHI Credentials: When you save a credential, enter the Client ID and Client Secret. The secret is encrypted and stored; tokens are retrieved per host using these values.
- Token acquisition: The app calls FabricStudio to get access tokens with the client credentials flow. Tokens are stored server-side and refreshed automatically.
- Event schedules: When an auto-run event executes, the stored NHI credential (backed by your Client ID/Secret) is used to fetch/refresh tokens to run tasks.

If you rotate your Client Secret, update the corresponding NHI credential in the app so token acquisition continues to work.

## Database

The application uses SQLite for data storage. The database file `fabricstudio_ui.db` is created automatically when the application starts, or you can initialize it manually using `init_empty_db.py`.

The database contains the following tables:
- `users`: User accounts for authentication (with encrypted passwords)
- `sessions`: Server-side session storage for user authentication and token management
- `configurations`: Saved FabricStudio configurations
- `event_schedules`: Scheduled events
- `event_executions`: Execution history for scheduled events (including SSH execution details)
- `nhi_credentials`: NHI credential storage (with encrypted secrets)
- `nhi_tokens`: Encrypted tokens per host per credential
- `cached_templates`: Cached template information
- `cached_repositories`: Cached repository information per host
- `ssh_keys`: SSH key pairs (public keys and encrypted private keys)
- `ssh_command_profiles`: SSH command profiles with optional SSH key association
- `audit_logs`: Audit trail of user actions

## Project Structure

```
FabricStudioAPI/
├── src/
│   ├── app.py                 # FastAPI application and API endpoints
│   ├── init_empty_db.py       # Database initialization script
│   └── fabricstudio/
│       ├── auth.py           # Authentication utilities
│       └── fabricstudio_api.py # FabricStudio API client
├── scripts/
│   ├── create_users.py       # User creation/management script
│   ├── reset_user_password.py # Password reset utility
│   ├── docker-start.sh       # Container startup helper script
│   ├── docker-entrypoint.sh  # Container entrypoint script
│   └── setup-colima.sh       # Colima setup script (Mac)
├── frontend/
│   ├── index.html        # Main HTML file
│   ├── app.js            # Frontend JavaScript
│   ├── styles.css        # Stylesheet
│   ├── preparation.html  # FabricStudio Runs section
│   ├── configurations.html # Configurations section
│   ├── event-schedule.html # Event Schedule section
│   ├── nhi-management.html # NHI Management section
│   ├── ssh-command-profiles.html # SSH Command Profiles section
│   ├── ssh-keys.html     # SSH Keys section
│   └── fonts/            # Custom font files (Inter)
│       ├── inter-regular.woff2
│       └── inter-bold.woff2
├── data/                 # Database and persistent data (created at runtime)
├── logs/                 # Application logs (created at runtime)
├── Dockerfile            # Docker image definition
├── docker-compose.yml    # Docker Compose configuration
├── .env                  # Environment variables (not in git)
└── requirements.txt      # Python dependencies
```

## Security

- **User Authentication**: Secure password-based authentication with bcrypt password hashing
- **Session-Based Token Management**: Tokens are stored server-side in encrypted sessions, never exposed to the frontend
- **Automatic Token Refresh**: Tokens refresh automatically before expiration (5 minutes before) to prevent interruptions
- **NHI Credential Security**: Client secrets are encrypted using Fernet (symmetric encryption) and never returned to the frontend
- **SSH Key Security**: Private SSH keys are encrypted using Fernet before storage and are never returned to the frontend
- **Token Encryption**: All tokens are encrypted before storage in the database
- **Password-Based Key Derivation**: Passwords are used to derive encryption keys using PBKDF2 (100,000 iterations)
- **Password Hashing**: User passwords are hashed using bcrypt before storage
- **HTTP-Only Cookies**: Session cookies are HTTP-only, preventing JavaScript access
- **Secure Session Keys**: Session keys are derived from encryption passwords and session IDs
- **SSH Command Execution**: SSH commands are executed securely using Paramiko, with error validation and output checking
- **Audit Logging**: User actions are logged for security auditing

### Token Management

The application uses a sophisticated token management system:

- **Lazy Refresh**: Tokens are automatically refreshed when API requests detect expiration or imminent expiration (< 1 minute)
- **Proactive Refresh**: A background task runs every 2 minutes to refresh tokens expiring within 5 minutes
- **Session-Based Storage**: Tokens are stored server-side in encrypted sessions, identified by HTTP-only cookies
- **Transparent Operation**: Token refresh happens automatically without user intervention

## License

[Add your license here]

