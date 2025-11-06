# FabricStudio API

A FastAPI-based web application for managing FabricStudio configurations, NHI credentials, and event scheduling.

## Features

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

- Python 3.8+
- pip

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd FabricStudioAPI
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
python init_empty_db.py
```

Or the database will be automatically created when you first run the application.

### Running the Application

**Option 1: Run locally (without Docker)**
```bash
uvicorn app:app --reload --port 8000
```

**Option 2: Run with Docker (Recommended)**

This project uses **Colima** (a lightweight Docker alternative for Mac) instead of Docker Desktop. See [Docker Deployment](#docker-deployment) section below for details.

The application will be available at `http://localhost:8000`

## Docker Deployment

This project uses **Colima** as a lightweight Docker alternative for Mac. Colima is much lighter than Docker Desktop (~200MB vs 1GB+) and works seamlessly with Docker commands.

### Prerequisites

- Colima installed (see setup instructions below)
- Docker Compose installed

### Quick Setup

1. **Install Colima (one command):**
   ```bash
   ./setup-colima.sh
   ```

2. **Set up environment variables:**
   ```bash
   cp env.example .env
   # Edit .env and set FS_SERVER_SECRET (generate with: openssl rand -base64 32)
   ```

3. **Start the application:**
   ```bash
   ./docker-start.sh
   ```
   
   **To rebuild without cache:**
   ```bash
   ./docker-start.sh --rebuild
   ```

### Manual Setup

If you prefer to set up manually:

1. **Install Colima:**
   ```bash
   brew install colima docker docker-compose
   colima start
   ```

2. **Create environment file:**
   ```bash
   cp env.example .env
   # Edit .env and set FS_SERVER_SECRET
   ```

3. **Build and start:**
   ```bash
   docker-compose build
   docker-compose up -d
   ```

### Building the Docker Image

To build the Docker image:
```bash
docker-compose build
```

To rebuild from scratch (no cache):
```bash
docker-compose build --no-cache
docker-compose down  # Stop existing containers
docker-compose up -d  # Start with new image
```

**Using the helper script:**
```bash
./docker-start.sh --rebuild
```

This will rebuild without cache and restart containers automatically.

### Starting/Stopping the Container

**Start:**
```bash
docker-compose up -d
```

**Stop:**
```bash
docker-compose down
```

**Restart (to pick up code changes):**
```bash
docker-compose down
docker-compose up -d
```

**View logs:**
```bash
docker-compose logs -f
```

### Troubleshooting Docker Build Issues

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

3. **Verify the new image is being used:**
   ```bash
   docker-compose ps  # Check container status
   docker-compose logs -f  # Check logs for errors
   ```

4. **Check if files are in the build context:**
   - Ensure `.dockerignore` isn't excluding files you've changed
   - Frontend files should be in `frontend/` directory

### Database Persistence

The database and logs are stored in the `./data` and `./logs` directories, which are mounted as volumes. This ensures:
- Data persists across container restarts
- Easy backup and restore
- Data survives container deletion

**Important:** Backup the `./data` directory regularly!

### Security Notes

- The `FS_SERVER_SECRET` environment variable is **required** for encrypting sensitive data in the database
- Never commit `.env` file to version control
- The container runs as a non-root user for enhanced security
- All sensitive data (passwords, tokens) are encrypted before storage

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
- `configurations`: Saved FabricStudio configurations
- `event_schedules`: Scheduled events
- `event_executions`: Execution history for scheduled events (including SSH execution details)
- `nhi_credentials`: NHI credential storage (with encrypted secrets)
- `nhi_tokens`: Encrypted tokens per host per credential
- `sessions`: Server-side session storage for token management
- `cached_templates`: Cached template information
- `ssh_keys`: SSH key pairs (public keys and encrypted private keys)
- `ssh_command_profiles`: SSH command profiles with optional SSH key association

## Project Structure

```
FabricStudioAPI/
├── app.py                 # FastAPI application and API endpoints
├── init_empty_db.py       # Database initialization script
├── fabricstudio/
│   ├── auth.py           # Authentication utilities
│   └── fabricstudio_api.py # FabricStudio API client
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
└── requirements.txt       # Python dependencies
```

## Security

- **Session-Based Token Management**: Tokens are stored server-side in encrypted sessions, never exposed to the frontend
- **Automatic Token Refresh**: Tokens refresh automatically before expiration (5 minutes before) to prevent interruptions
- **NHI Credential Security**: Client secrets are encrypted using Fernet (symmetric encryption) and never returned to the frontend
- **SSH Key Security**: Private SSH keys are encrypted using Fernet before storage and are never returned to the frontend
- **Token Encryption**: All tokens are encrypted before storage in the database
- **Password-Based Key Derivation**: Passwords are used to derive encryption keys using PBKDF2 (100,000 iterations)
- **HTTP-Only Cookies**: Session cookies are HTTP-only, preventing JavaScript access
- **Secure Session Keys**: Session keys are derived from encryption passwords and session IDs
- **SSH Command Execution**: SSH commands are executed securely using Paramiko, with error validation and output checking

### Token Management

The application uses a sophisticated token management system:

- **Lazy Refresh**: Tokens are automatically refreshed when API requests detect expiration or imminent expiration (< 1 minute)
- **Proactive Refresh**: A background task runs every 2 minutes to refresh tokens expiring within 5 minutes
- **Session-Based Storage**: Tokens are stored server-side in encrypted sessions, identified by HTTP-only cookies
- **Transparent Operation**: Token refresh happens automatically without user intervention

## License

[Add your license here]

