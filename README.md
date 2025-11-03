# FabricStudio API

A FastAPI-based web application for managing FabricStudio configurations, NHI credentials, and event scheduling.

## Features

- **FabricStudio Preparation**: Configure and manage FabricStudio hosts, authenticate, and create/run workspaces
- **NHI Management**: Store and manage NHI credentials with encrypted client secrets
- **Configuration Management**: Save, load, and edit FabricStudio configurations
- **Event Scheduling**: Schedule automated tasks with date and time support
- **Template Caching**: Cache templates for faster access

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
```

### Starting/Stopping the Container

**Start:**
```bash
docker-compose up -d
```

**Stop:**
```bash
docker-compose down
```

**View logs:**
```bash
docker-compose logs -f
```

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

For more detailed Docker documentation, see [DOCKER.md](DOCKER.md) or [README-DOCKER.md](README-DOCKER.md).

## Database

The application uses SQLite for data storage. The database file `fabricstudio_ui.db` is created automatically when the application starts, or you can initialize it manually using `init_empty_db.py`.

The database contains the following tables:
- `configurations`: Saved FabricStudio configurations
- `event_schedules`: Scheduled events
- `nhi_credentials`: NHI credential storage (with encrypted secrets)
- `nhi_tokens`: Encrypted tokens per host per credential
- `cached_templates`: Cached template information

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
│   ├── preparation.html  # FabricStudio Preparation section
│   ├── configurations.html # Configurations section
│   ├── event-schedule.html # Event Schedule section
│   └── nhi-management.html # NHI Management section
└── requirements.txt       # Python dependencies
```

## Security

- NHI client secrets are encrypted using Fernet (symmetric encryption)
- Tokens are encrypted before storage in the database
- Passwords are used to derive encryption keys using PBKDF2

## License

[Add your license here]

