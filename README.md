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

```bash
uvicorn app:app --reload --port 8000
```

The application will be available at `http://localhost:8000`

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
├── main.py                # Example/test script
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

