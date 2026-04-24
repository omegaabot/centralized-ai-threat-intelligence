# Centralized AI-Based Threat Intelligence Dashboard

Centralized AI-Based Threat Intelligence Dashboard is a FastAPI-based cybersecurity project that collects, analyzes, stores, and visualizes Indicators of Compromise (IOCs) such as domains, IP addresses, URLs, and file hashes.

## Overview

The main goal of this project is to create a centralized threat intelligence platform for academic demonstration and practical cybersecurity analysis. Instead of only storing IOC records, the system intelligently:

- classifies IOC types automatically
- assigns threat families
- generates confidence and risk scores
- stores all threat records in a database
- visualizes the data in charts and dashboard panels
- highlights high-risk alerts
- provides detailed threat views
- generates report-style summaries from the same dataset

## Key Features

- Login page for controlled dashboard access
- Add IOC module for manual threat entry
- Automatic IOC detection for:
  - Domain
  - IP Address
  - URL
  - File Hash
- AI-style threat analysis and scoring
- Risk classification as `LOW`, `MEDIUM`, and `HIGH`
- Threat feed simulation with bulk IOC generation
- Dashboard with graphs and KPI cards
- Search and filter support by IOC, type, risk, and status
- Alerts page for high-risk threats
- Threat detail page for incident drilldown
- Reports page with malware, phishing, and other threat summaries
- Status tracking as `Open`, `Investigating`, and `Closed`

## Tech Stack

- Backend: FastAPI
- Language: Python
- Database: SQLite
- Templates: Jinja2
- Frontend: HTML, CSS, JavaScript
- Visualization: Chart.js
- Server: Uvicorn
- Containerization: Docker & Docker Compose

## Project Structure

```text
centralized-ai-threat-intelligence/
├── backend/
│   ├── api/
│   │   └── health.py
│   ├── services/
│   │   ├── analysis.py
│   │   ├── repository.py
│   │   └── __init__.py
│   ├── static/
│   │   ├── css/
│   │   │   └── styles.css
│   │   └── js/
│   │       └── dashboard.js
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── add_ioc.html
│   │   ├── feed.html
│   │   ├── alerts.html
│   │   ├── reports.html
│   │   └── threat_detail.html
│   ├── main.py
│   └── project.db
├── docs/
├── screenshots/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Main Modules

### 1. Dashboard

The dashboard is the main monitoring interface of the system. It includes:

- KPI summary cards
- top threat family chart
- risk distribution chart
- source distribution chart
- threat trend chart
- status overview chart
- tactics coverage chart
- active vulnerabilities panel
- latest reports panel
- filterable IOC explorer table

### 2. Add IOC

This module allows the user to add a suspicious indicator manually. Each IOC is analyzed and stored with:

- detected type
- threat category
- confidence
- score
- risk level
- source
- status

### 3. Threat Feed

This module simulates external threat intelligence ingestion. It supports:

- manual feed entry
- automatic bulk feed generation

### 4. Alerts

The alerts module focuses on high-risk threats and supports:

- high-risk filtering
- status-based filtering
- critical threat monitoring
- status updates

### 5. Threat Detail

Each IOC row can open a dedicated threat detail page that shows:

- event profile
- score and confidence
- threat summary
- telemetry
- recommended actions
- related threats
- workflow status

### 6. Reports

The reports module automatically groups current threat data by family and generates:

- threat-family summaries
- average score details
- top IOC type and source
- latest seen time
- example related IOCs
- new additions section

## How the System Works

1. User logs into the platform.
2. User adds IOC manually or through the feed module.
3. Backend detects IOC type.
4. Threat analysis engine assigns:
   - threat family
   - confidence
   - score
   - risk level
5. Threat record is stored in SQLite.
6. Dashboard reads the stored data and generates visual analytics.
7. High-risk threats are shown in Alerts.
8. Reports are generated from the same stored dataset.
9. Clicking an IOC opens a detailed threat page.

## Backend Logic

### IOC Analysis

The analysis logic is implemented in `backend/services/analysis.py`.

It performs:

- IOC type detection
- threat family mapping
- deterministic score generation
- confidence calculation
- risk classification

### Repository Layer

The repository logic is implemented in `backend/services/repository.py`.

It handles:

- database initialization
- table creation
- threat insertion
- record updates
- search and filtering
- dashboard analytics
- report generation
- threat detail retrieval

## Database

The project uses a SQLite table named `threats`.

Main fields:

- `id`
- `ioc`
- `type`
- `threat`
- `confidence`
- `score`
- `status`
- `source`
- `created_at`
- `updated_at`

## Setup Instructions

### Option 1: Local Setup

#### 1. Clone the project

```bash
git clone https://github.com/your-repository/centralized-ai-threat-intelligence.git
cd centralized-ai-threat-intelligence
```

#### 2. Create a virtual environment

```bash
python -m venv venv
```

#### 3. Activate the environment

Windows:

```bash
venv\Scripts\activate
```

macOS / Linux:

```bash
source venv/bin/activate
```

#### 4. Install dependencies

```bash
pip install -r requirements.txt
```

#### 5. Run the application

```bash
uvicorn backend.main:app --reload
```

#### 6. Open in browser

```text
http://127.0.0.1:8000
```

Demo credentials:

- Username: `admin`
- Password: `admin123`

### Option 2: Docker Setup

#### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed on your system
- [Docker Compose](https://docs.docker.com/compose/install/) installed on your system

#### Steps

1. **Clone the repository**

```bash
git clone https://github.com/your-repository/centralized-ai-threat-intelligence.git
cd centralized-ai-threat-intelligence
```

2. **Build and start the containers**

```bash
docker-compose up -d
```

3. **Wait for the application to start**

The application will be available at:

```text
http://localhost:8000
```

4. **View logs**

```bash
docker-compose logs -f app
```

5. **Stop the containers**

```bash
docker-compose down
```

#### Docker Commands Reference

**Build the Docker image:**

```bash
docker build -t threat-intelligence:latest .
```

**Run container directly (without compose):**

```bash
docker run -d -p 8000:8000 --name threat-app threat-intelligence:latest
```

**View running containers:**

```bash
docker ps
```

**View container logs:**

```bash
docker logs -f threat-app
```

**Stop and remove containers:**

```bash
docker stop threat-app
docker rm threat-app
```

**Rebuild without cache:**

```bash
docker-compose up -d --build --no-cache
```

#### Dockerfile Details

The Dockerfile includes:

- Python 3.11 slim base image
- Installation of system dependencies
- Python dependencies from requirements.txt
- Exposure of port 8000
- Uvicorn server startup with host 0.0.0.0

#### docker-compose.yml Details

The compose file configures:

- Service name: `app`
- Port mapping: 8000:8000
- Volume mount for database persistence
- Environment variables
- Automatic restart policy

#### Troubleshooting Docker Issues

**Port 8000 is already in use:**

```bash
# Find process using port 8000
lsof -i :8000

# Kill the process (macOS/Linux)
kill -9 <PID>

# Or use a different port in docker-compose.yml
```

**Permission denied errors:**

```bash
# On Linux, add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Container exits immediately:**

```bash
# Check logs for errors
docker-compose logs app

# Verify requirements are installed
docker-compose up --build
```

**Clear Docker resources:**

```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune

# Remove unused volumes
docker volume prune

# Full cleanup (careful!)
docker system prune -a
```

## Requirements

The project currently uses:

- `fastapi`
- `uvicorn[standard]`
- `jinja2`
- `python-multipart`

## Health Route

The backend also includes a health-check endpoint:

- `GET /api/health`

## Future Enhancements

- Integration with real threat intelligence APIs
- VirusTotal / AbuseIPDB / MISP support
- PostgreSQL migration
- Real-time updates using websockets
- PDF report export
- Role-based authentication
- Advanced ML-based threat scoring
- Kubernetes deployment
- Multi-container orchestration


## Project Status

- Core backend completed
- Dashboard UI completed
- Alerts module completed
- Threat feed simulation completed
- Reports module completed
- Threat detail drilldown completed
- Docker support added
