# SentinelCore Autonomous Recon Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER'S LAPTOP (Arch Linux)                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐        ┌─────────────────────────────────┐    │
│  │   Web Browser   │◄──────►│  FastAPI Backend (Port 8000)    │    │
│  │   (index.html)  │        │                                 │    │
│  └─────────────────┘        │  - /api/autonomous/*            │    │
│                             │  - NVIDIA NIM API Integration   │    │
│                             │  - SQLite Database              │    │
│                             │  - Report Management            │    │
│                             └────────────┬────────────────────┘    │
│                                          │                         │
│                                          ▼                         │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              Docker Container (Recon Agent)                   │ │
│  │  ┌─────────────────────────────────────────────────────────┐ │ │
│  │  │  Security Tools:                                        │ │ │
│  │  │  - nmap (port scanning, service detection)              │ │ │
│  │  │  - gobuster (directory/DNS brute-force)                 │ │ │
│  │  │  - nuclei (vulnerability scanning)                      │ │ │
│  │  │  - nikto (web server scanning)                          │ │ │
│  │  │  - subfinder (subdomain enumeration)                    │ │ │
│  │  │  - whatweb (tech fingerprinting)                        │ │ │
│  │  │  - ffuf (web fuzzer)                                   │ │ │
│  │  └─────────────────────────────────────────────────────────┘ │ │
│  │                                                               │ │
│  │  Capabilities: NET_ADMIN, NET_RAW (for nmap SYN scans)       │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌─────────────────┐        ┌─────────────────┐                    │
│  │  SQLite DB      │        │  Reports Dir    │                    │
│  │  (sentinelcore) │        │  (./reports/)   │                    │
│  └─────────────────┘        └─────────────────┘                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
1. USER INPUT
   User enters target domain → Web UI → POST /api/autonomous/start

2. JOB CREATION
   Backend creates AutonomousReconJob record → Status: PENDING
   Backend spawns async task for recon execution

3. AI ORCHESTRATION
   Backend calls NVIDIA NIM API with system prompt
   AI analyzes target and decides which tools to run
   
4. TOOL EXECUTION
   Backend executes tools (nmap, gobuster, etc.) via subprocess
   Tools run on host system (for local development)
   OR inside Docker container (for production/isolation)
   
5. RESULT ANALYSIS
   AI interprets tool outputs
   AI decides next steps or generates report
   
6. REPORT GENERATION
   AI generates markdown report with:
   - Executive Summary
   - Technical Findings
   - Raw Tool Outputs
   - Recommendations

7. DELIVERY
   Report saved to ./reports/ and database
   User views in browser or downloads as .md file
```

## API Endpoints

### Autonomous Recon Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/autonomous/start` | Start new recon job |
| GET | `/api/autonomous/status/{job_id}` | Get job status/progress |
| GET | `/api/autonomous/report/{job_id}` | Get completed report |
| GET | `/api/autonomous/report/{job_id}/download` | Download report as .md |
| GET | `/api/autonomous/history` | List recent jobs |
| GET | `/api/autonomous/outputs/{job_id}` | Get raw tool outputs |
| POST | `/api/autonomous/cancel/{job_id}` | Cancel running job |
| DELETE | `/api/autonomous/{job_id}` | Delete job and data |

### Request/Response Examples

**Start Recon:**
```json
POST /api/autonomous/start
{
  "target": "example.com"
}

Response:
{
  "job_id": 1,
  "target": "example.com",
  "status": "pending",
  "message": "Autonomous recon job started."
}
```

**Check Status:**
```json
GET /api/autonomous/status/1

Response:
{
  "id": 1,
  "target": "example.com",
  "status": "running",
  "progress": 45,
  "current_step": "Running nmap -sV",
  "tools_used": ["subfinder", "whatweb", "nmap"],
  "created_at": "2024-03-21T12:00:00",
  "started_at": "2024-03-21T12:00:05"
}
```

**Get Report:**
```json
GET /api/autonomous/report/1

Response:
{
  "id": 1,
  "target": "example.com",
  "status": "completed",
  "report": "# Recon Report: example.com\n\n## Executive Summary\n...",
  "tools_used": ["nmap", "gobuster", "nuclei"],
  "completed_at": "2024-03-21T12:15:00"
}
```

## Database Schema

### autonomous_recon_jobs
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| target | String | Target domain/IP |
| status | String | pending/running/completed/failed/cancelled |
| progress | Integer | 0-100 completion percentage |
| current_step | String | Current tool/action |
| report_markdown | Text | Generated report content |
| report_path | String | Path to .md file |
| error_message | Text | Error details if failed |
| tools_used | Text | JSON list of tools executed |
| started_at | DateTime | Job start timestamp |
| completed_at | DateTime | Job completion timestamp |
| created_at | DateTime | Record creation timestamp |

### recon_tool_outputs
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| job_id | Integer | Foreign key to job |
| tool_name | String | Tool that was run |
| command | Text | Full command executed |
| raw_output | Text | Raw tool output |
| parsed_findings | Text | Parsed/structured findings |
| execution_time_seconds | Float | Tool runtime |
| created_at | DateTime | Record creation timestamp |

## Environment Variables

```bash
# NVIDIA NIM API
NVIDIA_NIM_API_KEY=your_key_here
NVIDIA_NIM_MODEL=meta/llama-3.1-8b-instruct

# Docker Settings
RECON_CONTAINER_NAME=sentinelcore-recon-agent
RECON_DOCKER_IMAGE=sentinelcore-recon:latest

# File Paths
REPORTS_DIR=./reports
MAX_CONCURRENT_RECON_JOBS=3
```

## Setup Instructions

### Option 1: Local Development (Tools on Host)

```bash
# Install security tools on Arch
sudo pacman -S nmap gobuster nikto ffuf

# Install AUR packages
yay -S subfinder-bin nuclei-bin whatweb

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Add NVIDIA NIM API key to .env
echo "NVIDIA_NIM_API_KEY=your_key_here" >> .env

# Run backend
python -m backend.main
```

### Option 2: Docker Deployment

```bash
# Build containers
docker-compose build

# Run containers
docker-compose up -d

# View logs
docker-compose logs -f sentinelcore-backend
```

## Security Considerations

1. **Container Isolation**: Tools run in Docker container with limited capabilities
2. **Network Capabilities**: Only NET_ADMIN and NET_RAW for nmap SYN scans
3. **No Privileged Mode**: Container does NOT have full host access
4. **API Key Security**: Keys stored in .env, not committed to git
5. **Target Validation**: Input sanitization prevents command injection
6. **Rate Limiting**: MAX_CONCURRENT_RECON_JOBS prevents resource exhaustion

## Future Enhancements

1. WebSocket real-time progress updates
2. PDF report generation
3. CVE database integration for vulnerability correlation
4. Custom wordlist upload
5. Scan scheduling and automation
6. Multi-target comparison reports
